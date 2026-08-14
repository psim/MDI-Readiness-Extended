<#
    A BROKEN sensor install must not vanish from the "Sensors healthy" card.

    A half-installed sensor - the updater present, the AATPSensor service absent - reports
    Installed=False. The card's population was strictly Installed -eq 'True', so that machine fell out
    of it; and because False is not null it was not "unreadable" either, so it left BOTH sides of the
    ratio. Measured on the shipped functions:

        one healthy server + one HALF-INSTALLED   ok    1/1  "All sensor services running"
        one healthy server alone                  ok    1/1  "All sensor services running"

    byte-identical - while the SAME PAGE carried a red row for that machine and the issue "The
    AATPSensor service is not installed, although the updater is present". The producer had already
    decided (isOk=False); only the card disagreed. One step away, the honest case:

        one healthy server + one STOPPED service  bad   1/2  "1 not running"

    So a BROKEN INSTALL disclosed less than a merely stopped service, and a gap in the estate improved
    the headline - the campaign's defining defect class.

    The line drawn is between "not deployed" and "deployed wrong", which is the line the producer
    already draws: a server with genuinely no sensor raises no issue and reports no failure, and must
    still be excluded so the card can say "No v2.x sensor installed yet". That control is asserted here
    with equal weight, because counting every sensorless server as broken would be a false red on every
    estate that has not been deployed to yet.

    Asserted on the RENDERED KPI markup of the real Get-mdiOverviewHtml, tone read from the card's own
    class attribute.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$domainAuditing = [PSCustomObject]@{
    Domain                 = 'contoso.com'
    ObjectAuditing         = [PSCustomObject]@{ isObjectAuditingOk = $true }
    ExchangeAuditing       = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    AdfsAuditing           = [PSCustomObject]@{ isAdfsAuditingOk = $true }
    DeletedObjects         = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
    ObjectAuditingMeasured = $true; ExchangeAuditingMeasured = $true
    AdfsAuditingMeasured   = $true; DeletedObjectsMeasured = $true
}

# Built in the shape the REAL producer stores (Get-mdiSensorHealth). Note carefully: it raises "The
# AATPSensor service is not installed" whenever the sensor service is missing, so isSensorHealthOk -
# and therefore SensorHealth - is $false for a genuinely NOT-INSTALLED server as well as for a
# half-installed one. The two are told apart by the UPDATER, which is why NotInstalled below reports
# UpdaterService 'Not installed' and HalfInstalled reports it Running.
function New-Server {
    param([string] $Fqdn, [ValidateSet('Healthy', 'Stopped', 'HalfInstalled', 'NotInstalled')] [string] $State)
    $detail = switch ($State) {
        'Healthy' { [PSCustomObject]@{ Installed = $true; UpdaterService = 'Running'; SensorService = 'Running'; Issues = @(); SensorVersion = '2.240.0' } }
        'Stopped' { [PSCustomObject]@{ Installed = $true; UpdaterService = 'Running'; SensorService = 'Stopped'; Issues = @('The AATPSensor service is Stopped (start mode: Auto)'); SensorVersion = '2.240.0' } }
        'HalfInstalled' { [PSCustomObject]@{ Installed = $false; UpdaterService = 'Running'; SensorService = 'Not installed'; Issues = @('The AATPSensor service is not installed, although the updater is present'); SensorVersion = $null } }
        'NotInstalled' { [PSCustomObject]@{ Installed = $false; UpdaterService = 'Not installed'; SensorService = 'Not installed'; Issues = @('The AATPSensor service is not installed, although the updater is present', 'The AATPSensorUpdater service is not installed; the sensor cannot update itself'); SensorVersion = $null } }
    }
    # The producer's verdict is simply "no issues", so an absent sensor is a failed check in BOTH the
    # half-installed and the not-installed case. Derived here rather than hard-coded so the fixture
    # cannot claim a combination the producer would never emit.
    $health = (@($detail.Issues).Count -eq 0)
    $details = [PSCustomObject]@{}
    Add-Member -InputObject $details -MemberType NoteProperty -Name 'SensorHealthDetails' -Value $detail
    $o = [PSCustomObject]@{
        FQDN        = $Fqdn; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false; Comment = ''
        Details     = $details
    }
    foreach ($c in @('AdvancedAuditing', 'NtlmAuditing', 'PowerSettings', 'RequiredPorts', 'TimeSync')) {
        Add-Member -InputObject $o -MemberType NoteProperty -Name $c -Value $true
    }
    Add-Member -InputObject $o -MemberType NoteProperty -Name 'SensorHealth' -Value $health
    $o
}

function New-Report {
    param([object[]] $Servers)
    [PSCustomObject]@{
        Domain              = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers   = @($Servers); CAServers = @(); EntraConnectServers = @()
        DomainAuditing      = @($domainAuditing); ForestDiscovery = $null
        DomainSchemaVersion = [PSCustomObject]@{ details = 'x'; schemaVersion = 1 }
        LdapPlanGapDomains  = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
    }
}

function Get-SensorKpi {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    $html = (Get-mdiOverviewHtml -Statistics $stats -ReportData $Report) -join ''
    $m = [regex]::Match($html, '<div class="kpi (ok|warn|bad|na)"><span class="kpi-label">Sensors healthy</span><span class="kpi-value">([^<]*)</span><span class="kpi-sub">([^<]*)')
    if (-not $m.Success) { return [PSCustomObject]@{ Tone = 'none'; Value = 'none'; Sub = 'none' } }
    [PSCustomObject]@{ Tone = $m.Groups[1].Value; Value = $m.Groups[2].Value; Sub = [Net.WebUtility]::HtmlDecode($m.Groups[3].Value) }
}

$healthyOnly = Get-SensorKpi (New-Report @((New-Server 'dc1.contoso.com' 'Healthy')))
$half = Get-SensorKpi (New-Report @((New-Server 'dc1.contoso.com' 'Healthy'), (New-Server 'dc2.contoso.com' 'HalfInstalled')))
$stopped = Get-SensorKpi (New-Report @((New-Server 'dc1.contoso.com' 'Healthy'), (New-Server 'dc2.contoso.com' 'Stopped')))
$absent = Get-SensorKpi (New-Report @((New-Server 'dc1.contoso.com' 'Healthy'), (New-Server 'dc2.contoso.com' 'NotInstalled')))
$absentOnly = Get-SensorKpi (New-Report @((New-Server 'dc1.contoso.com' 'NotInstalled')))

'[baseline] the healthy control and the honest failure case'
Assert-That 'one healthy server reads 1/1 green' (($healthyOnly.Tone -eq 'ok') -and ($healthyOnly.Value -eq '1/1')) "(tone='$($healthyOnly.Tone)' value='$($healthyOnly.Value)')"
Assert-That 'a STOPPED service is red' ($stopped.Tone -eq 'bad') "(tone='$($stopped.Tone)' sub='$($stopped.Sub)')"
Assert-That 'and it is counted in the denominator' ($stopped.Value -eq '1/2') "(value='$($stopped.Value)')"

'[the defect] a half-installed sensor must not disappear from the card'
Assert-That 'a half install is counted in the denominator' ($half.Value -eq '1/2') "(value='$($half.Value)')"
Assert-That 'the card is not green' ($half.Tone -ne 'ok') "(tone='$($half.Tone)' sub='$($half.Sub)')"
Assert-That 'the card does not claim all sensor services are running' ($half.Sub -notmatch 'All sensor services running') "(sub='$($half.Sub)')"
# The whole defect in one line: losing a machine must not make the report look like a smaller,
# healthier estate.
Assert-That 'the estate does not render identically to the healthy server alone' (($half.Value -ne $healthyOnly.Value) -or ($half.Tone -ne $healthyOnly.Tone)) "(half='$($half.Tone) $($half.Value)' healthyOnly='$($healthyOnly.Tone) $($healthyOnly.Value)')"

'[consistency] a broken install must not disclose less than a stopped service'
Assert-That 'the half install is toned the same as the stopped service' ($half.Tone -eq $stopped.Tone) "(half='$($half.Tone)' stopped='$($stopped.Tone)')"
Assert-That 'and counted the same' ($half.Value -eq $stopped.Value) "(half='$($half.Value)' stopped='$($stopped.Value)')"

'[wording] the sub-label must not call a half install "installed"'
Assert-That 'the failure sub-label names the service not running' ($half.Sub -match 'not running') "(sub='$($half.Sub)')"
Assert-That 'it does not assert the sensor is installed' ($half.Sub -notmatch 'installed but not running') "(sub='$($half.Sub)')"

'[not-deployed control] a server with genuinely no sensor is NOT a broken install'
# This control is the reason the fix keys on the UPDATER and not on the health verdict: the producer
# reports a FAILED check for a not-installed server too, so admitting every failure would paint a red
# "not running" over an estate that is simply awaiting rollout.
Assert-That 'it stays out of the population' ($absent.Value -eq '1/1') "(value='$($absent.Value)')"
Assert-That 'so a healthy estate awaiting deployment is still green' ($absent.Tone -eq 'ok') "(tone='$($absent.Tone)' sub='$($absent.Sub)')"
Assert-That 'and an estate with no sensor anywhere still says so' ($absentOnly.Sub -match 'No v2.x sensor installed yet') "(sub='$($absentOnly.Sub)')"
Assert-That 'that estate is not painted red' ($absentOnly.Tone -ne 'bad') "(tone='$($absentOnly.Tone)')"

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
