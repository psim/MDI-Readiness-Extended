<#
    Giving up must never score better than measuring.

    A server whose scan stopped PART WAY is never asked about its ports or its name resolution, so it
    contributes no records at all - it does not appear as a blocked port or as an untested probe, it
    simply VANISHES from the population. Every guard on those two cards was then satisfied by the
    servers that did finish, and both went GREEN. Measured on the shipped renderer, the same estate
    produced this ladder:

        port measured BLOCKED      (complete)   bad   1/2  "1 required port(s) blocked"
        probe recorded NOT TESTED  (complete)   warn  1/1  "1 required probe(s) could not be tested"
        server ABANDONED part way               ok    1/1  "No required port blocked among those probed"

    bad -> warn -> OK FOR GIVING UP. The run that looked at least scored best, which is the exact
    defect class this campaign exists to remove, and it is the same fact the console (SCAN INCOMPLETE)
    and the exit code (255) already refuse to present as a measurement.

    The counts themselves are honest - those probes really did pass - so the fix keeps the number and
    refuses the clean bill of health, exactly as the sampling disclosure does.

    Asserted on the RENDERED KPI MARKUP of the real Get-mdiOverviewHtml, with the tone read from the
    card's own class attribute. A test that recomputed the tone expression would keep passing while
    the defect was reintroduced.

    The controls carry equal weight and are the whole point: a genuinely complete, genuinely clean
    estate must STILL render ok/green on both cards, or this "fix" is just a permanent amber that
    everyone learns to ignore.
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

function New-PortRecord {
    param([int] $Port, [string] $Requirement, [string] $Group, [string] $Target, [string] $Detail, $Success)
    [PSCustomObject]@{
        Port = $Port; Requirement = $Requirement; Group = $Group
        Target = $Target; TargetIP = '10.0.0.1'
        Detail = $Detail; Success = $Success; Applicable = $true
    }
}

# The check ORDER matters: a server whose scan stopped part way has the checks it completed and simply
# NO PROPERTY for the ones that never ran, so the partial fixture stops before RequiredPorts.
$checkOrder = @('AdvancedAuditing', 'NtlmAuditing', 'PowerSettings', 'RequiredPorts', 'TimeSync', 'SensorHealth')

function New-Server {
    param([string] $Fqdn, [bool] $Partial, [hashtable] $Checks, $PortResults)
    $details = [PSCustomObject]@{}
    # Port records are read off the SERVER (Get-mdiPortResultRecord), not off a report property. A
    # server abandoned before its ports carries no RequiredPortsDetails at all, which is exactly how it
    # vanishes from the population.
    if ($null -ne $PortResults) {
        Add-Member -InputObject $details -MemberType NoteProperty -Name 'RequiredPortsDetails' `
            -Value ([PSCustomObject]@{ Results = @($PortResults) })
    }
    $o = [PSCustomObject]@{
        FQDN        = $Fqdn; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $Partial
        Comment     = $(if ($Partial) { 'Testing stopped early: The RPC server is unavailable' } else { '' })
        Details     = $details
    }
    foreach ($k in $checkOrder) { if ($Checks.ContainsKey($k)) { Add-Member -InputObject $o -MemberType NoteProperty -Name $k -Value $Checks[$k] } }
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

function Get-Kpi {
    param($Report, [string] $Label)
    $stats = Get-mdiReportStatistics -ReportData $Report
    $html = (Get-mdiOverviewHtml -Statistics $stats -ReportData $Report) -join ''
    $rx = '<div class="kpi (ok|warn|bad|na)"><span class="kpi-label">' + [regex]::Escape($Label) +
          '</span><span class="kpi-value">([^<]*)</span><span class="kpi-sub">([^<]*)'
    $m = [regex]::Match($html, $rx)
    if (-not $m.Success) { return [PSCustomObject]@{ Tone = 'none'; Value = 'none'; Sub = 'none'; Partial = [int] $stats.PartialScanCount } }
    [PSCustomObject]@{
        Tone = $m.Groups[1].Value; Value = $m.Groups[2].Value
        Sub = [Net.WebUtility]::HtmlDecode($m.Groups[3].Value); Partial = [int] $stats.PartialScanCount
    }
}

$allOk = @{ AdvancedAuditing = $true; NtlmAuditing = $true; PowerSettings = $true; RequiredPorts = $true; TimeSync = $true; SensorHealth = $true }
$portsBad = @{ AdvancedAuditing = $true; NtlmAuditing = $true; PowerSettings = $true; RequiredPorts = $false; TimeSync = $true; SensorHealth = $true }
# Stops BEFORE RequiredPorts: the remaining checks never ran, so they are absent, not false.
$stoppedEarly = @{ AdvancedAuditing = $true; NtlmAuditing = $true; PowerSettings = $true }

$dc1Ports = @(
    (New-PortRecord -Port 3268 -Requirement 'Required' -Group 'LDAP' -Target 'dc1.contoso.com' -Detail 'Open' -Success $true)
    (New-PortRecord -Port 137 -Requirement 'AtLeastOne' -Group 'NNR' -Target 'host9.contoso.com' -Detail 'Resolved' -Success $true)
)
$dc2Blocked = @(
    (New-PortRecord -Port 3268 -Requirement 'Required' -Group 'LDAP' -Target 'dc2.contoso.com' -Detail 'Connection refused' -Success $false)
    (New-PortRecord -Port 137 -Requirement 'AtLeastOne' -Group 'NNR' -Target 'host8.contoso.com' -Detail 'No response' -Success $false)
)
$dc2Untested = @(
    (New-PortRecord -Port 3268 -Requirement 'Required' -Group 'LDAP' -Target 'dc2.contoso.com' -Detail 'Not tested (budget exhausted)' -Success $false)
    (New-PortRecord -Port 137 -Requirement 'AtLeastOne' -Group 'NNR' -Target 'host8.contoso.com' -Detail 'Not tested (budget exhausted)' -Success $false)
)
$dc2Open = @(
    (New-PortRecord -Port 3268 -Requirement 'Required' -Group 'LDAP' -Target 'dc2.contoso.com' -Detail 'Open' -Success $true)
    (New-PortRecord -Port 137 -Requirement 'AtLeastOne' -Group 'NNR' -Target 'host8.contoso.com' -Detail 'Resolved' -Success $true)
)
$dc1 = New-Server -Fqdn 'dc1.contoso.com' -Partial $false -Checks $allOk -PortResults $dc1Ports

'[the defect] an abandoned server must not turn the ports card green'
# dc2 stopped part way BEFORE its ports were probed, so it contributes no port record at all.
$partial = New-Report @($dc1, (New-Server -Fqdn 'dc2.contoso.com' -Partial $true -Checks $stoppedEarly -PortResults $null))
$pPorts = Get-Kpi $partial 'Required ports open'
Assert-That 'the fixture really did stop part way' ($pPorts.Partial -ge 1) "(partial=$($pPorts.Partial))"
Assert-That 'the ports card is not painted ok' ($pPorts.Tone -ne 'ok') "(tone='$($pPorts.Tone)' sub='$($pPorts.Sub)')"
Assert-That 'the ports card names the abandoned scan' ($pPorts.Sub -match 'stopped part way') "(sub='$($pPorts.Sub)')"
Assert-That 'the ports card does not claim a clean bill of health' ($pPorts.Sub -notmatch '^No required port blocked$') "(sub='$($pPorts.Sub)')"

'[the defect] and must not turn the NNR card green either'
$pNnr = Get-Kpi $partial 'NNR resolvable targets'
Assert-That 'the NNR card is not painted ok' ($pNnr.Tone -ne 'ok') "(tone='$($pNnr.Tone)' sub='$($pNnr.Sub)')"
Assert-That 'the NNR card names the abandoned scan' ($pNnr.Sub -match 'stopped part way') "(sub='$($pNnr.Sub)')"
Assert-That 'the NNR card does not claim every target resolvable outright' ($pNnr.Sub -notmatch '^Every target resolvable$') "(sub='$($pNnr.Sub)')"

'[ladder] giving up must never outrank measuring'
# The same estate, complete, with the port MEASURED BLOCKED - the honest bad case.
$blocked = New-Report @($dc1, (New-Server -Fqdn 'dc2.contoso.com' -Partial $false -Checks $portsBad -PortResults $dc2Blocked))
$bPorts = Get-Kpi $blocked 'Required ports open'
Assert-That 'a measured blocked port is still bad' ($bPorts.Tone -eq 'bad') "(tone='$($bPorts.Tone)' sub='$($bPorts.Sub)')"

# The same estate, complete, with the probes recorded as NOT TESTED. This is the comparison that
# matters, and the only one that is logically sound: it is the SAME EPISTEMIC STATE as "never
# reached" - in both runs nobody knows whether that server's ports are open - so the two must be
# toned the same. Deliberately NOT compared against the measured-blocked case above: red means "known
# broken, act now" and amber means "unknown", so an abandoned scan ranking above a measured failure is
# correct and forcing it red would be a false alarm on every partial run - a different defect.
$untested = New-Report @($dc1, (New-Server -Fqdn 'dc2.contoso.com' -Partial $false -Checks $allOk -PortResults $dc2Untested))
$uPorts = Get-Kpi $untested 'Required ports open'
$uNnr = Get-Kpi $untested 'NNR resolvable targets'
Assert-That 'an untested probe is amber on a complete scan' ($uPorts.Tone -eq 'warn') "(tone='$($uPorts.Tone)' sub='$($uPorts.Sub)')"
Assert-That 'the abandoned run is toned the same as the untested-probe run' ($pPorts.Tone -eq $uPorts.Tone) "(partial='$($pPorts.Tone)' untested='$($uPorts.Tone)')"
Assert-That 'and the same on the NNR card' ($pNnr.Tone -eq $uNnr.Tone) "(partial='$($pNnr.Tone)' untested='$($uNnr.Tone)')"
# The defect in one line: the two runs know exactly the same nothing, so neither may be greener.
Assert-That 'neither unknown state is green' (($pPorts.Tone -ne 'ok') -and ($uPorts.Tone -ne 'ok')) "(partial='$($pPorts.Tone)' untested='$($uPorts.Tone)')"

'[clean estate control] a genuinely complete, clean run must STILL be green on both cards'
$clean = New-Report @($dc1, (New-Server -Fqdn 'dc2.contoso.com' -Partial $false -Checks $allOk -PortResults $dc2Open))
$cPorts = Get-Kpi $clean 'Required ports open'
$cNnr = Get-Kpi $clean 'NNR resolvable targets'
Assert-That 'the control really is complete' ($cPorts.Partial -eq 0) "(partial=$($cPorts.Partial))"
Assert-That 'the ports card is still ok' ($cPorts.Tone -eq 'ok') "(tone='$($cPorts.Tone)' sub='$($cPorts.Sub)')"
Assert-That 'the ports card still reads clean' ($cPorts.Sub -match 'No required port blocked') "(sub='$($cPorts.Sub)')"
Assert-That 'the ports card does not mention a part-way scan' ($cPorts.Sub -notmatch 'stopped part way') "(sub='$($cPorts.Sub)')"
Assert-That 'the NNR card is still ok' ($cNnr.Tone -eq 'ok') "(tone='$($cNnr.Tone)' sub='$($cNnr.Sub)')"
Assert-That 'the NNR card still reads clean' ($cNnr.Sub -match 'Every target resolvable') "(sub='$($cNnr.Sub)')"
Assert-That 'the NNR card does not mention a part-way scan' ($cNnr.Sub -notmatch 'stopped part way') "(sub='$($cNnr.Sub)')"

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
