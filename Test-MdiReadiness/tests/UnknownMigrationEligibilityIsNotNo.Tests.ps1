<#
    A migration eligibility that was never established must not be published as a measured "No".

    Get-mdiSensorV3Readiness makes its overall verdict tri-state - $true / $false / 'N/A' - because a
    server whose checks could not be read is not ready and is not blocked, it is UNKNOWN. The
    neighbouring MigrationEligible field was a bare boolean AND, so every way of not being able to
    answer collapsed into $false:

        MigrationEligible = ($v3Ready -eq $true) -and ($migrationWarnings.Count -eq 0) -and
                            ($migrationUnknowns.Count -eq 0) -and $hasV2Sensor

    Driven with every WMI, registry and service read failing, the shipped producer emitted
    isSensorV3Ready = 'N/A' with five unknown required checks - and MigrationEligible = $false. The
    HTML then printed a measured amber "No" for "Eligible for in-place migration" directly above its
    own "Not tested" row for "Meets the v3.x prerequisites": two surfaces of the same fact
    contradicting each other, the definite one asserted from evidence nobody collected. The same
    false reached -AsJson, where it is indistinguishable from a server genuinely measured ineligible.

    Get-mdiSensorV3Html has had a three-way renderer for this field all along ($true -> Yes,
    $false -> No, anything else -> Not determined). It could never render the third arm because a
    definite boolean was all the producer ever gave it.

    Merge-mdiSensorV3ReadyDetails repeated the collapse independently for colocated roles: a boolean
    AND of the two roles' values turned "one role could not be measured" into a definite "No". It
    now merges through Merge-mdiCheckValue, the one computation that already encodes the pessimistic
    tri-state rule for every other check.

    The fix must NOT throw away answers that are genuinely knowable: a measured blocker, a v2.x
    sensor measured as too old, and an ANSWERED service query that found no v2.x sensor at all are
    each definite, and must stay a real boolean $false.

    Behavioural: every assertion drives the shipped producer, the shipped merger or the shipped HTML
    renderer and reads the value it actually produced.
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

# 'N/A' -eq $true is TRUE in PowerShell (the right operand is cast to the left operand's type) and
# every non-empty string is truthy, so "unknown" is asserted by TYPE and text together - never by a
# bare comparison, which is the very confusion this test exists to police.
function Test-IsUnknown { param($Value) ($Value -isnot [bool]) -and ([string] $Value -eq 'N/A') }
function Test-IsMeasuredFalse { param($Value) ($Value -is [bool]) -and ($Value -eq $false) }
function Test-IsMeasuredTrue { param($Value) ($Value -is [bool]) -and ($Value -eq $true) }

$minimum = $settings.SensorV3.MinV2VersionForMigration

# ---------------------------------------------------------------------------------------------
# Stub sets. Each one is a complete, self-consistent picture of one machine.
# ---------------------------------------------------------------------------------------------
function Set-UnreadableServer {
    # Nothing about this machine can be read: no WMI, no registry, no service list.
    Set-Item -Path function:script:Get-WmiObject -Value {
        param($ComputerName, $Namespace, $Class, $Property, $Filter, $Query, $ErrorAction)
        throw 'test access denied'
    }
    Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value {
        param($ComputerName, $Key, $Value)
        [PSCustomObject]@{ Readable = $false; Value = $null; Error = 'test access denied' }
    }
    Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
        param($ComputerName, $ServiceName)
        [PSCustomObject]@{ Service = $null; Readable = $false; Error = 'test access denied' }
    }
    Set-Item -Path function:script:Get-mdiServiceState -Value { param($ComputerName, $ServiceName) $null }
    Set-Item -Path function:script:Get-mdiCaptureComponent -Value { param($ComputerName) 'N/A' }
}

function Set-ReadableServer {
    param(
        [string] $OSVersion = '10.0.20348',
        [string] $Caption = 'Microsoft Windows Server 2022 Datacenter',
        [string[]] $Services = @('AATPSensor', 'Sense')
    )
    $script:osVersion = $OSVersion
    $script:osCaption = $Caption
    $script:existing = $Services
    Set-Item -Path function:script:Get-WmiObject -Value {
        param($ComputerName, $Namespace, $Class, $Property, $Filter, $Query, $ErrorAction)
        [PSCustomObject]@{
            Version     = $script:osVersion
            Caption     = $script:osCaption
            ProductType = 2
            BuildNumber = ($script:osVersion -split '\.')[-1]
        }
    }
    Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value {
        param($ComputerName, $Key, $Value)
        if ($Value -eq 'UBR') { return [PSCustomObject]@{ Readable = $true; Value = 5386; Error = $null } }
        [PSCustomObject]@{ Readable = $true; Value = 1; Error = $null }
    }
    Set-Item -Path function:script:Get-mdiSensorHealth -Value {
        param($ComputerName) [PSCustomObject]@{ Readable = $true; Running = $true }
    }
    Set-Item -Path function:script:Get-mdiCaptureComponent -Value { param($ComputerName) 'Npcap' }
    Set-Item -Path function:script:Get-mdiServiceState -Value {
        param($ComputerName, $ServiceName)
        if ($script:existing -contains $ServiceName) {
            return [PSCustomObject]@{ Name = $ServiceName; State = 'Running'; StartMode = 'Auto' }
        }
        $null
    }
    Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
        param($ComputerName, $ServiceName)
        if ($script:existing -contains $ServiceName) {
            return [PSCustomObject]@{
                Readable = $true
                Service  = [PSCustomObject]@{ Name = $ServiceName; State = 'Running'; StartMode = 'Auto' }
                Error    = $null
            }
        }
        [PSCustomObject]@{ Readable = $true; Service = $null; Error = $null }
    }
}

function New-V3Server {
    param($Readiness, [string] $Fqdn = 'dc1.contoso.com')
    [PSCustomObject]@{
        FQDN          = $Fqdn
        SensorV3Ready = $Readiness.isSensorV3Ready
        Details       = [PSCustomObject]@{ SensorV3ReadyDetails = $Readiness.details }
    }
}

function Get-MigrationRow { param([string] $Html) [regex]::Match($Html, '<tr><td style="text-align:left"><b>Eligible for in-place migration</b>.*?</tr>').Value }
function Get-ReadyRow { param([string] $Html) [regex]::Match($Html, '<tr><td style="text-align:left"><b>Meets the v3\.x prerequisites</b>.*?</tr>').Value }

# ---------------------------------------------------------------------------------------------
Write-Host "`n[1] A server nobody could read has an UNKNOWN eligibility, not a measured No" -ForegroundColor Yellow
Set-UnreadableServer
$unreadable = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com'
Assert-That 'the overall v3 verdict is unknown' (Test-IsUnknown $unreadable.isSensorV3Ready) "(got '$($unreadable.isSensorV3Ready)')"
Assert-That 'required checks went unread' (@($unreadable.details.UnknownChecks).Count -gt 0) "(got $(@($unreadable.details.UnknownChecks).Count))"
Assert-That 'MigrationEligible is not a measured verdict' (-not (Test-IsMeasuredFalse $unreadable.details.MigrationEligible)) "(got [$($unreadable.details.MigrationEligible.GetType().Name)] '$($unreadable.details.MigrationEligible)')"
Assert-That 'MigrationEligible is unknown' (Test-IsUnknown $unreadable.details.MigrationEligible) "(got '$($unreadable.details.MigrationEligible)')"
Assert-That 'MigrationEligible does not claim eligibility either' (-not (Test-IsMeasuredTrue $unreadable.details.MigrationEligible)) "(got '$($unreadable.details.MigrationEligible)')"
Assert-That 'no measured blockers were invented' (@($unreadable.details.Blockers).Count -eq 0) "(got $(@($unreadable.details.Blockers).Count))"

Write-Host "`n[2] The two HTML rows about that server agree with each other" -ForegroundColor Yellow
$htmlUnknown = Get-mdiSensorV3Html -Server @(New-V3Server $unreadable)
$migrationRow = Get-MigrationRow $htmlUnknown
$readyRow = Get-ReadyRow $htmlUnknown
Assert-That 'the migration row is rendered' (-not [string]::IsNullOrEmpty($migrationRow)) '(row not found)'
Assert-That 'the migration row does not say No' ($migrationRow -notmatch '>No<') "(got '$migrationRow')"
Assert-That 'the migration row says Not determined' ($migrationRow -match 'Not determined') "(got '$migrationRow')"
Assert-That 'the migration row is not styled as a measurement' ($migrationRow -notmatch 'class="amber"' -and $migrationRow -notmatch 'class="green"') "(got '$migrationRow')"
Assert-That 'the prerequisites row still says Not tested' ($readyRow -match 'Not tested') "(got '$readyRow')"

Write-Host "`n[3] The machine-readable surface carries the same unknown" -ForegroundColor Yellow
$round = ([PSCustomObject]@{ DomainControllers = @(New-V3Server $unreadable) } | ConvertTo-Json -Depth 8 -Compress) | ConvertFrom-Json
$roundDetail = $round.DomainControllers[0].Details.SensorV3ReadyDetails
Assert-That 'JSON does not carry a measured false' (-not (Test-IsMeasuredFalse $roundDetail.MigrationEligible)) "(got '$($roundDetail.MigrationEligible)')"
Assert-That 'JSON carries the unknown marker' (Test-IsUnknown $roundDetail.MigrationEligible) "(got '$($roundDetail.MigrationEligible)')"
Assert-That 'JSON agrees with the overall verdict' ([string] $round.DomainControllers[0].SensorV3Ready -eq 'N/A') "(got '$($round.DomainControllers[0].SensorV3Ready)')"

Write-Host "`n[4] A healthy, fully readable server with a current v2.x sensor is still eligible" -ForegroundColor Yellow
Set-ReadableServer
$healthy = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' -SensorVersion $minimum
Assert-That 'the overall v3 verdict is measured true' (Test-IsMeasuredTrue $healthy.isSensorV3Ready) "(got '$($healthy.isSensorV3Ready)')"
Assert-That 'MigrationEligible is a real boolean true' (Test-IsMeasuredTrue $healthy.details.MigrationEligible) "(got [$($healthy.details.MigrationEligible.GetType().Name)] '$($healthy.details.MigrationEligible)')"
$htmlHealthy = Get-mdiSensorV3Html -Server @(New-V3Server $healthy)
Assert-That 'the healthy migration row says Yes' ((Get-MigrationRow $htmlHealthy) -match '>Yes<') "(got '$(Get-MigrationRow $htmlHealthy)')"

Write-Host "`n[5] A DEFINITE disqualifier is still a measured No" -ForegroundColor Yellow
Set-ReadableServer
$tooOld = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' -SensorVersion '2.254.19112.469'
Assert-That 'a v2.x sensor measured too old is not eligible' (Test-IsMeasuredFalse $tooOld.details.MigrationEligible) "(got [$($tooOld.details.MigrationEligible.GetType().Name)] '$($tooOld.details.MigrationEligible)')"
Assert-That 'and the too-old server is still ready for a fresh v3.x activation' (Test-IsMeasuredTrue $tooOld.isSensorV3Ready) "(got '$($tooOld.isSensorV3Ready)')"

Set-ReadableServer -Services @('Sense')
$noSensor = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com'
Assert-That 'an ANSWERED query finding no v2.x sensor is a measured No' (Test-IsMeasuredFalse $noSensor.details.MigrationEligible) "(got [$($noSensor.details.MigrationEligible.GetType().Name)] '$($noSensor.details.MigrationEligible)')"

Set-ReadableServer -OSVersion '10.0.14393' -Caption 'Microsoft Windows Server 2016 Standard'
$blocked = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' -SensorVersion $minimum
Assert-That 'a server with a measured blocker is not v3 ready' (Test-IsMeasuredFalse $blocked.isSensorV3Ready) "(got '$($blocked.isSensorV3Ready)')"
Assert-That 'a server with a measured blocker is a measured No' (Test-IsMeasuredFalse $blocked.details.MigrationEligible) "(got [$($blocked.details.MigrationEligible.GetType().Name)] '$($blocked.details.MigrationEligible)')"

Write-Host "`n[6] An unreadable MIGRATION prerequisite alone is unknown, not No" -ForegroundColor Yellow
Set-ReadableServer
$shortVersion = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' -SensorVersion '2.254'
Assert-That 'the prerequisites themselves were all read' (Test-IsMeasuredTrue $shortVersion.isSensorV3Ready) "(got '$($shortVersion.isSensorV3Ready)')"
Assert-That 'an undecidable sensor version leaves eligibility unknown' (Test-IsUnknown $shortVersion.details.MigrationEligible) "(got [$($shortVersion.details.MigrationEligible.GetType().Name)] '$($shortVersion.details.MigrationEligible)')"

Set-ReadableServer
$noVersion = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' -SensorVersion 'unknown'
Assert-That 'an unparseable sensor version leaves eligibility unknown' (Test-IsUnknown $noVersion.details.MigrationEligible) "(got '$($noVersion.details.MigrationEligible)')"

Write-Host "`n[7] The colocated-role merge keeps the tri-state" -ForegroundColor Yellow
function New-Detail {
    param($Eligible)
    [PSCustomObject]@{
        SensorState        = 'v2.x sensor running'
        SensorV2Version    = '2.254.19112.470'
        MigrationEligible  = $Eligible
        Blockers           = @()
        ActionableBlockers = @()
        UnknownChecks      = @()
        Checks             = @()
    }
}
$cases = @(
    @{ First = 'N/A'; Second = $true; Expect = 'N/A'; Why = 'one role unread, the other eligible' }
    @{ First = $true; Second = 'N/A'; Expect = 'N/A'; Why = 'unread in the second role' }
    @{ First = 'N/A'; Second = $false; Expect = 'False'; Why = 'a measured No dominates an unknown' }
    @{ First = $false; Second = 'N/A'; Expect = 'False'; Why = 'a measured No dominates an unknown, either way round' }
    @{ First = $true; Second = $true; Expect = 'True'; Why = 'both roles eligible' }
    @{ First = $false; Second = $true; Expect = 'False'; Why = 'one role measured ineligible' }
    @{ First = $null; Second = $true; Expect = 'N/A'; Why = 'a role that never carried the field' }
    @{ First = 'False'; Second = $true; Expect = 'False'; Why = 'a stringified False from a JSON round trip' }
)
foreach ($case in $cases) {
    $merged = Merge-mdiSensorV3ReadyDetails -First (New-Detail $case.First) -Second (New-Detail $case.Second)
    $got = $merged.MigrationEligible
    $ok = switch ($case.Expect) {
        'N/A' { Test-IsUnknown $got }
        'True' { Test-IsMeasuredTrue $got }
        'False' { Test-IsMeasuredFalse $got }
    }
    Assert-That ("merge {0}: {1}" -f $case.Why, $case.Expect) $ok "(got [$(if ($null -eq $got) { 'null' } else { $got.GetType().Name })] '$got')"
    $reversed = Merge-mdiSensorV3ReadyDetails -First (New-Detail $case.Second) -Second (New-Detail $case.First)
    Assert-That ("merge {0}: order does not matter" -f $case.Why) ([string] $reversed.MigrationEligible -eq [string] $got) "(got '$($reversed.MigrationEligible)' vs '$got')"
}

Write-Host "`n[8] The renderer distinguishes all three states" -ForegroundColor Yellow
$rendered = foreach ($value in @($true, $false, 'N/A')) {
    $srv = [PSCustomObject]@{
        FQDN          = 'dc1.contoso.com'
        SensorV3Ready = $true
        Details       = [PSCustomObject]@{ SensorV3ReadyDetails = (New-Detail $value) }
    }
    Get-MigrationRow (Get-mdiSensorV3Html -Server @($srv))
}
Assert-That 'true renders Yes' ($rendered[0] -match '>Yes<') "(got '$($rendered[0])')"
Assert-That 'false renders No' ($rendered[1] -match '>No<') "(got '$($rendered[1])')"
Assert-That 'unknown renders neither Yes nor No' ($rendered[2] -notmatch '>Yes<' -and $rendered[2] -notmatch '>No<') "(got '$($rendered[2])')"
Assert-That 'the three states render differently' (($rendered | Select-Object -Unique).Count -eq 3) "(got $(($rendered | Select-Object -Unique).Count) distinct rows)"

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
