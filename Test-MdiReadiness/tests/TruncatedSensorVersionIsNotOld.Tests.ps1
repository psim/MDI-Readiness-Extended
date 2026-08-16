<#
    A v2.x sensor version that was read SHORT must not become a measured "upgrade the sensor".

    Get-mdiSensorV3Readiness compared the reported v2.x sensor version to the minimum for in-place
    migration with a bare `-ge` on two [version] objects. [version] fills the components a string did
    not carry with -1, so a version that ties the minimum on every component it actually carries
    always compares LESS:

        [version]'2.254'        -> Major=2 Minor=254 Build=-1    Revision=-1
        [version]'2.254.19112'  -> Major=2 Minor=254 Build=19112 Revision=-1

    Both measured $false against the minimum 2.254.19112.470, so the report stated, as a MEASURED
    fact, "v2.x sensor 2.254 is older than 2.254.19112.470 - upgrade the v2.x sensor before
    migrating" and dropped MigrationEligible - decided entirely by components nobody read.

    The version arrives from Get-mdiSensorVersion, which returns CIM_DataFile.Version verbatim: the
    binary's version resource, which is not guaranteed to carry four components.

    The function already refuses to turn an UNPARSEABLE version into $false for exactly this reason
    ("a truncated read ... is not evidence that the sensor is TOO OLD"), but a truncated version
    PARSES, so it walked straight past that guard.

    The fix must not throw away answers that are genuinely knowable. '2.255' is newer than
    '2.254.19112.470' whatever its missing components hold, and '2.253' is older; only a version that
    ties as far as it goes AND is shorter than the minimum is unknowable.

    Behavioural, not textual: every assertion drives the shipped function (or the shipped comparison
    helper) and reads the Status, the Detail and the Measured flag it produced.
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

# A healthy, fully readable Windows Server 2022 domain controller carrying a running v2.x sensor.
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    [PSCustomObject]@{
        Version     = '10.0.20348'
        Caption     = 'Microsoft Windows Server 2022 Datacenter'
        ProductType = 2
        BuildNumber = '20348'
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

# Only the sensor and Sense exist. The identity-role services must be ABSENT, otherwise every server
# looks like it carries AD FS / AD CS / Entra Connect and drops out of migration for an unrelated
# reason, which would make these assertions pass without measuring anything.
$script:existing = @('AATPSensor', 'Sense')
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

$checkName = 'Defender for Identity sensor v2.x version supports migration'
$minimum = $settings.SensorV3.MinV2VersionForMigration

function Get-VersionCheck {
    param([string] $Version)
    $r = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' -SensorVersion $Version
    $chk = @($r.details.Checks) | Where-Object { $_.Name -eq $checkName }
    [PSCustomObject]@{
        Status            = $chk.Status
        Detail            = [string] $chk.Detail
        Measured          = $chk.Measured
        MigrationEligible = $r.details.MigrationEligible
    }
}

Write-Host "`n[0] The minimum this test reasons about is the shipped one" -ForegroundColor Yellow
Assert-That 'the minimum carries four components' (([version] $minimum).Revision -ge 0) "(got '$minimum')"

Write-Host "`n[1] A version read SHORT that ties the minimum as far as it goes is UNMEASURED" -ForegroundColor Yellow
foreach ($short in '2.254', '2.254.19112') {
    $r = Get-VersionCheck $short
    Assert-That "'$short' is not a measured verdict" ([string] $r.Status -eq 'N/A') "(got '$($r.Status)')"
    Assert-That "'$short' is flagged unmeasured" ($r.Measured -eq $false) "(got '$($r.Measured)')"
    Assert-That "'$short' does not tell the operator to upgrade" ($r.Detail -notmatch 'upgrade the v2\.x sensor') "(got '$($r.Detail)')"
    Assert-That "'$short' carries the Not tested convention" ($r.Detail -like 'Not tested*') "(got '$($r.Detail)')"
}

Write-Host "`n[2] A complete version below the minimum is STILL a measured failure" -ForegroundColor Yellow
$r = Get-VersionCheck '2.254.19112.469'
Assert-That 'a genuinely old sensor still reads False' ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"
Assert-That 'a genuinely old sensor is measured' ($r.Measured -eq $true) "(got '$($r.Measured)')"
Assert-That 'a genuinely old sensor is told to upgrade' ($r.Detail -match 'upgrade the v2\.x sensor') "(got '$($r.Detail)')"
Assert-That 'a genuinely old sensor is not migration eligible' ($r.MigrationEligible -eq $false) "(got '$($r.MigrationEligible)')"

Write-Host "`n[3] A complete version at or above the minimum still passes" -ForegroundColor Yellow
foreach ($ok in '2.254.19112.470', '2.254.19112.471', '2.300.1.1', '  2.254.19112.470  ') {
    $r = Get-VersionCheck $ok
    Assert-That "'$($ok.Trim())' reads True" ($r.Status -is [bool] -and $r.Status -eq $true) "(got '$($r.Status)')"
    Assert-That "'$($ok.Trim())' is migration eligible" ($r.MigrationEligible -eq $true) "(got '$($r.MigrationEligible)')"
}

Write-Host "`n[4] A SHORT version whose present components already settle it keeps its answer" -ForegroundColor Yellow
# These are the answers the fix must not throw away: the ordering is decided before the missing
# components are ever reached, so turning them into 'N/A' would lose a real measurement.
$r = Get-VersionCheck '2.255'
Assert-That "'2.255' is a measured pass" ($r.Status -is [bool] -and $r.Status -eq $true) "(got '$($r.Status)')"
$r = Get-VersionCheck '2.253'
Assert-That "'2.253' is a measured failure" ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"
$r = Get-VersionCheck '3.0'
Assert-That "'3.0' is a measured pass" ($r.Status -is [bool] -and $r.Status -eq $true) "(got '$($r.Status)')"
$r = Get-VersionCheck '1.9'
Assert-That "'1.9' is a measured failure" ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"
$r = Get-VersionCheck '2.254.19113'
Assert-That "'2.254.19113' is a measured pass" ($r.Status -is [bool] -and $r.Status -eq $true) "(got '$($r.Status)')"
$r = Get-VersionCheck '2.254.19111'
Assert-That "'2.254.19111' is a measured failure" ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"

Write-Host "`n[5] An unparseable version keeps its own distinct sentence" -ForegroundColor Yellow
$r = Get-VersionCheck 'unknown'
Assert-That "'unknown' is unmeasured" ([string] $r.Status -eq 'N/A' -and $r.Measured -eq $false) "(got '$($r.Status)'/'$($r.Measured)')"
Assert-That "'unknown' says it is not a recognisable version" ($r.Detail -match 'not a recognisable version number') "(got '$($r.Detail)')"
$rShort = Get-VersionCheck '2.254'
Assert-That 'the short and unparseable sentences differ' ($rShort.Detail -ne $r.Detail) "(both '$($r.Detail)')"

Write-Host "`n[6] The comparison helper answers the tri-state directly" -ForegroundColor Yellow
Assert-That 'short tie is N/A' ([string] (Get-mdiVersionAtLeast -Version '2.254' -Minimum $minimum) -eq 'N/A')
Assert-That 'exact minimum is True' ((Get-mdiVersionAtLeast -Version $minimum -Minimum $minimum) -eq $true)
Assert-That 'longer than the minimum and tying is True' ((Get-mdiVersionAtLeast -Version '3.0.1' -Minimum '3.0') -eq $true)
Assert-That 'a null version is N/A' ([string] (Get-mdiVersionAtLeast -Version $null -Minimum $minimum) -eq 'N/A')
Assert-That 'an unparseable minimum is N/A' ([string] (Get-mdiVersionAtLeast -Version '2.254.19112.470' -Minimum 'nonsense') -eq 'N/A')

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
