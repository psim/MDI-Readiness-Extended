<#
    Migration eligibility must rest on evidence.

    The report tells an administrator whether a domain controller can be migrated IN PLACE to the
    v3.x sensor. Getting that wrong sends somebody either to rebuild a server that did not need it,
    or into a maintenance window to attempt a migration that cannot work.

    The defect: MigrationEligible was computed from $migrationWarnings, and that filter catches only
    Status -eq $false. A migration prerequisite that could not be MEASURED was invisible to it, so a
    domain controller whose v2.x sensor version could not be read reported "eligible for in-place
    migration" while its own check on the same page read "its version could not be determined". The
    section exists to answer one question and it answered it from evidence it did not have.

    Two smaller defects found alongside:
      - an unparseable version string was reported as a measured "older than the minimum - upgrade
        the v2.x sensor before migrating". Not being able to READ a version is not evidence that it
        is old, and that wording sends someone to upgrade a sensor that may already be current.
      - a version carrying surrounding whitespace failed [version]::TryParse outright, so a
        perfectly current '  2.254.19112.470  ' was reported as too old.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# Everything except the version is held constant and healthy, so only the version varies.
$script:serviceReadable = $true
$script:sensorPresent = $true
Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
    param($ComputerName, $ServiceName)
    if (-not $script:serviceReadable) {
        return [PSCustomObject]@{ Service = $null; Readable = $false; Error = 'Access is denied.' }
    }
    # Only the sensor and MDE services exist on this notional server. Returning a running service for
    # EVERY name - including adfssrv, CertSvc and ADSync - made the "no additional identity roles"
    # migration check fail, so the server was ineligible for a reason that had nothing to do with the
    # version under test and the whole file measured the wrong thing.
    $isKnown = $ServiceName -match 'AATPSensor|Sense'
    $svc = if ($script:sensorPresent -and $isKnown) {
        [PSCustomObject]@{ Name = $ServiceName; State = 'Running'; StartMode = 'Auto' }
    } else { $null }
    [PSCustomObject]@{ Service = $svc; Readable = $true; Error = $null }
}
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $Query, $ErrorAction)
    if ($Class -eq 'Win32_OperatingSystem') {
        return [PSCustomObject]@{ Version = '10.0.20348'; Caption = 'Windows Server 2022'; ProductType = 2; BuildNumber = '20348' }
    }
    $null
}
Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value {
    param($ComputerName, $Key, $Value)
    [PSCustomObject]@{ Readable = $true; Value = $(if ($Value -eq 'UBR') { 99999 } else { 1 }); Error = $null }
}
Set-Item -Path function:script:Get-mdiCaptureComponent -Value { param($ComputerName) 'N/A' }

function Get-Verdict($version) {
    $r = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' -SensorVersion $version 3>$null
    $check = @($r.details.Checks | Where-Object { [string] $_.Name -match '(?i)v2\.x version|version supports migration' })[0]
    [PSCustomObject]@{
        Eligible = $r.details.MigrationEligible
        Status   = $(if ($check) { $check.Status } else { '<missing>' })
        Measured = $(if ($check) { $check.Measured } else { $null })
        Detail   = $(if ($check) { [string] $check.Detail } else { '' })
    }
}

$minVersion = $settings.SensorV3.MinV2VersionForMigration

Write-Host 'Versions are compared as versions, not as text' -ForegroundColor Cyan
# The classic trap: as strings '2.9' sorts ABOVE '2.254', so a sensor two hundred builds out of date
# reports as current. Stated here as a fact about PowerShell so the intent is unmistakable.
Assert-That "as text, '2.9' wrongly sorts above '2.254'" ('2.9' -gt '2.254')
Assert-That '  but as versions it does not' (-not ([version]'2.9' -gt [version]'2.254'))
$old = Get-Verdict '2.9'
Assert-That 'a 2.9 sensor is correctly older than the 2.254 minimum' ($old.Status -eq $false) "(status=$($old.Status))"
Assert-That '  and is not eligible' ($old.Eligible -ne $true)
Assert-That '  and is told to upgrade' ($old.Detail -match 'upgrade')
$new = Get-Verdict '2.999'
Assert-That 'a newer version passes' ($new.Status -eq $true) "(status=$($new.Status))"
Assert-That '  and is eligible' ($new.Eligible -eq $true)
Assert-That 'the exact minimum version passes' ((Get-Verdict $minVersion).Status -eq $true)
# '2.254' is not BELOW the minimum: it ties it on both components it actually carries and says
# nothing about the build and revision the minimum still cares about. A two-part version that
# genuinely is below the minimum still fails; one that merely stops short is unmeasured, not old.
Assert-That 'a two-part version genuinely below the minimum fails' ((Get-Verdict '2.253').Status -eq $false)
Assert-That 'a two-part version that only ties as far as it goes is not a measured failure' ([string] (Get-Verdict '2.254').Status -eq 'N/A')

Write-Host 'A version that could not be READ is not a version that is OLD' -ForegroundColor Cyan
foreach ($case in @(
        @{ N = 'empty'; V = '' }
        @{ N = "'N/A'"; V = 'N/A' }
        @{ N = "'unknown'"; V = 'unknown' }
        @{ N = "'v2.254.19112.470'"; V = 'v2.254.19112.470' }
        @{ N = 'null'; V = $null }
    )) {
    $r = Get-Verdict $case.V
    Assert-That ("{0} is not reported as eligible" -f $case.N) ($r.Eligible -ne $true) "(eligible=$($r.Eligible))"
    Assert-That ("  {0} is not a measured failure" -f $case.N) ($r.Status -ne $false) "(status=$($r.Status))"
    Assert-That ("  {0} does not tell the operator to upgrade" -f $case.N) ($r.Detail -notmatch 'upgrade') "(detail='$($r.Detail)')"
    Assert-That ("  {0} is marked not measured" -f $case.N) ($r.Measured -ne $true) "(measured=$($r.Measured))"
}

Write-Host 'Padding is kept out of the sentence shown to the operator' -ForegroundColor Cyan
# NOT a parse fix. [version]::TryParse already tolerates surrounding whitespace - measured directly,
# '  2.254.19112.470  ' parses fine - so trimming changes only the DETAIL text, which would otherwise
# read "v2.x sensor   2.254.19112.470   meets the minimum version". Asserted for what it actually
# does rather than for a defect that was never there.
$padded = Get-Verdict ('  {0}  ' -f $minVersion)
$clean = Get-Verdict $minVersion
Assert-That 'a padded current version still passes' ($padded.Status -eq $true) "(status=$($padded.Status))"
Assert-That '  and reaches the same verdict as the unpadded one' ($padded.Eligible -eq $clean.Eligible)
Assert-That '  and the displayed detail carries no double space' ($padded.Detail -notmatch '\S  +\S') "(detail='$($padded.Detail)')"
Assert-That '  and reads identically to the unpadded detail' ($padded.Detail -eq $clean.Detail) `
    "(padded='$($padded.Detail)' clean='$($clean.Detail)')"

Write-Host 'An unmeasured migration prerequisite blocks eligibility' -ForegroundColor Cyan
# Behavioural, not a grep of the source. This block used to assert that the literal text
# '$migrationUnknowns.Count -eq 0' appeared in the file. That kind of assertion passes while the
# behaviour is wrong and FAILS on a refactor that improved it - which is exactly what happened when
# MigrationEligible became tri-state and the expression legitimately became '-gt 0'. What the report
# owes the operator is the verdict the function reaches, so that is what is measured here.
#
# Every REQUIRED prerequisite is held healthy by the stubs above, so only the migration prerequisite
# varies and nothing else can explain the eligibility answer.
$unreadableVerdict = Get-Verdict 'unknown'
Assert-That 'an unmeasured migration prerequisite is not eligible' ($unreadableVerdict.Eligible -ne $true) `
    "(eligible='$($unreadableVerdict.Eligible)')"
Assert-That '  and is not a measured NO either' ([string] $unreadableVerdict.Eligible -eq 'N/A') `
    "(eligible='$($unreadableVerdict.Eligible)')"
Assert-That '  because the prerequisite itself reads unmeasured' ($unreadableVerdict.Measured -eq $false) `
    "(measured='$($unreadableVerdict.Measured)')"
$measuredGood = Get-Verdict $minVersion
Assert-That 'a fully measured, current prerequisite IS eligible' ($measuredGood.Eligible -eq $true) `
    "(eligible='$($measuredGood.Eligible)')"
$measuredOld = Get-Verdict '2.9'
Assert-That 'a measured, too-old prerequisite is a definite NO' ($measuredOld.Eligible -eq $false) `
    "(eligible='$($measuredOld.Eligible)')"
# A failure and an unknown remain DIFFERENT findings - the remedies are not the same.
$unknownVerdict = Get-Verdict 'unknown'
Assert-That 'an unknown version is distinguishable from an old one' (
    $unknownVerdict.Detail -ne $old.Detail)

Write-Host 'A server with no v2 sensor at all is a different case' -ForegroundColor Cyan
# Nothing to migrate FROM: the check passes informationally and must not be confused with a failure.
$script:sensorPresent = $false
$none = Get-Verdict ''
Assert-That 'no v2 sensor installed is not a measured failure' ($none.Status -ne $false) "(status=$($none.Status))"
Assert-That '  and says the server can be activated directly' ($none.Detail -match 'activated directly|No v2.x sensor')
$script:sensorPresent = $true

Write-Host 'An unreadable service list is still N/A on the v2 path' -ForegroundColor Cyan
# Same shape as the MDE 'Sense' defect fixed earlier: access denied must not read as a result.
$script:serviceReadable = $false
$denied = Get-Verdict $minVersion
Assert-That 'a denied service list yields N/A' ([string] $denied.Status -eq 'N/A') "(status=$($denied.Status))"
Assert-That '  and names the reason' ($denied.Detail -match 'Access is denied')
Assert-That '  and is not eligible' ($denied.Eligible -ne $true)
$script:serviceReadable = $true

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
