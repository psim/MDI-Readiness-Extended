# A BUILD MISSING FROM THE CU TABLE WAS DECLARED "NEWER" THAN EVERY BUILD THE SCRIPT KNOWS
#
# Get-mdiSensorV3Readiness checks the cumulative update level by looking the OS build up in a
# hashtable keyed by EXACT build number:
#
#     $expectedUpdate = if ($null -eq $osBuild) { $null } else { $v3.JulyCumulativeUpdate[$osBuild] }
#
# It carries three entries - 17763 (Server 2019), 20348 (Server 2022), 26100 (Server 2025). When
# the lookup missed, the operator-facing detail asserted, unconditionally:
#
#     'OS build {0}.{1} is newer than the builds known to this script, verify the cumulative
#      update level manually'
#
# and the comment above it stated the assumption out loud: "A build newer than every entry in the
# table". But a hashtable keyed by exact build misses for ANY build that is not one of the three,
# not only for a newer one. Windows Server, version 23H2 is build 25398: a real, supported,
# domain-controller-capable SKU that is OLDER than 26100, which the table does know. Measured on
# the shipped function, build 25398 produced exactly that sentence - so the report told the
# operator the opposite of the truth about their own server. Build 22000 did the same.
#
# The severity is in what a reader DOES with it. "Newer than anything this script knows" is a
# reassurance: build numbers only increase, so a newer build is almost certainly patched past the
# July 2026 level, and an operator who trusts the sentence reasonably stops looking. For 23H2 the
# script has no opinion at all, and saying "newer" converts "unknown" into "probably fine" - the
# same unread-value-presented-as-a-measurement family as the rest of this suite, expressed in
# prose instead of in a number.
#
# The tri-state was and remains correct: an INFORMATIONAL N/A that leaves the overall v3 verdict
# intact and advises a manual check. Only the claim about WHY was wrong.
#
# What this test pins:
#   1. A build BELOW the newest known build that misses the table must not be called "newer".
#   2. A build genuinely above every table entry still is called newer - the fix must not simply
#      delete the word, or it would stop saying the true thing in the case where it was true.
#   3. Either way the message still tells the operator to verify manually, and the check is still
#      informational N/A with the v3 verdict left intact.
#   4. The three known builds are still measured against the table, unchanged.
#   5. The sentence names what the script actually knows, so the claim can be checked by the reader.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:pass = 0; $script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# The whole v3 probe is driven through WMI and the remote registry. Both are shadowed so the build
# number under test is the only thing that varies between cases.
$script:osProps = @{ Caption = 'Microsoft Windows Server 2022 Standard'; Version = '10.0.20348'; ProductType = 2; BuildNumber = '20348' }
function global:Get-WmiObject {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    if ($Class -eq 'Win32_OperatingSystem') { return [PSCustomObject] $script:osProps }
    [PSCustomObject]@{ Name = 'x' }
}
# A UBR high enough that, for the builds the table DOES know, the CU check passes. That keeps the
# known-build controls green for the right reason and makes a table miss the only variable.
Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value {
    param($ComputerName, $Key, $Value)
    [PSCustomObject]@{ Value = 99999999; Readable = $true; Error = $null }
}
Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
    param($ComputerName, $ServiceName)
    [PSCustomObject]@{ Readable = $true; Installed = $true; State = 'Running'; StartMode = 'Auto'; Error = $null }
}
Set-Item -Path function:script:Get-mdiSensorVersion -Value {
    param($ComputerName) [PSCustomObject]@{ Installed = $false; Version = $null; Readable = $true }
}
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

function Get-CuCheck {
    param([string] $BuildNumber)
    $script:osProps = @{ Caption = 'Microsoft Windows Server'; Version = "10.0.$BuildNumber"; ProductType = 2; BuildNumber = $BuildNumber }
    $r = Get-mdiSensorV3Readiness -ComputerName 'dcfab01.fabrikam.local' 3>$null 4>$null
    [PSCustomObject]@{
        Check  = @($r.details.Checks | Where-Object { $_.Name -eq 'July 2026 or later cumulative update' })[0]
        Result = $r
    }
}

$known = @($settings.SensorV3.JulyCumulativeUpdate.Keys | ForEach-Object { [int] $_ } | Sort-Object)
$newest = $known[-1]
Write-Host ("table builds: {0}   newest known: {1}" -f ($known -join ', '), $newest) -ForegroundColor Cyan

Write-Host ''
Write-Host '[controls] the builds the table knows are still measured against it' -ForegroundColor Cyan
foreach ($b in $known) {
    $c = (Get-CuCheck -BuildNumber ([string] $b)).Check
    Assert-That "build $b is a measured verdict, not an N/A" ([string] $c.Status -ne 'N/A') "got '$($c.Status)' detail='$($c.Detail)'"
    Assert-That "  ...and build $b never claims to be outside the table" ($c.Detail -notmatch 'known to this script|builds this script carries') "got '$($c.Detail)'"
}

Write-Host ''
Write-Host '[the defect] a build BELOW the newest known build must not be called "newer"' -ForegroundColor Cyan
# 25398 is Windows Server, version 23H2. 22000 is another real build below 26100. Both miss the
# table; neither is newer than everything in it.
foreach ($b in @(25398, 22000)) {
    if ($b -ge $newest) { continue }
    $o = Get-CuCheck -BuildNumber ([string] $b)
    $c = $o.Check
    Assert-That "build $b misses the table (precondition)" ($null -eq $settings.SensorV3.JulyCumulativeUpdate[$b]) 'the table unexpectedly knows this build'
    Assert-That "build $b is NOT described as newer than the known builds" ($c.Detail -notmatch '(?i)\bis newer than\b') "got '$($c.Detail)'"
    Assert-That "  ...and is still an informational N/A" ([string] $c.Status -eq 'N/A') "got '$($c.Status)'"
    Assert-That "  ...that leaves the verdict intact (not a 'Not tested' N/A)" ($c.Detail -notlike 'Not tested*') "got '$($c.Detail)'"
    Assert-That "  ...and still tells the operator to verify manually" ($c.Detail -match '(?i)verify the cumulative update level manually') "got '$($c.Detail)'"
    Assert-That "  ...and names what the script actually knows" ($c.Detail -match [regex]::Escape([string] $newest)) "got '$($c.Detail)'"
    Assert-That "  ...and never claims the CU level was measured" ($c.Detail -notmatch '(?i)meets the July 2026 level|older than the July 2026') "got '$($c.Detail)'"
}

Write-Host ''
Write-Host '[the true case] a build genuinely above the table still says so' -ForegroundColor Cyan
$high = (Get-CuCheck -BuildNumber ([string] ($newest + 4000))).Check
Assert-That 'a genuinely newer build IS described as newer' ($high.Detail -match '(?i)\bis newer than\b') "got '$($high.Detail)'"
Assert-That '  ...and is still an informational N/A' ([string] $high.Status -eq 'N/A') "got '$($high.Status)'"
Assert-That '  ...and still advises the manual check' ($high.Detail -match '(?i)verify the cumulative update level manually') "got '$($high.Detail)'"

Write-Host ''
Write-Host '[boundary] the newest known build itself is measured, not described' -ForegroundColor Cyan
$edge = (Get-CuCheck -BuildNumber ([string] $newest)).Check
Assert-That "build $newest is measured against the table" ([string] $edge.Status -ne 'N/A') "got '$($edge.Status)' detail='$($edge.Detail)'"
$justAbove = (Get-CuCheck -BuildNumber ([string] ($newest + 1))).Check
Assert-That "build $($newest + 1) is one above the table and is called newer" ($justAbove.Detail -match '(?i)\bis newer than\b') "got '$($justAbove.Detail)'"

Write-Host ''
Write-Host '[unchanged] an unsupported or unreadable build is untouched by this' -ForegroundColor Cyan
$old = (Get-CuCheck -BuildNumber '14393').Check
Assert-That 'a build below the minimum is still not evaluated' ($old.Detail -match '(?i)not supported by the v3.x sensor') "got '$($old.Detail)'"
$unread = (Get-CuCheck -BuildNumber 'Server 2022').Check
Assert-That 'an unreadable build is still Not tested' ($unread.Detail -like 'Not tested*') "got '$($unread.Detail)'"
Assert-That '  ...and never claims anything about the table' ($unread.Detail -notmatch '(?i)\bis newer than\b') "got '$($unread.Detail)'"

Write-Host ''
Write-Host "pass=$script:pass  fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
