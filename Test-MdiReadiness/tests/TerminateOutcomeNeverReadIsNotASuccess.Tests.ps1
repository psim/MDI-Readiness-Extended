# DEFECT PINNED: a process termination whose outcome was NEVER READ was reported to the operator as
# a completed termination.
#
# Invoke-mdiRemoteCommand starts a command on a remote server with Win32_Process.Create and, if that
# process outlives the wait, terminates it with Win32_Process.Terminate. Both WMI methods report
# failure through a RETURN VALUE rather than by throwing. The comment above the terminate block
# records a defect already fixed once there - a warning that claimed "and was terminated" before the
# attempt had been made - and states the rule that replaced it:
#
#     # Win32_Process.Terminate reports failure through its RETURN VALUE, not by throwing, so both
#     # are checked: 0 is success, anything else is not, and 'it threw' is not success either.
#
# The shipped line did not honour that rule for a third case:
#
#     $terminateReturn = if ($null -ne $terminateStatus) { [int] $terminateStatus.ReturnValue } else { 0 }
#
# The else branch yields 0 - the single value that MEANS success - for a call that returned nothing
# at all. And [int] $null is also 0, so a result object carrying no ReturnValue, or a $null
# ReturnValue, arrives at the same false success by a second and third route. Only a non-zero status
# and a thrown exception were treated as failure; "the outcome was never read" was treated as "it
# worked".
#
# Measured on the shipped lines, executed verbatim out of the product file:
#
#     Terminate() outcome                  $terminateReturn   operator was told
#     ---------------------------------------------------------------------------------------
#     returned $null                       0                  "...and WAS TERMINATED."      WRONG
#     result present, ReturnValue absent   0                  "...and WAS TERMINATED."      WRONG
#     result present, ReturnValue = $null  0                  "...and WAS TERMINATED."      WRONG
#     ReturnValue = 0                      0                  "...and WAS TERMINATED."      correct
#     ReturnValue = 2 (access denied)      2                  "could NOT be terminated: 2"  correct
#     ReturnValue = 3 (insufficient priv)  3                  "could NOT be terminated: 3"  correct
#
# WHAT THE FALSE CLAIM COSTS is written in the block's own comment: the orphaned powershell.exe
# "kept running on the domain controller, still probing ports and still holding its temp file open,
# which is precisely what this block exists to prevent, and the cleanup below could not remove the
# file either". The operator is told the opposite and has no reason to look.
#
# THE SAME FUNCTION ALREADY KNEW BETTER. Fifty lines earlier, on the identical question for the
# Create call:
#
#     $createStatus = if ($null -eq $result) { $null } else { [int] $result.ReturnValue }
#     if ($null -eq $createStatus -or $createStatus -ne 0) { ...warn, return $null }
#
# An absent result is $null and $null is a failure. One rule, two hands, one function - and the hand
# that got it wrong is the one whose failure is silent.
#
# Access denied is, in this script's own words, "the ORDINARY case for the non-admin caller this
# tool is documented to support", and a cross-forest Terminate over a trust is exactly where an
# incomplete answer rather than a clean status arrives.
#
# THE FIX: an absent status, an absent ReturnValue and a $null ReturnValue all resolve to $null, and
# $null raises the same kill error as a non-zero status - naming the real cause rather than
# inventing a number. This test fails if the `else { 0 }` spelling ever returns.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The decision sits deep inside a function that starts a real remote process, so it cannot be
# reached by calling the function. The shipped LINES are located by content and executed verbatim -
# retyping the condition here would test only that this file agrees with itself.
$lines = Get-Content -LiteralPath $target
$anchor = -1
for ($n = 0; $n -lt $lines.Count; $n++) {
    if ($lines[$n] -match '^\s*\$terminateReturn\s*=') { $anchor = $n; break }
}
Assert-That 'the terminate-status decision is still present in the product' ($anchor -ge 0) '(anchor not found)'
if ($anchor -lt 0) {
    "================ $script:pass passed / $script:fail failed ================"
    exit 1
}

# Take the assignment plus the whole if/elseif chain that reads it.
$sliceLines = @(); $depth = 0; $started = $false
for ($n = $anchor; $n -lt [Math]::Min($anchor + 24, $lines.Count); $n++) {
    $sliceLines += $lines[$n]
    $depth += ([regex]::Matches($lines[$n], '\{')).Count - ([regex]::Matches($lines[$n], '\}')).Count
    if (([regex]::Matches($lines[$n], '\{')).Count -gt 0) { $started = $true }
    if ($started -and $depth -le 0 -and (($sliceLines -join "`n") -match '\$killError\s*=')) { break }
}
$slice = $sliceLines -join "`n"

Assert-That 'the slice carries the assignment and the killError decision' (
    ($slice -match '\$terminateReturn\s*=') -and ($slice -match '\$killError\s*=')) '(extraction drifted)'

$decide = [scriptblock]::Create(@"
param(`$terminateStatus)
`$killError = `$null
$slice
[PSCustomObject]@{ KillError = `$killError }
"@)

function Test-ClaimsSuccess {
    param($Status)
    $r = @(& $decide $Status)[-1]
    return [bool] (-not $r.KillError)
}

'[terminate outcome] a status nobody read is not a successful termination'

# THE DEFECT ITSELF - three routes to the same false success.
Assert-That 'Terminate() returning $null is NOT claimed as a completed termination' (
    -not (Test-ClaimsSuccess -Status $null)) '(claimed success)'
Assert-That 'a result object with NO ReturnValue is NOT claimed as a completed termination' (
    -not (Test-ClaimsSuccess -Status ([PSCustomObject]@{ Other = 1 }))) '(claimed success)'
Assert-That 'a $null ReturnValue is NOT claimed as a completed termination' (
    -not (Test-ClaimsSuccess -Status ([PSCustomObject]@{ ReturnValue = $null }))) '(claimed success)'

# CONTROLS - the fix must not turn every termination into a failure.
Assert-That 'CONTROL: ReturnValue 0 IS a successful termination' (
    Test-ClaimsSuccess -Status ([PSCustomObject]@{ ReturnValue = 0 })) '(a real success was rejected)'
Assert-That 'CONTROL: ReturnValue 2 (access denied) is a failure' (
    -not (Test-ClaimsSuccess -Status ([PSCustomObject]@{ ReturnValue = 2 }))) '(a real failure was accepted)'
Assert-That 'CONTROL: ReturnValue 3 (insufficient privilege) is a failure' (
    -not (Test-ClaimsSuccess -Status ([PSCustomObject]@{ ReturnValue = 3 }))) '(a real failure was accepted)'
Assert-That 'CONTROL: a non-zero status is still named in the message' (
    (@(& $decide ([PSCustomObject]@{ ReturnValue = 2 }))[-1]).KillError -match '2') '(the status number was lost)'

# The shape of the fix, stated directly: an unread outcome must never be defaulted to the success
# value. This is what goes red the moment `else { 0 }` comes back.
Assert-That 'the unread branch does not default to 0, the success value' (
    $slice -notmatch '\}\s*else\s*\{\s*0\s*\}') '(the else { 0 } spelling is back in the product)'

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
