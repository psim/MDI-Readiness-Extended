<#
    Behavioural regression test: a MEASURED failure is never published as "unknown".

    Get-mdiPublishedReadiness produces report.Readiness - the MACHINE-READABLE verdict. It is
    tri-state by design: $true when the run proved readiness, $false when it proved a failure, and
    the string 'N/A' when the run did not gather enough evidence to decide. Its own contract has
    always read "a measured failure remains $false even when other checks are unread; only a result
    with no known failure can be unknown."

    The partial-scan gate was evaluated BEFORE known failures were considered, so it decided the
    answer alone. One partially scanned server was enough to publish 'N/A' for a run that had
    measured real failures. Measured on the shipped function:

        TotalServers=6  PartialScanCount=1  ChecksTotal=40  ChecksPassed=35  ChecksUnread=0
            -> 'N/A'    [String]        five checks observed failing, verdict "cannot decide"

        TotalServers=6  PartialScanCount=0  ChecksTotal=40  ChecksPassed=35  ChecksUnread=3
            -> False    [Boolean]       identical failures, correct verdict

    Two paths, identical measured evidence, opposite published answers. A pipeline gating on
    Readiness reads 'N/A' as "inconclusive, nothing proven wrong" and does not fail the build, so
    five failing checks pass silently - and the false verdict is produced by the presence of an
    unrelated incomplete scan, not by anything about the failures themselves.

    The cross-forest topology makes this ordinary rather than rare: a -MultiForest run reaching a
    second forest across the trust routinely scans some far-forest servers only partially, and that
    alone erased every failure the near forest had proven.

    Pinned here: a measured failure publishes $false whatever the partial-scan count is; the N/A
    verdict still stands for the cases that genuinely cannot be decided (nothing scanned, or a
    partial/unread run with nothing observed failing); a proven-ready run still publishes $true; and
    an unreadable PartialScanCount cannot manufacture an N/A over a run that measured failures.
#>

param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }

$text = [IO.File]::ReadAllText($scriptPath)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main'); if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:passed++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray }
    else { $script:failed++; Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red }
}

function New-Stats {
    param($TotalServers = 6, $PartialScanCount = 0, $ChecksTotal = 40, $ChecksPassed = 40, $ChecksUnread = 0)
    [pscustomobject]@{
        TotalServers     = $TotalServers
        PartialScanCount = $PartialScanCount
        ChecksTotal      = $ChecksTotal
        ChecksPassed     = $ChecksPassed
        ChecksUnread     = $ChecksUnread
    }
}

function Get-Published {
    param([bool] $ReadinessResult, $Stats)
    , (Get-mdiPublishedReadiness -ReadinessResult $ReadinessResult -Statistics $Stats)
}

function Format-Value {
    param($Value)
    ("'{0}' [{1}]" -f $Value, $(if ($null -eq $Value) { 'null' } else { $Value.GetType().Name }))
}

# --- A measured failure is decided evidence and outranks an incomplete scan --------------------
$withPartial = Get-Published $false (New-Stats -PartialScanCount 1 -ChecksPassed 35)
Assert-True 'five measured failures alongside a partial scan publish a boolean, not a string' `
    ($withPartial -is [bool]) (Format-Value $withPartial)
Assert-True 'and that boolean is False - the failures decide the verdict' `
    (($withPartial -is [bool]) -and $withPartial -eq $false) (Format-Value $withPartial)

$noPartial = Get-Published $false (New-Stats -PartialScanCount 0 -ChecksPassed 35 -ChecksUnread 3)
Assert-True 'the same failures without a partial scan publish False as they always did' `
    (($noPartial -is [bool]) -and $noPartial -eq $false) (Format-Value $noPartial)

Assert-True 'both paths agree, so identical measured evidence yields one published answer' `
    (($withPartial -is [bool]) -and ($noPartial -is [bool]) -and $withPartial -eq $noPartial) `
    ("partial {0}; no-partial {1}" -f (Format-Value $withPartial), (Format-Value $noPartial))

# A large partial-scan count, and a partial scan of EVERY server, still cannot erase a failure.
foreach ($count in @(1, 5, 6, 99)) {
    $v = Get-Published $false (New-Stats -PartialScanCount $count -ChecksPassed 35)
    Assert-True ("PartialScanCount={0} still publishes False over five measured failures" -f $count) `
        (($v -is [bool]) -and $v -eq $false) (Format-Value $v)
}

# A single failing check is still a failure, not an unknown.
$oneFailure = Get-Published $false (New-Stats -PartialScanCount 3 -ChecksTotal 40 -ChecksPassed 39)
Assert-True 'one measured failure among a partially scanned estate publishes False' `
    (($oneFailure -is [bool]) -and $oneFailure -eq $false) (Format-Value $oneFailure)

# --- The unknown verdict still stands where the run genuinely could not decide -----------------
$nothingScanned = Get-Published $false (New-Stats -TotalServers 0 -ChecksTotal 0 -ChecksPassed 0)
Assert-True 'a run that scanned no server at all still publishes N/A' `
    ($nothingScanned -is [string] -and $nothingScanned -eq 'N/A') (Format-Value $nothingScanned)

$partialNoFailure = Get-Published $false (New-Stats -PartialScanCount 1 -ChecksTotal 40 -ChecksPassed 40)
Assert-True 'a partial scan with nothing observed failing still publishes N/A' `
    ($partialNoFailure -is [string] -and $partialNoFailure -eq 'N/A') (Format-Value $partialNoFailure)

$unreadNoFailure = Get-Published $false (New-Stats -ChecksTotal 40 -ChecksPassed 40 -ChecksUnread 3)
Assert-True 'unread checks with nothing observed failing still publish N/A' `
    ($unreadNoFailure -is [string] -and $unreadNoFailure -eq 'N/A') (Format-Value $unreadNoFailure)

$provenReady = Get-Published $true (New-Stats -PartialScanCount 1 -ChecksPassed 35)
Assert-True 'a run that proved readiness still publishes True' `
    (($provenReady -is [bool]) -and $provenReady -eq $true) (Format-Value $provenReady)

$decidedFailure = Get-Published $false (New-Stats -ChecksTotal 40 -ChecksPassed 40 -ChecksUnread 0)
Assert-True 'a failure outside the check counts - nothing unread, nothing partial - still publishes False' `
    (($decidedFailure -is [bool]) -and $decidedFailure -eq $false) (Format-Value $decidedFailure)

# --- A count that was never read cannot manufacture an unknown over measured failures ----------
foreach ($shape in @(
        @{ Name = 'null'; Value = $null },
        @{ Name = 'empty string'; Value = '' },
        @{ Name = 'a non-numeric string'; Value = 'abc' },
        @{ Name = 'a numeric string'; Value = '1' },
        @{ Name = 'a boolean'; Value = $true },
        @{ Name = 'a hashtable'; Value = @{ x = 1 } },
        @{ Name = 'an empty array'; Value = @() }
    )) {
    $v = $null
    $threw = $false
    try { $v = Get-Published $false (New-Stats -PartialScanCount $shape.Value -ChecksPassed 35) }
    catch { $threw = $true }
    Assert-True ("PartialScanCount as {0} does not throw" -f $shape.Name) (-not $threw)
    Assert-True ("PartialScanCount as {0} still publishes False over measured failures" -f $shape.Name) `
        ((-not $threw) -and ($v -is [bool]) -and $v -eq $false) (Format-Value $v)
}

# An unreadable check population must not invent failures either: nothing measured is not a failure.
foreach ($shape in @($null, '', 'abc')) {
    $v = Get-Published $false (New-Stats -TotalServers 6 -PartialScanCount 1 -ChecksTotal $shape -ChecksPassed $shape)
    Assert-True ("an unreadable ChecksTotal/ChecksPassed ({0}) is not treated as a failure" -f $(if ($null -eq $shape) { 'null' } else { "'$shape'" })) `
        ($v -is [string] -and $v -eq 'N/A') (Format-Value $v)
}

# A statistics object missing the fields entirely must not throw or invent a verdict.
# Such a report publishes $false, unchanged by this fix and measured identically on the code before
# it: with no check counts there are no known failures, so the guard added here is never reached.
# What matters for this defect is only that the value stays inside the documented tri-state.
$sparse = [pscustomobject]@{ TotalServers = 6 }
$sparseValue = $null
$sparseThrew = $false
try { $sparseValue = Get-Published $false $sparse } catch { $sparseThrew = $true }
Assert-True 'a statistics object with no check counts does not throw' (-not $sparseThrew)
Assert-True 'and still publishes one of the documented states rather than a bare string' `
    ((-not $sparseThrew) -and ((($sparseValue -is [bool])) -or ($sparseValue -is [string] -and $sparseValue -eq 'N/A'))) `
    (Format-Value $sparseValue)

# --- The published value is always one of the three documented states --------------------------
$allValues = @($withPartial, $noPartial, $oneFailure, $nothingScanned, $partialNoFailure,
    $unreadNoFailure, $provenReady, $decidedFailure, $sparseValue)
$badShape = @($allValues | Where-Object { -not (($_ -is [bool]) -or ($_ -is [string] -and $_ -eq 'N/A')) })
Assert-True 'every published value is a boolean or the string N/A' ($badShape.Count -eq 0) `
    ((@($badShape | ForEach-Object { Format-Value $_ }) -join '; '))

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
