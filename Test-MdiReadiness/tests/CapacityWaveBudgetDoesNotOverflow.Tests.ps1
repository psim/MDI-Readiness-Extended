<#
    AN INT32 OVERFLOW SILENTLY EMPTIED THE WHOLE CAPACITY PHASE.

    Get-mdiTrafficSampleSet waits for its runspace jobs against a budget that scales with the number
    of WAVES, so a forest larger than the throttle is not punished for being queued:

        $perJobWaitMs = ([Math]::Max(1, $DurationSeconds) * 1000) + 120000
        $totalWaitMs  = [double] $perJobWaitMs * $waveCount
        $remainingMs  = [int] [Math]::Max(0, $totalWaitMs - $elapsed)      # <-- the defect

    $totalWaitMs is a double. -CapacityPlanningDuration is documented and validated up to 86400, at
    which the per-wave budget is 86,520,000 ms - so 25 waves reaches 2,163,000,000 ms against an
    Int32 ceiling of 2,147,483,647. At the shipped throttle of 64 that is 1,537 domain controllers.

    It did not truncate. `[Math]::Max(0, <double>)` binds the Int32 overload from its integer first
    argument, so the conversion happened INSIDE Max and THREW. The catch below it turns any throw
    into `$collected[$job.Computer] = $null` - and because the budget does not depend on which job is
    being waited on, it threw identically for EVERY job. Measured on the shipped function:

        1536 targets (24 waves): correctlyOwned=1536  null=0     caughtErrors=0
        1537 targets (25 waves): correctlyOwned=0     null=1537  caughtErrors=1537

    Every server's capacity sample became $null. The only trace was a Write-mdiVerbose - a stream a
    default run never shows - so the report simply had no capacity data and said nothing about why.
    That is this project's worst failure shape: not a wrong number, but a whole measured phase
    quietly replaced by nothing.

    This test drives the same code path with MaxParallel = 1, so 25 TARGETS produce 25 waves and the
    identical overflow, instead of needing 1,537 runspace jobs to prove it.

    Behavioural: it calls the shipped Get-mdiTrafficSampleSet and inspects what came back per server.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

# The worker that runs INSIDE each runspace. A Set-Item stub does not cross a runspace boundary, but
# this IS the scriptblock the function hands to AddScript, so replacing it is what actually takes
# effect there. It returns instantly and stamps the server it ran for, so attribution is provable.
$script:mdiTrafficSampleScript = {
    param($ComputerName, $DurationSeconds, $IntervalSeconds, $Rest)
    [PSCustomObject]@{
        Computer = $ComputerName
        Harness  = 'OVERFLOW-TEST-WORKER'
        Marker   = ('SAMPLE<{0}>' -f $ComputerName)
    }
}

function Invoke-Sample {
    param([int] $Count, [int] $Duration)
    $targets = @(1..$Count | ForEach-Object { 'dc{0:D4}.contoso.com' -f $_ })
    # MaxParallel = 1 makes waves == targets, so the wave-scaled budget is reached with 25 servers
    # rather than 1,537. It is the same arithmetic on the same line.
    $collected = Get-mdiTrafficSampleSet -ComputerName $targets -DurationSeconds $Duration `
        -IntervalSeconds 5 -MaxParallel 1
    $owned = 0
    $null_ = 0
    foreach ($t in $targets) {
        $v = $collected[$t]
        if ($null -eq $v) { $null_++; continue }
        $row = @($v)[0]
        if ([string] $row.Marker -ceq ('SAMPLE<{0}>' -f $t) -and [string] $row.Harness -ceq 'OVERFLOW-TEST-WORKER') { $owned++ }
    }
    [PSCustomObject]@{ Targets = $targets.Count; Keys = $collected.Keys.Count; Owned = $owned; Null = $null_ }
}

# The stub must actually be the thing running in the runspaces, or a green result means nothing.
$stubCheck = Invoke-Sample -Count 1 -Duration 30
if ($stubCheck.Owned -ne 1) { throw 'the worker stub did not take effect inside the runspace pool' }

Write-Host 'A wave budget beyond Int32 must not empty the whole phase' -ForegroundColor Cyan
# 25 waves at the documented maximum duration: 25 * 86,520,000 = 2,163,000,000 > Int32.MaxValue.
$subject = Invoke-Sample -Count 25 -Duration 86400
Assert-That 'every server still has a key' ($subject.Keys -eq 25) "keys=$($subject.Keys)"
Assert-That 'no server was nulled by the budget arithmetic' ($subject.Null -eq 0) "null=$($subject.Null)"
Assert-That 'every sample is attributed to its own server' ($subject.Owned -eq 25) "owned=$($subject.Owned)"

# One wave short of the ceiling - the boundary that always worked - must be unchanged.
Write-Host ''
Write-Host 'CONTROL - just inside the ceiling, and ordinary durations' -ForegroundColor Cyan
$control = Invoke-Sample -Count 24 -Duration 86400
Assert-That 'CONTROL: 24 waves still collects every server' ($control.Owned -eq 24) "owned=$($control.Owned)"
Assert-That 'CONTROL: 24 waves nulls nothing' ($control.Null -eq 0) "null=$($control.Null)"

$ordinary = Invoke-Sample -Count 25 -Duration 120
Assert-That 'CONTROL: the default duration is unaffected' ($ordinary.Owned -eq 25) "owned=$($ordinary.Owned)"
Assert-That 'CONTROL: and nulls nothing' ($ordinary.Null -eq 0) "null=$($ordinary.Null)"

# Far past the ceiling: the clamp must hold rather than merely moving the cliff.
Write-Host ''
Write-Host 'Far beyond the ceiling the clamp must still hold' -ForegroundColor Cyan
$far = Invoke-Sample -Count 60 -Duration 86400
Assert-That 'a 60-wave budget still collects every server' ($far.Owned -eq 60) "owned=$($far.Owned)"
Assert-That 'and still nulls nothing' ($far.Null -eq 0) "null=$($far.Null)"

Write-Host ''
Write-Host 'The clamp arithmetic itself, at the boundaries' -ForegroundColor Cyan
# The shape of the fixed expression, checked directly so the intent is pinned as well as the effect.
function Get-Clamped { param([double] $Total, [double] $Elapsed)
    [int] [Math]::Min([double] [int]::MaxValue, [Math]::Max(0.0, $Total - $Elapsed))
}
Assert-That 'an over-ceiling budget clamps to Int32.MaxValue' (
    (Get-Clamped 2163000000.0 0.0) -eq [int]::MaxValue) ("got=" + (Get-Clamped 2163000000.0 0.0))
Assert-That 'an ordinary budget is untouched' ((Get-Clamped 120000.0 0.0) -eq 120000)
Assert-That 'exactly Int32.MaxValue is untouched' (
    (Get-Clamped 2147483647.0 0.0) -eq [int]::MaxValue)
# A spent budget must floor at zero, NOT at the ceiling - that would turn an expired wait into a
# 24-day one and hang the phase.
Assert-That 'a spent budget floors at zero, not at the ceiling' ((Get-Clamped 1000.0 5000.0) -eq 0) (
    "got=" + (Get-Clamped 1000.0 5000.0))
Assert-That 'a budget spent to the millisecond is zero' ((Get-Clamped 5000.0 5000.0) -eq 0)

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
