<#
    Two defects in the capacity sampling loop ($script:mdiTrafficSampleScript), both of the
    "a long measurement is thrown away or overrun" class.

    1. ONE transient WMI blip discarded the ENTIRE accumulated sample. The catch was a bare
       "return $null", so every reading taken before the failure was lost and the operator was told
       the network performance counters could not be read at all. Measured before the fix: 9 good
       readings discarded after 9.1s. -CapacityPlanningDuration accepts up to 86400, which at the
       default 5s interval is 17,280 polls - a single RPC hiccup on any one of them threw away a
       full 24-hour sample. The samples live only inside the sampling runspace, so nothing partial
       survives anywhere to fall back on.

    2. The loop slept a FULL interval before re-checking the deadline, so it ran past the requested
       duration. -CapacityPlanningDuration is [ValidateRange(30, 86400)] and -CapacityPlanningInterval
       is [ValidateRange(1, 60)], validated independently with no cross-validation, so
       "-CapacityPlanningDuration 30 -CapacityPlanningInterval 60" is entirely legal and measured
       60.18s for a 30s request - double the wait, for a single reading that the capacity table then
       renders as "0 s".

    The assertions here are BEHAVIOURAL: they RUN the real sampling script block with WMI stubbed and
    time the result. Asserting on source text would pass against any rewrite that reintroduced either
    behaviour - and a source-text assertion in this suite has already gone red for a correct change.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

if (-not $script:mdiTrafficSampleScript) { throw 'mdiTrafficSampleScript not loaded from the script' }

<#
    The sampler is a standalone script block that takes every setting as an argument and calls
    Get-WmiObject. It is invoked here in a CHILD SCOPE with a stubbed Get-WmiObject, which is the only
    way to dictate both the counter values and exactly which poll fails. $script:pollCount is visible
    to the stub because the whole file shares one script scope.
#>
function Invoke-Sampler {
    param(
        [int] $DurationSeconds,
        [int] $IntervalSeconds,
        [int] $FailOnPoll = 0
    )
    $script:pollCount = 0
    $script:failOnPoll = $FailOnPoll
    Set-Item -Path function:script:Get-WmiObject -Value {
        param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
        # Only the adapter class advances the poll counter; the CPU/memory reads are supplementary and
        # are already wrapped in their own tolerant try/catch inside the sampler.
        if ($Class -notmatch 'PerfFormattedData_Tcpip_NetworkInterface|NetworkInterface') {
            return [PSCustomObject]@{ Name = '_Total'; PercentProcessorTime = 5; AvailableMBytes = 4096 }
        }
        $script:pollCount++
        if ($script:failOnPoll -gt 0 -and $script:pollCount -eq $script:failOnPoll) {
            throw [System.Runtime.InteropServices.COMException]::new('The RPC server is unavailable')
        }
        [PSCustomObject]@{ Name = 'Ethernet'; PacketsPersec = 25000 }
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $result = & $script:mdiTrafficSampleScript `
        -ComputerName 'dc1.contoso.com' `
        -DurationSeconds $DurationSeconds `
        -IntervalSeconds $IntervalSeconds `
        -PerfClass 'Win32_PerfFormattedData_Tcpip_NetworkInterface' `
        -CpuPerfClass 'Win32_PerfFormattedData_PerfOS_Processor' `
        -MemoryPerfClass 'Win32_PerfFormattedData_PerfOS_Memory' `
        -ExcludeAdapterName 'isatap|Teredo|Loopback'
    $sw.Stop()
    [PSCustomObject]@{
        Samples = @($result)
        Count   = @($result | Where-Object { $_ }).Count
        IsNull  = ($null -eq $result)
        Elapsed = $sw.Elapsed.TotalSeconds
        Polls   = $script:pollCount
    }
}

Write-Host 'A healthy sample is unaffected' -ForegroundColor Cyan
$healthy = Invoke-Sampler -DurationSeconds 4 -IntervalSeconds 1
Assert-That 'a clean run returns its readings' ($healthy.Count -ge 4) "got $($healthy.Count)"
Assert-That '  ...and does not return null' (-not $healthy.IsNull)
Assert-That '  ...and finishes within its budget' ($healthy.Elapsed -lt 6) "took $([math]::Round($healthy.Elapsed,2))s"

Write-Host 'A transient WMI failure keeps the readings already taken' -ForegroundColor Cyan
# The blip lands on the final poll, after several good readings - the shape that used to lose them all.
$blip = Invoke-Sampler -DurationSeconds 6 -IntervalSeconds 1 -FailOnPoll 5
Assert-That 'a late blip does not discard the whole sample' (-not $blip.IsNull) 'returned null - every reading was thrown away'
Assert-That '  ...the earlier readings survive' ($blip.Count -ge 4) "kept $($blip.Count) of the 4 taken before the blip"
Assert-That '  ...and the failed poll contributes no reading' ($blip.Count -lt $blip.Polls) "count=$($blip.Count) polls=$($blip.Polls)"

# Every surviving reading must still be a real measurement, or "keep what we had" would be worse than
# discarding: a partial sample of zeroes reads as an idle server with spare capacity.
$badValues = @($blip.Samples | Where-Object { $_ -and ($null -eq $_.PacketsPerSec -or $_.PacketsPerSec -le 0) })
Assert-That '  ...and each surviving reading is a real measurement' ($badValues.Count -eq 0) "$($badValues.Count) empty or zero readings survived"

Write-Host 'A failure before ANY reading is still a failure' -ForegroundColor Cyan
# Nothing measured must stay indistinguishable from "counters unreadable" - otherwise the capacity
# verdict would be computed from an empty sample.
$deadFirst = Invoke-Sampler -DurationSeconds 4 -IntervalSeconds 1 -FailOnPoll 1
Assert-That 'a blip on the very first poll returns null' ($deadFirst.IsNull -or $deadFirst.Count -eq 0) "returned $($deadFirst.Count) readings"

Write-Host 'The sample never runs past the duration it was given' -ForegroundColor Cyan
# Both of these values pass the shipped ValidateRange attributes, and nothing cross-validates them.
$overshoot = Invoke-Sampler -DurationSeconds 4 -IntervalSeconds 30
Assert-That 'an interval longer than the duration does not extend the run' ($overshoot.Elapsed -lt 8) "took $([math]::Round($overshoot.Elapsed,2))s for a 4s request"
Assert-That '  ...and it still returns a reading' ($overshoot.Count -ge 1) "got $($overshoot.Count)"

$awkward = Invoke-Sampler -DurationSeconds 4 -IntervalSeconds 3
# 4s with a 3s interval is the tightest discriminator available: capped it ends at ~4s (sleep 3, then
# sleep the remaining 1), uncapped it sleeps 3+3 and ends at ~6s. The bound sits between the two, so a
# flat full-interval sleep cannot slip past it.
Assert-That 'an interval that straddles the deadline does not overrun' ($awkward.Elapsed -lt 5) "took $([math]::Round($awkward.Elapsed,2))s for a 4s request"
Assert-That '  ...and still takes the second reading before stopping' ($awkward.Count -ge 2) "got $($awkward.Count) readings"

$normal = Invoke-Sampler -DurationSeconds 4 -IntervalSeconds 1
Assert-That 'the ordinary case still samples for its full duration' ($normal.Elapsed -ge 3.5) "took only $([math]::Round($normal.Elapsed,2))s"
Assert-That '  ...and is not cut short' ($normal.Count -ge 4) "got $($normal.Count) readings"

Write-Host 'Capping the sleep does not collapse the interval' -ForegroundColor Cyan
# A cap implemented as "sleep the remainder" must not become "do not sleep at all", which would spin
# the loop and hammer the DC with WMI calls for the whole duration.
Assert-That 'a 1s interval over 4s does not spin' ($normal.Polls -le 8) "polled $($normal.Polls) times in $([math]::Round($normal.Elapsed,2))s"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
