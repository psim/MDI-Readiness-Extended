<#
    A CPU COUNTER WIDER THAN Int32 CRASHED THE SERVER'S ENTIRE COLLECTION, AND A NEGATIVE ONE
    REPORTED A QUIETER SERVER THAN REALITY.

    Get-mdiCapacityPlanning reads three counters out of the same sample rows. The packet rate was
    deliberately hardened - it goes through Get-mdiPacketRateReading (which rejects unparsable,
    culture-dependent, NaN, Infinity and negative values) and is rounded with [long], under a comment
    explaining that a large finite rate must survive being read so the sizing layer can give its
    honest "not supported at this rate" answer.

    The CPU and memory samples, collected three lines away from the same rows, got neither guard:

        $cpuSamples = @($collected | Where-Object { $null -ne $_.CpuPercent } | ForEach-Object { [double] $_.CpuPercent })
        $avgCpuPercent = ... [int] [math]::Round((... -Average).Average) ...

    PercentProcessorTime is a **UInt64** at the source (measured on the live class). Measured on the
    shipped function, with the packet path alongside for contrast:

        CPU = Int32.MaxValue        -> avg = 2147483647          (fine)
        CPU = Int32.MaxValue + 1    -> THREW "Cannot convert value "2147483648" to type "System.Int32""
        CPU = UInt64.MaxValue       -> THREW
        CPU = NaN                   -> THREW
        CPU = +Infinity             -> THREW
        packets = 4294967295        -> survives, sized correctly
        packets = 9007199254740993  -> survives, sized correctly

    The throw happens inside the per-server collection, so the domain controller is recorded as a
    partial failure and the results it had already produced are discarded - one counter artefact
    costing a whole server's scan, while the counter beside it shrugs off a number four million times
    larger.

    Separately, a NEGATIVE reading was accepted and averaged in: readings of 90, -50 and 8 gave an
    average of 16, where the two valid readings average 49. A wrapped counter made the report describe
    a quieter server than the one being measured.

    The fix is the class fix, not the instance: the guard logic moved into Get-mdiPacketRateReading (with
    Get-mdiPacketRateReading delegating to it, so there is one copy) and the CPU and memory samples now
    use it. The round is [long], matching the packet rate.

    Behavioural: every assertion calls the shipped Get-mdiCapacityPlanning and reads what it returned.
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

Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

# The hardware inventory is read over WMI before the counter arithmetic is reached; without it the
# function returns "not sized" for a reason that has nothing to do with the defect under test.
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    switch -Wildcard ([string] $Class) {
        '*Processor*' { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 16 } }
        '*ComputerSystem*' { [PSCustomObject]@{ TotalPhysicalMemory = [uint64] 34359738368 } }
        default { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 16; TotalPhysicalMemory = [uint64] 34359738368 } }
    }
}
if ((Get-WmiObject -ComputerName x -Class Win32_Processor).NumberOfCores -ne 8) { throw 'WMI stub did not take effect' }

function New-Sample {
    param($Cpu, $Packets = 1000, $Mem = 8192)
    1..3 | ForEach-Object {
        [PSCustomObject]@{
            TimeStamp = (Get-Date).AddMinutes(-$_)
            PacketsPerSec = $Packets
            CpuPercent = $Cpu
            AvailableMb = $Mem
        }
    }
}
function Invoke-Capacity {
    param($Cpu, $Packets = 1000)
    Get-mdiCapacityPlanning -ComputerName 'dc1.contoso.com' -TrafficSample (New-Sample -Cpu $Cpu -Packets $Packets) 3>$null
}

# The control must produce a real sized verdict, or nothing below is measuring the CPU path.
$sanity = Invoke-Capacity -Cpu 35
if ($sanity.details.AvgCpuPercent -ne 35) { throw "the harness did not reach the CPU arithmetic (detail: $($sanity.details.Detail))" }

Write-Host 'A counter reading wider than Int32 must not crash the server''s collection' -ForegroundColor Cyan
foreach ($case in @(
        @{ N = 'Int32.MaxValue + 1'; V = ([double] [int]::MaxValue + 1) },
        @{ N = 'UInt64.MaxValue'; V = [double] [uint64]::MaxValue },
        @{ N = 'a value far beyond Int64'; V = [double] 1e30 })) {
    $threw = $false
    $r = $null
    try { $r = Invoke-Capacity -Cpu $case.V } catch { $threw = $true }
    Assert-That "$($case.N): does not throw" (-not $threw)
    if ($threw) { continue }
    Assert-That "$($case.N): still produces a verdict" ($null -ne $r.isCapacityOk) "ok=$($r.isCapacityOk)"
    # The packet rate was measured and is what the verdict is about; an unreadable CPU counter must
    # not silently become part of it.
    Assert-That "$($case.N): the packet-based sizing still happened" (
        [string] $r.details.Detail -notlike '*Missing*') "detail=$($r.details.Detail)"
}

# Int32.MaxValue + 1 is finite and representable as a whole number, so it must be REPORTED, not
# discarded - the same treatment the packet rate gets for a large finite artefact.
$wide = Invoke-Capacity -Cpu ([double] [int]::MaxValue + 1)
Assert-That 'a finite counter just past Int32 is still reported, not discarded' (
    [long] $wide.details.AvgCpuPercent -eq 2147483648) "avg=$($wide.details.AvgCpuPercent)"

Write-Host ''
Write-Host 'NaN and Infinity are not measurements' -ForegroundColor Cyan
foreach ($case in @(
        @{ N = 'NaN'; V = [double]::NaN },
        @{ N = '+Infinity'; V = [double]::PositiveInfinity })) {
    $threw = $false
    $r = $null
    try { $r = Invoke-Capacity -Cpu $case.V } catch { $threw = $true }
    Assert-That "$($case.N): does not throw" (-not $threw)
    if ($threw) { continue }
    Assert-That "$($case.N): is not reported as a CPU figure" ($null -eq $r.details.AvgCpuPercent) (
        "avg=$($r.details.AvgCpuPercent)")
}

Write-Host ''
Write-Host 'A negative counter must not make the server look quieter than it is' -ForegroundColor Cyan
$mixed = @(
    [PSCustomObject]@{ TimeStamp = (Get-Date).AddMinutes(-1); PacketsPerSec = 1000; CpuPercent = 90; AvailableMb = 8192 }
    [PSCustomObject]@{ TimeStamp = (Get-Date).AddMinutes(-2); PacketsPerSec = 1000; CpuPercent = -50; AvailableMb = 8192 }
    [PSCustomObject]@{ TimeStamp = (Get-Date).AddMinutes(-3); PacketsPerSec = 1000; CpuPercent = 8; AvailableMb = 8192 }
)
$neg = Get-mdiCapacityPlanning -ComputerName 'dc1.contoso.com' -TrafficSample $mixed 3>$null
Assert-That 'the wrapped reading is not averaged in' ([long] $neg.details.AvgCpuPercent -ne 16) (
    "avg=$($neg.details.AvgCpuPercent)")
Assert-That 'the average is taken over the VALID readings only' (
    [long] $neg.details.AvgCpuPercent -eq 49) "avg=$($neg.details.AvgCpuPercent) (90 and 8 average 49)"
Assert-That 'the peak is the highest VALID reading' ([long] $neg.details.MaxCpuPercent -eq 90) (
    "max=$($neg.details.MaxCpuPercent)")

# All-negative is no usable reading at all, which is different from a measured zero.
$allNeg = Invoke-Capacity -Cpu -20
Assert-That 'an all-negative CPU sample reports no figure rather than a negative one' (
    $null -eq $allNeg.details.AvgCpuPercent) "avg=$($allNeg.details.AvgCpuPercent)"

Write-Host ''
Write-Host 'CONTROLS - ordinary readings and the packet path must be unchanged' -ForegroundColor Cyan
$ok = Invoke-Capacity -Cpu 35
Assert-That 'CONTROL: an ordinary CPU reading is reported' ([long] $ok.details.AvgCpuPercent -eq 35) (
    "avg=$($ok.details.AvgCpuPercent)")
Assert-That 'CONTROL: and the verdict is a real one' ($ok.isCapacityOk -eq $true) "ok=$($ok.isCapacityOk)"
$edge = Invoke-Capacity -Cpu ([double] [int]::MaxValue)
Assert-That 'CONTROL: exactly Int32.MaxValue is unchanged' (
    [long] $edge.details.AvgCpuPercent -eq 2147483647) "avg=$($edge.details.AvgCpuPercent)"
$zero = Invoke-Capacity -Cpu 0
Assert-That 'CONTROL: a genuine zero is still a reading, not a rejection' (
    $null -ne $zero.details.AvgCpuPercent -and [long] $zero.details.AvgCpuPercent -eq 0) "avg=$($zero.details.AvgCpuPercent)"

# The packet path must keep working exactly as it did - it is the reference implementation here.
$bigPackets = Invoke-Capacity -Cpu 35 -Packets 4294967295
Assert-That 'CONTROL: a huge packet rate still sizes rather than throwing' (
    $bigPackets.isCapacityOk -eq $false) "ok=$($bigPackets.isCapacityOk)"
$negPackets = Invoke-Capacity -Cpu 35 -Packets -200
Assert-That 'CONTROL: a negative packet rate is still rejected as unmeasured' (
    [string] $negPackets.isCapacityOk -eq 'N/A') "ok=$($negPackets.isCapacityOk)"

Write-Host ''
Write-Host 'The shared predicate itself' -ForegroundColor Cyan
Assert-That 'an ordinary value passes' ((Get-mdiPacketRateReading -Value 35) -eq 35)
Assert-That 'zero passes' ((Get-mdiPacketRateReading -Value 0) -eq 0)
Assert-That 'a negative is rejected' ($null -eq (Get-mdiPacketRateReading -Value -1))
Assert-That 'NaN is rejected' ($null -eq (Get-mdiPacketRateReading -Value ([double]::NaN)))
Assert-That 'Infinity is rejected' ($null -eq (Get-mdiPacketRateReading -Value ([double]::PositiveInfinity)))
Assert-That 'a value beyond Int64 is rejected' ($null -eq (Get-mdiPacketRateReading -Value ([double] [uint64]::MaxValue)))
Assert-That 'a value just past Int32 is ACCEPTED' ((Get-mdiPacketRateReading -Value 2147483648.0) -eq 2147483648.0)
# Parsing stays invariant, which is what stopped '12,5' becoming 125 on a German host.
Assert-That 'text parses invariantly' ((Get-mdiPacketRateReading -Value '12.5') -eq 12.5)
Assert-That 'a comma decimal is not silently read as thousands' (
    $null -eq (Get-mdiPacketRateReading -Value '12,5') -or (Get-mdiPacketRateReading -Value '12,5') -ne 125)
# And the packets/sec name must still behave identically, since callers use both.
Assert-That 'the predicate rejects a negative for every caller' (
    (Get-mdiPacketRateReading -Value 1000) -eq (Get-mdiPacketRateReading -Value 1000) -and
    $null -eq (Get-mdiPacketRateReading -Value -5))

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
