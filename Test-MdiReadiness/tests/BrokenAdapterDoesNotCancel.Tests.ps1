<#
    A broken adapter counter must not cancel a working one.

    Packets/sec is a rate and cannot be below zero. A negative reading is a wrapped or broken counter,
    and Get-mdiPacketRateReading already refuses one for exactly that reason - but it only ever sees
    the TOTAL, and the total is summed inside the sampler. So a broken adapter SUBTRACTED from a
    working one and handed the aggregate guard a plausible number. Measured on the shipped sampler:

        adapters 100000                -> 100000 packets/sec, CapacitySufficient=False
                                          "not supported ... at or above the 100000 packets/sec ceiling"
        adapters 100000 and -99500     ->    500 packets/sec, CapacitySufficient=True
                                          "The server has enough resources for a sensor v2.x"

    One broken counter turned a server that is over the top of the published sizing table into a green
    pass. A subtracted reading is the one direction that flatters the verdict, and it flips the answer
    on precisely the busiest servers - the ones where being wrong costs most.

    Asserted through the REAL sampler script block, lifted verbatim out of the canonical file and run
    with WMI stubbed in SCRIPT scope, then its actual output row is fed to the REAL capacity function.
    A test that recomputed the sum would prove nothing about the shipped sampler.

    Controls carry equal weight. Rejecting adapters wholesale would also "fix" this and would break
    every multi-homed domain controller, so a two-adapter server with two GOOD readings must still sum
    them, and a single good adapter must be unchanged.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = (Resolve-Path -LiteralPath $target).ProviderPath
$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $body.IndexOf('#region Main'); if ($i -gt 0) { $body = $body.Substring(0, $i) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The per-adapter summation lives inside Get-mdiCapacityPlanning's sampling loop. It is lifted VERBATIM
# between two anchors so this test exercises the shipped arithmetic rather than a copy of it.
$lines = [IO.File]::ReadAllLines($target)
$startIdx = -1; $endIdx = -1
for ($n = 0; $n -lt $lines.Count; $n++) {
    if ($startIdx -lt 0 -and $lines[$n] -match '^\s*\$total = 0\s*$' -and $lines[$n + 1] -match '^\s*\$readAdapterCount = 0\s*$') { $startIdx = $n }
    if ($startIdx -ge 0 -and $lines[$n] -match '^\s*if \(\$readAdapterCount -eq 0\) \{ return \$null \}\s*$') { $endIdx = $n; break }
}
if ($startIdx -lt 0 -or $endIdx -lt 0) { throw "adapter summation anchors not found (start=$startIdx end=$endIdx)" }
# The trailing `return $null` is dropped: it is valid only inside the sampler's own scope. Its
# condition is asserted directly instead.
$sumBlock = ($lines[$startIdx..($endIdx - 1)] -join "`r`n")

function Measure-Adapters {
    param([object[]] $Values)
    $adapters = @($Values | ForEach-Object { [PSCustomObject]@{ Name = 'nic'; PacketsPersec = $_ } })
    Invoke-Expression $sumBlock
    [PSCustomObject]@{ Total = $total; ReadCount = $readAdapterCount }
}

'[the defect] a broken negative counter must not subtract from a real reading'
$busy = Measure-Adapters @(100000)
$cancelled = Measure-Adapters @(100000, -99500)
Assert-That 'the control really is a busy server' ($busy.Total -eq 100000) "(total=$($busy.Total))"
Assert-That 'the broken adapter does not reduce the total' ($cancelled.Total -eq 100000) "(total=$($cancelled.Total))"
Assert-That 'the broken adapter is not counted as read' ($cancelled.ReadCount -eq 1) "(readCount=$($cancelled.ReadCount))"

'[verdict] the flattered verdict must not survive the broken counter'
# Get-mdiCapacityPlanning reads the hardware inventory over WMI before it will size anything, so the
# cmdlet is stubbed in SCRIPT scope - a `function global:` would NOT override the script's own call and
# every case would come back 'N/A', which looks like a pass here.
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $ErrorAction)
    switch ($Class) {
        'Win32_Processor' { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 8 } }
        'Win32_ComputerSystem' { [PSCustomObject]@{ TotalPhysicalMemory = 32GB } }
        default { $null }
    }
}
function Get-Verdict {
    param([double] $PacketsPerSec)
    $sample = @([PSCustomObject]@{ Timestamp = [datetime]::Now; PacketsPerSec = $PacketsPerSec; CpuPercent = 5; AvailableMb = 8192 })
    Get-mdiCapacityPlanning -ComputerName 'dc1.contoso.com' -DurationSeconds 1 -IntervalSeconds 1 -TrafficSample $sample
}
$vBusy = Get-Verdict -PacketsPerSec $busy.Total
$vCancelled = Get-Verdict -PacketsPerSec $cancelled.Total
Assert-That 'the hardware stub really took effect' ($vBusy.isCapacityOk -ne 'N/A') "(isCapacityOk=$($vBusy.isCapacityOk))"
Assert-That 'the busy control is not sized as sufficient' ($vBusy.isCapacityOk -eq $false) "(isCapacityOk=$($vBusy.isCapacityOk))"
Assert-That 'the same server with a broken adapter is still not sufficient' ($vCancelled.isCapacityOk -eq $false) "(isCapacityOk=$($vCancelled.isCapacityOk))"
Assert-That 'it is not reported as having enough resources' ([string] $vCancelled.details.Detail -notmatch 'has enough resources') "(details='$($vCancelled.details.Detail)')"

'[all-broken control] a server whose every adapter is broken has no sample at all'
$allBad = Measure-Adapters @(-500)
Assert-That 'nothing was read' ($allBad.ReadCount -eq 0) "(readCount=$($allBad.ReadCount))"
Assert-That 'so the sampler reports no measurement rather than a number' ($allBad.Total -eq 0) "(total=$($allBad.Total))"

'[multi-homed control] two good adapters must still be summed'
$multi = Measure-Adapters @(4000, 6000)
Assert-That 'both readings are counted' ($multi.ReadCount -eq 2) "(readCount=$($multi.ReadCount))"
Assert-That 'the rates are added, not replaced' ($multi.Total -eq 10000) "(total=$($multi.Total))"

'[text counter control] an invariantly-parsed string reading is unaffected'
$textual = Measure-Adapters @('12.5', '7.5')
Assert-That 'both text readings are counted' ($textual.ReadCount -eq 2) "(readCount=$($textual.ReadCount))"
Assert-That 'they are summed invariantly' ($textual.Total -eq 20) "(total=$($textual.Total))"
$textNeg = Measure-Adapters @('100000', '-99500')
Assert-That 'a negative TEXT reading is rejected too' ($textNeg.Total -eq 100000) "(total=$($textNeg.Total))"

'[zero control] a genuine zero reading is still a reading'
$zero = Measure-Adapters @(0)
Assert-That 'zero is counted as read' ($zero.ReadCount -eq 1) "(readCount=$($zero.ReadCount))"

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
