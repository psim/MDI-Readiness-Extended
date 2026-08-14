<#
    A packets/sec reading that is not a usable measurement must not be sized as one.

    Get-mdiCapacityPlanning already refuses to size a server whose traffic never arrived, and the
    comments around that gate record how expensive the lesson was. But the gate tested only
    `$null -ne $_.PacketsPerSec`, and the arithmetic behind it converted with a bare `[double]` cast.
    Three values survive that pair while carrying no information:

      * an empty string - `[double] ''` is a clean ZERO, so a broken counter was sized as an idle DC;
      * a value that only parses under the operator's own culture - a counter surfaced as text
        reading '12,5' on a German host casts to 125, an order of magnitude out and enough to move
        the server into the wrong sizing band, while the SAMPLER parses the same text invariantly and
        rejects it, so the two halves of the tool disagreed about one reading;
      * a NEGATIVE rate, which means a wrapped or broken counter. This was the worst of the three:
        no row of the sizing table matches a negative value, so the band lookup fell through to its
        "above the top of the table" fallback and sized the server against the LARGEST band, while
        the verdict - which only ever tests upper bounds - still returned 'Yes'. The report read
        "The server has enough resources for a sensor v2.x at -200 busy packets/sec" in green.

    These tests assert BEHAVIOUR: the verdict, the status string, the band, and the rendered row.
    A test that grepped for '[double]' would pass with every one of these defects reintroduced.
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

# The hardware behind every case is identical and generous, so the ONLY thing that can move the
# verdict is the packet rate itself.
function New-Sample {
    param($Rates)
    $t = [datetime]'2026-08-13T10:00:00Z'
    $i = 0
    @($Rates | ForEach-Object {
            $row = [PSCustomObject]@{ Timestamp = $t.AddSeconds(5 * $i); PacketsPerSec = $_; CpuPercent = 5; AvailableMb = 8192 }
            $i++
            $row
        })
}
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    if ($Class -like '*Processor*') { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 8 } }
    else { [PSCustomObject]@{ NumberOfCores = 8; NumberOfLogicalProcessors = 8; TotalPhysicalMemory = 34359738368 } }
}
function Get-Capacity($rates) {
    Get-mdiCapacityPlanning -ComputerName 'dc1.contoso.com' -TrafficSample (New-Sample $rates)
}

Write-Host 'A real reading is still sized normally (the control)' -ForegroundColor Cyan
$good = Get-Capacity @(500, 520, 480)
Assert-That 'an ordinary 500 packets/sec sample is sized' ($good.details.Status -eq 'Yes') "got '$($good.details.Status)'"
Assert-That '  ...and lands in the 0-1k band' ($good.details.Band -eq '0-1k') "got '$($good.details.Band)'"
Assert-That '  ...and the check passes' ($good.isCapacityOk -eq $true) "got '$($good.isCapacityOk)'"

Write-Host 'A negative packet rate is a broken counter, not a quiet server' -ForegroundColor Cyan
foreach ($case in @(
        @{ Name = 'every reading negative'; Rates = @(-200, -300, -100) }
        @{ Name = 'one negative reading among good ones'; Rates = @(500, -200, 480) }
    )) {
    $r = Get-Capacity $case.Rates
    # It must NOT be a measured pass. 'N/A' is the tri-state's unmeasured value.
    Assert-That "$($case.Name): the capacity check is not a measured pass" `
    ($r.isCapacityOk -ne $true) "got '$($r.isCapacityOk)'"
    Assert-That "  ...and no busy rate is published at all" `
    ($null -eq $r.details.PSObject.Properties['BusyPacketsPerSec']) "got '$($r.details.BusyPacketsPerSec)'"
    # The specific catastrophe: a negative rate matched no band and fell through to the LARGEST one.
    Assert-That "  ...and it is not sized against a band" `
    ([string] $r.details.Band -ne '75k-100k') "got band '$($r.details.Band)'"
    Assert-That "  ...and the detail never quotes a negative rate to the operator" `
    ($r.details.Detail -notmatch '-\d+ busy packets/sec') "got '$($r.details.Detail)'"
}

Write-Host 'An empty counter value is not a measured zero' -ForegroundColor Cyan
$empty = Get-Capacity @('', '', '')
Assert-That 'an all-empty sample is not a measured pass' ($empty.isCapacityOk -ne $true) "got '$($empty.isCapacityOk)'"
Assert-That '  ...and does not claim "0 busy packets/sec"' ($empty.details.Detail -notmatch 'at 0 busy packets/sec') "got '$($empty.details.Detail)'"

Write-Host 'A rate is parsed invariantly, so the operator''s culture cannot change the band' -ForegroundColor Cyan
# The sampler rejects '12,5' via an invariant TryParse. The aggregation must agree with it rather
# than casting the same text to 125 and sizing the server ten times too high.
Assert-That "'12,5' is rejected, not read as 125" ($null -eq (Get-mdiPacketRateReading '12,5')) "got '$(Get-mdiPacketRateReading '12,5')'"
Assert-That "'12.5' is read as 12.5 in any culture" ((Get-mdiPacketRateReading '12.5') -eq 12.5) "got '$(Get-mdiPacketRateReading '12.5')'"
Assert-That "a plain integer string still reads" ((Get-mdiPacketRateReading '5000') -eq 5000) "got '$(Get-mdiPacketRateReading '5000')'"
Assert-That "a numeric type still reads" ((Get-mdiPacketRateReading 5000) -eq 5000) "got '$(Get-mdiPacketRateReading 5000)'"
Assert-That "a genuine zero is still a reading, not a rejection" ((Get-mdiPacketRateReading 0) -eq 0) "got '$(Get-mdiPacketRateReading 0)'"
Assert-That "  ...and is distinguishable from a rejection" ($null -ne (Get-mdiPacketRateReading 0)) 'zero must not be confused with $null'
foreach ($bad in @($null, '', '   ', 'N/A', 'Unknown', 'abc', -1, -0.5)) {
    $shown = if ($null -eq $bad) { '<null>' } else { "'$bad'" }
    Assert-That "  $shown is not a usable reading" ($null -eq (Get-mdiPacketRateReading $bad)) "got '$(Get-mdiPacketRateReading $bad)'"
}

Write-Host 'Out-of-order samples do not produce a negative sample duration' -ForegroundColor Cyan
$t = [datetime]'2026-08-13T10:00:00Z'
$reversed = @(
    [PSCustomObject]@{ Timestamp = $t.AddSeconds(600); PacketsPerSec = 500 }
    [PSCustomObject]@{ Timestamp = $t.AddSeconds(300); PacketsPerSec = 500 }
    [PSCustomObject]@{ Timestamp = $t; PacketsPerSec = 500 }
)
$rev = Get-mdiBusyPacketsPerSecond -Sample $reversed -WindowMinutes 15
Assert-That 'a reversed sample reports a positive duration' ($rev.SampleSeconds -ge 0) "got $($rev.SampleSeconds)"

Write-Host 'Get-mdiBusyPacketsPerSecond refuses an unusable sample on its own' -ForegroundColor Cyan
# Get-mdiCapacityPlanning gates on Get-mdiPacketRateReading before calling this function, so the
# conversion inside it is defence in depth - and defence in depth that nothing exercises is just
# unreachable code that quietly rots. These call it DIRECTLY, which is a supported surface: it is
# the function the sizing arithmetic lives in.
function Get-DirectSample($rates) {
    $base = [datetime]'2026-08-13T10:00:00Z'
    $i = 0
    @($rates | ForEach-Object {
            $row = [PSCustomObject]@{ Timestamp = $base.AddSeconds(5 * $i); PacketsPerSec = $_ }
            $i++
            $row
        })
}
$directNeg = Get-mdiBusyPacketsPerSecond -Sample (Get-DirectSample @(-200, -300)) -WindowMinutes 15
Assert-That 'an all-negative sample yields no result at all' ($null -eq $directNeg) "got BusyPacketsPerSec=$($directNeg.BusyPacketsPerSec)"

$directEmpty = Get-mdiBusyPacketsPerSecond -Sample (Get-DirectSample @('', '')) -WindowMinutes 15
Assert-That 'an all-empty sample yields no result at all' ($null -eq $directEmpty) "got BusyPacketsPerSec=$($directEmpty.BusyPacketsPerSec)"

$directNull = Get-mdiBusyPacketsPerSecond -Sample (Get-DirectSample @($null, $null)) -WindowMinutes 15
Assert-That 'an all-null sample yields no result at all' ($null -eq $directNull) "got BusyPacketsPerSec=$($directNull.BusyPacketsPerSec)"

$directMixed = Get-mdiBusyPacketsPerSecond -Sample (Get-DirectSample @(500, -200, 500)) -WindowMinutes 15
Assert-That 'a negative reading is dropped, never averaged in' ($directMixed.BusyPacketsPerSec -eq 500) "got $($directMixed.BusyPacketsPerSec)"
Assert-That '  ...so the peak is never negative either' ($directMixed.PeakPacketsPerSec -ge 0) "got $($directMixed.PeakPacketsPerSec)"

$directCulture = Get-mdiBusyPacketsPerSecond -Sample (Get-DirectSample @('500', '12,5')) -WindowMinutes 15
Assert-That "a '12,5' reading is dropped, not multiplied to 125" ($directCulture.BusyPacketsPerSec -eq 500) "got $($directCulture.BusyPacketsPerSec)"

$directGood = Get-mdiBusyPacketsPerSecond -Sample (Get-DirectSample @(400, 600)) -WindowMinutes 15
Assert-That 'a good sample still averages correctly' ($directGood.BusyPacketsPerSec -eq 500) "got $($directGood.BusyPacketsPerSec)"

Write-Host 'The rendered row for a broken counter is grey, not a green sizing verdict' -ForegroundColor Cyan
$neg = Get-Capacity @(-200, -300, -100)
$srv = [PSCustomObject]@{
    FQDN    = 'dc-neg.contoso.com'
    Details = [PSCustomObject]@{ CapacityDetails = $neg.details }
}
$html = Get-mdiCapacityHtml -Server @($srv)
Assert-That 'the row is not painted green' ($html -notmatch '<td class="green">Yes</td>') "got: $html"
Assert-That '  ...and no negative packet rate is printed in the table' ($html -notmatch '>-\d+<') "got: $html"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
