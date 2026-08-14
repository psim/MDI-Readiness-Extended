# [w102] One domain controller's packet counter must not be able to abort the whole scan.
#
# Get-mdiBusyPacketsPerSecond cast its three rates to [int]. A packets/sec reading above
# 2,147,483,647 therefore threw:
#
#   Cannot convert value "2147483648" to type "System.Int32". Error: "Value was either too large or
#   too small for an Int32."
#
# The whole scan runs under a trap that turns any unhandled exception into "Test-MdiReadiness did not
# complete" and exit 255, so ONE domain controller reporting a large finite rate destroyed the entire
# run - every other server's results lost with it, and a compliance gate reading the exit code told
# "the scan did not run" for an estate that was almost entirely measured.
#
# A rate that large is far more likely to be a counter artefact than real traffic, but the sizing
# layer already HAS an honest answer for traffic it cannot size - "not supported at this rate, which
# is at or above the published ceiling" - and reaching that answer only requires the number to
# survive being read. The rates are now [long]; counted in packets per second a long cannot
# realistically overflow.
#
# The rendering path cast the same three values to [int] as well, so a report could still throw while
# drawing a row for a rate the producer had accepted. Those are [long] too, and this file drives the
# real renderer to prove it.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
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

# Samples in the shape the collector produces: a timestamp and a packets/sec reading.
function New-Sample {
    param([double] $Rate, [int] $Count = 4, [int] $IntervalSeconds = 300)
    $t0 = Get-Date '2026-08-14T00:00:00'
    @(0..($Count - 1) | ForEach-Object {
            [PSCustomObject]@{ Timestamp = $t0.AddSeconds($_ * $IntervalSeconds); PacketsPerSec = $Rate }
        })
}

$overflow = 2147483648   # int32 max + 1

'[w102] a rate above the int32 ceiling is READ rather than thrown'
$threw = $null
$result = $null
try { $result = Get-mdiBusyPacketsPerSecond -Sample (New-Sample -Rate $overflow) -WindowMinutes 15 }
catch { $threw = $_.Exception.Message }
Assert-That 'reading the sample does not throw' ($null -eq $threw) "(threw: $threw)"
Assert-That 'and it returns a result object' ($null -ne $result) '(returned $null)'
if ($null -ne $result) {
    Assert-That 'the busy rate survives intact, not truncated or wrapped' `
        ([long] $result.BusyPacketsPerSec -eq [long] $overflow) "(BusyPacketsPerSec $($result.BusyPacketsPerSec))"
    Assert-That 'the peak rate survives too' ([long] $result.PeakPacketsPerSec -eq [long] $overflow) `
        "(PeakPacketsPerSec $($result.PeakPacketsPerSec))"
    Assert-That 'and it is never negative (an int32 wrap would go negative)' `
        ([long] $result.BusyPacketsPerSec -gt 0) "(BusyPacketsPerSec $($result.BusyPacketsPerSec))"
}

'[w102] the rate stays usable downstream rather than being lost'
# The sizing decision itself lives inside Get-mdiCapacityPlanning, which needs a live collector; what
# matters here is that the value survives the producer intact and in a type the sizing layer can
# compare, so it can reach its honest "at or above the published ceiling" answer instead of the run
# dying on the conversion.
$sizingInput = $null
try { $sizingInput = (Get-mdiBusyPacketsPerSecond -Sample (New-Sample -Rate $overflow) -WindowMinutes 15).BusyPacketsPerSec }
catch { $sizingInput = "threw: $($_.Exception.Message)" }
Assert-That 'the value compares correctly against the published ceiling' `
    ($sizingInput -is [ValueType] -and [long] $sizingInput -ge 100000) "(BusyPacketsPerSec $sizingInput)"
Assert-That 'and it is a whole number, not a float or a string' `
    (($sizingInput -is [long]) -or ($sizingInput -is [int])) "(got $sizingInput)"

'[w102] the report can be RENDERED for such a server without throwing'
$srv = [PSCustomObject]@{
    FQDN = 'dc-overflow.contoso.com'; Domain = 'contoso.com'
    Unreachable = $false; PartialFailure = $false
    Details = [PSCustomObject]@{
        CapacityDetails = [PSCustomObject]@{
            BusyPacketsPerSec = [long] $overflow
            AveragePacketsPerSec = [long] $overflow
            PeakPacketsPerSec = [long] $overflow
            SampleSeconds = 1200
            FullBusyWindow = $true
            Status = 'No'
            Cores = 64; MemoryGb = 128
        }
    }
}
$renderThrew = $null
$html = $null
try { $html = Get-mdiCapacityHtml -Server @($srv) } catch { $renderThrew = $_.Exception.Message }
Assert-That 'rendering the capacity table does not throw' ($null -eq $renderThrew) "(threw: $renderThrew)"
Assert-That 'and the rendered row carries the full rate' `
    ($null -ne $html -and ([string] $html) -match '2147483648') `
    "(rendered: $(([string] $html).Substring(0, [Math]::Min(160, ([string] $html).Length))))"

'[w102] controls: ordinary rates are unchanged'
# Wrapped so that a regression which makes the producer THROW still reaches the summary line below
# and reports a clean failure count, instead of killing the file part way and leaving the harness to
# infer what happened from a missing summary.
foreach ($rate in 0, 1000, 50000, 99999) {
    $got = $null
    try { $got = (Get-mdiBusyPacketsPerSecond -Sample (New-Sample -Rate $rate) -WindowMinutes 15).BusyPacketsPerSec }
    catch { $got = "threw: $($_.Exception.Message)" }
    Assert-That "  a rate of $rate is read back exactly" ($got -is [ValueType] -and [long] $got -eq [long] $rate) `
        "(got $got)"
}
$ok = $null
try { $ok = Get-mdiBusyPacketsPerSecond -Sample (New-Sample -Rate 1000) -WindowMinutes 15 } catch { $ok = $null }
Assert-That 'an in-table rate is still read back as a whole number' `
    ($null -ne $ok -and ([long] $ok.BusyPacketsPerSec -eq 1000) -and ([long] $ok.PeakPacketsPerSec -eq 1000)) `
    "(busy $($ok.BusyPacketsPerSec), peak $($ok.PeakPacketsPerSec))"

''
"CapacityRateDoesNotOverflow: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
