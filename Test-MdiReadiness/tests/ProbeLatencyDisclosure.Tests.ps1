<#
    A truncated table says how much it truncated.

    The probe-latency table renders only the ten slowest probes. Bounding the table is right - a large
    estate produces hundreds of probes and nobody reads them - but for a long time nothing on the page
    said it had happened. The lead sentence read

        Round-trip time of each successful probe. Average 130 ms.

    above ten rows whose own mean was 205 ms, because the average covered all 25 measured probes while
    the rows were the slow tail. Fifteen measurements were dropped with no row count, no footnote and no
    heading to reveal it, so the two numbers on the page could not be reconciled with each other and a
    reader could not tell measured-and-omitted from never-measured.

    This is the same illusion the ports and NNR cards were corrected for, and it is fixed the same way:
    state the sample. These assertions drive the real renderer and read the numbers back out of the
    emitted HTML, so they hold across any rewrite that keeps the behaviour.
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

# Drives the real Get-mdiRequiredPortsHtml with a synthetic set of successful, timed probes and returns
# just the probe-latency section of the emitted HTML.
function Get-LatencySection {
    param([int[]] $LatencyMs)

    $script:FakeLatencies = $LatencyMs
    Set-Item -Path function:script:Get-mdiPortResultRecord -Value {
        param ($Server)
        $i = 0
        return @($script:FakeLatencies | ForEach-Object {
                $i++
                [PSCustomObject]@{
                    Id          = "probe-$i"; Server = 'server1'; Name = "probe$i"; Target = "target$i"
                    TargetIP    = '1.2.3.4'; LatencyMs = $_; Success = $true; Applicable = $true
                    Requirement = 'Required'; Protocol = 'TCP'; Port = '443'; Detail = 'OK'
                }
            })
    }

    $servers = @([PSCustomObject]@{
            Name    = 'server1'
            Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ ProbedFrom = 'test' } }
        })

    $html = (Get-mdiRequiredPortsHtml -Server $servers) -join "`n"
    if ($html -notmatch '<h4>Probe latency</h4>') { throw 'probe latency section was not rendered' }
    $section = ($html -split '<h4>Probe latency</h4>', 2)[1]
    return ($section -split '</table></div>', 2)[0]
}

function Get-RenderedLatency {
    param([string] $Section)
    return @([regex]::Matches($Section, '<td class="(?:red|amber|green)">(\d+) ms</td>') |
            ForEach-Object { [int] $_.Groups[1].Value })
}

function Get-StatedAverage {
    param([string] $Section)
    $m = [regex]::Match($Section, 'Average (\d+) ms')
    if (-not $m.Success) { return -1 }
    return [int] $m.Groups[1].Value
}

Write-Host 'Probe latency table: truncation is disclosed' -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------------
# More probes measured than the table can show. 25 probes at 10..250 ms: mean of all 25 is 130 ms,
# mean of the ten slowest is 205 ms - the exact case that produced the contradictory page.
# ---------------------------------------------------------------------------------------------------
$latencies = @(1..25 | ForEach-Object { $_ * 10 })
$section = Get-LatencySection -LatencyMs $latencies
$rendered = Get-RenderedLatency -Section $section
$stated = Get-StatedAverage -Section $section
$trueMean = [int] [math]::Round((($latencies | Measure-Object -Average).Average))
$visibleMean = [int] [math]::Round((($rendered | Measure-Object -Average).Average))

Assert-That 'table renders fewer rows than probes measured' ($rendered.Count -lt $latencies.Count) `
    ("rendered=$($rendered.Count) measured=$($latencies.Count)")

Assert-That 'does not claim to show every successful probe' ($section -notmatch 'time of each successful probe')

Assert-That 'states rows shown out of probes measured' `
    ($section -match ('\b{0}\b[^<]*\bof\b[^<]*\b{1}\b' -f $rendered.Count, $latencies.Count)) `
    ("expected '$($rendered.Count) ... of ... $($latencies.Count)'")

Assert-That 'average still covers every measured probe' ($stated -eq $trueMean) "stated=$stated true=$trueMean"

Assert-That 'stated average is not the mean of the visible rows' ($stated -ne $visibleMean) `
    "stated=$stated visible=$visibleMean"

Assert-That 'names the population the average covers' `
    ($section -match ('Average {0} ms across all {1}' -f $stated, $latencies.Count))

$expectedRows = @($latencies | Sort-Object -Descending | Select-Object -First $rendered.Count)
Assert-That 'shows the slowest probes' (($rendered -join ',') -eq ($expectedRows -join ',')) `
    ("rendered=$($rendered -join ',')")

Assert-That 'describes the rows it kept as the slowest' ($section -match 'slowest')

# ---------------------------------------------------------------------------------------------------
# Every probe fits: the completeness claim is true, so it must survive, and no truncation wording may
# be invented. A fix that always prints "showing N of M" would be as wrong as the original.
# ---------------------------------------------------------------------------------------------------
$small = @(10, 20, 30)
$smallSection = Get-LatencySection -LatencyMs $small
$smallRendered = Get-RenderedLatency -Section $smallSection
$smallStated = Get-StatedAverage -Section $smallSection
$smallVisibleMean = [int] [math]::Round((($smallRendered | Measure-Object -Average).Average))

Assert-That 'renders every probe when they all fit' ($smallRendered.Count -eq $small.Count) `
    ("rendered=$($smallRendered.Count) measured=$($small.Count)")
Assert-That 'keeps the completeness claim when it is true' ($smallSection -match 'time of each successful probe')
Assert-That 'invents no truncation wording when nothing was truncated' `
    (($smallSection -notmatch 'slowest') -and ($smallSection -notmatch 'across all'))
Assert-That 'average equals the mean of the rows on screen' ($smallStated -eq $smallVisibleMean) `
    "stated=$smallStated visible=$smallVisibleMean"

# ---------------------------------------------------------------------------------------------------
# The boundary. Exactly at the cap nothing is hidden; one past it, something is.
# ---------------------------------------------------------------------------------------------------
$atCap = Get-LatencySection -LatencyMs @(1..10 | ForEach-Object { $_ * 10 })
$atCapRendered = Get-RenderedLatency -Section $atCap
Assert-That 'exactly at the cap, all rows render' ($atCapRendered.Count -eq 10) "rendered=$($atCapRendered.Count)"
Assert-That 'exactly at the cap, no truncation is claimed' `
    (($atCap -match 'time of each successful probe') -and ($atCap -notmatch 'slowest'))

$overCap = Get-LatencySection -LatencyMs @(1..11 | ForEach-Object { $_ * 10 })
$overCapRendered = Get-RenderedLatency -Section $overCap
Assert-That 'one past the cap, the table is still capped' ($overCapRendered.Count -eq 10) `
    "rendered=$($overCapRendered.Count)"
Assert-That 'one past the cap, the omission is disclosed' `
    (($overCap -notmatch 'time of each successful probe') -and ($overCap -match '\b10\b[^<]*\bof\b[^<]*\b11\b'))

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) `
    -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $(if ($script:fail) { 1 } else { 0 })
