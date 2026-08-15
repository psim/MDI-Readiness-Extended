# The trend pill contradicted itself, printed "0 pt" for a real change, and leaked the operator's
# decimal separator into the HTML.
#
# One <span class="pill"> under the trend chart carries three things that must be the same fact: an
# ARROW, a TONE (green / grey / red) and a NUMBER. They were computed from two different values - the
# arrow and tone tested the TRUE delta against +/-0.5, while the label printed
# [math]::Round($delta, 1) - so two runs printing an IDENTICAL number rendered opposite verdicts.
#
# Measured on the shipped Get-mdiTrendHtml, minimal pair:
#
#     100/200  -> 101/200    true delta 0.500      grey  "-> 0.5 pt vs previous run"
#     950/1900 -> 960/1900   true delta 0.526...   green "^  0.5 pt vs previous run"
#
# Same printed number, opposite arrow and opposite tone, on the one control whose entire job is to say
# which way the estate moved. A sweep over denominators 200..4000 found the pair at every denominator
# where a step straddles the threshold.
#
# Two further defects on the same three lines:
#   * 1000/2000 -> 1001/2000 is a genuine gain and rendered "-> 0 pt vs previous run". "0 pt" is the
#     one number a reader takes as "nothing changed"; this pill has already shipped that lie once for
#     a different reason (the denominator note in the source).
#   * The label was built with -f, which formats using the CURRENT THREAD CULTURE, so under de-DE or
#     it-IT it rendered "-0,1 pt" - a decimal comma inside a report whose numbers are otherwise
#     written invariantly, against this file's own stated rule.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$source = [IO.File]::ReadAllText($target)
$source = $source -replace '(?m)^\s*#Requires.*$', ''
$source = $source -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$main = $source.IndexOf('#region Main')
if ($main -lt 1) { throw 'Could not isolate the canonical function definitions.' }
Invoke-Expression $source.Substring(0, $main)
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# Two history points differing only in ChecksPassed, so the delta is exactly (Curr-Prev)/Den * 100.
function New-Hist {
    param([string] $Ts, [double] $Passed, [double] $Total)
    [PSCustomObject]@{
        Timestamp = $Ts; ScriptVersion = '1.0.0'; Domain = 'contoso.com'; Forest = 'contoso.com'
        CheckNames = @('A', 'B'); ServerNames = @('dc1.contoso.com')
        ChecksPassed = $Passed; ChecksTotal = $Total; ChecksUnread = 0
        ServersTotal = 1; ServersReady = 0; PortsOpen = 0; PortsTotal = 0; NnrResolvable = 0
    }
}

function Get-Pill {
    param([double] $Den, [double] $Prev, [double] $Curr)
    $h = @((New-Hist '2026-08-01T00:00:00' $Prev $Den), (New-Hist '2026-08-02T00:00:00' $Curr $Den))
    $html = (New-mdiTrendChart -History $h) -join ''
    $m = [regex]::Match($html, '<span class="pill (\w+)">([^<]*)</span>')
    if (-not $m.Success) { throw "no pill emitted for $Prev/$Den -> $Curr/$Den" }
    $text = [Net.WebUtility]::HtmlDecode($m.Groups[2].Value)
    [PSCustomObject]@{
        Tone   = $m.Groups[1].Value
        Text   = $text
        Number = ([regex]::Match($text, '(-?[\d.,]+) pt')).Groups[1].Value
        Arrow  = $(if ($text.Contains([char]0x2191)) { 'UP' } elseif ($text.Contains([char]0x2193)) { 'DOWN' } else { 'FLAT' })
        True   = (Get-mdiCoveragePercent -Passed $Curr -Measured $Den -Unread 0) -
        (Get-mdiCoveragePercent -Passed $Prev -Measured $Den -Unread 0)
    }
}

'[trend pill] the arrow, the tone and the number are one fact'
# THE DEFECT, as its minimal pair. Both print the same number; before the fix one was green/up.
$straddleA = Get-Pill -Den 200 -Prev 100 -Curr 101      # true 0.5     - not above the dead band
$straddleB = Get-Pill -Den 1900 -Prev 950 -Curr 960     # true 0.526.. - was above it
"      den=200  100->101 : tone=$($straddleA.Tone) arrow=$($straddleA.Arrow) text='$($straddleA.Text)'"
"      den=1900 950->960 : tone=$($straddleB.Tone) arrow=$($straddleB.Arrow) text='$($straddleB.Text)'"
Assert-That 'both straddling runs print the same number' ($straddleA.Number -eq $straddleB.Number) `
    "('$($straddleA.Number)' vs '$($straddleB.Number)')"
Assert-That '  ...so they must carry the same arrow' ($straddleA.Arrow -eq $straddleB.Arrow) `
    "($($straddleA.Arrow) vs $($straddleB.Arrow))"
Assert-That '  ...and the same tone' ($straddleA.Tone -eq $straddleB.Tone) `
    "($($straddleA.Tone) vs $($straddleB.Tone))"

''
'[trend pill] a sweep: no printed number ever carries two different verdicts'
# The general invariant, not just the one pair that exposed it.
$rows = @()
foreach ($den in @(200, 400, 800, 1000, 1600, 1900, 2000, 2500, 4000)) {
    $base = [int] ($den / 2)
    foreach ($step in 1..12) {
        if (($base + $step) -gt $den) { continue }
        $p = Get-Pill -Den $den -Prev $base -Curr ($base + $step)
        $rows += [PSCustomObject]@{ Den = $den; Step = $step; Number = $p.Number; Tone = $p.Tone; Arrow = $p.Arrow }
    }
}
$conflicts = @($rows | Group-Object Number | Where-Object {
        (@($_.Group | Select-Object -ExpandProperty Tone -Unique).Count -gt 1) -or
        (@($_.Group | Select-Object -ExpandProperty Arrow -Unique).Count -gt 1)
    })
"      swept $($rows.Count) run pair(s) across $(@($rows | Select-Object -ExpandProperty Den -Unique).Count) denominators"
Assert-That 'every distinct printed number has exactly one arrow and one tone' ($conflicts.Count -eq 0) `
    ("(conflicting: " + (@($conflicts | ForEach-Object { '{0} -> tones [{1}] arrows [{2}]' -f $_.Name,
                (@($_.Group | Select-Object -ExpandProperty Tone -Unique) -join ','),
                (@($_.Group | Select-Object -ExpandProperty Arrow -Unique) -join ',') }) -join '; ') + ')')

''
'[trend pill] the number keeps its direction: monotonic in the true delta'
# A larger true gain must never print a smaller number than a smaller gain at the same denominator.
foreach ($den in @(400, 1000, 4000)) {
    $base = [int] ($den / 2)
    $seq = @(1..10 | ForEach-Object { [double] (Get-Pill -Den $den -Prev $base -Curr ($base + $_)).Number })
    $ok = $true
    for ($i = 1; $i -lt $seq.Count; $i++) { if ($seq[$i] -lt $seq[$i - 1]) { $ok = $false } }
    Assert-That ("den={0}: the printed number never decreases as the gain grows" -f $den) $ok "($($seq -join ' '))"
}

''
'[trend pill] a real change is never printed as "0 pt"'
# 1000/2000 -> 1001/2000 is a genuine gain of 0.05 pt and rendered "0 pt vs previous run".
foreach ($case in @(@{ D = 2000; P = 1000; C = 1001 }, @{ D = 4000; P = 2000; C = 2001 }, @{ D = 2500; P = 1250; C = 1251 })) {
    $p = Get-Pill -Den $case.D -Prev $case.P -Curr $case.C
    "      den=$($case.D) $($case.P)->$($case.C) : true=$([math]::Round($p.True,4)) text='$($p.Text)'"
    Assert-That ("den={0}: a real gain does not print as 0" -f $case.D) (
        [double] $p.Number -ne 0) "(printed '$($p.Number)' for a true delta of $($p.True))"
    Assert-That ("den={0}: the printed sign matches the direction" -f $case.D) (
        [double] $p.Number -gt 0) "(printed '$($p.Number)')"
}
# A real LOSS keeps its sign.
$loss = Get-Pill -Den 2000 -Prev 1001 -Curr 1000
"      den=2000 1001->1000 : text='$($loss.Text)'"
Assert-That 'a real loss keeps a negative sign' ([double] $loss.Number -lt 0) "(printed '$($loss.Number)')"
# ...and a genuinely unchanged run still prints a plain zero.
$same = Get-Pill -Den 2000 -Prev 1000 -Curr 1000
"      den=2000 1000->1000 : text='$($same.Text)'"
Assert-That 'an unchanged run still prints 0' ([double] $same.Number -eq 0) "(printed '$($same.Number)')"
Assert-That '  ...flat and neutral' (($same.Arrow -eq 'FLAT') -and ($same.Tone -eq 'na')) "($($same.Arrow)/$($same.Tone))"

''
'[trend pill] the number is written invariantly, whatever the operator locale'
# -f formats with the CURRENT THREAD CULTURE. Under a comma-decimal locale the pill read "-0,1 pt".
$original = [System.Threading.Thread]::CurrentThread.CurrentCulture
try {
    foreach ($name in @('en-US', 'de-DE', 'it-IT')) {
        [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo($name)
        $p = Get-Pill -Den 1000 -Prev 500 -Curr 507
        "      $name : '$($p.Text)'"
        Assert-That ("{0}: the number uses a decimal POINT" -f $name) ($p.Number -notmatch ',') "(printed '$($p.Number)')"
        Assert-That ("{0}: and reads 0.7" -f $name) ($p.Number -eq '0.7') "(printed '$($p.Number)')"
    }
} finally {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $original
}

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
