# The grey "not read" segment of every bar chart was invisible.
#
#  w57-F1  New-mdiBarChart emits two children inside .bar-track: the coloured fill for what passed,
#          and a grey .bar-fill.na segment for what could not be read. The comment on that segment
#          says it exists so unmeasured work is "visibly unaccounted for".
#
#          .bar-track was a plain block box (height:16px, overflow:hidden) and .bar-fill was a block
#          with height:100%. Two block children therefore STACK VERTICALLY: the second one starts at
#          y=16px inside a 16px box and is clipped away. Measured in a real browser: of the grey
#          segment's 16px only 0.89px fell inside the track, and it began at the track's LEFT edge
#          rather than after the coloured fill.
#
#          The consequence is a report that states something untrue. A server where NOTHING could be
#          measured - "0/6 (0%), 6 not read" - rendered as an empty track, pixel-identical to a
#          server that was measured and failed - "0/4 (0%)". The two are opposite facts: one is a
#          gap to go and measure, the other is a defect to go and fix. The caption distinguished
#          them; the bar, which is what the eye reads first, did not.
#
#          The fix makes .bar-track a flex container so the segments sit side by side, and stops the
#          fills shrinking. The border-radius moves off the fill onto the track, which already clips
#          with overflow:hidden, so the pill shape is preserved without rounding the seam between
#          two adjacent segments.
#
# This is a LAYOUT defect, so a test that greps the markup cannot see it - the existing assertion in
# ReportRendering.Tests.ps1 checks only that the segment is emitted, and it passed throughout. These
# tests assert on the CSS CONTRACT that makes the markup render correctly: the track must establish
# a horizontal formatting context, and the fills must not shrink.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$style = Get-mdiReportStyle
function Get-Rule {
    param([string] $Selector)
    $m = [regex]::Match($style, '(?m)^' + [regex]::Escape($Selector) + '\{([^}]*)\}')
    if ($m.Success) { $m.Groups[1].Value } else { '' }
}
$track = Get-Rule '.bar-track'
$fill = Get-Rule '.bar-fill'

'[bar layout] the track lays its segments out horizontally'
Assert-That 'the .bar-track rule exists' (-not [string]::IsNullOrWhiteSpace($track))
Assert-That 'the .bar-fill rule exists' (-not [string]::IsNullOrWhiteSpace($fill))
# The whole defect in one assertion: without a horizontal formatting context the two fills are
# block-level siblings and stack vertically, and the second is clipped away by overflow:hidden.
Assert-That 'the track establishes a horizontal layout' ($track -match 'display\s*:\s*(flex|inline-flex)') "(got '$track')"
Assert-That '  ...and still clips to its pill shape' ($track -match 'overflow\s*:\s*hidden') "(got '$track')"
Assert-That '  ...and still has a fixed height' ($track -match 'height\s*:\s*\d') "(got '$track')"
Assert-That '  ...and keeps the rounded ends' ($track -match 'border-radius') "(got '$track')"

'[bar layout] a segment keeps the width it was given'
# In a flex row the default flex-shrink is 1, so two segments totalling 100% would be compressed by
# the track's border and the grey part would under-report what was not read.
Assert-That 'the fill does not shrink' ($fill -match 'flex\s*:\s*0\s+0' -or $fill -match 'flex-shrink\s*:\s*0') "(got '$fill')"
Assert-That 'the fill still fills the track height' ($fill -match 'height\s*:\s*100%') "(got '$fill')"

'[bar markup] the unread segment is emitted only when something was unread'
# The markup contract the layout depends on: a second .bar-fill.na child inside the same track.
$bars = @(
    [PSCustomObject]@{ Label = 'nothing measured'; Value = 0; Total = 0; Unread = 6; Hint = 'h' }
    [PSCustomObject]@{ Label = 'measured and failed'; Value = 0; Total = 4; Unread = 0; Hint = 'h' }
    [PSCustomObject]@{ Label = 'half read'; Value = 3; Total = 3; Unread = 3; Hint = 'h' }
    [PSCustomObject]@{ Label = 'all passed'; Value = 6; Total = 6; Unread = 0; Hint = 'h' }
)
$html = New-mdiBarChart -Bar $bars
$rows = @([regex]::Matches($html, '<div class="bar-row">.*?<div class="bar-value">.*?</div></div>'))
Assert-That 'a row is emitted for each bar' ($rows.Count -eq 4) "(got $($rows.Count))"

function Get-Track {
    param([string] $LabelText)
    $m = [regex]::Match($html, [regex]::Escape($LabelText) + '</div>(?<t><div class="bar-track">.*?</div></div>)')
    if ($m.Success) { $m.Groups['t'].Value } else { '' }
}
$unmeasured = Get-Track 'nothing measured'
$failed = Get-Track 'measured and failed'
$half = Get-Track 'half read'
$allok = Get-Track 'all passed'

Assert-That 'the wholly unmeasured bar carries an na segment' (@([regex]::Matches($unmeasured, 'bar-fill na')).Count -ge 1) "(got '$unmeasured')"
Assert-That 'the measured-and-failed bar carries none' (@([regex]::Matches($failed, 'bar-fill na')).Count -eq 0) "(got '$failed')"
Assert-That 'the partly read bar carries one' (@([regex]::Matches($half, 'bar-fill na')).Count -eq 1) "(got '$half')"
Assert-That 'the fully passed bar carries none' (@([regex]::Matches($allok, 'bar-fill na')).Count -eq 0) "(got '$allok')"

'[bar markup] the two facts are distinguishable from each other'
# The defect's visible symptom: these two rendered identically. They must differ in the markup AND
# the markup must be laid out horizontally (asserted above) for the difference to reach the eye.
Assert-That 'unmeasured and failed do not produce the same track' ($unmeasured -ne $failed) "(both '$failed')"

'[bar markup] the segment widths add up to the whole track'
# 3 of 6 passed with 3 unread is 50% coloured and 50% grey - the grey must be the unread share, not
# the remainder of the bar.
$halfWidths = @([regex]::Matches($half, 'width:(?<w>[0-9.]+)%') | ForEach-Object { [double] $_.Groups['w'].Value })
Assert-That 'the partly read bar has two widths' ($halfWidths.Count -eq 2) "(got $($halfWidths -join ', '))"
if ($halfWidths.Count -eq 2) {
    Assert-That '  ...the coloured share is the passed share' ([math]::Abs($halfWidths[0] - 50) -lt 0.6) "(got $($halfWidths[0]))"
    Assert-That '  ...the grey share is the unread share' ([math]::Abs($halfWidths[1] - 50) -lt 0.6) "(got $($halfWidths[1]))"
    Assert-That '  ...and together they do not overflow the track' (($halfWidths[0] + $halfWidths[1]) -le 100.5) "(got $(($halfWidths | Measure-Object -Sum).Sum))"
}
$unmeasuredWidths = @([regex]::Matches($unmeasured, 'width:(?<w>[0-9.]+)%') | ForEach-Object { [double] $_.Groups['w'].Value })
Assert-That 'a wholly unmeasured bar is entirely grey' (($unmeasuredWidths | Measure-Object -Maximum).Maximum -ge 99.4) "(got $($unmeasuredWidths -join ', '))"

'[bar markup] the caption still names the unread count'
Assert-That 'the caption reports what was not read' ($html -match '6 not read') "(missing)"
Assert-That '  ...and does not invent one when all was read' ($allok -notmatch 'not read')

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
