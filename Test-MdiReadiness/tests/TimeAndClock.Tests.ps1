<#
    Time and clock handling.

    One of the checks IS a clock check - MDI requires every sensor server to be within five minutes
    of the others - so this layer decides a real pass/fail, and it had never been examined.

    The subtle risk here is not the arithmetic, it is the CLOCK MOVING. Every bounded wait in a scan
    was computed as [datetime]::Now.AddSeconds(n), and wall-clock arithmetic breaks precisely when
    this tool is most likely to be running: during an NTP correction, across a DST transition, or
    while an administrator fixes the skew the tool just reported. A clock jumping forward expires the
    wait instantly; a clock jumping back means it never expires at all.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Write-Host 'Clock skew is measured as a magnitude, in both directions' -ForegroundColor Cyan
# A domain controller five minutes AHEAD breaks Kerberos exactly as one five minutes behind does.
# The WMI read is shadowed so the remote clock can be dictated precisely.
$script:fakeOffsetMinutes = 0
function global:Get-WmiObject {
    param($ComputerName, $Namespace, $Class, $Property, $ErrorAction)
    $t = [datetime]::UtcNow.AddMinutes($script:fakeOffsetMinutes).ToLocalTime()
    [PSCustomObject]@{ LocalDateTime = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($t) }
}
function Get-Skew($minutes) {
    $script:fakeOffsetMinutes = $minutes
    Get-mdiTimeSync -ComputerName 'dc1' -MaxSkewMinutes 5
}

Assert-That 'a synchronised clock passes' ((Get-Skew 0).isTimeSyncOk -eq $true)
Assert-That 'a clock 10 minutes BEHIND fails' ((Get-Skew -10).isTimeSyncOk -eq $false)
Assert-That 'a clock 10 minutes AHEAD also fails' ((Get-Skew 10).isTimeSyncOk -eq $false)
Assert-That '  ...and neither direction is privileged' ((Get-Skew 10).isTimeSyncOk -eq (Get-Skew -10).isTimeSyncOk)
Assert-That 'the reported skew keeps its sign for the operator' ((Get-Skew -10).details.SkewSeconds -lt 0)
Assert-That '  ...while a clock ahead reports positive' ((Get-Skew 10).details.SkewSeconds -gt 0)
# The threshold is bracketed rather than asserted at the exact boundary. The stub builds the remote
# time from the clock that is running while the test executes, so "exactly five minutes" is really
# "five minutes plus however long the call took" - which lands on either side of the limit depending
# on machine load. Asserting it directly produced a test that failed roughly one run in five, and an
# intermittently red test is worse than no test: it trains the reader to ignore the colour. 4.9 must
# pass and 5.5 must fail, which pins the limit to five minutes without racing the clock.
Assert-That '4.9 minutes is still within tolerance' ((Get-Skew 4.9).isTimeSyncOk -eq $true)
Assert-That '  ...and 5.5 minutes is not' ((Get-Skew 5.5).isTimeSyncOk -eq $false)
$script:fakeOffsetMinutes = 0
Remove-Item Function:\global:Get-WmiObject -ErrorAction SilentlyContinue

Write-Host 'A domain controller abroad is not mistaken for a skewed clock' -ForegroundColor Cyan
# Win32_OperatingSystem.LocalDateTime is a DMTF string carrying the machine's UTC offset. A DC in
# India has a local time five and a half hours from UTC and a perfectly correct clock; reading it as
# skew would fail every DC outside the scanning host's zone. The half-hour and three-quarter-hour
# zones are included because an offset assumed to be whole hours breaks on exactly those.
foreach ($zone in @(
        @{ N = 'UTC'; O = 0 }, @{ N = 'India +05:30'; O = 330 }, @{ N = 'Nepal +05:45'; O = 345 }
        @{ N = 'Chatham +12:45'; O = 765 }, @{ N = 'Hawaii -10:00'; O = -600 }
    )) {
    $utcNow = [datetime]::UtcNow
    $localInZone = $utcNow.AddMinutes($zone.O)
    $dmtf = '{0:yyyyMMddHHmmss.ffffff}{1}{2:D3}' -f $localInZone, $(if ($zone.O -ge 0) { '+' } else { '-' }), [math]::Abs($zone.O)
    $drift = [math]::Abs(([System.Management.ManagementDateTimeConverter]::ToDateTime($dmtf).ToUniversalTime() - $utcNow).TotalMinutes)
    Assert-That "a correct clock in $($zone.N) shows no skew" ($drift -lt 1) "(drift $([math]::Round($drift,2)) min)"
}

Write-Host 'Bounded waits survive the clock moving' -ForegroundColor Cyan
# This is the defect this file exists for. A wall-clock deadline is wrong for a timeout: Stopwatch
# reads a monotonic source and cannot be affected by an NTP correction or a DST transition.
$wallClockDeadlines = [regex]::Matches($text, '\[datetime\]::Now\.Add(Seconds|Minutes)')
Assert-That 'no wait is bounded by wall-clock arithmetic' ($wallClockDeadlines.Count -eq 0) `
    "(found $($wallClockDeadlines.Count))"
Assert-That '  ...they use a monotonic stopwatch instead' (
    ([regex]::Matches($text, 'Stopwatch\]::StartNew')).Count -ge 5) `
    "(found $(([regex]::Matches($text,'Stopwatch\]::StartNew')).Count))"
# Including the code EMITTED into the remediation script, which runs on a domain controller and is
# the most likely of all of them to be running while somebody corrects a clock.
Assert-That 'the generated remediation script also uses a stopwatch' (
    $text -match "& \`$add '    \`$waitTimer = \[System\.Diagnostics\.Stopwatch\]::StartNew\(\)'")
Assert-That '  ...and emits no wall-clock deadline' ($text -notmatch "\(Get-Date\)\.AddSeconds")

Write-Host 'The trend orders runs correctly whatever the timestamps' -ForegroundColor Cyan
$cn = @('A', 'B'); $sn = @('dc1')
function New-TimePoint($stamp, $passed) {
    [PSCustomObject]@{ Timestamp = $stamp; ChecksPassed = $passed; ChecksTotal = 5; ChecksUnread = 0
        CheckNames = $cn; ServerNames = $sn; ScriptVersion = '1.1.0' }
}
function Get-Pill($svg) { [regex]::Match($svg, '<span class="pill[^"]*">([^<]*)</span>').Groups[1].Value }

Assert-That 'a history written out of order is sorted' (
    (Get-Pill (New-mdiTrendChart -History @((New-TimePoint '2026-08-08T09:00:00' 5), (New-TimePoint '2026-08-01T09:00:00' 3)))) -match '&uarr;')
Assert-That 'runs either side of midnight order correctly' (
    (Get-Pill (New-mdiTrendChart -History @((New-TimePoint '2026-08-01T23:59:00' 3), (New-TimePoint '2026-08-02T00:01:00' 5)))) -match '&uarr;')
Assert-That 'runs across a year boundary order correctly' (
    (Get-Pill (New-mdiTrendChart -History @((New-TimePoint '2026-12-31T23:00:00' 3), (New-TimePoint '2027-01-01T01:00:00' 5)))) -match '&uarr;')
# Sort-Object is not stable in Windows PowerShell 5.1, so two runs recorded in the same second need
# an explicit tiebreaker or they can swap places on every render.
Assert-That 'two runs in the same second keep their file order' (
    (Get-Pill (New-mdiTrendChart -History @((New-TimePoint '2026-08-01T09:00:00' 3), (New-TimePoint '2026-08-01T09:00:00' 5)))) -match '&uarr;')

# Neither a malformed timestamp nor one inside the DST "missing hour" may throw the chart away.
$threwMalformed = $false
try { $null = New-mdiTrendChart -History @((New-TimePoint 'not-a-date' 3), (New-TimePoint '2026-08-08T09:00:00' 5)) } catch { $threwMalformed = $true }
Assert-That 'a malformed timestamp does not throw' (-not $threwMalformed)
$threwDst = $false
try { $null = New-mdiTrendChart -History @((New-TimePoint '2026-03-29T02:30:00' 3), (New-TimePoint '2026-03-29T04:00:00' 5)) } catch { $threwDst = $true }
Assert-That 'a timestamp in the DST gap does not throw' (-not $threwDst)

Write-Host 'The report says WHICH time it was generated at' -ForegroundColor Cyan
# This report gets emailed between teams in different countries. "2026-08-12 08:57" alone is
# ambiguous; the offset removes the ambiguity without hiding the local time the operator recognises.
#
# The expression is EXTRACTED FROM THE SOURCE AND EXECUTED rather than pattern-matched. The previous
# form of this assertion matched the literal text "ToString('yyyy-MM-dd HH:mm zzz')" and went red the
# moment the culture wave correctly appended [cultureinfo]::InvariantCulture to that same call - a
# test failing on an improvement to the code it guards is worse than no test. Running the real
# expression pins the OUTCOME the operator depends on (an offset is present, and it does not move
# with the culture) while staying silent about how it is spelled.
$tsExpr = $null
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$errors)
$tsCall = $ast.FindAll({
        param($n)
        $n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and
        $n.Member.Value -eq 'Replace' -and
        $n.Arguments.Count -eq 2 -and
        $n.Arguments[0].Extent.Text -match '@@TIMESTAMP@@'
    }, $true) | Select-Object -First 1
if ($tsCall) { $tsExpr = $tsCall.Arguments[1].Extent.Text }
Assert-That 'the report substitutes a generated timestamp' ($null -ne $tsExpr) 'no Replace(@@TIMESTAMP@@, ...) found in the source'

if ($tsExpr) {
    # HTML-encoded on the way in, so the encoder is stubbed out to leave the raw stamp visible.
    Set-Item -Path function:script:ConvertTo-mdiHtmlEncoded -Value { param([Parameter(ValueFromPipeline = $true)]$Value) $Value }
    $rendered = & ([scriptblock]::Create($tsExpr))
    Assert-That '  ...that carries a UTC offset' ($rendered -match '[+-]\d{2}:\d{2}$') "(rendered '$rendered')"
    Assert-That '  ...and a four-digit year an operator can read' ($rendered -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2} ') "(rendered '$rendered')"

    # A generated-at stamp that changes shape with the machine's locale is the same ambiguity the
    # offset was added to remove: th-TH renders a Buddhist year, ar-SA an Islamic one.
    $priorCulture = [Threading.Thread]::CurrentThread.CurrentCulture
    try {
        foreach ($c in 'th-TH', 'ar-SA', 'fa-IR', 'de-DE') {
            [Threading.Thread]::CurrentThread.CurrentCulture = [cultureinfo]::GetCultureInfo($c)
            $hostile = & ([scriptblock]::Create($tsExpr))
            Assert-That "  ...unchanged in shape under $c" ($hostile -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2} [+-]\d{2}:\d{2}$') "(rendered '$hostile')"
        }
    } finally {
        [Threading.Thread]::CurrentThread.CurrentCulture = $priorCulture
    }
}

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
