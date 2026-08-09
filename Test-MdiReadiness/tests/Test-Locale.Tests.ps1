<#
    Verifies that the report renders correctly on a non-English Windows.

    On an Italian, German, French or Spanish system the decimal separator is a COMMA. A comma inside
    an SVG coordinate or a CSS percentage is not a decimal point - it is a value separator - so
    width:"12,5%" and cy="43,7" are invalid, and the browser silently drops the attribute. The chart
    does not error; it simply disappears, and only for the administrators who are not on en-US.

    This is exactly the class of defect that never shows up in testing done on an English machine, so
    it is asserted against the real cultures rather than reasoned about. The script has a
    ConvertTo-mdiSvgNumber helper for this; these assertions prove it is actually reached everywhere
    a number is written into markup, which is the part that a helper alone does not guarantee.
#>
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors -join '; ')" }

$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))
foreach ($constAst in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -like '$script:*' -and
            $null -eq $n.Parent.Parent.Parent }, $false)) {
    . ([scriptblock]::Create($constAst.Extent.Text))
}

$pass = 0; $fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name $Detail" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

$comparableHistory = @(
    [PSCustomObject]@{ Timestamp = '2026-08-01T09:00:00'; ChecksPassed = 8; ChecksTotal = 10
        CheckNames = @('A', 'B'); ServerNames = @('dc1') }
    [PSCustomObject]@{ Timestamp = '2026-08-04T09:00:00'; ChecksPassed = 7; ChecksTotal = 10
        CheckNames = @('A', 'B'); ServerNames = @('dc1') }
    [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00'; ChecksPassed = 9; ChecksTotal = 10
        CheckNames = @('A', 'B'); ServerNames = @('dc1') }
)
# Values chosen to produce fractional coordinates - whole numbers would pass on any culture and prove
# nothing.
$bars = @(
    [PSCustomObject]@{ Label = 'dc1.contoso.com'; Value = 3; Total = 7; Hint = 'Checks passed' }
    [PSCustomObject]@{ Label = 'dc2.contoso.com'; Value = 1; Total = 3; Hint = 'Checks passed' }
)

$originalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
try {
    foreach ($cultureName in 'en-US', 'it-IT', 'de-DE', 'fr-FR', 'es-ES') {
        $culture = [System.Globalization.CultureInfo]::new($cultureName)
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
        $separator = $culture.NumberFormat.NumberDecimalSeparator

        Write-Host "`n[$cultureName] decimal separator '$separator'" -ForegroundColor Yellow

        Assert-That 'the SVG number helper always emits a dot' (
            (ConvertTo-mdiSvgNumber 12.5) -eq '12.50') "(got '$(ConvertTo-mdiSvgNumber 12.5)')"

        $trend = New-mdiTrendChart -History $comparableHistory
        # A single-value attribute must never contain a comma. points="x,y x,y" legitimately does, so
        # it is excluded: there the comma is a coordinate separator, not a decimal mark.
        $badTrend = [regex]::Matches($trend, '(?:\bcx|\bcy|\bx|\by|\bwidth|\bheight|\br)="[^"]*,[^"]*"')
        Assert-That 'no single-value SVG attribute contains a comma' ($badTrend.Count -eq 0) `
            "($($badTrend.Count): $(@($badTrend | Select-Object -First 2 | ForEach-Object { $_.Value }) -join ' '))"
        # Inside points="..." the pairs must still be dot-decimal: "12,50 30,20" would be read as four
        # coordinates rather than two.
        $points = [regex]::Matches($trend, 'points="([^"]*)"')
        $badPairs = 0
        foreach ($p in $points) {
            foreach ($pair in ($p.Groups[1].Value -split '\s+' | Where-Object { $_ })) {
                if (@($pair -split ',').Count -ne 2) { $badPairs++ }
            }
        }
        Assert-That 'every points pair is exactly two numbers' ($badPairs -eq 0) "(got $badPairs malformed)"
        Assert-That 'the trend chart has no NaN' ($trend -notmatch 'NaN')
        Assert-That 'the trend chart has no Infinity' ($trend -notmatch 'Infinity')

        $bar = New-mdiBarChart -Bar $bars
        Assert-That 'no CSS percentage uses a comma decimal' (
            ([regex]::Matches($bar, '[\d]+,[\d]+%')).Count -eq 0) "(got $(([regex]::Matches($bar, '[\d]+,[\d]+%')).Count))"
        Assert-That 'the bar chart has no NaN' ($bar -notmatch 'NaN')
    }
} finally {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
}

Write-Host "`n[degenerate] charts with nothing to plot" -ForegroundColor Yellow
# A division by zero yields NaN or Infinity, which is silently invalid in an SVG attribute - the
# chart vanishes rather than erroring, so it has to be asserted rather than noticed.
$zeroHistory = @(
    [PSCustomObject]@{ Timestamp = '2026-08-01T09:00:00'; ChecksPassed = 0; ChecksTotal = 0; CheckNames = @('A'); ServerNames = @('dc1') }
    [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00'; ChecksPassed = 0; ChecksTotal = 0; CheckNames = @('A'); ServerNames = @('dc1') }
)
$zeroTrend = New-mdiTrendChart -History $zeroHistory
Assert-That 'a zero-total history produces no NaN' ($zeroTrend -notmatch 'NaN')
Assert-That 'a zero-total history produces no Infinity' ($zeroTrend -notmatch 'Infinity')
# Either honest answer is acceptable: a run that measured nothing is dropped by the point filter
# before comparability is even considered, so the chart says there is not enough history. What must
# NOT happen is a drawn trend line over runs that measured nothing.
Assert-That 'a zero-total history draws no trend line' (
    $zeroTrend -notmatch 'pt vs previous run') "-> $($zeroTrend.Substring(0, [Math]::Min(90, $zeroTrend.Length)))"
Assert-That 'and it says why' (
    $zeroTrend -match 'Not comparable|At least two runs')

$zeroBar = New-mdiBarChart -Bar @([PSCustomObject]@{ Label = 'x'; Value = 0; Total = 0; Hint = 'h' })
Assert-That 'a zero-total bar produces no NaN' ($zeroBar -notmatch 'NaN')
Assert-That 'a zero-total bar produces no Infinity' ($zeroBar -notmatch 'Infinity')
Assert-That 'an empty bar chart renders something harmless' (
    (New-mdiBarChart -Bar @()).Length -lt 200)

$onePoint = New-mdiTrendChart -History @($comparableHistory[0])
Assert-That 'one history point cannot be a trend' ($onePoint -notmatch 'pt vs previous run')
Assert-That 'and it does not emit a broken chart' ($onePoint -notmatch 'NaN')

Write-Host "`n================ $pass passed / $fail failed ================" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
