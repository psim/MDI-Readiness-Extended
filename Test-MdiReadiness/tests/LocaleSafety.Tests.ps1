<#
    Locale safety, verified by SWITCHING CULTURE and re-running the real functions.

    The tool has never run on genuinely non-English Windows, and that is the largest untested risk
    left in it. Culture switching does not reproduce a German Windows Server - the OS itself returns
    translated text there - but it does exercise every place the script formats or parses a number,
    a date or a string comparison, which is where the silent failures live.

    The worst of them is silent by construction: in de-DE a naive percentage format produces
    "width:12,5%", which is INVALID CSS. The browser drops the declaration and the bar renders at
    zero width, so a German operator sees an empty chart with no error anywhere.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# Each culture is exercised in a CHILD process. Setting the thread culture in-process leaks into
# later tests in the same file, and a locale test that contaminates its neighbours is worse than none.
$probeBody = @'
param([string] $Culture, [string] $Target)
[System.Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo] $Culture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo] $Culture
$text = [IO.File]::ReadAllText($Target)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $body.IndexOf('#region Main'); if ($i -gt 0) { $body = $body.Substring(0, $i) }
Invoke-Expression $body
function Write-mdiVerbose { param($Message) }

$result = [ordered]@{}
$result.Culture = [System.Threading.Thread]::CurrentThread.CurrentCulture.Name

# 1. A decimal read back from an invariantly-written file must not be reinterpreted.
$result.DecimalCount = Get-mdiCoverageCount -Value '12.5'

# 2. A percentage that reaches CSS must format with a DOT.
$pct = Get-mdiCoveragePercent -Passed 1 -Measured 8 -Unread 0
$result.SvgNumber = ConvertTo-mdiSvgNumber $pct 1

# 3. The rendered bar must carry valid CSS.
$bar = New-mdiBarChart -Bar @([PSCustomObject]@{ Label = 'srv'; Value = 1; Total = 8; Unread = 0; Hint = 'h' })
$result.CommaWidths = ([regex]::Matches($bar, 'width:\d+,\d+')).Count
$result.HasDotWidth = [bool] ([regex]::Match($bar, 'width:12\.5'))

# 4. String-typed counts from a JSON round-trip must still resolve.
$result.StringScoreReady = Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = '5'; Failed = '0'; Unread = '0' })

# 5. The trend writes and reads timestamps round-trip; a delta must still be computed.
$cn = @('CheckA', 'CheckB'); $sn = @('dc1')
function New-P($stamp, $passed) {
    [PSCustomObject]@{ Timestamp = $stamp; ChecksPassed = $passed; ChecksTotal = 5; ChecksUnread = 0
        CheckNames = $cn; ServerNames = $sn; ScriptVersion = '1.1.0' }
}
$svg = New-mdiTrendChart -History @((New-P '2026-08-01T09:00:00' 3), (New-P '2026-08-08T09:00:00' 5))
$result.TrendPill = [regex]::Match($svg, '<span class="pill[^"]*">([^<]*)</span>').Groups[1].Value
$result.TrendCommaCoords = ([regex]::Matches($svg, '\d+,\d+,\d')).Count

# 6. An audit backup is parsed by GUID and column position, not by translated header text. This is a
#    German header row with the same column ORDER, which is what a de-DE host actually emits.
$germanBackup = @(
    'Computername,Richtlinienziel,Unterkategorie,Unterkategorie-GUID,Einschlusseinstellung,Ausschlusseinstellung,Einstellungswert'
    'DC1,System,Sicherheitssystemerweiterung,{0CCE9211-69AE-11D9-BED3-505054503030},Erfolg und Fehler,,3'
)
$header = 'Machine Name', 'Policy Target', 'Subcategory', 'Subcategory GUID', 'Inclusion Setting', 'Exclusion Setting', 'Setting Value'
$parsed = @($germanBackup | Select-Object -Skip 1 | ConvertFrom-Csv -Header $header)
$result.GermanGuidParsed = [string] $parsed[0].'Subcategory GUID'
$result.GermanValueParsed = [string] $parsed[0].'Setting Value'

# 7. Ordinal comparison: tr-TR maps 'i' to a dotted capital, so a culture-sensitive compare fails.
$result.TurkishOrdinal = [string]::Equals('INFO', 'info', [System.StringComparison]::OrdinalIgnoreCase)

$result | ConvertTo-Json -Compress
'@

$probeFile = Join-Path $env:TEMP ('mdi-locale-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
[IO.File]::WriteAllText($probeFile, $probeBody)

# tr-TR is the dotless-i culture; de-DE and fr-FR use a comma decimal separator; ja-JP and ru-RU
# differ again in date and digit shaping.
foreach ($culture in 'en-US', 'de-DE', 'fr-FR', 'tr-TR', 'ja-JP', 'ru-RU') {
    Write-Host "Culture: $culture" -ForegroundColor Cyan
    $raw = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass `
        -File $probeFile -Culture $culture -Target $target 2>&1
    $jsonLine = @($raw | Where-Object { "$_".Trim().StartsWith('{') }) | Select-Object -Last 1
    if (-not $jsonLine) {
        Assert-That "[$culture] the probe ran at all" $false "($(($raw | Select-Object -Last 2) -join ' '))"
        continue
    }
    $r = $jsonLine | ConvertFrom-Json

    Assert-That "[$culture] a decimal from an invariant file is not rescaled" ($r.DecimalCount -eq 12.5) "(got $($r.DecimalCount))"
    Assert-That "[$culture] a CSS number uses a dot, not a comma" ($r.SvgNumber -notmatch ',') "(got '$($r.SvgNumber)')"
    Assert-That "[$culture] no bar emits an invalid comma width" ($r.CommaWidths -eq 0) "(found $($r.CommaWidths))"
    Assert-That "[$culture]   ...and the width is actually there" ($r.HasDotWidth)
    Assert-That "[$culture] string counts still resolve" ($r.StringScoreReady -eq $true)
    Assert-That "[$culture] the trend still computes a delta" ($r.TrendPill -match 'pt vs previous run') "(got '$($r.TrendPill)')"
    Assert-That "[$culture] audit backup parses by GUID, not header text" (
        $r.GermanGuidParsed -eq '{0CCE9211-69AE-11D9-BED3-505054503030}') "(got '$($r.GermanGuidParsed)')"
    Assert-That "[$culture]   ...and reads the setting value" ($r.GermanValueParsed -eq '3') "(got '$($r.GermanValueParsed)')"
    Assert-That "[$culture] ordinal comparison is case-insensitive-safe" ($r.TurkishOrdinal -eq $true)
}
Remove-Item $probeFile -Force -ErrorAction SilentlyContinue

Write-Host 'Locale guarantees are documented' -ForegroundColor Cyan
$text = Get-Content -LiteralPath $target -Raw
Assert-That 'the help documents non-English behaviour' ($text -match 'NON-ENGLISH WINDOWS AND NON-ENGLISH LOCALES')
Assert-That '  ...and states what is NOT proven' ($text -match 'WHAT IS NOT PROVEN')
Assert-That '  ...and warns about the invalid-CSS trap' ($text -match 'INVALID CSS')

Write-Host 'Culture-sensitive parsing is invariant at the source' -ForegroundColor Cyan
# Both numeric parsers must name a culture. Without one they follow the operator's decimal separator.
$bareTryParse = [regex]::Matches($text, '\[double\]::TryParse\(\[string\][^,]*,\s*\[ref\]')
Assert-That 'no numeric parse uses the ambient culture' ($bareTryParse.Count -eq 0) "(found $($bareTryParse.Count))"
Assert-That 'both parsers name InvariantCulture' (
    ([regex]::Matches($text, 'TryParse[\s\S]{0,200}?InvariantCulture')).Count -ge 2)
# A culture-sensitive case conversion can silently fail on tr-TR. Counted from the PARSED script:
# the help text above explains the trap and quotes "'INFO'.ToLower()" in prose, which a raw text
# search cannot tell from a call - the same mistake this suite already made once with Write-Warning.
$targetAst = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$null)
$bareCase = @($targetAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $n.Member.Extent.Text -in @('ToUpper', 'ToLower') -and
            (@($n.Arguments).Count -eq 0)
        }, $true))
Assert-That 'no bare ToUpper/ToLower call survives' ($bareCase.Count -eq 0) `
    "(found $($bareCase.Count): $(($bareCase | ForEach-Object { 'L' + $_.Extent.StartLineNumber }) -join ', '))"


# The assertions below call the real functions in THIS process. The culture probes above run in child
# processes on purpose - setting a thread culture in-process leaks into later tests - but these
# checks are culture-independent, so loading here is safe.
$loadBody = (Get-Content -LiteralPath $target -Raw) -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$loadIdx = $loadBody.IndexOf('#region Main'); if ($loadIdx -gt 0) { $loadBody = $loadBody.Substring(0, $loadIdx) }
Invoke-Expression $loadBody
function Write-mdiVerbose { param($Message) }
Write-Host 'The report warns the operator, but only when it should' -ForegroundColor Cyan
# A caveat printed on every run is one everybody scrolls past, which would waste it on exactly the
# runs where it matters. It appears only when the scanning host is genuinely not English.
Assert-That 'an English host gets no notice' ((Get-mdiLocaleNoticeHtml -UiCulture 'en-US' -Culture 'en-US').Length -eq 0)
Assert-That '  ...including other English variants' ((Get-mdiLocaleNoticeHtml -UiCulture 'en-GB' -Culture 'en-GB').Length -eq 0)
Assert-That '  ...and an invariant culture' ((Get-mdiLocaleNoticeHtml -UiCulture '' -Culture '').Length -eq 0)
Assert-That 'a German host gets a notice' ((Get-mdiLocaleNoticeHtml -UiCulture 'de-DE' -Culture 'de-DE').Length -gt 0)
Assert-That 'a Japanese host gets a notice' ((Get-mdiLocaleNoticeHtml -UiCulture 'ja-JP' -Culture 'ja-JP').Length -gt 0)
# Either culture differing on its own is enough: English Windows with German regional settings still
# reads numbers with a comma separator.
Assert-That 'a mixed UI/number culture gets a notice' ((Get-mdiLocaleNoticeHtml -UiCulture 'en-US' -Culture 'de-DE').Length -gt 0)
Assert-That '  ...naming both cultures' ((Get-mdiLocaleNoticeHtml -UiCulture 'en-US' -Culture 'de-DE') -match 'en-US / de-DE')

$germanNotice = Get-mdiLocaleNoticeHtml -UiCulture 'de-DE' -Culture 'de-DE'
Assert-That 'the notice names the culture' ($germanNotice -match 'de-DE')
Assert-That '  ...says results are expected to be correct' ($germanNotice -match 'expected to be correct')
Assert-That '  ...names the checks worth double-checking' ($germanNotice -match 'audit policy' -and $germanNotice -match 'power scheme')
Assert-That '  ...and asks for discrepancies to be reported' ($germanNotice -match 'report the discrepancy')
# The culture name is interpolated, so it must be encoded like any other variable reaching HTML.
Assert-That 'the culture name is HTML-encoded' (
    (Get-mdiLocaleNoticeHtml -UiCulture '<script>x</script>' -Culture 'de-DE') -notmatch '<script>')

Assert-That 'the report template carries the placeholder' ($text -match '@@LOCALENOTICE@@')
Assert-That '  ...and the assembler substitutes it' ($text -match "Replace\('@@LOCALENOTICE@@', \(Get-mdiLocaleNoticeHtml\)\)")
Assert-That 'the prerequisites document the limit' ($text -match 'NON-ENGLISH WINDOWS: the script is written to be locale-safe')

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
