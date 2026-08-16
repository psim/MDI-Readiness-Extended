<#
    The report's JavaScript must not contain a template token, or the report will rewrite its own code.

    The HTML report is assembled by an ordered chain of literal .Replace calls (line ~16483):

        $body.Replace('@@STYLE@@',  (Get-mdiReportStyle)).
              Replace('@@SCRIPT@@', (Get-mdiReportScript)).
              Replace('@@OVERVIEW@@', $htmlOverview).
              Replace('@@DCS@@', $htmlDCs).
              ... thirteen more ...
              Replace('@@DOMAIN@@', ...).Replace('@@FOREST@@', ...)

    Literal replacement is used deliberately, because the CSS and JavaScript are full of braces that
    the format operator would try to read as placeholders. The consequence is that the substitution
    is ORDERED, and @@SCRIPT@@ is substituted SECOND - ahead of all fifteen content tokens.

    So if the emitted JavaScript ever contained a string like @@DOMAIN@@ or @@DCS@@, the later links
    in the chain would replace it with report HTML: a table, or an HTML-encoded domain name, spliced
    into the middle of a function body. The report would still be written, the file would still open,
    and the scripting - the tab switching, the filters, the CSV export - would silently be broken or
    subtly wrong. Nothing would raise an error, because from PowerShell's point of view every
    replacement succeeded. That is this project's recurring shape: a well-formed, confident output
    that is quietly wrong.

    No defect was found. Get-mdiReportScript is a constant-returning function with no parameters, so
    there is no unread-versus-measured question to ask of it; the hazard is entirely in how its
    output meets the template. This test pins that relationship.

    Pinned here:

    1. The emitted script contains NO @@TOKEN@@ of any kind. This is the invariant that matters, and
       it is asserted generically rather than against a fixed list, so a token added to the template
       in future is caught even though this test was written before it existed.
    2. Running the script through the ACTUAL remaining replacement chain, in the real order, leaves
       it byte-for-byte unchanged. This is the same fact proved end to end rather than by pattern.
    3. It is a single, balanced <script> block: exactly one opening and one closing tag, and equal
       counts of braces and parentheses. A truncated here-string would satisfy point 1 while emitting
       JavaScript that cannot parse.
    4. It is deterministic - two calls return identical text - so the report is reproducible and a
       baseline diff cannot show a change that nothing caused.
    5. The same no-token invariant is asserted for Get-mdiReportStyle, which is substituted FIRST and
       would otherwise be able to inject the entire script block into the stylesheet.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiReportScript') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
$text = $text -replace '(?m)^\s*#Requires.*$', ''
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

$js = Get-mdiReportScript | Out-String
$css = Get-mdiReportStyle | Out-String

'1. No template token survives inside the injected blocks'
$jsTokens = @([regex]::Matches($js, '@@[A-Za-z0-9_]+@@') | ForEach-Object { $_.Value } | Select-Object -Unique)
Assert-That 'the report script contains no @@TOKEN@@' ($jsTokens.Count -eq 0) "found [$($jsTokens -join ', ')]"

'2. It survives the real replacement chain unchanged'
# The tokens substituted AFTER @@SCRIPT@@, in the order the report applies them.
$after = $js
foreach ($t in '@@OVERVIEW@@', '@@DCS@@', '@@PORTS@@', '@@SENSORV3@@', '@@DS@@', '@@SENSORHEALTH@@',
    '@@CAPACITY@@', '@@TIMESYNC@@', '@@REMEDIATION@@', '@@TREND@@', '@@DELETEDOBJECTS@@', '@@CAS@@',
    '@@ENTRACONNECT@@', '@@DOMAIN@@', '@@FOREST@@') {
    $after = $after.Replace($t, '<<<REPORT-CONTENT-INJECTED>>>')
}
Assert-That 'the later replacements cannot inject report content into the JavaScript' ($after -eq $js)
Assert-That 'and nothing was injected' ($after -notmatch 'REPORT-CONTENT-INJECTED')

'3. A single, balanced script block'
Assert-That 'the script is not empty' ($js.Trim().Length -gt 0) "length=$($js.Length)"
Assert-That 'it opens with <script>' ($js.Trim().StartsWith('<script>'))
Assert-That 'it closes with </script>' ($js.Trim().EndsWith('</script>'))
Assert-That 'exactly one opening tag' ((([regex]::Matches($js, '<script>')).Count) -eq 1) "got $((([regex]::Matches($js,'<script>')).Count))"
Assert-That 'exactly one closing tag' ((([regex]::Matches($js, '</script>')).Count) -eq 1) "got $((([regex]::Matches($js,'</script>')).Count))"
$open = ([regex]::Matches($js, '\{')).Count; $close = ([regex]::Matches($js, '\}')).Count
Assert-That 'braces are balanced' ($open -eq $close) "open=$open close=$close"
$po = ([regex]::Matches($js, '\(')).Count; $pc = ([regex]::Matches($js, '\)')).Count
Assert-That 'parentheses are balanced' ($po -eq $pc) "open=$po close=$pc"

'4. Deterministic'
Assert-That 'two calls return identical text' (((Get-mdiReportScript | Out-String)) -eq $js)

'5. The stylesheet, substituted FIRST, is held to the same invariant'
$cssTokens = @([regex]::Matches($css, '@@[A-Za-z0-9_]+@@') | ForEach-Object { $_.Value } | Select-Object -Unique)
Assert-That 'the report style contains no @@TOKEN@@' ($cssTokens.Count -eq 0) "found [$($cssTokens -join ', ')]"
Assert-That 'the style could not swallow the script block' ($css -notmatch '@@SCRIPT@@')

''
"PASS: $script:pass  FAIL: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
