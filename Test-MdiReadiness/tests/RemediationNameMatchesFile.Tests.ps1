<#
    The report must name the remediation script file that is ACTUALLY written.

    New-mdiRemediationScript builds its path with ConvertTo-mdiSafeFileName, which rewrites every
    character illegal in a file name to an underscore. The -SkipRemediationScript message on the page
    used the RAW domain instead, so the report told the operator to re-run and look for a file that is
    never produced. Measured on the shipped functions:

        domain                 hostile<domain.local
        the page said          Fix-MdiReadiness-hostile&lt;domain.local.ps1
        the writer produces    Fix-MdiReadiness-hostile_domain.local.ps1

    Harmless-looking, but it is the one instruction on that panel and it sends the reader to a file
    that does not exist.

    Asserted on the RENDERED MARKUP of the real renderer, and the expected name is taken from the
    script's OWN ConvertTo-mdiSafeFileName rather than hard-coded, so the test still holds if the
    sanitiser's rules change - it pins the AGREEMENT between the two surfaces, which is the actual
    invariant.

    Controls: an ordinary domain needs no sanitising and must be unchanged; and the name must still be
    HTML-escaped, because sanitising is not escaping and dropping the encoder here would be an
    injection.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
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

# The panel text is built inline in Set-MdiReadinessReport, so it is lifted VERBATIM from the canonical
# file and executed with $Domain bound. Re-typing it into the test would prove nothing about the
# shipped script.
$lines = [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $target).ProviderPath)
$startIdx = -1; $endIdx = -1
for ($n = 0; $n -lt $lines.Count; $n++) {
    if ($lines[$n] -match "No remediation script was generated because this run used") { $startIdx = $n; break }
}
if ($startIdx -lt 0) { throw 'the -SkipRemediationScript panel text was not found' }
for ($n = $startIdx; $n -lt [math]::Min($startIdx + 6, $lines.Count); $n++) {
    if ($lines[$n] -match "clock resynchronisation") { $endIdx = $n; break }
}
if ($endIdx -lt 0) { throw 'the end of the panel text was not found' }
$snippet = ($lines[$startIdx..$endIdx] -join "`r`n")

function Get-Panel {
    param([string] $Domain)
    Invoke-Expression $snippet
}

'[hostile domain] the page must name the file the writer actually produces'
$hostile = 'hostile<domain.local'
$expected = ConvertTo-mdiSafeFileName $hostile
$html = Get-Panel -Domain $hostile
Assert-That 'the sanitised name really differs from the raw one' ($expected -ne $hostile) "(sanitised='$expected')"
Assert-That 'the page names the file that is written' ($html -match [regex]::Escape('Fix-MdiReadiness-' + $expected + '.ps1')) "(html='$html')"
Assert-That 'the page does not name a file that is never written' ($html -notmatch [regex]::Escape('hostile&lt;domain.local.ps1')) "(html='$html')"
Assert-That 'the raw unescaped domain does not reach the page' ($html -notmatch [regex]::Escape($hostile)) "(html='$html')"

'[escaping control] sanitising must not replace HTML encoding'
$quoted = 'con"toso&.com'
$quotedSafe = ConvertTo-mdiSafeFileName $quoted
$html2 = Get-Panel -Domain $quoted
Assert-That 'the page names the sanitised file' ($html2 -match [regex]::Escape('Fix-MdiReadiness-' + (ConvertTo-mdiHtmlEncoded $quotedSafe) + '.ps1')) "(html='$html2')"
Assert-That 'no raw ampersand-less-than pair survives into the markup' ($html2 -notmatch '<script') "(html='$html2')"

'[ordinary domain control] a name needing no sanitising must be unchanged'
$plain = 'contoso.com'
$html3 = Get-Panel -Domain $plain
Assert-That 'the sanitiser leaves an ordinary domain alone' ((ConvertTo-mdiSafeFileName $plain) -eq $plain)
Assert-That 'the page still names it correctly' ($html3 -match [regex]::Escape('Fix-MdiReadiness-contoso.com.ps1')) "(html='$html3')"
Assert-That 'the panel still explains the switch' ($html3 -match 'SkipRemediationScript') "(html='$html3')"

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
