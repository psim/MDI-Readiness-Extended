<#
    A TYPOGRAPHIC APOSTROPHE IN THE REMOTE TEMP PATH SILENTLY KILLED THE WHOLE PORT PROBE.

    The port-probe payload embeds the output file path in a single-quoted PowerShell literal:

        [io.file]::WriteAllText('<path>', $json, ...)

    Only ASCII U+0027 was escaped. Windows PowerShell 5.1 also accepts U+2018, U+2019, U+201A and
    U+201B as single-quote delimiters, and U+2019 is the ordinary apostrophe in French - a directory
    named "Company<U+2019>s Temp" is a perfectly legal Windows path.

    Measured on the shipped generator, executing the result the way Win32_Process.Create does:

        CONTROL (U+0027)   GENERATED_PARSE_ERROR_COUNT=0   EXIT=0   OUTPUT_JSON_PARSES=True
        U+2019             GENERATED_PARSE_ERROR_COUNT=3   EXIT=1   OUTPUT_FILE_EXISTS=False
                           first error: Missing ')' in method call.

    So a server whose machine-wide TEMP carries a typographic apostrophe ran NO port probe at all -
    and the caller reads a missing result file as a server it could not measure, not as a defect. The
    whole network-port surface for that server is lost, quietly.

    The remediation generator had already learned this lesson and normalises all five quote
    characters; the port-probe path had not. The rule now lives in one function,
    Get-mdiSingleQuoteLiteral, so the two producers cannot drift apart again.

    These assertions drive the real generator and PARSE what it produced, because "it is escaped" is
    a claim about a parser and only a parser can settle it.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

$plan = New-mdiPortProbePlan -Domain 'contoso.com' -TimeoutMs 300 `
    -DomainController @([PSCustomObject]@{ Name = 'dc01.contoso.com'; IP = '10.0.0.1' }) -NnrTarget @()

function Get-ParseErrorCount {
    param([string] $ScriptText)
    $errors = $null
    [void] [System.Management.Automation.Language.Parser]::ParseInput($ScriptText, [ref] $null, [ref] $errors)
    @($errors).Count
}

# Every character Windows PowerShell accepts as a single-quote delimiter. U+0027 is the control - it
# was already handled - and the other four are the defect.
$quoteChars = [ordered]@{
    'U+0027 ASCII apostrophe'      = [char] 0x0027
    'U+2018 left single quote'     = [char] 0x2018
    'U+2019 right single quote'    = [char] 0x2019
    'U+201A single low-9 quote'    = [char] 0x201A
    'U+201B single high-reversed'  = [char] 0x201B
}

Write-Host 'Every quote character PowerShell honours must survive as literal data' -ForegroundColor Cyan
foreach ($name in $quoteChars.Keys) {
    $path = 'C:\Company{0}s Temp\mdi-ports.json' -f $quoteChars[$name]
    $generated = Get-mdiPortProbeScriptText -Plan $plan -OutputFile $path
    Assert-That "$name : the generated payload still parses" (
        (Get-ParseErrorCount -ScriptText $generated) -eq 0) (
        'parse errors: ' + (Get-ParseErrorCount -ScriptText $generated))
}

Write-Host ''
Write-Host 'The path must arrive at the writer intact - byte for byte' -ForegroundColor Cyan
# Parsing is necessary but not sufficient: a mangled path could still parse and write the results to
# a DIFFERENT directory, which is worse than failing - the caller would read a missing file as an
# unmeasurable server. The generated script is executed with the probe itself stubbed out, so the
# path it would really have written to is observed rather than assumed.
foreach ($name in $quoteChars.Keys) {
    $quote = $quoteChars[$name]
    $path = 'C:\Company{0}s Temp\mdi-ports.json' -f $quote
    $generated = Get-mdiPortProbeScriptText -Plan $plan -OutputFile $path

    $captured = $null
    $harness = @"
function Invoke-mdiPortProbePlan { param(`$Plan) @() }
`$script:capturedPath = `$null
"@ + [Environment]::NewLine + $generated
    # The generated script ends by calling [io.file]::WriteAllText, so the run is done in a child
    # scope with a temp root that really exists and the written file is then located.
    $sandbox = Join-Path ([IO.Path]::GetTempPath()) ('mdi-quote-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void] (New-Item -ItemType Directory -Path $sandbox -Force)
    try {
        $sandboxPath = Join-Path $sandbox ('Company{0}s Temp' -f $quote)
        [void] (New-Item -ItemType Directory -Path $sandboxPath -Force)
        $realTarget = Join-Path $sandboxPath 'mdi-ports.json'
        $generatedReal = Get-mdiPortProbeScriptText -Plan $plan -OutputFile $realTarget
        $runner = @"
function Invoke-mdiPortProbePlan { param(`$Plan) @([PSCustomObject]@{ Id = 'probe'; Success = `$true }) }
"@ + [Environment]::NewLine + $generatedReal
        $sb = [scriptblock]::Create($runner)
        & $sb 2>$null | Out-Null
        Assert-That "$name : the results land at the EXACT requested path" (
            Test-Path -LiteralPath $realTarget) "expected file at [$realTarget]"
        if (Test-Path -LiteralPath $realTarget) {
            $content = [IO.File]::ReadAllText($realTarget)
            Assert-That "$name : and the file it wrote is valid JSON" (
                $null -ne ($content | ConvertFrom-Json)) "content=$content"
        }
        # And nothing was written to the ASCII-folded neighbour, which is the failure mode a
        # normalising fix would have introduced.
        if ($quote -ne [char] 0x0027) {
            $folded = Join-Path (Join-Path $sandbox "Company's Temp") 'mdi-ports.json'
            Assert-That "$name : nothing was written to the ASCII-folded path instead" (
                -not (Test-Path -LiteralPath $folded)) "unexpected file at [$folded]"
        }
    } finally {
        Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host 'CONTROLS - ordinary paths are untouched' -ForegroundColor Cyan
foreach ($case in @(
        'C:\Windows\Temp\mdi-ports.json',
        'D:\Program Files\Company Temp\mdi-ports.json',
        "C:\Temp\dc-muenchen-$([char]0xE4)$([char]0xF6)$([char]0xFC)\mdi-ports.json")) {
    $generated = Get-mdiPortProbeScriptText -Plan $plan -OutputFile $case
    Assert-That "CONTROL: '$case' still parses" (
        (Get-ParseErrorCount -ScriptText $generated) -eq 0)
    # The path is carried as base64, so it is recovered by decoding it back out of the payload -
    # which also proves the encoding survives non-ASCII, not just quotes.
    $encoded = [regex]::Match($generated, "outputFile = \[text\.encoding\]::UTF8\.GetString\(\[convert\]::FromBase64String\('([^']+)'\)\)").Groups[1].Value
    $recovered = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
    Assert-That "CONTROL: '$case' round-trips unchanged" ($recovered -ceq $case) (
        "recovered=[$recovered]")
}

Write-Host ''
Write-Host 'The payload carries the path as data, not as source' -ForegroundColor Cyan
# Stated directly so a future change back to a quoted literal fails here rather than in the field.
$sample = Get-mdiPortProbeScriptText -Plan $plan -OutputFile ('C:\Company{0}s Temp\mdi-ports.json' -f [char] 0x2019)
Assert-That 'the emitted payload contains no raw quote character from the path' (
    $sample -notmatch [regex]::Escape([string] [char] 0x2019)) 'a raw U+2019 reached the payload'
Assert-That 'and the writer is handed a variable rather than a literal' (
    $sample -match '\[io\.file\]::WriteAllText\(\$outputFile,') 'the path is still inlined as a literal'

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
