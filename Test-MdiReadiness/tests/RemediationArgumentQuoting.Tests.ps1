<#
    Arbitrary code execution on a DOMAIN CONTROLLER through the generated remediation script.

    The generated Invoke-MdiRemote helper rebuilds its arguments as PowerShell literals before sending
    them to a DC through Win32_Process.Create, because a scriptblock sent over WMI carries no session
    state. It wrapped each value in an ASCII apostrophe and escaped only the ASCII apostrophe.

    Windows PowerShell accepts FIVE characters as single-quote string delimiters - U+0027 and the
    typographic forms U+2018, U+2019, U+201A, U+201B - and they are interchangeable: a U+2019 CLOSES a
    literal opened with U+0027. Measured before the fix, an argument of

        dc1<U+2019>; Set-Content -LiteralPath <U+2019>C:\...<U+2019> -Value PWNED; <U+2019>

    parsed as a TWO-element array and the Set-Content ran - arbitrary code executing on a domain
    controller with the privileges of the administrator who was told to run the remediation script.

    This was not a theoretical input. Server names, adapter names and CA names reach the generator from
    Active Directory and from -DomainController / -CAServer, and a name pasted from a ticket, an email
    or a Word document carries typographic quotes routinely - Word substitutes them automatically.

    The generator's own literal helper already stripped the whole set, so the codebase knew about the
    hazard; only the WMI argument path had been left on the ASCII-only escape.

    These assertions are BEHAVIOURAL: they GENERATE a real remediation script, extract the serialiser
    the generator actually emitted, run it against hostile values, and parse the result. Matching
    source text would not notice a rewrite that reintroduced the ASCII-only escape.
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

# The five characters Windows PowerShell accepts as single-quote delimiters.
$quoteChars = @([char]0x0027, [char]0x2018, [char]0x2019, [char]0x201A, [char]0x201B)

Write-Host 'The premise: every one of these really is a string delimiter' -ForegroundColor Cyan
# If this stops being true the rest of the file is testing nothing, so it is asserted rather than
# assumed - and it is the fact the original escape overlooked.
foreach ($q in $quoteChars) {
    $probe = '$x = ' + $q + 'abc' + $q
    $e = $null; $t = $null
    [void][Management.Automation.Language.Parser]::ParseInput($probe, [ref]$t, [ref]$e)
    $lit = @($t | Where-Object { $_.Kind -eq 'StringLiteral' })
    Assert-That ("U+{0:X4} opens and closes a literal" -f [int] $q) ($e.Count -eq 0 -and $lit.Count -eq 1) "errors=$($e.Count) literals=$($lit.Count)"
}
# The interchangeability is the actual attack: a U+0027 wrapper closed by a U+2019 from the data.
$mixed = '$x = ' + [char]0x0027 + 'abc' + [char]0x2019 + '; $y = 1; ' + [char]0x2019 + [char]0x0027
$em = $null; $tm = $null
[void][Management.Automation.Language.Parser]::ParseInput($mixed, [ref]$tm, [ref]$em)
Assert-That 'a U+2019 closes a literal opened with U+0027' (
    @($tm | Where-Object { $_.Kind -eq 'StringLiteral' }).Count -gt 1) 'the delimiters are not interchangeable - premise broken'

Write-Host 'A remediation script is generated and parses' -ForegroundColor Cyan
$outFile = Join-Path ([IO.Path]::GetTempPath()) ('mdi-remed-' + [Guid]::NewGuid().ToString('N') + '.ps1')
Set-Item -Path function:script:Write-mdiReportFile -Value {
    param($Content, $FilePath, $TimeoutSeconds)
    [IO.File]::WriteAllText($FilePath, $Content, (New-Object Text.UTF8Encoding $true))
}
$reportData = [PSCustomObject]@{
    Domain            = 'contoso.com'
    DomainControllers = @([PSCustomObject]@{
            FQDN                = 'dc1.contoso.com'
            OperatingSystem     = 'Windows Server 2022'
            PowerScheme         = 'Balanced'
            PowerSchemeMeasured = $true
        })
    CAServers           = @()
    EntraConnectServers = @()
}
$generated = $null
try {
    [void](New-mdiRemediationScript -ReportData $reportData -FilePath $outFile)
    $generated = [IO.File]::ReadAllText($outFile)
} finally {
    Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
}
Assert-That 'the generator produced a script' ($generated -and $generated.Length -gt 0)

$genErrors = $null; $genTokens = $null
[void][Management.Automation.Language.Parser]::ParseInput($generated, [ref]$genTokens, [ref]$genErrors)
Assert-That '  ...and it is valid PowerShell' ($genErrors.Count -eq 0) ("first error: " + $(if ($genErrors.Count) { $genErrors[0].Message } else { '' }))

Write-Host 'The emitted argument serialiser contains every quote variant' -ForegroundColor Cyan
# The serialiser the GENERATOR EMITTED is extracted and executed, so this tests the artefact an
# administrator actually runs rather than the generator's own source.
$serialiserLine = @($generated -split "`r?`n" |
        Where-Object { $_ -match '\[string\]\s*\$argument\s+-replace' }) | Select-Object -First 1
Assert-That 'the generated helper serialises its arguments' ($null -ne $serialiserLine) 'no scalar serialiser emitted'

if ($serialiserLine) {
    $serialise = [scriptblock]::Create('param($argument) ' + $serialiserLine.Trim())

    foreach ($q in $quoteChars) {
        $hostile = 'dc1' + $q + '; $mdiInjected = 1; ' + $q
        $literal = & $serialise $hostile
        $line = '$__mdiArgs = @(' + $literal + ')'
        $e = $null; $t = $null
        [void][Management.Automation.Language.Parser]::ParseInput($line, [ref]$t, [ref]$e)
        $strings = @($t | Where-Object { $_.Kind -eq 'StringLiteral' })
        $commands = @($t | Where-Object { $_.Kind -eq 'Variable' -and $_.Name -eq 'mdiInjected' })
        Assert-That ("U+{0:X4} stays inside its literal" -f [int] $q) ($strings.Count -eq 1) "produced $($strings.Count) literals"
        Assert-That ("  ...and U+{0:X4} injects no code" -f [int] $q) ($commands.Count -eq 0) 'injected variable reached the token stream'
    }

    # A value made ONLY of quote characters is the densest form of the attack.
    $allQuotes = -join $quoteChars
    $litAll = & $serialise $allQuotes
    $eAll = $null; $tAll = $null
    [void][Management.Automation.Language.Parser]::ParseInput('$__mdiArgs = @(' + $litAll + ')', [ref]$tAll, [ref]$eAll)
    Assert-That 'a value of nothing but quote characters is contained' (
        $eAll.Count -eq 0 -and @($tAll | Where-Object { $_.Kind -eq 'StringLiteral' }).Count -eq 1) "errors=$($eAll.Count)"

    Write-Host 'Ordinary values still survive the escape intact' -ForegroundColor Cyan
    # Over-escaping would corrupt real data, which is its own defect: a DC named O'Brien-DC must keep
    # its name, and the escape must be reversible by the parser back to the exact original string.
    foreach ($ordinary in 'dc1.contoso.com', "O'Brien-DC", 'dc-muenchen.contoso.com', 'CN=Foo,OU=Bar,DC=contoso,DC=com', 'C:\Windows\Temp') {
        $lit = & $serialise $ordinary
        $e = $null; $t = $null
        [void][Management.Automation.Language.Parser]::ParseInput('$v = ' + $lit, [ref]$t, [ref]$e)
        $got = @($t | Where-Object { $_.Kind -eq 'StringLiteral' } | ForEach-Object { $_.Value })
        Assert-That "'$ordinary' round-trips unchanged" ($e.Count -eq 0 -and $got.Count -eq 1 -and $got[0] -eq $ordinary) "got '$($got -join '|')'"
    }

    Write-Host 'The hostile value does not execute when the generated line is run' -ForegroundColor Cyan
    # The decisive proof: a side effect that output capture cannot hide.
    $marker = Join-Path ([IO.Path]::GetTempPath()) ('mdi-pwn-' + [Guid]::NewGuid().ToString('N') + '.txt')
    $rsq = [char]0x2019
    $payload = 'dc1' + $rsq + '; Set-Content -LiteralPath ' + $rsq + $marker + $rsq + ' -Value PWNED; ' + $rsq
    $runFile = Join-Path ([IO.Path]::GetTempPath()) ('mdi-run-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    $runText = '$__mdiArgs = @(' + (& $serialise $payload) + ')' + [Environment]::NewLine + '"count=" + $__mdiArgs.Count'
    [IO.File]::WriteAllText($runFile, $runText, (New-Object Text.UTF8Encoding $true))
    try {
        $null = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $runFile 2>&1
        Assert-That 'the injected command does not run' (-not (Test-Path -LiteralPath $marker)) 'the payload executed - this is remote code execution on a DC'
    } finally {
        Remove-Item -LiteralPath $runFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
