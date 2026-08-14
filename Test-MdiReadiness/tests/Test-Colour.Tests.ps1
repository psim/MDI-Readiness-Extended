<#
    Verifies the coloured verbose output.

    The two things that matter are that the helper cannot call itself, and that colour is suppressed
    when the output is redirected. A run such as "Test-MdiReadiness.ps1 -Verbose *> run.log" is the
    normal way this script is used unattended, and escape sequences in that log would be worse than
    no colour at all.
#>
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors -join '; ')" }

$pass = 0; $fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name $Detail" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

Write-Host "`n[1] The helper cannot recurse" -ForegroundColor Yellow
$helperAst = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -eq 'Write-mdiVerbose' }, $true)[0]
Assert-That 'Write-mdiVerbose exists' ($null -ne $helperAst)
$body = $helperAst.Extent.Text
# Checked through the AST rather than by text: the function's own declaration line contains its name,
# so a plain string search reports a recursion that is not there.
$selfCalls = $helperAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
        $n.GetCommandName() -eq 'Write-mdiVerbose' }, $true)
Assert-That 'it never calls itself' (@($selfCalls).Count -eq 0) "(found $(@($selfCalls).Count) self-call(s))"
Assert-That 'it calls the cmdlet by its qualified name' (
    ([regex]::Matches($body, 'Microsoft\.PowerShell\.Utility\\Write-Verbose')).Count -eq 2)

Write-Host "`n[2] Colour is decided once, and safely" -ForegroundColor Yellow
$source = Get-Content $scriptPath -Raw
Assert-That 'redirection is checked'   ($source -match '\[Console\]::IsOutputRedirected')
Assert-That 'terminal support is checked' ($source -match 'SupportsVirtualTerminal')
Assert-That 'NO_COLOR is honoured'     ($source -match 'NO_COLOR')

Write-Host "`n[3] Behaviour with colour on and off" -ForegroundColor Yellow
$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))
foreach ($name in '$script:mdiUseColour', '$script:mdiColour') {
    $a = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -eq $name }, $true)[0]
    if ($a) { . ([scriptblock]::Create($a.Extent.Text)) }
}
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))

# EVERY script-scoped constant is loaded. These live at file scope rather than inside a function, so
# dot-sourcing the function bodies alone leaves them null - and a null regex in "-notmatch" matches
# everything, which silently inverted a filter and failed a suite for a reason unrelated to the script.
foreach ($constAst in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -like '$script:*' -and
            $null -eq $n.Parent.Parent.Parent }, $false)) {
    . ([scriptblock]::Create($constAst.Extent.Text))
}

$esc = [char] 27
$VerbosePreference = 'Continue'

# PowerShell 7 strips escape sequences from a redirected or piped stream when
# $PSStyle.OutputRendering is 'Host', which is the default. The assertions below read the verbose
# stream through a pipeline, so without this every colour test fails on PowerShell 7 and passes on
# Windows PowerShell 5.1 - measuring the host's rendering policy rather than the helper. Windows
# PowerShell 5.1 has no $PSStyle and does no stripping, which is exactly why the helper needs its
# own guard.
if (Get-Variable -Name PSStyle -Scope Global -ErrorAction SilentlyContinue) {
    $script:originalRendering = $PSStyle.OutputRendering
    $PSStyle.OutputRendering = 'ANSI'
}

$script:mdiUseColour = $false
$plain = (Write-mdiVerbose 'Testing server requirements for dc01.contoso.com' 4>&1 | Out-String)
Assert-That 'no escape sequences when colour is off' ($plain -notmatch [regex]::Escape($esc))
Assert-That 'the message survives intact' ($plain -match 'dc01\.contoso\.com')

$script:mdiUseColour = $true
$coloured = (Write-mdiVerbose 'Testing server requirements for dc01.contoso.com' 4>&1 | Out-String)
Assert-That 'the server name is coloured' ($coloured -match [regex]::Escape($esc + '[96m') )
Assert-That 'colour is reset afterwards'  ($coloured -match [regex]::Escape($esc + '[0m'))
# Stripping the sequences must return exactly the original text, or the log is being altered
$stripped = [regex]::Replace($coloured, "$esc\[\d+m", '')
Assert-That 'stripping the colour restores the original text' ($stripped.Trim() -eq 'Testing server requirements for dc01.contoso.com')

$counted = (Write-mdiVerbose 'Found 5 domain controller(s) in 1 domain(s)' 4>&1 | Out-String)
Assert-That 'counts are highlighted' ($counted -match [regex]::Escape($esc + '[93m') + '5')

$bad = (Write-mdiVerbose 'Unable to run the port probes on dc01.contoso.com, falling back to probing it remotely' 4>&1 | Out-String)
Assert-That 'a degraded path is highlighted' ($bad -match [regex]::Escape($esc + '[91m'))

$script:mdiUseColour = $false
if (Get-Variable -Name PSStyle -Scope Global -ErrorAction SilentlyContinue) {
    $PSStyle.OutputRendering = $script:originalRendering
}
Write-Host ("`n================ {0} passed / {1} failed ================" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
