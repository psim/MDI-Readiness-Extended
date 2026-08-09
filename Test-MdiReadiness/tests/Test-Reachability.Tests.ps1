<#
    Verifies that a server whose ICMP is blocked is still tested.

    This is the case the readiness script used to get wrong: it gated every per-server check behind a
    ping, so an environment that blocks ICMP by policy produced a report where every server was
    "not available" and nothing was checked, which reads as a clean run rather than a failure.
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

# EVERY script-scoped constant is loaded. These live at file scope rather than inside a function, so
# dot-sourcing the function bodies alone leaves them null - and a null regex in "-notmatch" matches
# everything, which silently inverted a filter and failed a suite for a reason unrelated to the script.
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

Write-Host "`n[1] No per-server check is gated behind ping alone" -ForegroundColor Yellow
$source = Get-Content $scriptPath -Raw
# The helper legitimately contains one ping gate: that is the cheap first attempt. What matters is
# that no gate survives anywhere else, since those were the ones that skipped whole servers.
$helperAst = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -eq 'Test-mdiServerReachable' }, $true)[0]
$helperText = $helperAst.Extent.Text
$outsideHelper = $source.Replace($helperText, '')
$pingGates = [regex]::Matches($outsideHelper, 'if\s*\(\s*Test-Connection[^)]*\)\s*\{')
Assert-That 'no ping gate outside the reachability helper' ($pingGates.Count -eq 0) "(found $($pingGates.Count))"
Assert-That 'the helper itself still tries ICMP first' (
    ([regex]::Matches($helperText, 'Test-Connection')).Count -eq 1)
Assert-That 'Test-Connection appears nowhere else' (
    ([regex]::Matches($outsideHelper, 'Test-Connection')).Count -eq 0)

Write-Host "`n[2] The helper falls back rather than trusting ICMP" -ForegroundColor Yellow
$helper = (Get-Command Test-mdiServerReachable -CommandType Function).Definition
Assert-That 'tries ICMP'    ($helper -match 'Test-Connection')
Assert-That 'falls back to TCP 135' ($helper -match 'TcpClient' -and $helper -match '135')
Assert-That 'falls back to WMI'     ($helper -match 'Get-WmiObject')
Assert-That 'reports which method succeeded' ($helper -match 'Method')

Write-Host "`n[3] Behaviour against real endpoints" -ForegroundColor Yellow
# Loopback answers ICMP, so the cheapest path should be taken
$loop = Test-mdiServerReachable -ComputerName '127.0.0.1'
Assert-That 'a pingable host is reachable via ICMP' ($loop.Reachable -and $loop.Method -eq 'ICMP') "(method: $($loop.Method))"

# RFC 5737 documentation address: nothing answers, so every method must fail and it must not throw
$sw = [Diagnostics.Stopwatch]::StartNew()
$dead = Test-mdiServerReachable -ComputerName '192.0.2.77' -TimeoutMs 1500
$sw.Stop()
Assert-That 'an unreachable host returns false rather than throwing' (-not $dead.Reachable)
Assert-That 'the failure names every method tried' ($dead.Method -match 'ICMP' -and $dead.Method -match '135' -and $dead.Method -match 'WMI') "($($dead.Method))"

Write-Host "`n[4] The ICMP-blocked case" -ForegroundColor Yellow
# A host that refuses ICMP but accepts TCP 135 must still be reported reachable. A local listener on
# 135 already exists on Windows (the RPC endpoint mapper), and 127.0.0.2 does not answer ping on all
# builds, so the TCP path is exercised directly instead.
$tcpOnly = $null
try {
    $client = New-Object System.Net.Sockets.TcpClient
    $async = $client.BeginConnect('127.0.0.1', 135, $null, $null)
    $tcpOnly = $async.AsyncWaitHandle.WaitOne(2000, $false) -and $client.Connected
    $client.Close()
} catch { $tcpOnly = $false }
Assert-That 'TCP 135 is a usable liveness signal on this machine' ([bool] $tcpOnly) "(RPC endpoint mapper reachable: $tcpOnly)"

Write-Host "`n[5] The unavailable message explains itself" -ForegroundColor Yellow
Assert-That 'the comment carries the method detail' ($source -match "Server is not available: \{0\}' -f \`$reach\.Method")
Assert-That 'the warning mentions the ICMP fallbacks' ($source -match 'If ICMP is blocked by policy')

Write-Host ("`n================ {0} passed / {1} failed ================" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
