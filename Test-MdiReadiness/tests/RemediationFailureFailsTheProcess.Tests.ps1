<#
    THE GENERATED REMEDIATION SCRIPT REPORTED ITS OWN FAILURES AND STILL EXITED 0.

    New-mdiRemediationScript writes a .ps1 the operator runs to apply the fixes the scan found.
    Every section of that file catches its own failure into $script:mdiFailed, and the closing block
    prints the names:

        WARNING: Remediation finished with failures on 1 server(s): dc1.contoso.com
        WARNING: Fix the cause and re-run this script, then re-run Test-MdiReadiness.ps1 to verify.

    and then returned exit code 0.

    Write-Warning does not touch the exit code. Nothing that runs this file unattended reads the
    transcript - a scheduled task, a deployment pipeline or a maintenance wrapper reads the exit
    code - so a run in which every scripted change failed was recorded as a successful remediation,
    and the estate was left unremediated with a green tick beside it.

    Measured on the shipped generator before the fix: one section, the emitted WinRM call made to
    throw, the failure list printed, PROCESS_EXIT_CODE=0.

    This is the same rule the scanner already applies to itself: a scan that stops part way exits
    255 rather than letting a wrapper read an incomplete run as a result.

    These assertions GENERATE the script with the shipped generator and then EXECUTE it unmodified
    in a child Windows PowerShell 5.1 process, because the exit code of that process is the entire
    subject - a test that inspected the emitted text would pass on a file that still exits 0.
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
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$winps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path $winps)) { throw 'Windows PowerShell 5.1 was not found - this test needs it to run the generated script' }

$workDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi-remedexit-{0}' -f [guid]::NewGuid().ToString('N'))
[void] (New-Item -ItemType Directory -Path $workDir -Force)

# One ordinary finding that produces one ordinary section: a domain controller whose power scheme is
# not High Performance. Any section would do - they all record failures the same way - and this one
# needs no directory data.
$reportData = [PSCustomObject]@{
    Domain              = 'contoso.com'
    Forest              = 'contoso.com'
    DomainsInScope      = @('contoso.com')
    DomainControllers   = @([PSCustomObject]@{
            FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'
            Unreachable = $false; PartialFailure = $false
            PowerSettings = $false
            Details = [PSCustomObject]@{}
        })
    CAServers           = @()
    EntraConnectServers = @()
    DomainAuditing      = @()
}

$generated = Join-Path $workDir 'remediation.ps1'
$result = New-mdiRemediationScript -ReportData $reportData -FilePath $generated 3>$null 4>$null
if ([int] $result.SectionCount -lt 1) { throw 'the generator emitted no sections - the fixture produces no finding' }
if (-not (Test-Path $generated)) { throw 'the generator wrote no file' }

# The generated script is run UNMODIFIED. Only the boundary it calls out on is replaced, in the
# runner that invokes it, so the emitted error handling is the code under test.
function Invoke-Generated {
    param(
        [Parameter(Mandatory = $true)] [string] $InvokeCommandBody,
        [string[]] $ExtraArgument = @()
    )
    $runner = Join-Path $workDir ('runner-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    $argText = if ($ExtraArgument.Count -gt 0) { ' ' + ($ExtraArgument -join ' ') } else { '' }
    # The generated script has to be invoked from a wrapper, because the only way to replace the
    # boundary it calls out on is to define the stub in a parent scope. `exit N` inside a script
    # invoked with & ends THAT script and sets $LASTEXITCODE in the caller - it does not end the
    # caller - so the wrapper re-raises it. That is exactly what powershell.exe -File does with the
    # same script when an operator or a scheduled task runs it directly, which is the case this
    # measures. $LASTEXITCODE is cleared first so a stale value cannot be read as this run's verdict.
    $runnerText = @"
function Invoke-Command {
    param(`$ComputerName, `$ScriptBlock, `$ArgumentList, `$ErrorAction, `$Session, `$Credential)
$InvokeCommandBody
}
`$global:LASTEXITCODE = 0
& '$($generated -replace "'", "''")' -Transport WinRM$argText
exit `$LASTEXITCODE
"@
    [IO.File]::WriteAllText($runner, $runnerText, (New-Object System.Text.UTF8Encoding $true))
    $output = (& $winps -NoProfile -ExecutionPolicy Bypass -File $runner 2>&1 | Out-String).TrimEnd()
    [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

try {
    Write-Host 'A remediation run that records failures must fail the process' -ForegroundColor Cyan
    $failed = Invoke-Generated -InvokeCommandBody "    throw 'SIMULATED REMOTE FAILURE'"

    # The harness has to have reached the failure path, or the exit code below proves nothing.
    if ($failed.Output -notmatch 'Remediation finished with failures') {
        throw "the generated script did not record a failure - the harness never reached the path under test:`n$($failed.Output)"
    }
    Assert-That 'the failing server is named in the summary' (
        $failed.Output -match 'dc1\.contoso\.com') $failed.Output
    Assert-That 'the process exit code is NOT zero' (
        $failed.ExitCode -ne 0) "exit=$($failed.ExitCode)"
    Assert-That 'and it does not claim the remediation completed' (
        $failed.Output -notmatch 'Remediation complete') $failed.Output

    Write-Host ''
    Write-Host 'CONTROLS - a run with no recorded failure must still succeed' -ForegroundColor Cyan
    # Nothing thrown: whatever the section makes of the returned status, no server is added to
    # mdiFailed, so the process must not report failure to whatever launched it.
    $ok = Invoke-Generated -InvokeCommandBody '    return $null'
    Assert-That 'CONTROL: no failure recorded' (
        $ok.Output -notmatch 'Remediation finished with failures') $ok.Output
    Assert-That 'CONTROL: the process exit code is zero' ($ok.ExitCode -eq 0) "exit=$($ok.ExitCode)"

    # A rehearsal must never fail a pipeline. Under -WhatIf every remote call sits inside
    # ShouldProcess and never runs, so there is nothing to fail - and the exit code has to say so.
    $preview = Invoke-Generated -InvokeCommandBody "    throw 'SIMULATED REMOTE FAILURE'" -ExtraArgument @('-WhatIf')
    Assert-That 'CONTROL: -WhatIf exits zero even with a boundary that throws' (
        $preview.ExitCode -eq 0) "exit=$($preview.ExitCode) output=$($preview.Output)"
    Assert-That 'CONTROL: -WhatIf says nothing was changed' (
        $preview.Output -match 'nothing was changed') $preview.Output
} finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
