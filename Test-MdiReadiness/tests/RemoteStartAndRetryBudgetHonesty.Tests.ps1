<#
    Two more places where the tool reported something the run does not support.

    1. A REMOTE COMMAND THAT NEVER STARTED LOOKED LIKE ONE THAT RAN AND SAID NOTHING.

       Invoke-mdiRemoteCommand starts powershell.exe on the target with Win32_Process.Create. The
       call is made with -ErrorAction SilentlyContinue - deliberately, because a probe against an
       unreachable server must not spray the error stream - and Win32_Process.Create reports failure
       through its RETURN VALUE rather than by throwing: 2 access denied, 3 insufficient privilege,
       9 path not found, 21 invalid parameter.

       The ReturnValue was consulted ONLY to decide whether to wait for the process. Every non-zero
       status, and a $null result from a WMI call that failed outright, fell straight through to the
       output-file read, found nothing (the file was never created) and returned EMPTY OUTPUT.

       Empty output is indistinguishable from a successful command with nothing to say. So a server
       this account simply could not start a process on was reported as a server whose checks all
       came back blank - and access denied is the ORDINARY case for the non-admin caller this tool
       is documented to support, so it is the common path, not the exotic one.

    2. A RETRIED PORT PROBE REPORTED A WAIT THAT NEVER HAPPENED.

       Test-mdiTcpPort retries a timed-out probe with a longer budget (max(TimeoutMs*3, 5000)). The
       failure detail printed $TimeoutMs - which on the retry call IS the retry budget - so a 1500 ms
       probe that was retried for 5000 ms reported "no response within 5000 ms". No attempt ever
       waited 1500 ms according to the report, and the operator sizing a firewall timeout from that
       number was reading a value the first attempt never used.

       The SUCCESS path already got this right: "Connected on the second attempt after N ms - the
       first 1500 ms probe timed out". Only the failure path had lost a budget.
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

$script:warnings = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:warnings.Add([string] $Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Start-Sleep -Value { param($Seconds, $Milliseconds) }
Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value { param($ComputerName) 'C:\Windows\Temp' }

# ===================================================================================================
# PART 1 - a Create that failed must not read as a command that ran
# ===================================================================================================
$script:createReturn = 0          # Win32_Process.Create ReturnValue, or 'null' for no result at all
$script:fileWasRead = $false

Set-Item -Path function:script:Invoke-WmiMethod -Value {
    param($ComputerName, $Namespace, $Class, $Name, $ArgumentList, $ErrorAction)
    if ($script:createReturn -eq 'null') { return $null }
    [PSCustomObject]@{ ReturnValue = [int] $script:createReturn; ProcessId = 4242 }
}
Set-Item -Path function:script:Get-WmiObject -Value {
    param($Class, $ComputerName, $Namespace, $Filter, $ErrorAction)
    $null
}
# If the guard works, nothing below it ever runs, so a read here is itself the defect.
Set-Item -Path function:script:Get-Content -Value {
    param($Path, $ErrorAction, $Raw, $Tail, $TotalCount, $LiteralPath)
    $script:fileWasRead = $true
    throw 'file not found'
}
Set-Item -Path function:script:Remove-Item -Value { param($Path, $Force, $ErrorAction, $LiteralPath) }

function Invoke-Create {
    param($Return)
    $script:warnings = New-Object System.Collections.ArrayList
    $script:fileWasRead = $false
    $script:createReturn = $Return
    $out = Invoke-mdiRemoteCommand -ComputerName 'dc1.contoso.com' -CommandLine 'whoami' -TimeoutSeconds 1 3>$null 4>$null
    [PSCustomObject]@{
        Output     = $out
        Warnings   = @($script:warnings)
        WarnedFail = @($script:warnings | Where-Object { $_ -like '*Could not start the remote command*' }).Count
        FileRead   = $script:fileWasRead
    }
}

Write-Host 'A remote command that never started must not read as one that ran' -ForegroundColor Cyan

$denied = Invoke-Create -Return 2
$noResult = Invoke-Create -Return 'null'

Assert-That 'an access-denied Create raises a warning' ($denied.WarnedFail -eq 1) (
    "warnings: $($denied.Warnings -join ' | ')")
Assert-That 'the warning discloses the Create status' (
    @($denied.Warnings | Where-Object { $_ -like '*returned 2*' }).Count -eq 1
) ("warnings: $($denied.Warnings -join ' | ')")
Assert-That 'the warning says the dependent checks did not run' (
    @($denied.Warnings | Where-Object { $_ -like '*NOT run*' }).Count -eq 1
) ("warnings: $($denied.Warnings -join ' | ')")
Assert-That 'a failed Create does not go on to read the output file' (-not $denied.FileRead) (
    'the output file was read for a process that was never created')
Assert-That 'a WMI call returning nothing at all also warns' ($noResult.WarnedFail -eq 1) (
    "warnings: $($noResult.Warnings -join ' | ')")
Assert-That 'the no-result warning explains itself' (
    @($noResult.Warnings | Where-Object { $_ -like '*did not return a result*' }).Count -eq 1
) ("warnings: $($noResult.Warnings -join ' | ')")

# CONTROL: a SUCCESSFUL create must behave exactly as before - no warning, and it proceeds to read.
$ok = Invoke-Create -Return 0
Assert-That 'CONTROL: a successful Create raises no start-failure warning' ($ok.WarnedFail -eq 0) (
    "warnings: $($ok.Warnings -join ' | ')")
Assert-That 'CONTROL: a successful Create still proceeds to read its output' ($ok.FileRead) (
    'the success path no longer reads the output file at all')

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
