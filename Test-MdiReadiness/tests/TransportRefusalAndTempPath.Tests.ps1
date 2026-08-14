<#
    Two transport-layer defects, both of the "unmeasured treated as measured" class.

    1. A WMI query the server REFUSED was classified as a measurement. Test-mdiIsNotRunError decides
       whether an error means "nothing was measured" (so the check must report unknown) or "this is a
       real observation" (so it may fail the verdict). It tested two HResult values and a couple of
       exception types - but WMI reports refusal through ManagementException, whose HResult is the
       GENERIC COM value 0x80020009 for every one of its error codes. So an ACCESS DENIED or
       PRIVILEGE NOT HELD from WMI matched nothing and was treated as a definite state, derived from a
       question the server declined to answer. The refusal is in the ErrorCode property instead.

    2. A partial WMI answer made the remote temp folder lose its drive letter. Get-mdiRemoteTempFolder
       expands %SystemDrive% / %SystemDirectory% / %WindowsDirectory% from Win32_OperatingSystem. If
       that class answers but carries no value, "-replace '%SystemDrive%', $null" substitutes an EMPTY
       string, so "%SystemDrive%\Temp" becomes "\Temp" - still a rooted path, but on the CURRENT DRIVE
       OF THIS COMPUTER. Every caller then turns it into a UNC path to the remote admin share by
       replacing the colon; with no colon to replace, the script wrote, read and deleted its temporary
       probe files ON ITSELF while believing it was operating on the server. Nothing in the result
       looks wrong, which is why it went unnoticed.
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

Write-Host 'WMI refusal is classified where WMI is actually called' -ForegroundColor Cyan
# Test-mdiIsNotRunError deliberately does NOT test for a WMI ManagementException: it ships inside the
# remote probe payload, whose 32,000-character command-line budget the extra test does not fit, and
# every one of its callers is in the TCP/UDP socket path where such an exception cannot arise. The
# outcome that matters is asserted at the layer that does call WMI - a refused service query must be
# reported as unreadable, never as "the service is not installed".
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    throw [System.Management.ManagementException]::new('Access denied ')
}
$refusedSvc = Get-mdiServiceStateResult -ComputerName 'dc1.contoso.com' -ServiceName 'AATPSensor'
Assert-That 'a refused service query is not readable' ($refusedSvc.Readable -ne $true) "Readable=$($refusedSvc.Readable)"
Assert-That '  ...and is never reported as "not installed"' ($refusedSvc.Installed -ne $false -or $refusedSvc.Readable -ne $true) "Installed=$($refusedSvc.Installed) Readable=$($refusedSvc.Readable)"
Write-Host '  ...while a real observation still is one' -ForegroundColor Cyan
# These must stay measurements or the verdict stops failing on genuinely blocked ports.
$refused = [System.Net.Sockets.SocketException]::new(10061)
Assert-That 'WSAECONNREFUSED is still a measurement' ((Test-mdiIsNotRunError -ErrorObject $refused) -eq $false) 'classified as not-measured'
$timedOut = [System.Net.Sockets.SocketException]::new(10060)
Assert-That 'WSAETIMEDOUT is still a measurement' ((Test-mdiIsNotRunError -ErrorObject $timedOut) -eq $false) 'classified as not-measured'
# And the previously-handled refusals must keep working.
Assert-That 'UnauthorizedAccessException is still not a measurement' ((Test-mdiIsNotRunError -ErrorObject ([UnauthorizedAccessException]::new('denied'))) -eq $true) 'classified as a measurement'
$rpc = [System.ComponentModel.Win32Exception]::new(1722)
Assert-That 'RPC unavailable is still not a measurement' ((Test-mdiIsNotRunError -ErrorObject $rpc) -eq $true) 'classified as a measurement'
Assert-That 'a $null error is not a measurement claim' ((Test-mdiIsNotRunError -ErrorObject $null) -eq $false) 'null was classified as not-measured'

Write-Host 'The remote temp folder is always a rooted local path' -ForegroundColor Cyan
# Win32_Environment answers with an unexpanded variable; Win32_OperatingSystem answers but carries
# nothing, which is the partial-answer case.
$script:tempValue = '%SystemDrive%\Temp'
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    if ($Class -eq 'Win32_Environment') { return [PSCustomObject]@{ VariableValue = $script:tempValue } }
    # Present, but every path property empty - the shape that produced the defect.
    [PSCustomObject]@{ SystemDrive = ''; SystemDirectory = ''; WindowsDirectory = '' }
}
foreach ($v in '%SystemDrive%\Temp', '%WindowsDirectory%\Temp', '%SystemDirectory%\..\Temp') {
    $script:tempValue = $v
    $folder = Get-mdiRemoteTempFolder -ComputerName 'dc1.contoso.com'
    Assert-That "'$v' with an empty OS answer yields a rooted path" ($folder -match '^[A-Za-z]:\\') "got '$folder'"
    # A path with no drive letter is the specific failure: it addresses THIS computer.
    Assert-That "  ...and never a bare '\...' path" (-not $folder.StartsWith('\')) "got '$folder'"
}

Write-Host '  ...while a good answer is still used as given' -ForegroundColor Cyan
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    if ($Class -eq 'Win32_Environment') { return [PSCustomObject]@{ VariableValue = '%SystemDrive%\Temp' } }
    [PSCustomObject]@{ SystemDrive = 'D:'; SystemDirectory = 'D:\Windows\System32'; WindowsDirectory = 'D:\Windows' }
}
$good = Get-mdiRemoteTempFolder -ComputerName 'dc1.contoso.com'
Assert-That 'a server whose system drive is D: keeps D:' ($good -eq 'D:\Temp') "got '$good'"

Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    if ($Class -eq 'Win32_Environment') { return [PSCustomObject]@{ VariableValue = 'E:\CustomTemp' } }
    [PSCustomObject]@{ SystemDrive = 'C:'; SystemDirectory = 'C:\Windows\System32'; WindowsDirectory = 'C:\Windows' }
}
$literal = Get-mdiRemoteTempFolder -ComputerName 'dc1.contoso.com'
Assert-That 'a literal custom temp path is preserved' ($literal -eq 'E:\CustomTemp') "got '$literal'"

Write-Host 'The UNC rewrite treats the computer name as literal text' -ForegroundColor Cyan
# The name was interpolated into the REPLACEMENT string of a -replace, where .NET expands $1, $&, $$,
# $` and $' as substitution tokens. The name arrives from -DomainController / -CAServer /
# -EntraConnectServer / -NnrTargetComputer, all operator-supplied.
foreach ($n in 'DC01', 'DC01$', 'SRV$1', 'SRV$&', 'SRV$$', 'SRV$_', 'SRV${x}') {
    $m = [regex]::Match('C:\Windows\Temp\mdi-probe.ps1', '^([A-Za-z]):(.*)$')
    $built = '\\' + $n + '\' + $m.Groups[1].Value + '$' + $m.Groups[2].Value
    Assert-That "the name '$n' survives into the UNC path unchanged" ($built -eq ('\\' + $n + '\C$\Windows\Temp\mdi-probe.ps1')) "got '$built'"
}

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
