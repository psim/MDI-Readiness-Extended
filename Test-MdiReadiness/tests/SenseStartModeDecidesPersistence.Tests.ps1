<#
    A Sense service that will not survive a reboot is not a passing check.

    The v3 check "Defender for Endpoint (Sense) service is running" read the service's StartMode,
    printed it in its own Detail, and then never used it. So a Sense service Running under start mode
    Disabled - or Manual - was a green PASS whose own sentence read "(start mode: Disabled)".

    That service does not come back after a reboot. Defender for Endpoint onboarding lapses at the
    next restart, and the report called the server ready.

    The contradiction was internal: Get-mdiSensorHealth already FAILS the identical configuration on
    the sensor service - "The AATPSensor service start mode is Manual, not Auto; it will not start
    after a reboot" - so the same two tokens produced a pass on one surface and a failure on the
    other, in the same run, for the same machine. Measured by holding State at Running and sweeping
    StartMode across every token Win32_Service can carry: the Sense verdict never moved once.

    What a fix must NOT break, asserted here as controls:
      * Running + Auto must remain a measured PASS;
      * a service that is not running must remain a measured FAILURE whatever its start mode - a
        definite failure outranks an unreadable start mode;
      * a genuinely absent service must remain a measured FAILURE;
      * an UNREADABLE state or start mode must be 'N/A', never a failure - the service control
        manager's 'Unknown' token and a property WMI never carried are gaps, not findings.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = [IO.File]::ReadAllText([IO.Path]::GetFullPath($target))
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main'); if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body

Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    [PSCustomObject]@{ Version = '10.0.20348'; Caption = 'Windows Server 2022'; ProductType = 2; BuildNumber = '20348' }
}
Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value {
    param($ComputerName, $Key, $Value)
    [PSCustomObject]@{ Readable = $true; Value = $(if ($Value -eq 'UBR') { 99999 } else { 1 }); Error = $null }
}
Set-Item -Path function:script:Get-mdiSensorHealth -Value { param($ComputerName) [PSCustomObject]@{ Readable = $true; Running = $true } }
Set-Item -Path function:script:Get-mdiCaptureComponent -Value { param($ComputerName) 'N/A' }

# ONLY Sense exists. adfssrv / CertSvc / ADSync must be ABSENT or the server is disqualified for an
# identity role and this file measures something else entirely.
$script:senseState = 'Running'
$script:senseStartMode = 'Auto'
$script:sensePresent = $true
Set-Item -Path function:script:Get-mdiServiceState -Value {
    param($ComputerName, $ServiceName)
    if ($ServiceName -eq 'Sense' -and $script:sensePresent) {
        return [PSCustomObject]@{ Name = $ServiceName; State = $script:senseState; StartMode = $script:senseStartMode }
    }
    $null
}
Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
    param($ComputerName, $ServiceName)
    if ($ServiceName -eq 'Sense' -and $script:sensePresent) {
        return [PSCustomObject]@{ Readable = $true; Error = $null
            Service = [PSCustomObject]@{ Name = $ServiceName; State = $script:senseState; StartMode = $script:senseStartMode } }
    }
    [PSCustomObject]@{ Readable = $true; Service = $null; Error = $null }
}

$checkName = 'Defender for Endpoint (Sense) service is running'
function Get-SenseCheck {
    param($State, $StartMode, [switch] $Absent)
    $script:senseState = $State; $script:senseStartMode = $StartMode; $script:sensePresent = -not $Absent
    $r = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com'
    $chk = @($r.details.Checks) | Where-Object { $_.Name -eq $checkName }
    [PSCustomObject]@{ Status = $chk.Status; Measured = $chk.Measured; Detail = [string] $chk.Detail }
}

Write-Host "`n[1] Control: only Running + Auto is a pass" -ForegroundColor Yellow
$r = Get-SenseCheck 'Running' 'Auto'
Assert-That 'Running/Auto is a measured pass' ($r.Status -is [bool] -and $r.Status -eq $true) "(got '$($r.Status)')"

Write-Host "`n[2] Running but not persistent is a measured FAILURE" -ForegroundColor Yellow
foreach ($mode in 'Disabled', 'Manual') {
    $r = Get-SenseCheck 'Running' $mode
    Assert-That "Running/$mode is a measured failure" ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"
    Assert-That "  Running/$mode is not a silent pass" ($r.Status -ne $true)
    Assert-That "  Running/$mode explains the reboot consequence" ($r.Detail -match 'will not start after a reboot') "(detail='$($r.Detail)')"
}

Write-Host "`n[3] StartMode actually moves the verdict (it used to be inert)" -ForegroundColor Yellow
$auto = Get-SenseCheck 'Running' 'Auto'
$disabled = Get-SenseCheck 'Running' 'Disabled'
Assert-That 'the same State with a different StartMode reaches a different verdict' `
([string] $auto.Status -ne [string] $disabled.Status) "(auto='$($auto.Status)' disabled='$($disabled.Status)')"

Write-Host "`n[5] A definite failure outranks an unreadable start mode" -ForegroundColor Yellow
foreach ($mode in 'Auto', 'Disabled', 'Unknown', $null) {
    $r = Get-SenseCheck 'Stopped' $mode
    $shown = if ($null -eq $mode) { '(null)' } else { $mode }
    Assert-That "Stopped/$shown is still a measured failure" ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"
}
$r = Get-SenseCheck 'Running' 'Auto' -Absent
Assert-That 'a genuinely absent service is still a measured failure' ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"

Write-Host "`n[6] An unreadable start mode is unmeasured, never a failure" -ForegroundColor Yellow
foreach ($mode in 'Unknown', $null, '', '   ') {
    $r = Get-SenseCheck 'Running' $mode
    $shown = if ($null -eq $mode) { '(null)' } else { "[$mode]" }
    Assert-That "Running with StartMode $shown is unmeasured" ([string] $r.Status -eq 'N/A') "(got '$($r.Status)')"
    Assert-That "  $shown carries the Not tested convention" ($r.Detail -like 'Not tested*') "(detail='$($r.Detail)')"
}
$r = Get-SenseCheck 'Unknown' 'Auto'
Assert-That 'an unreadable STATE is still unmeasured' ([string] $r.Status -eq 'N/A') "(got '$($r.Status)')"

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
