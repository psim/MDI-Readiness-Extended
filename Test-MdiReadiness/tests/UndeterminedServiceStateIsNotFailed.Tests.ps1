<#
    A Sense service state the SCM could not determine must not become a measured failure.

    Win32_Service returns the literal string 'Unknown' when the service control manager could not
    determine a service's State, and WMI can answer a query without carrying the property at all
    (null/empty). The v3 Sense check computed its verdict as

        $isSenseRunning = if (-not $wmiReadable -or -not $senseReadable) { 'N/A' }
                          else { $senseState -eq 'Running' }

    so 'Unknown' -eq 'Running' produced $false and the report published, as a MEASURED fact:

        Status  = False
        Detail  = "Sense service is Unknown (start mode: Auto) - it must be running"
        Blockers / ActionableBlockers = that sentence
        isSensorV3Ready = False
        UnknownChecks   = []          <-- the gap was not even disclosed

    Get-mdiSensorHealth already refuses to judge that exact token, returning 'N/A' with "the service
    control manager reported ... as Unknown on this server, so the sensor state could not be
    determined". So one server was called unreadable by one check and definitively broken by another,
    from the same tokens - and the Sense failure is Remediable, so it becomes work someone is asked
    to do on a machine nobody could read.

    A null/empty State produced the same measured False with a malformed sentence:
    "Sense service is  (start mode: Auto) - it must be running".

    Behavioural: drives the shipped Get-mdiSensorV3Readiness and reads the check it produced.
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
    [PSCustomObject]@{
        Version = '10.0.20348'; Caption = 'Windows Server 2022'
        ProductType = 2; BuildNumber = '20348'
    }
}
Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value {
    param($ComputerName, $Key, $Value)
    [PSCustomObject]@{ Readable = $true; Value = $(if ($Value -eq 'UBR') { 99999 } else { 1 }); Error = $null }
}
Set-Item -Path function:script:Get-mdiSensorHealth -Value {
    param($ComputerName) [PSCustomObject]@{ Readable = $true; Running = $true }
}
Set-Item -Path function:script:Get-mdiCaptureComponent -Value { param($ComputerName) 'N/A' }

# ONLY Sense exists. The identity-role services (adfssrv, CertSvc, ADSync) must be ABSENT, or every
# server is disqualified for a reason unrelated to the Sense state and this file measures nothing.
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
        return [PSCustomObject]@{
            Readable = $true
            Service  = [PSCustomObject]@{ Name = $ServiceName; State = $script:senseState; StartMode = $script:senseStartMode }
            Error    = $null
        }
    }
    [PSCustomObject]@{ Readable = $true; Service = $null; Error = $null }
}

$checkName = 'Defender for Endpoint (Sense) service is running'
function Get-SenseCheck {
    param($State, $StartMode = 'Auto', [switch] $Absent)
    $script:senseState = $State
    $script:senseStartMode = $StartMode
    $script:sensePresent = -not $Absent
    $r = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com'
    $chk = @($r.details.Checks) | Where-Object { $_.Name -eq $checkName }
    [PSCustomObject]@{
        Status             = $chk.Status
        Measured           = $chk.Measured
        Detail             = [string] $chk.Detail
        ActionableBlockers = @($r.details.ActionableBlockers)
        UnknownChecks      = @($r.details.UnknownChecks)
    }
}

Write-Host "`n[1] Control: determinate states keep their measured verdicts" -ForegroundColor Yellow
$r = Get-SenseCheck 'Running'
Assert-That 'Running is a measured pass' ($r.Status -is [bool] -and $r.Status -eq $true) "(got '$($r.Status)')"
$r = Get-SenseCheck 'Stopped'
Assert-That 'Stopped is a measured failure' ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"
Assert-That '  and is raised as actionable work' (@($r.ActionableBlockers | Where-Object { $_ -like "*$checkName*" }).Count -eq 1) `
    "(blockers=$($r.ActionableBlockers -join ' | '))"
$r = Get-SenseCheck 'StartPending'
Assert-That 'StartPending is still a measured failure' ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"

Write-Host "`n[2] A genuinely absent service is still a measured failure" -ForegroundColor Yellow
$r = Get-SenseCheck 'Running' -Absent
Assert-That 'an answered query with no Sense service reads False' ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"
Assert-That '  and says it is not installed' ($r.Detail -match 'not installed') "(detail='$($r.Detail)')"

Write-Host "`n[3] The SCM's 'Unknown' token is NOT a measured failure" -ForegroundColor Yellow
$r = Get-SenseCheck 'Unknown'
Assert-That "State 'Unknown' is not a measured verdict" ([string] $r.Status -eq 'N/A') "(got '$($r.Status)')"
Assert-That '  it is flagged unmeasured' ($r.Measured -eq $false) "(got '$($r.Measured)')"
Assert-That '  it carries the Not tested convention' ($r.Detail -like 'Not tested*') "(detail='$($r.Detail)')"
Assert-That '  it does NOT claim the service must be running' ($r.Detail -notmatch 'it must be running') "(detail='$($r.Detail)')"
Assert-That '  it raises no actionable work' (@($r.ActionableBlockers | Where-Object { $_ -like "*$checkName*" }).Count -eq 0) `
    "(blockers=$($r.ActionableBlockers -join ' | '))"
Assert-That '  and the gap IS disclosed in UnknownChecks' ($r.UnknownChecks -contains $checkName) `
    "(unknown=$($r.UnknownChecks -join ' | '))"

Write-Host "`n[4] A state WMI never carried is not a measured failure either" -ForegroundColor Yellow
foreach ($blank in $null, '', '   ') {
    $r = Get-SenseCheck $blank
    $shown = if ($null -eq $blank) { '(null)' } else { "[$blank]" }
    Assert-That "State $shown is unmeasured" ([string] $r.Status -eq 'N/A') "(got '$($r.Status)')"
    Assert-That "  $shown produces no malformed sentence" ($r.Detail -notmatch 'Sense service is\s+\(') "(detail='$($r.Detail)')"
    Assert-That "  $shown raises no actionable work" (@($r.ActionableBlockers | Where-Object { $_ -like "*$checkName*" }).Count -eq 0) `
        "(blockers=$($r.ActionableBlockers -join ' | '))"
}

Write-Host "`n[5] The rule agrees with the sibling that already applied it" -ForegroundColor Yellow
Assert-That "the shared predicate rejects 'Unknown'" ((Test-mdiServiceTokenKnown -Token 'Unknown') -eq $false)
Assert-That '  rejects null' ((Test-mdiServiceTokenKnown -Token $null) -eq $false)
Assert-That '  rejects empty' ((Test-mdiServiceTokenKnown -Token '') -eq $false)
Assert-That "  accepts 'Running'" ((Test-mdiServiceTokenKnown -Token 'Running') -eq $true)
Assert-That "  accepts 'Stopped'" ((Test-mdiServiceTokenKnown -Token 'Stopped') -eq $true)

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
