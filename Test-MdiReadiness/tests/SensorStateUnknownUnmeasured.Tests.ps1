<#
    "Unknown" is the service control manager's way of saying it could not determine a value. It is the
    absence of a reading, not a reading of "not running".

    Get-mdiSensorHealth tested the sensor and updater with `-ne 'Running'` and `-ne 'Auto'`, which
    collapse "could not determine" into "wrong". An undetermined state therefore produced
    isSensorHealthOk = $false - a MEASURED failure, a High finding, a red HTML row and a place in the
    readiness score - built on a query that produced no answer.

    It was then erased from the advisory too. Test-mdiSensorIssueFixable is a denylist keyed on the
    text 'is not installed', so "The AATPSensor service is Unknown" was classified FIXABLE, marked as
    covered by the remediation generator, and dropped from the outstanding list - while the code the
    generator actually emits is only Set-Service/Start-Service, which cannot resolve a state nobody
    could read. The generated script then closed "Remediation complete."

    The distinction that matters, and that these tests pin down: Paused, Pause Pending and the other
    transitional tokens are REAL, determinate states in which the sensor is genuinely not running, so
    they must remain measured failures. Only the token meaning "no answer" belongs on the unmeasured
    path - the same path this function already uses when WMI or the service list cannot be read.
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

# WMI reachability is established by Win32_OperatingSystem, so that has to answer for the function to
# reach the service logic at all.
function global:Get-WmiObject {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2022 Standard' }
}
$script:sensorSvc = $null
$script:updaterSvc = $null
Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
    param($ComputerName, $ServiceName)
    $svc = if ($ServiceName -eq 'AATPSensor') { $script:sensorSvc } else { $script:updaterSvc }
    [PSCustomObject]@{ Service = $svc; Readable = $true; Error = $null }
}
function Get-Health {
    param([string] $SensorState, [string] $SensorMode, [string] $UpdaterState, [string] $UpdaterMode)
    $script:sensorSvc = [PSCustomObject]@{ State = $SensorState; StartMode = $SensorMode }
    $script:updaterSvc = [PSCustomObject]@{ State = $UpdaterState; StartMode = $UpdaterMode }
    Get-mdiSensorHealth -ComputerName 'dc1.contoso.com'
}

Write-Host 'The controls: real states are still measured, and still judged the same way' -ForegroundColor Cyan
$healthy = Get-Health -SensorState 'Running' -SensorMode 'Auto' -UpdaterState 'Running' -UpdaterMode 'Auto'
Assert-That 'a fully running sensor passes' ($healthy.isSensorHealthOk -eq $true) "got '$($healthy.isSensorHealthOk)'"
Assert-That '  ...as a measured result' ($healthy.details.Detail -notlike 'Not tested*') "got '$($healthy.details.Detail)'"

$stopped = Get-Health -SensorState 'Stopped' -SensorMode 'Auto' -UpdaterState 'Running' -UpdaterMode 'Auto'
Assert-That 'a STOPPED sensor is still a measured failure' ($stopped.isSensorHealthOk -eq $false) "got '$($stopped.isSensorHealthOk)'"
Assert-That '  ...and names the state' ($stopped.details.Detail -like '*Stopped*') "got '$($stopped.details.Detail)'"

# These are determinate states in which the service is genuinely not running. The fix must NOT
# quietly reclassify them as unmeasured - that would hide real failures.
foreach ($s in 'Paused', 'Pause Pending', 'Start Pending', 'Stop Pending', 'Continue Pending') {
    $r = Get-Health -SensorState $s -SensorMode 'Auto' -UpdaterState 'Running' -UpdaterMode 'Auto'
    Assert-That "'$s' is still a MEASURED failure" ($r.isSensorHealthOk -eq $false) "got '$($r.isSensorHealthOk)'"
    Assert-That "  ...and is not routed to 'Not tested'" ($r.details.Detail -notlike 'Not tested*') "got '$($r.details.Detail)'"
}

$disabled = Get-Health -SensorState 'Running' -SensorMode 'Disabled' -UpdaterState 'Running' -UpdaterMode 'Auto'
Assert-That 'a Disabled start mode is still a measured failure' ($disabled.isSensorHealthOk -eq $false) "got '$($disabled.isSensorHealthOk)'"

Write-Host "An 'Unknown' service state is unmeasured, never a measured failure" -ForegroundColor Cyan
$cases = @(
    @{ Name = 'sensor state Unknown'; SS = 'Unknown'; SM = 'Auto'; US = 'Running'; UM = 'Auto' }
    @{ Name = 'sensor start mode Unknown'; SS = 'Running'; SM = 'Unknown'; US = 'Running'; UM = 'Auto' }
    @{ Name = 'updater state Unknown'; SS = 'Running'; SM = 'Auto'; US = 'Unknown'; UM = 'Auto' }
    @{ Name = 'updater start mode Unknown'; SS = 'Running'; SM = 'Auto'; US = 'Running'; UM = 'Unknown' }
    @{ Name = 'both states Unknown'; SS = 'Unknown'; SM = 'Auto'; US = 'Unknown'; UM = 'Auto' }
)
foreach ($c in $cases) {
    $r = Get-Health -SensorState $c.SS -SensorMode $c.SM -UpdaterState $c.US -UpdaterMode $c.UM
    Assert-That "$($c.Name): the check is the tri-state 'N/A'" ([string] $r.isSensorHealthOk -eq 'N/A') "got '$($r.isSensorHealthOk)'"
    # The 'Not tested - ' prefix is the convention that routes a result to the unmeasured population.
    Assert-That "  ...and the detail marks it as not tested" ($r.details.Detail -like 'Not tested*') "got '$($r.details.Detail)'"
    # Installed must not be asserted either: the service list answered, but not usefully.
    Assert-That "  ...and Installed is not claimed as a fact" ([string] $r.details.Installed -eq 'N/A') "got '$($r.details.Installed)'"
    # And it must never reach the issue list as a fixable service problem.
    $issueText = [string] $r.details.Issues
    Assert-That "  ...and no 'service is Unknown' issue is raised" ($issueText -notlike '*is Unknown*') "got '$issueText'"
}

Write-Host 'Test-mdiCheckFailed agrees that an undetermined sensor is not a failure' -ForegroundColor Cyan
# This is what keeps it out of the readiness score and the remediation script.
$unknown = Get-Health -SensorState 'Unknown' -SensorMode 'Auto' -UpdaterState 'Running' -UpdaterMode 'Auto'
Assert-That 'an undetermined sensor is not counted as a failed check' `
((Test-mdiCheckFailed -Value $unknown.isSensorHealthOk) -eq $false) "got '$(Test-mdiCheckFailed -Value $unknown.isSensorHealthOk)'"
$reallyStopped = Get-Health -SensorState 'Stopped' -SensorMode 'Auto' -UpdaterState 'Running' -UpdaterMode 'Auto'
Assert-That '  ...while a genuinely stopped sensor still is' `
((Test-mdiCheckFailed -Value $reallyStopped.isSensorHealthOk) -eq $true) "got '$(Test-mdiCheckFailed -Value $reallyStopped.isSensorHealthOk)'"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
