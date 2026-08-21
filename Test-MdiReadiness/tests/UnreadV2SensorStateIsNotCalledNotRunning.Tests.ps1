<#
    A v2.x sensor STATE that was never read must not be published as "installed but not running".

    Get-mdiSensorV3Readiness ends by composing SensorState, the one sentence the report and the JSON
    export give about the Defender for Identity v2.x sensor on a server. It decided the sentence with
    a bare comparison:

        elseif ($hasV2Sensor -and $v2ServiceState -ne 'Running') { 'v2.x sensor installed but not running' }

    where $v2ServiceState is a plain [string] cast of Win32_Service.State. Every way of NOT having a
    state satisfies "-ne 'Running'". The service control manager returns the literal token 'Unknown'
    when it could not determine a service's state, and WMI can answer a query without carrying the
    property at all, leaving it null, empty or whitespace. All four therefore produced the DEFINITE,
    measured sentence "v2.x sensor installed but not running" about a service whose state nobody had
    established - and UnknownChecks came back EMPTY, so nothing else on the page disclosed the gap.

    Measured on the shipped function against a domain controller readable in every other respect
    (WS2022 build 20348 past the July 2026 revision, Sense running under Auto, MDE onboarded, no
    identity roles, no capture driver) so that neither of the earlier "Not determined" branches could
    mask the result: 4 of 4 unread shapes published the definite sentence.

    For the 'Unknown' token the same run then contradicted itself. Get-mdiSensorHealth, reading the
    SAME AATPSensor service on the SAME server, returned isSensorHealthOk = 'N/A' and "the service
    control manager did not report the AATPSensor service state ... so the sensor state could not be
    determined". One service, one server, one run, two opposite claims - the identical defect the
    Sense check in this very function had already been fixed for, via Test-mdiServiceTokenKnown, and
    which the v2.x line was never converted to use.

    THE SAME RULE AT ITS SECOND CALL SITE. Get-mdiSensorHealth routed an undetermined service to its
    unmeasured path with a bare `-eq 'Unknown'`, catching only one of the two shapes that mean "no
    answer". A service object present but carrying no State rendered to '', skipped the undetermined
    block entirely, and produced isSensorHealthOk = $false with the malformed issue "The AATPSensor
    service is  (start mode: Auto)" - a measured failure, from a property nobody read. Both call
    sites now go through Test-mdiServiceTokenKnown, whose docblock names both shapes.

    WHAT MUST NOT REGRESS: determinate states stay determinate. Stopped, Paused and the transitional
    tokens are real readings in which the sensor genuinely is not running, and must keep producing
    the definite sentence and a measured failure.

    Behavioural: drives the shipped Get-mdiSensorV3Readiness and Get-mdiSensorHealth and reads what
    they published.
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

# A domain controller readable in every respect EXCEPT the one token under test. Anything less and
# the "Not determined (the server could not be queried)" branch above answers instead, and this file
# would measure nothing.
Set-Item -Path function:script:Get-WmiObject -Value {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
    [PSCustomObject]@{ Version = '10.0.20348'; Caption = 'Windows Server 2022'; ProductType = 2; BuildNumber = '20348' }
}
Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value {
    param($ComputerName, $Key, $Value)
    [PSCustomObject]@{ Readable = $true; Value = $(if ($Value -eq 'UBR') { 99999 } else { 1 }); Error = $null }
}
Set-Item -Path function:script:Get-mdiCaptureComponent -Value { param($ComputerName) '' }

$script:v2State = 'Running'
$script:v2HasState = $true
$script:v2StartMode = 'Auto'
$script:updState = 'Running'
$script:updHasState = $true
$script:updStartMode = 'Auto'
Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
    param($ComputerName, $ServiceName)
    # Only Sense and the two AATP services exist. The identity-role services must stay ABSENT or the
    # server is disqualified for a reason unrelated to the state token under test.
    #
    # The sensor and the updater are driven INDEPENDENTLY on purpose. Get-mdiSensorHealth guards the
    # two services with four separate tests, and a fixture that blanks both at once passes whenever
    # ANY one of the four is right - which is how a test can stay green while the defect is back in
    # three of them. Each guard is pinned by a case that leaves the other service fully readable.
    if ($ServiceName -in 'Sense', 'AATPSensor', 'AATPSensorUpdater') {
        $svc = [PSCustomObject]@{ Name = $ServiceName; PathName = 'C:\x.exe' }
        if ($ServiceName -eq 'Sense') {
            $svc | Add-Member -NotePropertyName State -NotePropertyValue 'Running'
            $svc | Add-Member -NotePropertyName StartMode -NotePropertyValue 'Auto'
        } elseif ($ServiceName -eq 'AATPSensor') {
            if ($script:v2HasState) { $svc | Add-Member -NotePropertyName State -NotePropertyValue $script:v2State }
            $svc | Add-Member -NotePropertyName StartMode -NotePropertyValue $script:v2StartMode
        } else {
            if ($script:updHasState) { $svc | Add-Member -NotePropertyName State -NotePropertyValue $script:updState }
            $svc | Add-Member -NotePropertyName StartMode -NotePropertyValue $script:updStartMode
        }
        return [PSCustomObject]@{ Readable = $true; Service = $svc; Error = $null }
    }
    [PSCustomObject]@{ Readable = $true; Service = $null; Error = $null }
}

function Get-Published {
    param(
        $State, [switch] $NoStateProperty,
        $UpdaterState = 'Running', [switch] $NoUpdaterStateProperty,
        $StartMode = 'Auto', $UpdaterStartMode = 'Auto'
    )
    $script:v2State = $State
    $script:v2HasState = -not $NoStateProperty
    $script:v2StartMode = $StartMode
    $script:updState = $UpdaterState
    $script:updHasState = -not $NoUpdaterStateProperty
    $script:updStartMode = $UpdaterStartMode
    $r = Get-mdiSensorV3Readiness -ComputerName 'dcfab01.fabrikam.local' -SensorVersion '2.254.19112.470'
    $h = Get-mdiSensorHealth -ComputerName 'dcfab01.fabrikam.local'
    [PSCustomObject]@{
        SensorState  = [string] $r.details.SensorState
        HealthOk     = [string] $h.isSensorHealthOk
        HealthDetail = [string] $h.details.Detail
    }
}

$definite = 'v2.x sensor installed but not running'

Write-Host "`n[1] CONTROLS - a state that WAS read still decides the sentence" -ForegroundColor Yellow
$running = Get-Published 'Running'
Assert-That "Running -> 'v2.x sensor running'" ($running.SensorState -eq 'v2.x sensor running') "(got '$($running.SensorState)')"
foreach ($determinate in 'Stopped', 'Paused', 'Start Pending', 'Stop Pending') {
    $r = Get-Published $determinate
    Assert-That "$determinate -> '$definite'" ($r.SensorState -eq $definite) "(got '$($r.SensorState)')"
    Assert-That "  $determinate is still a MEASURED sensor-health failure" ($r.HealthOk -eq 'False') "(got '$($r.HealthOk)')"
}

Write-Host "`n[2] THE DEFECT - an unread state must not become 'installed but not running'" -ForegroundColor Yellow
# 'Unknown' is the SCM saying it could not determine the state; null/empty/whitespace is WMI
# answering without the property. Neither is a measurement.
foreach ($shape in @(
        @{ Label = "the SCM's 'Unknown' token"; State = 'Unknown'; NoProp = $false },
        @{ Label = 'the State property absent'; State = $null; NoProp = $true },
        @{ Label = 'an empty State'; State = ''; NoProp = $false },
        @{ Label = 'a whitespace State'; State = '   '; NoProp = $false })) {
    $r = if ($shape.NoProp) { Get-Published $shape.State -NoStateProperty } else { Get-Published $shape.State }
    Assert-That "$($shape.Label): does NOT publish '$definite'" ($r.SensorState -ne $definite) "(got '$($r.SensorState)')"
    Assert-That "  $($shape.Label): does not claim the sensor is running either" ($r.SensorState -ne 'v2.x sensor running') "(got '$($r.SensorState)')"
    # The merge in Merge-mdiSensorV3ReadyDetails recognises an unread SensorState by this prefix, so
    # the sentence has to carry it or a real reading from the other pass will lose to this one.
    Assert-That "  $($shape.Label): marked unread for the merge (^Not determined)" ($r.SensorState -match $script:mdiPortNotTestedPattern) "(got '$($r.SensorState)')"
}

Write-Host "`n[3] THE TWO SURFACES MUST AGREE ABOUT THE SAME SERVICE" -ForegroundColor Yellow
foreach ($shape in @(
        @{ Label = "'Unknown'"; State = 'Unknown'; NoProp = $false },
        @{ Label = 'absent State property'; State = $null; NoProp = $true },
        @{ Label = 'empty State'; State = ''; NoProp = $false })) {
    $r = if ($shape.NoProp) { Get-Published $shape.State -NoStateProperty } else { Get-Published $shape.State }
    Assert-That "$($shape.Label): Get-mdiSensorHealth answers N/A" ($r.HealthOk -eq 'N/A') "(got '$($r.HealthOk)')"
    Assert-That "  $($shape.Label): its detail is a 'Not tested' sentence" ($r.HealthDetail -match '^Not tested') "(got '$($r.HealthDetail)')"
    # The malformed sentence the blank shape used to publish, verbatim.
    Assert-That "  $($shape.Label): no 'The AATPSensor service is  (start mode' sentence" ($r.HealthDetail -notmatch 'The AATPSensor service is\s+\(start mode') "(got '$($r.HealthDetail)')"
    Assert-That "  $($shape.Label): the two surfaces do not contradict each other" (($r.HealthOk -eq 'N/A') -and ($r.SensorState -ne $definite))
}

Write-Host "`n[3b] EACH of the four sensor-health guards, pinned on its own" -ForegroundColor Yellow
# One case per guard, with every OTHER service and property left fully readable. Without this a
# single surviving guard answers for all four and the file goes green with the defect back in three.
$guards = @(
    @{ Label = 'AATPSensor state = Unknown'; Args = @{ State = 'Unknown' } },
    @{ Label = 'AATPSensor state absent'; Args = @{ State = $null; NoStateProperty = $true } },
    @{ Label = 'AATPSensor start mode = Unknown'; Args = @{ State = 'Running'; StartMode = 'Unknown' } },
    @{ Label = 'AATPSensor start mode blank'; Args = @{ State = 'Running'; StartMode = '' } },
    @{ Label = 'AATPSensorUpdater state = Unknown'; Args = @{ State = 'Running'; UpdaterState = 'Unknown' } },
    @{ Label = 'AATPSensorUpdater state absent'; Args = @{ State = 'Running'; NoUpdaterStateProperty = $true } },
    @{ Label = 'AATPSensorUpdater start mode = Unknown'; Args = @{ State = 'Running'; UpdaterStartMode = 'Unknown' } },
    @{ Label = 'AATPSensorUpdater start mode blank'; Args = @{ State = 'Running'; UpdaterStartMode = '' } }
)
foreach ($guard in $guards) {
    $splat = $guard.Args
    $r = Get-Published @splat
    Assert-That "$($guard.Label) -> isSensorHealthOk is N/A" ($r.HealthOk -eq 'N/A') "(got '$($r.HealthOk)' / '$($r.HealthDetail)')"
}
# CONTROL for [3b]: with all four readable the function must still reach its normal verdict, or the
# assertions above would pass simply because nothing can ever be measured.
$allGood = Get-Published 'Running'
Assert-That 'CONTROL: all four readable -> a measured verdict, not N/A' ($allGood.HealthOk -ne 'N/A') "(got '$($allGood.HealthOk)')"

Write-Host "`n[4] The rule is the shared one, not a second copy" -ForegroundColor Yellow
Assert-That "the shared predicate rejects 'Unknown'" ((Test-mdiServiceTokenKnown -Token 'Unknown') -eq $false)
Assert-That '  rejects null' ((Test-mdiServiceTokenKnown -Token $null) -eq $false)
Assert-That '  rejects whitespace' ((Test-mdiServiceTokenKnown -Token '   ') -eq $false)
Assert-That "  accepts 'Stopped'" ((Test-mdiServiceTokenKnown -Token 'Stopped') -eq $true)

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
