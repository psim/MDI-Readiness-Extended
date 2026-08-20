<#
    SensorStateThatWasReadSurvivesTheMerge.Tests.ps1

    Pins defect 299.

    THE DEFECT THIS TEST EXISTS TO CATCH

    When one physical server is discovered under more than one role - a certification authority
    running on a domain controller, which Merge-mdiServerByFqdn's own header calls routine in a small
    environment - the role rows are merged into a single host row. Merge-mdiSensorV3ReadyDetails
    merges the v3.x sensor blob, and picks one role's scalar facts with $scalarWinner, chosen by
    which role has more authority over the v3.x VERDICT.

    That ranking deliberately places a role that could NOT be read ABOVE a role that read everything.
    The producer emits a tri-state verdict - $false when there are blockers, 'N/A' when something
    needed was unreadable, $true when everything was read and passed - and Get-mdiCheckDetailRank
    scores those $false -> 2, 'N/A' -> 1, $true -> 0. Higher wins. That is correct and intended FOR
    THE VERDICT: a server whose checks could not be read must not be reported as ready.

    SensorState used to ride that same winner, and it is not that kind of fact.

    The role that could not be queried does not hold a dissenting opinion about the sensor; it holds
    its own admission that it never looked. The producer writes that admission out in words:

        'Not determined (the server could not be queried)'
        'Not determined (the installed services could not be read on this server)'

    So on a two-role host the blind role outranked the sighted one, 1 beating 0, and the merged host
    reported a sensor state nobody had read - discarding the state the other role HAD read, in both
    merge orders, for both not-determined branches. That value is rendered straight into the
    customer's report, so the operator was told the sensor state of a machine was undetermined on a
    machine where it had in fact been measured.

    The neighbouring SensorV2Version had been defended against precisely this since it was written,
    with the principle stated in its comment: a version that was read beats one that was not, because
    that is a fact about the machine one pass simply failed to collect, not two passes disagreeing.
    SensorState is the same kind of fact, in the same merge, and carried no such guard. The two
    facts, side by side in one function, answered the question differently.

    THE FIX THIS TEST PINS

    SensorState now takes the same fallback, recognising "text that is an admission nothing was read"
    with the pattern the project already uses for it. The winner keeps its state unless that state
    was never read AND the loser's state was. So an unread value is never promoted over a read one,
    and - the over-correction this test also guards - a merge of two blind roles still reports the
    blind explanation rather than collapsing to blank.

    A test that stays green when the bug returns is worthless: restoring
    `SensorState = $scalarWinner.SensorState` must turn this file red.
#>

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path -LiteralPath $target)) {
    $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
}
if (-not (Test-Path -LiteralPath $target)) { throw 'Test-MdiReadiness.ps1 not found beside or above the tests folder.' }

$body = [IO.File]::ReadAllText($target)
$body = $body -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main')
if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
. ([scriptblock]::Create($body))

$script:pass = 0
$script:fail = 0
function Assert-True {
    param ([string] $Name, [bool] $Condition, $Got)
    if ($Condition) {
        $script:pass++
        Write-Host ('  PASS  {0}' -f $Name) -ForegroundColor DarkGray
    } else {
        $script:fail++
        Write-Host ('  FAIL  {0} (got: {1})' -f $Name, $Got) -ForegroundColor Red
    }
}

# The exact strings the v3 blob producer emits.
$stateRunning = 'v2.x sensor running'
$stateNoSensor = 'No Defender for Identity sensor detected'
$stateNotRunning = 'v2.x sensor installed but not running'
$blindQueried = 'Not determined (the server could not be queried)'
$blindServices = 'Not determined (the installed services could not be read on this server)'

function New-V3RoleDetail {
    param ([string] $Tag, $SensorState, [string] $V2Version = '2.243')
    [pscustomobject]@{
        SensorState        = $SensorState
        SensorV2Version    = $V2Version
        MigrationEligible  = 'N/A'
        Blockers           = @()
        ActionableBlockers = @()
        UnknownChecks      = @()
        Checks             = @(
            [pscustomobject]@{ Name = "check-$Tag"; Success = $true; Requirement = 'Required'; Detail = "measured by $Tag" }
        )
    }
}

Write-Host 'SensorStateThatWasReadSurvivesTheMerge' -ForegroundColor Cyan

# The ranks are read from the shipped ranker rather than hard-coded, so that if the tri-state scoring
# is ever changed this test exercises the pairing that actually occurs instead of a stale one.
$rankRead = [int] (Get-mdiCheckDetailRank -Value $true)
$rankBlind = [int] (Get-mdiCheckDetailRank -Value 'N/A')
Assert-True -Name 'the producer''s unreadable verdict still outranks its measured pass (the pairing this defect needs)' `
    -Condition ($rankBlind -gt $rankRead) -Got ('read={0} blind={1}' -f $rankRead, $rankBlind)

Write-Host ' a state that was read survives a higher-ranked role that never looked' -ForegroundColor Cyan
foreach ($readState in @($stateRunning, $stateNoSensor, $stateNotRunning)) {
    foreach ($blindState in @($blindQueried, $blindServices)) {
        $sighted = New-V3RoleDetail -Tag 'sighted' -SensorState $readState
        $blind = New-V3RoleDetail -Tag 'blind' -SensorState $blindState

        $sightedFirst = Merge-mdiSensorV3ReadyDetails -First $sighted -Second $blind -FirstRank $rankRead -SecondRank $rankBlind
        Assert-True -Name ('"{0}" survives "{1}" (sighted first)' -f $readState, $blindState.Substring(0, 18)) `
            -Condition ([string] $sightedFirst.SensorState -eq $readState) -Got $sightedFirst.SensorState

        $blindFirst = Merge-mdiSensorV3ReadyDetails -First $blind -Second $sighted -FirstRank $rankBlind -SecondRank $rankRead
        Assert-True -Name ('"{0}" survives "{1}" (blind first)' -f $readState, $blindState.Substring(0, 18)) `
            -Condition ([string] $blindFirst.SensorState -eq $readState) -Got $blindFirst.SensorState
    }
}

Write-Host ' an absent state falls back to the role that recorded one' -ForegroundColor Cyan
foreach ($emptyState in @($null, '', '   ')) {
    $sighted = New-V3RoleDetail -Tag 'sighted' -SensorState $stateRunning
    $empty = New-V3RoleDetail -Tag 'empty' -SensorState $emptyState
    $merged = Merge-mdiSensorV3ReadyDetails -First $sighted -Second $empty -FirstRank $rankRead -SecondRank $rankBlind
    Assert-True -Name ('an unpopulated state does not blank the merged host (shape: {0})' -f $(if ($null -eq $emptyState) { 'null' } elseif ($emptyState -eq '') { 'empty' } else { 'whitespace' })) `
        -Condition ([string] $merged.SensorState -eq $stateRunning) -Got ('"{0}"' -f $merged.SensorState)
}

Write-Host ' the guard does not over-correct' -ForegroundColor Cyan
# Two roles that both failed to look must still explain themselves. Falling back unconditionally
# would report a blank cell here, which is a worse answer than the honest admission.
$blindA = New-V3RoleDetail -Tag 'blinda' -SensorState $blindQueried
$blindB = New-V3RoleDetail -Tag 'blindb' -SensorState $blindServices
$bothBlind = Merge-mdiSensorV3ReadyDetails -First $blindA -Second $blindB -FirstRank $rankBlind -SecondRank $rankBlind
Assert-True -Name 'two roles that both failed to look still report an explanation, not a blank' `
    -Condition (-not [string]::IsNullOrWhiteSpace([string] $bothBlind.SensorState)) -Got ('"{0}"' -f $bothBlind.SensorState)

# Rank semantics are untouched for states that WERE read: the more authoritative role still speaks.
$measuredLow = New-V3RoleDetail -Tag 'low' -SensorState $stateRunning
$measuredHigh = New-V3RoleDetail -Tag 'high' -SensorState $stateNotRunning
$ranked = Merge-mdiSensorV3ReadyDetails -First $measuredLow -Second $measuredHigh -FirstRank 0 -SecondRank 2
Assert-True -Name 'between two states that were BOTH read, the higher-ranked role still wins' `
    -Condition ([string] $ranked.SensorState -eq $stateNotRunning) -Got $ranked.SensorState

Write-Host ' the neighbouring facts are unbroken' -ForegroundColor Cyan
$sighted = New-V3RoleDetail -Tag 'sighted' -SensorState $stateRunning -V2Version '2.243'
$blindNoVersion = New-V3RoleDetail -Tag 'blind' -SensorState $blindQueried -V2Version ''
$neighbour = Merge-mdiSensorV3ReadyDetails -First $sighted -Second $blindNoVersion -FirstRank $rankRead -SecondRank $rankBlind
Assert-True -Name 'SensorV2Version that was read still survives (the guard this fix was modelled on)' `
    -Condition ([string] $neighbour.SensorV2Version -eq '2.243') -Got $neighbour.SensorV2Version
Assert-True -Name 'both roles'' checks still survive the union' `
    -Condition (@($neighbour.Checks).Count -eq 2) -Got @($neighbour.Checks).Count

$nullSecond = Merge-mdiSensorV3ReadyDetails -First $sighted -Second $null -FirstRank $rankRead -SecondRank -1
Assert-True -Name 'a blob merged against nothing is returned intact' `
    -Condition ([string] $nullSecond.SensorState -eq $stateRunning) -Got $nullSecond.SensorState

Write-Host ('pass={0} fail={1}' -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
