<#
    THE DEFECT THIS TEST PINS

    -MultiForest exists to promote two ports. LdapsTcp (LDAPS 636) and LdapsGcTcp (LDAPS-GC 3269)
    ship Optional, and New-mdiPortProbePlan promotes both to Required when the switch is used,
    because a multi-forest deployment is the case that actually needs them open. That promotion is
    the ENTIRE observable effect of the switch on the port plan.

    But the object the promotion has to reach is not the plan the caller holds. The plan that
    decides the answer is the one that arrives ON THE SENSOR:

        New-mdiPortProbePlan          promotes Requirement to 'Required' on a PSObject.Copy()
        Get-mdiSlimProbePlan          PROJECTS the probes with Select-Object -Property Id, Name,
                                      Protocol, Port, Scope, Group, Requirement - the documentation
                                      fields are deliberately dropped to fit the command line
        Get-mdiPortProbeScriptText    serialises that projection to JSON and base64s it into the
                                      script the sensor runs
        Invoke-mdiPortProbePlan       runs ON THE SENSOR and computes isRequiredPortsOk from the
                                      Requirement it finds in that payload, via
                                      Test-mdiRequirementIsMandatory

    Nothing re-stamps Requirement after the plan is built. So if the slim projection ever stopped
    carrying Requirement, or the round trip altered it, the promotion would be silently undone at
    the one place it is read: a REFUSED LDAPS 636 to a domain controller in the other forest would
    be judged Optional on the sensor, would not enter the mandatory population, and
    isRequiredPortsOk would come back True. The report would certify the two ports -MultiForest
    exists to require, on a run where one of them was measured shut. That is this project's defect
    family exactly - a value that was never read coming back looking like a measurement - reached
    here by a value that WAS read losing the only property that made it matter.

    Nothing pinned it. Requirement is asserted in three places and none of them ships a promoted
    plan through the payload:

        Test-PortProbes.Tests.ps1        checks the PLAN is promoted and that the shipped settings
                                         table is not mutated - it stops at New-mdiPortProbePlan
        RemotePayloadBudget.Tests.ps1    round-trips a plan built WITHOUT -MultiForest, so every
                                         probe it ships is Optional; its slim-plan assertions test
                                         that the Requirement PROPERTY EXISTS on probe [0], never
                                         what its value is
        PortRequirementIsRankedNotComparedToALiteral.Tests.ps1
                                         builds a -MultiForest plan but asserts on the ranking rule,
                                         not on the payload

    So the projection and the serialisation could both drop the promoted value with the whole tree
    green. The extended lab is what makes this ordinary rather than theoretical: -MultiForest now
    reaches a real second forest, fabrikam.local, across a bidirectional trust, and LDAPS to
    dcfab01.fabrikam.local is exactly the measurement the switch was set for.

    WHAT IS PINNED

    The promoted requirement is followed all the way to the far side and back into the verdict:
    promoted in the plan, promoted in the slim projection, promoted after the base64/JSON round trip
    the remote script performs, mandatory under the shared predicate there, and blocking the verdict
    when the port is measured refused across the trust.

    Both directions are pinned. The same estate built WITHOUT -MultiForest must arrive Optional and
    must NOT block, because a test that only checks the promoted side would stay green against a
    projection that hard-coded 'Required' onto every probe.
#>

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$script:target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $script:target)) {
    $script:target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
}
if (-not (Test-Path $script:target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$script:pass = 0
$script:fail = 0
function Assert-True {
    param([string] $What, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:pass++
        Write-Host ("  PASS  {0}" -f $What) -ForegroundColor Green
    } else {
        $script:fail++
        Write-Host ("  FAIL  {0} {1}" -f $What, $Detail) -ForegroundColor Red
    }
}

$text = Get-Content -LiteralPath $script:target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main')
if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body

function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

Write-Host 'The -MultiForest requirement promotion reaches the sensor, and only when it was asked for'

# A cross-forest estate: one domain controller in each forest, which is what -MultiForest is for.
$dcs = @(
    [PSCustomObject]@{ Name = 'dc01.mdilab.local'; IP = '10.10.2.10'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; IP = '10.10.1.50'; Domain = 'fabrikam.local' }
)
$promotedIds = @('LdapsTcp', 'LdapsGcTcp')

function New-Plan {
    param([switch] $MultiForest)
    New-mdiPortProbePlan -Domain 'mdilab.local' -DomainController $dcs -NnrTarget $dcs `
        -WorkspaceName 'contoso-corp' -TimeoutMs 1500 -MultiForest:$MultiForest
}

# The Requirement as it ARRIVES on the sensor: read back out of the base64 payload the remote script
# carries, never off the caller's plan - the caller's plan is the thing that is not under test here.
function Get-ShippedRequirement {
    param([object] $Plan, [string] $Id)
    $scriptText = Get-mdiPortProbeScriptText -Plan $Plan -OutputFile 'C:\Windows\Temp\mdi-shipped.json'
    $b64 = [regex]::Match($scriptText, "FromBase64String\('([A-Za-z0-9+/=]+)'\)").Groups[1].Value
    if ([string]::IsNullOrWhiteSpace($b64)) { return '(no payload found)' }
    $shipped = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | ConvertFrom-Json
    [string] (@($shipped.Probes | Where-Object { $_.Id -eq $Id })[0]).Requirement
}

$mfPlan = New-Plan -MultiForest
$plainPlan = New-Plan

Write-Host ''
Write-Host '[1] the promotion is present at every stage on the way to the sensor'
foreach ($id in $promotedIds) {
    $inPlan = [string] (@($mfPlan.Probes | Where-Object { $_.Id -eq $id })[0]).Requirement
    Assert-True "$id is Required in the -MultiForest plan" ($inPlan -eq 'Required') "-> '$inPlan'"

    # The slim projection is where the promoted value would be lost if Requirement left the
    # Select-Object property list. Asserted on the VALUE of the promoted probe, not on the presence
    # of the property on whichever probe happens to sort first.
    $inSlim = [string] (@((Get-mdiSlimProbePlan -Plan $mfPlan).Probes | Where-Object { $_.Id -eq $id })[0]).Requirement
    Assert-True "$id is still Required after the slim projection" ($inSlim -eq 'Required') "-> '$inSlim'"

    $shipped = Get-ShippedRequirement -Plan $mfPlan -Id $id
    Assert-True "$id is still Required in the payload the sensor receives" ($shipped -eq 'Required') "-> '$shipped'"

    # The shared predicate is what the sensor-side verdict actually calls.
    Assert-True "$id counts as mandatory on the far side" `
        ([bool] (Test-mdiRequirementIsMandatory -Requirement $shipped)) "-> '$shipped'"
}

Write-Host ''
Write-Host '[2] the same estate WITHOUT -MultiForest must not arrive promoted'
foreach ($id in $promotedIds) {
    $shipped = Get-ShippedRequirement -Plan $plainPlan -Id $id
    Assert-True "$id arrives Optional when -MultiForest was not asked for" ($shipped -eq 'Optional') "-> '$shipped'"
    Assert-True "$id is not mandatory on the far side" `
        (-not (Test-mdiRequirementIsMandatory -Requirement $shipped)) "-> '$shipped'"
}

Write-Host ''
Write-Host '[3] the consequence - a refused LDAPS across the trust must decide the verdict'
function New-RefusedRecord {
    param([string] $Requirement)
    [PSCustomObject]@{
        Id = 'LdapsTcp'; Name = 'LDAPS'; Protocol = 'TCP'; Port = 636; Scope = 'DomainController'
        Group = ''; Requirement = $Requirement
        Server = 'dc01.mdilab.local'; Target = 'dcfab01.fabrikam.local'; TargetIP = '10.10.1.50'
        Applicable = $true; Success = $false; LatencyMs = $null; Detail = 'Connection refused'
    }
}

$mfShipped = Get-ShippedRequirement -Plan $mfPlan -Id 'LdapsTcp'
$blockingPromoted = @(Get-mdiBlockingPortFailure -Record @(New-RefusedRecord -Requirement $mfShipped))
Assert-True 'a refused cross-forest LDAPS blocks the verdict on a -MultiForest run' `
    (@($blockingPromoted).Count -eq 1) ("blocking: {0}" -f @($blockingPromoted).Count)

$plainShipped = Get-ShippedRequirement -Plan $plainPlan -Id 'LdapsTcp'
$blockingPlain = @(Get-mdiBlockingPortFailure -Record @(New-RefusedRecord -Requirement $plainShipped))
Assert-True 'the identical failure does not block when LDAPS was never promoted' `
    (@($blockingPlain).Count -eq 0) ("blocking: {0}" -f @($blockingPlain).Count)

# An unmeasured promoted probe is a gap, not a pass: the other half of the tri-state, on the same
# shipped requirement, so a projection that dropped Requirement cannot hide here either.
$unmeasured = New-RefusedRecord -Requirement $mfShipped
$unmeasured.Success = $null
$unmeasured.Detail = 'Not tested - the port probes could not be run on dc01.mdilab.local'
Assert-True 'an unmeasured promoted LDAPS is charged as a required probe that never ran' `
    (@(Get-mdiUnmeasuredRequiredProbe -Record @($unmeasured)).Count -eq 1) `
    ("unmeasured: {0}" -f @(Get-mdiUnmeasuredRequiredProbe -Record @($unmeasured)).Count)

Write-Host ''
Write-Host ("PASS={0} FAIL={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
