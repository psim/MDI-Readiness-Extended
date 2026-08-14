# [w85] The 'Required ports open' card must not assert a required-port fact when no required probe
# was ever measured.
#
# The headline gates on PortsRequiredTested ('n/a' when none were tested). The sub-label and the tone
# gated on PortsTotal instead. When port records EXIST but not one of them is a Required probe, the
# headline correctly read 'n/a' while the sub-label fell through to "No required port blocked" and the
# tone to 'ok' - a GREEN card asserting that no required port is blocked, over a run in which no
# required port was probed at all.
#
# Reached on a SHIPPED path, not a synthetic one: a certification authority probed in the reverse
# direction (inbound from this computer) emits only NNR records, and Get-mdiRequiredPorts itself
# returns isRequiredPortsOk = 'N/A' for that case. The producer said "unknown"; the card said "all
# clear". Found by the w85 hunt, probe MDI-AB\live\w85-kpi-ports-norequired.ps1.
#
# Assertions drive the REAL Get-mdiReportStatistics and the REAL Get-mdiOverviewHtml, and the port
# records are built by the REAL Get-mdiPortResultRecord shape.
#
# MUTATION NOTE: swapping the guard's counter from PortsRequiredTested to PortsRequiredOpen produces
# an EQUIVALENT mutant that this file cannot kill, and that is correct rather than a gap. The branch
# is only reached once PortsRequiredFail is 0, and tested = open + fail, so at that point the two
# counters are necessarily equal. The 'EVERY required probe measured shut' case below pins the branch
# precedence that makes them equivalent - if a future edit moves the guard above the RequiredFail
# branch, that case turns red.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-PortRecord {
    param([string] $Name, [string] $Requirement, [bool] $Success, [string] $Scope = 'DomainController')
    # Applicable (not 'Measured') is the field Test-mdiProbeWasMeasured reads. Getting this wrong
    # makes every record count as untested, which silently turns the whole fixture into one case.
    [PSCustomObject]@{
        Name = $Name; Protocol = 'TCP'; Port = 389; Target = 'dc1.contoso.com'
        Requirement = $Requirement; Scope = $Scope
        Success = $Success; Applicable = $true; Detail = $(if ($Success) { 'Connected' } else { 'Refused' })
    }
}

function New-Card {
    param([object[]] $Records)
    $srv = [PSCustomObject]@{
        FQDN = 'srv.contoso.com'; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false
        NtlmAuditing = $true
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = $Records } }
    }
    $report = [PSCustomObject]@{
        DomainsInScope = @('contoso.com'); DomainControllers = @($srv); CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    $html = Get-mdiOverviewHtml -Statistics $stats -ReportData $report
    $tone = if ($html -match '<div class="kpi (ok|warn|bad|na)"><span class="kpi-label">Required ports open') { $Matches[1] } else { 'none' }
    $value = if ($html -match '<span class="kpi-label">Required ports open</span><span class="kpi-value">([^<]*)</span>') { $Matches[1] } else { '?' }
    $sub = if ($html -match '<span class="kpi-label">Required ports open</span><span class="kpi-value">[^<]*</span><span class="kpi-sub">([^<]*)</span>') { $Matches[1] } else { '?' }
    [PSCustomObject]@{ Tone = $tone; Value = $value; Sub = $sub; Stats = $stats }
}

'[w85] control: nothing probed at all'
$none = New-Card -Records @()
Assert-That 'no records at all is not evaluated' ($none.Tone -eq 'na') "(tone '$($none.Tone)' value '$($none.Value)' sub '$($none.Sub)')"
Assert-That 'and says so' ($none.Sub -match 'Not evaluated') "(sub '$($none.Sub)')"

'[w85] control: required probes really were measured open'
$ok = New-Card -Records @(
    (New-PortRecord -Name 'Ldap' -Requirement 'Required' -Success $true),
    (New-PortRecord -Name 'Ldaps' -Requirement 'Required' -Success $true))
Assert-That 'measured-open required ports are GREEN' ($ok.Tone -eq 'ok') "(tone '$($ok.Tone)')"
Assert-That 'the headline states the ratio' ($ok.Value -eq '2/2') "(value '$($ok.Value)')"
Assert-That 'the sub-label asserts the required-port fact' ($ok.Sub -match 'No required port blocked') "(sub '$($ok.Sub)')"

'[w85] control: a required probe measured shut is RED and says so'
$bad = New-Card -Records @(
    (New-PortRecord -Name 'Ldap' -Requirement 'Required' -Success $true),
    (New-PortRecord -Name 'Ldaps' -Requirement 'Required' -Success $false))
Assert-That 'a blocked required port is RED' ($bad.Tone -eq 'bad') "(tone '$($bad.Tone)')"
Assert-That 'and names the blockage' ($bad.Sub -match 'required port\(s\) blocked') "(sub '$($bad.Sub)')"

'[w85] control: EVERY required probe measured shut'
# The boundary that separates PortsRequiredOpen from PortsRequiredTested. Here open = 0 while tested
# = 2, so a guard written against the wrong counter would mistake a fully blocked estate for one that
# was never probed. The RequiredFail branch must win.
$allShut = New-Card -Records @(
    (New-PortRecord -Name 'Ldap' -Requirement 'Required' -Success $false),
    (New-PortRecord -Name 'Ldaps' -Requirement 'Required' -Success $false))
Assert-That 'a fully blocked estate is RED, not "not evaluated"' ($allShut.Tone -eq 'bad') "(tone '$($allShut.Tone)' sub '$($allShut.Sub)')"
Assert-That 'and it names the blockage rather than claiming nothing was probed' `
    ($allShut.Sub -match 'required port\(s\) blocked' -and $allShut.Sub -notmatch 'not evaluated') "(sub '$($allShut.Sub)')"
Assert-That 'the headline still states the ratio' ($allShut.Value -eq '0/2') "(value '$($allShut.Value)')"

'[w85] the defect: records exist but none of them is a required probe'
# The reverse-direction CA path: only NNR records, no Required probe anywhere.
$noReq = New-Card -Records @(
    (New-PortRecord -Name 'NnrRpc' -Requirement 'AtLeastOne' -Success $true -Scope 'NetworkDevice'),
    (New-PortRecord -Name 'NnrRdp' -Requirement 'AtLeastOne' -Success $true -Scope 'NetworkDevice'))
Assert-That 'no required probe was measured in this fixture' ([int] $noReq.Stats.PortsRequiredTested -eq 0) `
    "(PortsRequiredTested $($noReq.Stats.PortsRequiredTested))"
Assert-That 'but records DID exist' ([int] $noReq.Stats.PortsTotal -gt 0) "(PortsTotal $($noReq.Stats.PortsTotal))"
Assert-That 'the card is NOT green' ($noReq.Tone -ne 'ok') "(tone '$($noReq.Tone)' value '$($noReq.Value)' sub '$($noReq.Sub)')"
Assert-That 'the card does not claim no required port is blocked' `
    ($noReq.Sub -notmatch '^No required port blocked') "(sub '$($noReq.Sub)')"
Assert-That 'the card says nothing required was probed' ($noReq.Sub -match 'not evaluated|was probed') "(sub '$($noReq.Sub)')"

'[w85] the headline and the tone agree about the same population'
# The invariant behind the defect: whenever the headline cannot state a ratio, the tone must not be
# the all-clear colour, and the sub-label must not assert a required-port fact.
foreach ($case in @(
        @{ N = 'nothing probed'; C = $none },
        @{ N = 'required measured open'; C = $ok },
        @{ N = 'required measured shut'; C = $bad },
        @{ N = 'records but none required'; C = $noReq }
    )) {
    $c = $case.C
    $headlineIsNa = ($c.Value -eq 'n/a')
    $contradiction = $headlineIsNa -and ($c.Tone -eq 'ok' -or $c.Sub -match '^No required port blocked')
    Assert-That "  no all-clear over an 'n/a' headline ($($case.N))" (-not $contradiction) `
        "(value '$($c.Value)' tone '$($c.Tone)' sub '$($c.Sub)')"
}

'[w85] disclosure of other probe outcomes is not lost'
# The guard must not swallow facts that were measured. An optional probe measured shut still has to
# be named even though no required probe exists.
$blockedOptional = New-Card -Records @(
    (New-PortRecord -Name 'NnrRpc' -Requirement 'AtLeastOne' -Success $true -Scope 'NetworkDevice'),
    (New-PortRecord -Name 'Ptr' -Requirement 'Recommended' -Success $false -Scope 'NetworkDevice'))
Assert-That 'a blocked optional probe is still named' ($blockedOptional.Sub -match 'blocked') "(sub '$($blockedOptional.Sub)')"
Assert-That 'and the card is not green' ($blockedOptional.Tone -ne 'ok') "(tone '$($blockedOptional.Tone)')"

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
