# [w85] The 'Required ports open' sub-label must count REQUIRED probes only.
#
# The headline was already Required-only (PortsRequiredOpen / PortsRequiredTested). The "N probe(s)
# could not be tested" sub-label was built from PortsUntested, which counts EVERY Requirement class -
# Optional, Recommended and AtLeastOne (NNR) included. Two consequences, both reproduced by
# MDI-AB\live\w85-kpi-portsuntested.ps1 before the fix:
#
#   1. A run in which every required probe was measured OPEN, and only an OPTIONAL probe went
#      unmeasured, rendered "2/2" over "1 probe(s) could not be tested" - WORD FOR WORD the sentence
#      shown when a genuinely required probe could not be measured. The two cases were
#      indistinguishable on the card an operator actually reads, so a gap in required-port evidence
#      looked exactly like an untested optional extra, and vice versa.
#   2. The count is drawn from a wider population than the headline denominator, so it could exceed
#      it outright: "1/1" over "2 probe(s) could not be tested" - a card that cannot be reconciled
#      with itself.
#
# This is the same class of defect as the headline fix that preceded it (a Required-only figure
# reconciled against an all-class one) and as the RequiredPortsCardNotEvaluated case (the sub-label
# and the headline gating on different counters).
#
# Assertions drive the REAL Get-mdiReportStatistics and the REAL Get-mdiOverviewHtml and read the
# tone / value / sub straight back out of the rendered HTML. Nothing here asserts on source text.

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
    param(
        [string] $Name,
        [string] $Requirement,
        [ValidateSet('Open', 'Shut', 'Unmeasured')] [string] $Outcome
    )
    # Applicable (not 'Measured') is the field Test-mdiProbeWasMeasured reads, and an unmeasured
    # record must keep Applicable = $true: Get-mdiReportStatistics drops Applicable = $false records
    # from $portRecords entirely, so setting it there removes the record instead of leaving it
    # unmeasured, and the fixture silently stops testing anything.
    [PSCustomObject]@{
        Name = $Name; Protocol = 'TCP'; Port = 389; Target = 'dc1.contoso.com'
        Requirement = $Requirement; Scope = 'DomainController'
        Success = $(if ($Outcome -eq 'Open') { $true } else { $false })
        Applicable = $true
        Detail = $(switch ($Outcome) {
                'Open' { 'Connected' }
                'Shut' { 'Refused' }
                'Unmeasured' { 'Not tested - the name could not be resolved' }
            })
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

# The fixture the statistics layer must distinguish: identical REQUIRED evidence (two required probes,
# both measured open), differing only in the Requirement CLASS of the one probe that went unmeasured.
'[w85] an unmeasured OPTIONAL probe must not be reported as a required-port gap'
$optionalGap = New-Card -Records @(
    (New-PortRecord -Name 'Ldap' -Requirement 'Required' -Outcome 'Open'),
    (New-PortRecord -Name 'LdapGc' -Requirement 'Required' -Outcome 'Open'),
    (New-PortRecord -Name 'Ldaps' -Requirement 'Optional' -Outcome 'Unmeasured'))

$requiredGap = New-Card -Records @(
    (New-PortRecord -Name 'Ldap' -Requirement 'Required' -Outcome 'Open'),
    (New-PortRecord -Name 'LdapGc' -Requirement 'Required' -Outcome 'Open'),
    (New-PortRecord -Name 'Ldaps' -Requirement 'Required' -Outcome 'Unmeasured'))

Assert-That 'the fixture really did leave one probe unmeasured' ([int] $optionalGap.Stats.PortsUntested -eq 1) `
    "(PortsUntested $($optionalGap.Stats.PortsUntested) - if 0 the fixture measured everything and tests nothing)"
Assert-That 'and every REQUIRED probe in it was measured' ([int] $optionalGap.Stats.PortsRequiredUntested -eq 0) `
    "(PortsRequiredUntested $($optionalGap.Stats.PortsRequiredUntested))"
Assert-That 'while the required-gap fixture has an unmeasured required probe' ([int] $requiredGap.Stats.PortsRequiredUntested -eq 1) `
    "(PortsRequiredUntested $($requiredGap.Stats.PortsRequiredUntested))"

# The core invariant: two different facts must not render as the same sentence.
Assert-That 'the two cases do NOT render the same sub-label' ($optionalGap.Sub -ne $requiredGap.Sub) `
    "(both read '$($optionalGap.Sub)')"
Assert-That 'the required-gap card names the gap as REQUIRED' ($requiredGap.Sub -match 'required probe\(s\) could not be tested') `
    "(sub '$($requiredGap.Sub)')"
Assert-That 'the optional-gap card does NOT claim a required probe was untested' `
    (-not ($optionalGap.Sub -match 'required probe\(s\) could not be tested')) "(sub '$($optionalGap.Sub)')"
Assert-That 'the optional-gap card names the class it is actually describing' `
    ($optionalGap.Sub -match 'optional or recommended') "(sub '$($optionalGap.Sub)')"
Assert-That 'and it still states the required-port fact it DID establish' `
    ($optionalGap.Sub -match 'No required port blocked') "(sub '$($optionalGap.Sub)')"

# Both remain amber: something was not measured either way. The point is the sentence, not the colour.
Assert-That 'an unmeasured optional probe still tones the card amber' ($optionalGap.Tone -eq 'warn') "(tone '$($optionalGap.Tone)')"
Assert-That 'an unmeasured required probe tones the card amber' ($requiredGap.Tone -eq 'warn') "(tone '$($requiredGap.Tone)')"
Assert-That 'the headline is unchanged by the optional gap' ($optionalGap.Value -eq '2/2') "(value '$($optionalGap.Value)')"

'[w85] the sub-label count can never exceed the headline denominator it belongs to'
# The unreconcilable case: one required probe open, TWO optional probes unmeasured. Before the fix
# this read "1/1" over "2 probe(s) could not be tested".
$overrun = New-Card -Records @(
    (New-PortRecord -Name 'Ldap' -Requirement 'Required' -Outcome 'Open'),
    (New-PortRecord -Name 'Ldaps' -Requirement 'Optional' -Outcome 'Unmeasured'),
    (New-PortRecord -Name 'LdapsGc' -Requirement 'Optional' -Outcome 'Unmeasured'))
Assert-That 'the fixture has more unmeasured probes than the headline denominator' `
    ([int] $overrun.Stats.PortsUntested -gt [int] $overrun.Stats.PortsRequiredTested) `
    "(untested $($overrun.Stats.PortsUntested) vs required tested $($overrun.Stats.PortsRequiredTested))"
$claimedRequired = if ($overrun.Sub -match '(\d+) required probe\(s\) could not be tested') { [int] $Matches[1] } else { 0 }
Assert-That 'no required-probe count is claimed that exceeds the denominator' `
    ($claimedRequired -le [int] $overrun.Value.Split('/')[-1]) `
    "(claimed $claimedRequired over headline '$($overrun.Value)' - sub '$($overrun.Sub)')"
Assert-That 'the overrun card attributes the unmeasured probes to the non-required class' `
    ($overrun.Sub -match 'optional or recommended probe\(s\) could not be tested') "(sub '$($overrun.Sub)')"

'[w85] a Requirement = All probe is a REQUIRED probe for this purpose'
# Get-mdiUnmeasuredRequiredProbe - the population the verdict and the issue list charge - treats
# 'All' as required. An inline "-eq 'Required'" filter would drop it, and the card would report a
# gap the verdict is failing on as an optional extra.
$allClass = New-Card -Records @(
    (New-PortRecord -Name 'Ldap' -Requirement 'Required' -Outcome 'Open'),
    (New-PortRecord -Name 'Rpc' -Requirement 'All' -Outcome 'Unmeasured'))
Assert-That "an unmeasured 'All' probe counts as an unmeasured REQUIRED probe" `
    ([int] $allClass.Stats.PortsRequiredUntested -eq 1) "(PortsRequiredUntested $($allClass.Stats.PortsRequiredUntested))"
Assert-That 'and the card reports it as a required gap' ($allClass.Sub -match 'required probe\(s\) could not be tested') `
    "(sub '$($allClass.Sub)')"

'[w85] controls: the branches either side of the new one are unmoved'
$blockedWins = New-Card -Records @(
    (New-PortRecord -Name 'Ldap' -Requirement 'Required' -Outcome 'Shut'),
    (New-PortRecord -Name 'Ldaps' -Requirement 'Required' -Outcome 'Unmeasured'))
Assert-That 'a measured-shut required port still outranks an unmeasured one' ($blockedWins.Sub -match 'required port\(s\) blocked') `
    "(sub '$($blockedWins.Sub)')"
Assert-That 'and that card is RED, not amber' ($blockedWins.Tone -eq 'bad') "(tone '$($blockedWins.Tone)')"

$cleanRun = New-Card -Records @(
    (New-PortRecord -Name 'Ldap' -Requirement 'Required' -Outcome 'Open'),
    (New-PortRecord -Name 'Ldaps' -Requirement 'Optional' -Outcome 'Open'))
Assert-That 'a run with nothing unmeasured is GREEN' ($cleanRun.Tone -eq 'ok') "(tone '$($cleanRun.Tone)')"
Assert-That 'and says so plainly, with no untested clause' `
    (($cleanRun.Sub -match 'No required port blocked') -and ($cleanRun.Sub -notmatch 'could not be tested')) "(sub '$($cleanRun.Sub)')"

$noRequiredAtAll = New-Card -Records @(
    (New-PortRecord -Name 'Ldaps' -Requirement 'Optional' -Outcome 'Unmeasured'))
Assert-That 'with no required probe at all the card still says nothing required was probed' `
    ($noRequiredAtAll.Sub -match 'No required port was probed') "(sub '$($noRequiredAtAll.Sub)')"
Assert-That 'and it is not green' ($noRequiredAtAll.Tone -ne 'ok') "(tone '$($noRequiredAtAll.Tone)')"

''
"RequiredPortsCardUntestedClass: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
