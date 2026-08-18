# A DOMAIN IN SCOPE THAT RECEIVED NO NAME-RESOLUTION PROBE TARGET REACHED READY WITH A GREEN SCORE,
# BECAUSE NOTHING RECORDED THAT IT HAD BEEN SKIPPED.
#
# The two probe budgets are not the same kind of number, and the difference is invisible until the
# scope holds more than one domain:
#
#     -MaxLdapTargetsPerDomain = 2    spent PER DOMAIN  -> every domain is guaranteed targets
#     -MaxNnrTargets           = 5    one GLOBAL pool   -> the domains COMPETE for it
#
# Resolve-mdiNnrTarget spreads that pool across domains, and its own comment says why: "A forest
# nobody probed is not a forest that passed." Spreading can only honour that while the budget is at
# least as large as the number of domains in scope, and the shipped default is 5. Measured on the
# shipped sampler at that default, three controllers per domain:
#
#     5 domains in scope -> 5 targets, every domain probed
#     6 domains in scope -> 5 targets, NO NNR PROBE for the sixth
#     7 domains in scope -> two domains never probed
#     8 domains in scope -> three domains never probed
#
# LDAP covered every domain in all of those runs. So a domain whose controllers were fully scanned -
# passing the unexamined-domain gate AND the LDAP plan gap - could have its name resolution never
# measured at all.
#
# It was not merely undisclosed, it was UNRECORDED. The report carried LdapPlanGapDomains (read by
# the issue list, the statistics unread charge and the verdict), NnrUnresolvedTargets,
# NnrTargetComputer and MaxNnrTargets - but no resolved NNR target list and no per-domain NNR
# coverage, so no surface could have raised it even if it wanted to. The only NNR disclosure is a
# global host count, "name resolution 5 of 18 host(s), raise -MaxNnrTargets", which reads
# IDENTICALLY whether the sample was spread across every domain or an entire domain got nothing.
#
# This is the sixth gap of a family the script had already closed five times:
#
#     unreachable server            -> charged one unread   (fixed)
#     forest not fully enumerated   -> charged one unread   (fixed)
#     unexamined domain             -> charged one unread   (fixed)
#     LdapPlanGapDomains            -> charged one unread   (fixed)
#     NnrUnresolvedTargets          -> charged one unread   (fixed)
#     a domain starved of NNR targets -> NOT RECORDED AT ALL (this test)
#
# THE RULE IS NOT A COPY OF THE LDAP ONE, and this test pins the difference. Resolve-mdiLdapTarget
# only ever emits rows built from the domain-controller inventory, which always carries a Domain.
# The NNR sampler has a second branch: an operator-supplied target takes its Domain from its own DNS
# suffix, so a BARE IP ADDRESS yields $null by design and a DISJOINT NetBIOS suffix (ws4.FABCORP)
# yields a name that is in no scope. Measured with four targets named as IP addresses, the naive
# LDAP-style rule charged ALL FOUR scoped domains as unprobed. A target the run cannot place is not
# evidence that some other domain went unprobed, so any unplaceable target silences the charge
# entirely - the fix must not trade a false green for a false red.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$source = [IO.File]::ReadAllText($target)
$source = $source -replace '(?m)^\s*#Requires.*$', ''
$source = $source -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$main = $source.IndexOf('#region Main')
if ($main -lt 1) { throw 'Could not isolate the canonical function definitions.' }
Invoke-Expression $source.Substring(0, $main)
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# ---------------------------------------------------------------------------------------------
# 1. The SAMPLER really does starve a domain at the shipped default. Measured, not assumed.
# ---------------------------------------------------------------------------------------------
'[sampler] the global -MaxNnrTargets budget starves whole domains at its default of 5'

# The default is read off the real param block rather than hard-coded, so this test fails loudly
# if the default ever moves and the arithmetic below stops describing the shipped tool.
$defaultMatch = [regex]::Match($source, '\[int\]\s*\$MaxNnrTargets\s*=\s*(\d+)')
Assert-That 'the shipped -MaxNnrTargets default is still readable' $defaultMatch.Success
$defaultNnr = [int] $defaultMatch.Groups[1].Value
Assert-That "the shipped -MaxNnrTargets default is a single global pool of $defaultNnr" ($defaultNnr -eq 5) "(got $defaultNnr)"

Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param([Parameter(Mandatory = $true)][string] $ComputerName, $KnownAddress = $null)
    $known = @($KnownAddress | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
    if ($known.Count -gt 0) { return $known }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return @() }
    $h = 0
    foreach ($ch in $ComputerName.ToCharArray()) { $h = ($h * 31 + [int] $ch) % 250 }
    @('10.90.1.{0}' -f ([int] $h % 250 + 1))
}

$domainNames = @('d1.test', 'd2.test', 'd3.test', 'd4.test', 'd5.test', 'd6.test', 'd7.test', 'd8.test')
function New-Estate {
    param([int] $DomainCount)
    $rows = @()
    for ($d = 0; $d -lt $DomainCount; $d++) {
        for ($i = 1; $i -le 3; $i++) {
            $rows += [PSCustomObject]@{
                Name   = ('dc{0:00}.{1}' -f $i, $domainNames[$d])
                IP     = ('10.{0}.1.{1}' -f (10 + $d), (10 + $i))
                FQDN   = ('dc{0:00}.{1}' -f $i, $domainNames[$d])
                Domain = $domainNames[$d]
            }
        }
    }
    , $rows
}

# The shipped gap rule, exercised through the real sampler.
function Get-NnrGap {
    param([string[]] $Scope, $Targets)
    $keys = @($Scope | ForEach-Object { ([string] $_).Trim().TrimEnd('.') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $unplaceable = @($Targets | Where-Object {
            $d = ([string] $_.Domain).Trim().TrimEnd('.')
            [string]::IsNullOrWhiteSpace($d) -or ($keys -notcontains $d)
        }).Count
    if ($unplaceable -gt 0) { return @() }
    @($Scope | Where-Object {
            $s = ([string] $_).Trim().TrimEnd('.')
            -not [string]::IsNullOrWhiteSpace($s) -and
            @($Targets | Where-Object { ([string] $_.Domain).Trim().TrimEnd('.') -eq $s }).Count -eq 0
        })
}

foreach ($case in @(
        @{ Domains = 5; Starved = 0 }
        @{ Domains = 6; Starved = 1 }
        @{ Domains = 7; Starved = 2 }
        @{ Domains = 8; Starved = 3 }
    )) {
    $estate = New-Estate -DomainCount $case.Domains
    $scope = @($estate | ForEach-Object { $_.Domain } | Select-Object -Unique)
    $nnr = @(Resolve-mdiNnrTarget -DomainControllers $estate -Domain $scope[0] -MaxTargets $defaultNnr)
    $gap = Get-NnrGap -Scope $scope -Targets $nnr
    Assert-That ("{0} domains at the default budget -> {1} domain(s) with no NNR target" -f $case.Domains, $case.Starved) (
        @($gap).Count -eq $case.Starved) "(got $(@($gap).Count): $(@($gap) -join ', '))"

    # The contrast that makes this a defect rather than an arithmetic inevitability: the PER-DOMAIN
    # LDAP budget never starves a domain on the same estate.
    $ldap = @(Resolve-mdiLdapTarget -DomainControllers $estate -MaxPerDomain 2)
    $ldapGap = @($scope | Where-Object { $s = $_; @($ldap | Where-Object { [string] $_.Domain -eq $s }).Count -eq 0 })
    Assert-That ("{0} domains: the per-domain LDAP budget starves none" -f $case.Domains) (
        @($ldapGap).Count -eq 0) "(got $(@($ldapGap) -join ', '))"
}

''
'[sampler] an UNPLACEABLE target silences the charge - no false red'
$estate4 = New-Estate -DomainCount 4
$scope4 = @($estate4 | ForEach-Object { $_.Domain } | Select-Object -Unique)

# Bare IP addresses yield a null Domain by design, so the run cannot place them.
$byIp = @(Resolve-mdiNnrTarget -DomainControllers $estate4 -Domain $scope4[0] -MaxTargets 20 `
        -NnrTargetComputer @('10.10.1.77', '10.10.2.77', '10.10.3.77', '10.10.1.99'))
$unplaceable = @($byIp | Where-Object { [string]::IsNullOrWhiteSpace([string] $_.Domain) }).Count
Assert-That 'a target named as a bare IP address is unattributed' ($unplaceable -gt 0) "(got $unplaceable)"
Assert-That 'unattributed targets charge NO domain (the naive rule charged all four)' (
    @(Get-NnrGap -Scope $scope4 -Targets $byIp).Count -eq 0) "(got $(@(Get-NnrGap -Scope $scope4 -Targets $byIp) -join ', '))"

# A disjoint NetBIOS suffix attributes to a name that is in no scope - also unplaceable.
$byNetbios = @(Resolve-mdiNnrTarget -DomainControllers $estate4 -Domain $scope4[0] -MaxTargets 20 `
        -NnrTargetComputer @('ws4.FABCORP'))
Assert-That 'a disjoint NetBIOS suffix is not a scoped domain, so it charges nothing' (
    @(Get-NnrGap -Scope $scope4 -Targets $byNetbios).Count -eq 0) "(got $(@(Get-NnrGap -Scope $scope4 -Targets $byNetbios) -join ', '))"

# ---------------------------------------------------------------------------------------------
# 2. The gap now reaches all three disclosure surfaces.
# ---------------------------------------------------------------------------------------------
''
'[disclosure] the gap is charged, raised and blocks READY'

function New-CleanServer {
    param([string] $Fqdn = 'dc1.contoso.test', [string] $Domain = 'contoso.test')
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = $Domain
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        ServerRequirements = $true; AdvancedAuditing = $true; NtlmAuditing = $true
        Details = [ordered]@{}
    }
}
function New-CleanDomain {
    param([string] $Domain = 'contoso.test')
    [PSCustomObject]@{
        Domain = $Domain
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true; Measured = $true }
        ObjectAuditingMeasured = $true
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A'; Measured = $true }
        ExchangeAuditingMeasured = $true
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A'; Measured = $true }
        AdfsAuditingMeasured = $true
        DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; Measured = $true; NotAsserted = $false }
        DeletedObjectsMeasured = $true
        SchemaVersion = [PSCustomObject]@{ details = 'Windows Server 2016'; schemaVersion = 87 }
    }
}
function New-Report {
    param([string[]] $NnrGap = @(), [string[]] $LdapGap = @())
    # BOTH domains are fully scanned and fully examined - the point of the defect is that a domain
    # can pass every existing gate and still never have had its name resolution probed.
    [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.test'; Forest = 'contoso.test'
        ForestDiscovery = [PSCustomObject]@{
            Name = 'contoso.test'; Domains = @('contoso.test', 'child.contoso.test'); Method = 'stub'; Complete = $true; Error = $null
        }
        DomainsInScope = @('contoso.test', 'child.contoso.test')
        LdapPlanGapDomains = @($LdapGap)
        NnrPlanGapDomains = @($NnrGap)
        NnrUnresolvedTargets = @()
        NnrTargetComputer = @()
        MaxNnrTargets = 5
        DomainControllers = @((New-CleanServer), (New-CleanServer -Fqdn 'dc2.child.contoso.test' -Domain 'child.contoso.test'))
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @((New-CleanDomain), (New-CleanDomain -Domain 'child.contoso.test'))
        DomainSchemaVersion = [PSCustomObject]@{ details = 'Windows Server 2016'; schemaVersion = 87 }
        SkippedAreas = @()
    }
}

$clean = Get-mdiReportStatistics -ReportData (New-Report)
$gapped = Get-mdiReportStatistics -ReportData (New-Report -NnrGap @('child.contoso.test'))
Assert-That 'a clean run charges no unread' ([int] $clean.ChecksUnread -eq 0) "(got $($clean.ChecksUnread))"
Assert-That 'an NNR-starved domain is charged one unread' (
    [int] $gapped.ChecksUnread -eq 1) "(got $($gapped.ChecksUnread))"
Assert-That 'the numerator does not move - nothing new passed' (
    [int] $gapped.ChecksPassed -eq [int] $clean.ChecksPassed) "(got $($gapped.ChecksPassed) vs $($clean.ChecksPassed))"
$den = Get-mdiCoverageDenominator -Measured $gapped.ChecksTotal -Unread $gapped.ChecksUnread
Assert-That 'the gap lands in the denominator' (
    [int] $den -eq ([int] $gapped.ChecksTotal + 1)) "(got $den vs $($gapped.ChecksTotal))"

# De-duplication, and blanks charging nothing - the same contract the sibling gaps keep.
$dup = Get-mdiReportStatistics -ReportData (New-Report -NnrGap @('child.contoso.test', 'child.contoso.test'))
Assert-That 'a domain named twice is charged once' ([int] $dup.ChecksUnread -eq 1) "(got $($dup.ChecksUnread))"
$blank = Get-mdiReportStatistics -ReportData (New-Report -NnrGap @('', '   '))
Assert-That 'blank entries are not charged at all' ([int] $blank.ChecksUnread -eq 0) "(got $($blank.ChecksUnread))"
$both = Get-mdiReportStatistics -ReportData (New-Report -NnrGap @('child.contoso.test') -LdapGap @('child.contoso.test'))
Assert-That 'an LDAP gap and an NNR gap on one domain are two distinct holes' (
    [int] $both.ChecksUnread -eq 2) "(got $($both.ChecksUnread))"

''
'[disclosure] the issue list names the domain'
$issuesClean = @(Get-mdiIssueList -ReportData (New-Report) -Statistics $clean)
$issuesGap = @(Get-mdiIssueList -ReportData (New-Report -NnrGap @('child.contoso.test')) -Statistics $gapped)
$nnrIssue = @($issuesGap | Where-Object { $_.Area -eq 'Not measured' -and $_.Issue -match 'Network Name Resolution probe target' })
Assert-That 'a clean run raises no NNR plan-gap issue' (
    @($issuesClean | Where-Object { $_.Issue -match 'Network Name Resolution probe target could be built' }).Count -eq 0)
Assert-That 'the starved domain raises exactly one High "Not measured" issue' (
    $nnrIssue.Count -eq 1) "(got $($nnrIssue.Count))"
Assert-That 'the issue names the domain that was skipped' (
    $nnrIssue.Count -eq 1 -and [string] $nnrIssue[0].Server -eq 'child.contoso.test') "(got $($nnrIssue[0].Server))"
Assert-That 'the issue is High' (
    $nnrIssue.Count -eq 1 -and [string] $nnrIssue[0].Severity -eq 'High') "(got $($nnrIssue[0].Severity))"

''
'[disclosure] the verdict refuses READY'
$readyClean = Test-mdiReadinessResult -ReportData (New-Report) 3>$null
$readyGap = Test-mdiReadinessResult -ReportData (New-Report -NnrGap @('child.contoso.test')) 3>$null
Assert-That 'the clean run is READY' ($readyClean -eq $true) "(got $readyClean)"
Assert-That 'a domain whose name resolution was never probed is NOT READY' (
    $readyGap -ne $true) "(got $readyGap)"

''
'[invariant] the run can never be READY while a domain went unprobed'
foreach ($gap in @(@(), @('child.contoso.test'), @('contoso.test', 'child.contoso.test'))) {
    $s = Get-mdiReportStatistics -ReportData (New-Report -NnrGap $gap)
    $r = Test-mdiReadinessResult -ReportData (New-Report -NnrGap $gap) 3>$null
    Assert-That ("gap of {0}: ready only when the gap is empty" -f @($gap).Count) (
        ($r -ne $true) -or (@($gap).Count -eq 0)) "(ready=$r gap=$(@($gap).Count))"
    Assert-That ("gap of {0}: unread matches the number of distinct domains skipped" -f @($gap).Count) (
        [int] $s.ChecksUnread -eq @($gap).Count) "(got $($s.ChecksUnread))"
}

''
'[scope] the per-domain gap is NOT charged when the operator chose the target list'
# This guard lives in Main, below the #region marker the harness truncates at, so it cannot be
# exercised by calling a function - it is pinned here at the source level, the same technique
# PortRequirementIsRankedNotComparedToALiteral uses.
#
# With -NnrTargetComputer the plan is the operator's own list and nothing else, so a scoped domain
# they did not happen to name a host in is a CHOICE, not a gap. Charging it produced a false red
# advising "raise -MaxNnrTargets above the number of domains in scope", which cannot change
# anything because the budget was never the constraint. Measured with two domains in scope, two
# hosts named in one of them and a budget of 20: the other domain was charged one unread, raised a
# High finding and blocked READY, with nothing starved. It also double-charged - one deliberate
# choice plus one budget shortfall became four unread checks instead of three.
#
# NnrCandidateCount already makes exactly this judgement for the sampling disclosure, with the same
# predicate, so the two cannot drift apart.
$gapStart = $source.IndexOf('$nnrScopeKeys = @($domainsInScope')
Assert-That 'the per-domain NNR gap statement is still present in Main' ($gapStart -gt 0)
$gapBlock = if ($gapStart -gt 0) { $source.Substring($gapStart, 1400) } else { '' }
Assert-That 'the gap is guarded by Test-mdiNoNameSupplied, so a named list charges no domain' (
    $gapBlock -match 'if \(\(Test-mdiNoNameSupplied -Name \$NnrTargetComputer\) -and \$nnrUnplaceable -eq 0\)')
Assert-That 'the unplaceable-target guard survives alongside it' (
    $gapBlock -match '\$nnrUnplaceable -eq 0')


"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
