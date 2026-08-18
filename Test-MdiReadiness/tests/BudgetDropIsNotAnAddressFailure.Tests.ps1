# A NETWORK NAME RESOLUTION TARGET THE OPERATOR NAMED, WHICH RESOLVES PERFECTLY, WAS REPORTED AS A
# HOST WHOSE ADDRESS COULD NOT BE RESOLVED - WHEN THE TRUTH WAS THAT THE SAMPLER DROPPED IT FOR WANT
# OF BUDGET.
#
# Main built the unresolved list against the plan AFTER -MaxNnrTargets had been spent:
#
#     $nnrUnresolvedTargets = Get-mdiUnresolvedNnrTarget -Requested $NnrTargetComputer `
#                                 -Resolved @($nnrTargets | ForEach-Object { $_.Name })
#
# $nnrTargets is post-budget, so "resolved" silently meant "resolved AND survived the budget", and a
# host the budget dropped became indistinguishable from a host DNS cannot find.
#
# Measured on the shipped functions at the SHIPPED DEFAULT of -MaxNnrTargets 5, with eight named
# workstations every one of which resolves:
#
#     probed                  ws1..ws5
#     reported "unresolved"   ws6, ws7, ws8
#     of those, resolve fine  3 of 3
#
# and all three disclosure surfaces stated an address failure that had not happened:
#
#     console  "No address could be resolved for the Network Name Resolution target(s) you named: ..."
#     issues   "This Network Name Resolution target could not be resolved to an address ..."
#     verdict  "... could not be resolved to an address and were never probed"
#
# The VERDICT was right - those hosts genuinely were not probed - but the CAUSE was invented. The
# remedy it implied (fix name resolution) cannot work, and the one that would (raise -MaxNnrTargets)
# was never mentioned. A control run with a genuinely unresolvable host shows the wording is correct
# in that case, so this was wrong specifically for the budget drop.
#
# Naming workstations is exactly what -NnrTargetComputer is for - the tool's own console tip says
# "use -NnrTargetComputer to also validate NNR against workstations and member servers" - so naming
# more than five is ordinary usage at default settings, not a contrived case.
#
# The fix has two halves and this test pins BOTH:
#   1. Resolve-mdiNnrTarget reports what RESOLVED through a -ResolvedName [ref] out-parameter, taken
#      BEFORE the cap, and Main compares the request against that.
#   2. Named hosts that resolved but did not fit the budget are disclosed as their own gap,
#      NnrSampledOutTargets, with their own remedy - charged one unread each, raising their own High
#      finding, and still blocking READY, because they genuinely were not probed.
#
# It also pins the parameter DECLARATION: `[ref] $X = $null` cannot bind when the parameter is
# omitted ("Reference type is expected in argument"), which would break every caller that does not
# want the names. That mistake was made and caught while writing this fix.

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

# 'ghost*' does not resolve. Everything else does. There is no DNS failure in this file except that.
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param([Parameter(Mandatory = $true)][string] $ComputerName, $KnownAddress = $null)
    $known = @($KnownAddress | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
    if ($known.Count -gt 0) { return $known }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return @() }
    if ($ComputerName -like 'ghost*') { return @() }
    @('10.90.1.7')
}

$estate = @([PSCustomObject]@{ Name = 'dc01.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local' })

'[sampler] -ResolvedName reports what RESOLVED, taken before the cap'
$named = 1..8 | ForEach-Object { "ws$_.mdilab.local" }
$resolved = @()
$plan = @(Resolve-mdiNnrTarget -DomainControllers $estate -NnrTargetComputer $named `
        -Domain 'mdilab.local' -MaxTargets 5 -ResolvedName ([ref] $resolved))
Assert-That 'the plan is capped at the budget' (@($plan).Count -eq 5) "(got $(@($plan).Count))"
Assert-That 'ResolvedName carries every host that resolved, uncapped' (
    @($resolved).Count -eq 8) "(got $(@($resolved).Count))"
Assert-That 'ResolvedName is a superset of the plan' (
    @(@($plan | ForEach-Object { $_.Name }) | Where-Object { $resolved -notcontains $_ }).Count -eq 0)

''
'[sampler] the parameter is optional - omitting it must not throw'
# `[ref] $X = $null` raises "Reference type is expected in argument" when omitted. Every existing
# caller and every other test calls this function without -ResolvedName.
$omitted = $null
$threw = $false
try {
    $omitted = @(Resolve-mdiNnrTarget -DomainControllers $estate -NnrTargetComputer $named `
            -Domain 'mdilab.local' -MaxTargets 5)
} catch { $threw = $true }
Assert-That 'omitting -ResolvedName does not throw' (-not $threw)
Assert-That 'omitting -ResolvedName returns the same plan' (@($omitted).Count -eq 5) "(got $(@($omitted).Count))"

# ResolvedName must be reset per call, not accumulated - the same contract the sibling
# out-parameters carry, so a caller reusing one variable cannot inherit a previous resolution.
$reused = @('stale.mdilab.local')
$null = Resolve-mdiNnrTarget -DomainControllers $estate -NnrTargetComputer @('ws1.mdilab.local') `
    -Domain 'mdilab.local' -MaxTargets 5 -ResolvedName ([ref] $reused)
Assert-That 'ResolvedName is reset, never accumulated' (
    $reused -notcontains 'stale.mdilab.local') "(got $(@($reused) -join ', '))"

''
'[split] a budget drop is not an address failure'
function Get-Split {
    param([string[]] $Named, [int] $Budget)
    $r = @()
    $p = @(Resolve-mdiNnrTarget -DomainControllers $estate -NnrTargetComputer $Named `
            -Domain 'mdilab.local' -MaxTargets $Budget -ResolvedName ([ref] $r))
    $unres = @(Get-mdiUnresolvedNnrTarget -Requested $Named -Resolved $r)
    $sampled = @(Get-mdiUnresolvedNnrTarget -Requested $Named -Resolved @($p | ForEach-Object { $_.Name }) |
            Where-Object { $unres -notcontains $_ })
    [PSCustomObject]@{ Unresolved = $unres; SampledOut = $sampled }
}

$s = Get-Split -Named $named -Budget 5
Assert-That 'eight resolvable hosts at the default budget: NOTHING is unresolved' (
    @($s.Unresolved).Count -eq 0) "(got $(@($s.Unresolved) -join ', '))"
Assert-That 'the three that did not fit are reported as sampled out' (
    @($s.SampledOut).Count -eq 3) "(got $(@($s.SampledOut) -join ', '))"
Assert-That 'the sampled-out names are the ones the budget dropped' (
    (@($s.SampledOut | Sort-Object) -join ',') -eq 'ws6.mdilab.local,ws7.mdilab.local,ws8.mdilab.local') "(got $(@($s.SampledOut) -join ', '))"

$s = Get-Split -Named $named -Budget 20
Assert-That 'a generous budget reports neither gap' (
    @($s.Unresolved).Count -eq 0 -and @($s.SampledOut).Count -eq 0)

# The control: the message is CORRECT for a host that genuinely does not resolve.
$s = Get-Split -Named @('ws1.mdilab.local', 'ghost.mdilab.local') -Budget 20
Assert-That 'a genuinely unresolvable host IS reported unresolved' (
    @($s.Unresolved).Count -eq 1 -and $s.Unresolved[0] -eq 'ghost.mdilab.local') "(got $(@($s.Unresolved) -join ', '))"
Assert-That 'and it is NOT also reported as sampled out' (@($s.SampledOut).Count -eq 0)

# The hard case: both causes at once must separate cleanly.
$s = Get-Split -Named @('ws1.mdilab.local', 'ghost.mdilab.local', 'ws2.mdilab.local', 'ws3.mdilab.local') -Budget 2
Assert-That 'ghost + tight budget: the ghost is unresolved' (
    @($s.Unresolved) -contains 'ghost.mdilab.local') "(got $(@($s.Unresolved) -join ', '))"
Assert-That 'ghost + tight budget: the budget drop is sampled out' (
    @($s.SampledOut).Count -gt 0) "(got $(@($s.SampledOut) -join ', '))"
Assert-That 'ghost + tight budget: the two sets never overlap' (
    @($s.Unresolved | Where-Object { $s.SampledOut -contains $_ }).Count -eq 0)

# Unreadable entries belong to neither bucket - a blank was never a host anyone asked about.
$s = Get-Split -Named @('ws1.mdilab.local', '', '   ') -Budget 20
Assert-That 'blank requests are charged to neither gap' (
    @($s.Unresolved).Count -eq 0 -and @($s.SampledOut).Count -eq 0)

''
'[disclosure] the sampled-out gap is charged, raised and blocks READY'
function New-Server {
    [PSCustomObject]@{
        FQDN = 'dc1.mdilab.local'; Domain = 'mdilab.local'
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        ServerRequirements = $true; AdvancedAuditing = $true; NtlmAuditing = $true
        Details = [ordered]@{}
    }
}
function New-Domain {
    [PSCustomObject]@{
        Domain = 'mdilab.local'
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true; Measured = $true }; ObjectAuditingMeasured = $true
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A'; Measured = $true }; ExchangeAuditingMeasured = $true
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A'; Measured = $true }; AdfsAuditingMeasured = $true
        DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; Measured = $true; NotAsserted = $false }; DeletedObjectsMeasured = $true
        SchemaVersion = [PSCustomObject]@{ details = 'Windows Server 2016'; schemaVersion = 87 }
    }
}
function New-Report {
    param([string[]] $SampledOut = @(), [string[]] $Unresolved = @())
    [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'mdilab.local'; Forest = 'mdilab.local'
        ForestDiscovery = [PSCustomObject]@{ Name = 'mdilab.local'; Domains = @('mdilab.local'); Method = 'stub'; Complete = $true; Error = $null }
        DomainsInScope = @('mdilab.local')
        LdapPlanGapDomains = @(); NnrPlanGapDomains = @()
        NnrUnresolvedTargets = @($Unresolved)
        NnrSampledOutTargets = @($SampledOut)
        NnrTargetComputer = @(); MaxNnrTargets = 5
        DomainControllers = @(New-Server)
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(New-Domain)
        DomainSchemaVersion = [PSCustomObject]@{ details = 'Windows Server 2016'; schemaVersion = 87 }
        SkippedAreas = @()
    }
}

$clean = Get-mdiReportStatistics -ReportData (New-Report)
$gapped = Get-mdiReportStatistics -ReportData (New-Report -SampledOut @('ws6.mdilab.local'))
Assert-That 'a clean run charges no unread' ([int] $clean.ChecksUnread -eq 0) "(got $($clean.ChecksUnread))"
Assert-That 'a sampled-out target is charged one unread' (
    [int] $gapped.ChecksUnread -eq 1) "(got $($gapped.ChecksUnread))"
Assert-That 'the numerator does not move' (
    [int] $gapped.ChecksPassed -eq [int] $clean.ChecksPassed) "(got $($gapped.ChecksPassed))"

$dup = Get-mdiReportStatistics -ReportData (New-Report -SampledOut @('ws6.mdilab.local', 'ws6.mdilab.local'))
Assert-That 'a target named twice is charged once' ([int] $dup.ChecksUnread -eq 1) "(got $($dup.ChecksUnread))"
$blank = Get-mdiReportStatistics -ReportData (New-Report -SampledOut @('', '   '))
Assert-That 'blank entries are not charged' ([int] $blank.ChecksUnread -eq 0) "(got $($blank.ChecksUnread))"
$both = Get-mdiReportStatistics -ReportData (New-Report -SampledOut @('ws6.mdilab.local') -Unresolved @('ghost.mdilab.local'))
Assert-That 'an unresolved host and a sampled-out host are two distinct holes' (
    [int] $both.ChecksUnread -eq 2) "(got $($both.ChecksUnread))"

''
'[disclosure] the issue names the right cause and the right remedy'
$issues = @(Get-mdiIssueList -ReportData (New-Report -SampledOut @('ws6.mdilab.local')) -Statistics $gapped)
$sampledIssue = @($issues | Where-Object { $_.Area -eq 'Not measured' -and $_.Issue -match 'MaxNnrTargets budget was exhausted' })
Assert-That 'the sampled-out target raises exactly one High finding' (
    $sampledIssue.Count -eq 1) "(got $($sampledIssue.Count))"
Assert-That 'the finding names the host' (
    $sampledIssue.Count -eq 1 -and [string] $sampledIssue[0].Server -eq 'ws6.mdilab.local') "(got $($sampledIssue[0].Server))"
Assert-That 'the finding does NOT claim the address could not be resolved' (
    $sampledIssue.Count -eq 1 -and [string] $sampledIssue[0].Issue -notmatch 'could not be resolved to an address')
Assert-That 'a clean run raises no such finding' (
    @(@(Get-mdiIssueList -ReportData (New-Report) -Statistics $clean) |
        Where-Object { $_.Issue -match 'MaxNnrTargets budget was exhausted' }).Count -eq 0)

''
'[disclosure] the verdict refuses READY'
$readyClean = Test-mdiReadinessResult -ReportData (New-Report) 3>$null
$readyGap = Test-mdiReadinessResult -ReportData (New-Report -SampledOut @('ws6.mdilab.local')) 3>$null
Assert-That 'the clean run is READY' ($readyClean -eq $true) "(got $readyClean)"
Assert-That 'a host named but never probed is NOT READY' ($readyGap -ne $true) "(got $readyGap)"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
