<#
    Behavioural regression test: a blocker that MEASURED NOTHING is never published as PROOF.

    report.Readiness is the MACHINE-READABLE verdict, and Get-mdiPublishedReadiness is tri-state by
    contract: $true when the run proved readiness, $false when it proved a failure, and the string
    'N/A' when the run did not gather enough evidence to decide.

    It cannot see WHY the verdict said no. It decides from the statistics alone:

        if ($ReadinessResult) { return $true }
        if ($knownFailures -gt 0) { return $false }                       # a measured failure
        if ($totalServers -eq 0 -or $partialScans -gt 0) { return 'N/A' }
        if ($knownFailures -eq 0 -and $unread -gt 0) { return 'N/A' }
        $false                                                            # fall-through

    So the ONLY thing standing between "the verdict refused READY because nothing was measured" and
    a published, definite $false is an UNREAD CHECK charged in Get-mdiReportStatistics. The two
    functions are separate, and nothing connected them.

    Test-mdiReadinessResult refuses READY for a family of conditions whose defining property is that
    NOTHING WAS MEASURED - the product says so itself, in its own warnings:

        LdapPlanGapDomains            "The sensor-to-domain path was never measured there"
        NnrPlanGapDomains             "Whether the sensors can resolve names there was never measured"
        AddresslessDomainControllers  "They were never included in the LDAP or NNR probe plans"
        NnrUnresolvedTargets          "could not be resolved to an address and were never probed"
        NnrSampledOutTargets          "resolved but were never probed because the budget was exhausted"
        ForestDiscovery.Complete=$false  a domain this forest HAS that this run could not name
        an unexamined scoped domain      a domain in scope that no scanned server row matched

    If any one of them is NOT charged an unread check, that run publishes Readiness = $false: a
    definite machine-readable claim that the estate was PROVEN not ready, manufactured from a hole
    the tool states it never looked into. A pipeline gating on the field fails the build citing
    evidence that does not exist - the same "a value nobody read came back looking like a
    measurement" failure this tool exists to prevent, pointed at its own headline.

    The extended cross-forest topology is what makes every member of the family ordinary rather than
    exotic. -MaxNnrTargets is ONE GLOBAL budget the domains compete for and its shipped default is
    5, so with mdilab.local, emea.mdilab.local, apac.mdilab.local and fabrikam.local in scope a whole
    domain starves and is charged to NnrPlanGapDomains. A domain controller across the trust
    routinely resolves to no usable address. ADWS refusing a cross-forest caller is exactly what
    leaves ForestDiscovery incomplete.

    Measured on the shipped functions, one otherwise-perfect single-server run, one blocker at a
    time - every member of the family is charged and every one publishes 'N/A'. Removing the unread
    charge for any single member (mutation-tested against NnrSampledOutTargets) flips that member to
    published=False with unread=0 while the verdict is unchanged, which is the defect this pins.

    Also pinned: the contrast case - a MEASURED failing check still publishes a definite $false, so
    this invariant can never be satisfied by publishing 'N/A' for everything - and that an
    unreadable list ($null, '', whitespace, a non-numeric string, an int, a boolean, a hashtable, an
    empty array, an array of nulls) cannot manufacture a proven verdict either.
#>

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

function New-Server {
    param([bool] $RequirementsOk = $true)
    [PSCustomObject]@{
        FQDN = 'dc1.mdilab.local'; Domain = 'mdilab.local'
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        ServerRequirements = $RequirementsOk; AdvancedAuditing = $true; NtlmAuditing = $true
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
    param([hashtable] $Override = @{})
    $r = [ordered]@{
        ScriptVersion = 'test'; Domain = 'mdilab.local'; Forest = 'mdilab.local'
        ForestDiscovery = [PSCustomObject]@{ Name = 'mdilab.local'; Domains = @('mdilab.local'); Method = 'stub'; Complete = $true; Error = $null }
        DomainsInScope = @('mdilab.local')
        LdapPlanGapDomains = @(); NnrPlanGapDomains = @()
        NnrUnresolvedTargets = @(); NnrSampledOutTargets = @()
        AddresslessDomainControllers = @()
        NnrTargetComputer = @(); MaxNnrTargets = 5
        DomainControllers = @(New-Server)
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(New-Domain)
        DomainSchemaVersion = [PSCustomObject]@{ details = 'Windows Server 2016'; schemaVersion = 87 }
        SkippedAreas = @()
    }
    foreach ($k in $Override.Keys) { $r[$k] = $Override[$k] }
    [PSCustomObject] $r
}

# The three shipped functions, in the order Main calls them.
function Measure-Report {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    $result = Test-mdiReadinessResult -ReportData $Report 3>$null
    [PSCustomObject]@{
        Ready     = $result
        Unread    = [int] $stats.ChecksUnread
        Total     = [int] $stats.ChecksTotal
        Passed    = [int] $stats.ChecksPassed
        Published = Get-mdiPublishedReadiness -ReadinessResult ([bool] $result) -Statistics $stats
    }
}
function Format-Published {
    param($Value)
    ("'{0}' [{1}]" -f $Value, $(if ($null -eq $Value) { 'null' } else { $Value.GetType().Name }))
}

# --- Control: the baseline must be a clean, proven-ready run ----------------------------------
# Without this the whole file could pass by measuring a report that was already broken.
$clean = Measure-Report (New-Report)
Assert-That 'the baseline run is READY' ($clean.Ready -eq $true) "(got $($clean.Ready))"
Assert-That 'the baseline run charges no unread check' ($clean.Unread -eq 0) "(got $($clean.Unread))"
Assert-That 'the baseline run publishes $true' `
    (($clean.Published -is [bool]) -and $clean.Published -eq $true) (Format-Published $clean.Published)

# --- The family: one blocker at a time on an otherwise perfect run ----------------------------
$family = @(
    @{ Name = 'a named NNR target that resolved to no address'; Over = @{ NnrUnresolvedTargets = @('ghost.mdilab.local') } }
    @{ Name = 'a named NNR target dropped by the -MaxNnrTargets budget'; Over = @{ NnrSampledOutTargets = @('ws6.mdilab.local') } }
    @{ Name = 'a domain that received no LDAP probe target'; Over = @{ LdapPlanGapDomains = @('apac.mdilab.local') } }
    @{ Name = 'a domain that received no NNR probe target'; Over = @{ NnrPlanGapDomains = @('apac.mdilab.local') } }
    @{ Name = 'a domain controller with no usable address'; Over = @{ AddresslessDomainControllers = @('dcfab01.fabrikam.local') } }
    @{ Name = 'a forest whose domain list is incomplete'; Over = @{ ForestDiscovery = [PSCustomObject]@{
                Name = 'mdilab.local'; Domains = @('mdilab.local'); Method = 'stub'; Complete = $false
                Error = 'one or more domain records could not be named' } } }
    @{ Name = 'a scoped domain no scanned server matched'; Over = @{ DomainsInScope = @('mdilab.local', 'fabrikam.local') } }
)

foreach ($case in $family) {
    $m = Measure-Report (New-Report -Override $case.Over)

    # The verdict must refuse READY - that part has always worked and is not what this pins.
    Assert-That ("{0}: refuses READY" -f $case.Name) ($m.Ready -ne $true) "(got $($m.Ready))"

    # The charge is the mechanism. Without it the publish step cannot tell this apart from a run
    # that proved a failure, because the statistics are all it is given.
    Assert-That ("{0}: is charged at least one unread check" -f $case.Name) `
        ($m.Unread -ge 1) "(unread=$($m.Unread))"

    # The numerator must not move: nothing was observed failing, so no check may be marked failed.
    Assert-That ("{0}: does not invent a failed check" -f $case.Name) `
        ($m.Passed -eq $m.Total) "(passed=$($m.Passed) total=$($m.Total))"

    # The published verdict is the defect. 'N/A' means "not enough evidence"; $false is a claim.
    Assert-That ("{0}: publishes 'N/A' rather than a proven False" -f $case.Name) `
        (($m.Published -is [string]) -and $m.Published -eq 'N/A') (Format-Published $m.Published)
}

# --- Contrast: this invariant must not be satisfied by publishing 'N/A' for everything ---------
$measuredFailure = Measure-Report (New-Report -Override @{ DomainControllers = @(New-Server -RequirementsOk $false) })
Assert-That 'a MEASURED failing check still publishes a definite $false' `
    (($measuredFailure.Published -is [bool]) -and $measuredFailure.Published -eq $false) `
    (Format-Published $measuredFailure.Published)
Assert-That 'and that failure is counted, not charged as unread' `
    ($measuredFailure.Passed -lt $measuredFailure.Total -and $measuredFailure.Unread -eq 0) `
    "(passed=$($measuredFailure.Passed) total=$($measuredFailure.Total) unread=$($measuredFailure.Unread))"

# A measured failure alongside an unmeasured hole is still a proven failure.
$mixed = Measure-Report (New-Report -Override @{
        DomainControllers = @(New-Server -RequirementsOk $false)
        NnrPlanGapDomains = @('apac.mdilab.local')
    })
Assert-That 'a measured failure outranks an unmeasured hole in the same run' `
    (($mixed.Published -is [bool]) -and $mixed.Published -eq $false) (Format-Published $mixed.Published)

# --- An unreadable list cannot manufacture a proven verdict either -----------------------------
$lists = @('LdapPlanGapDomains', 'NnrPlanGapDomains', 'AddresslessDomainControllers',
    'NnrUnresolvedTargets', 'NnrSampledOutTargets')
$shapes = @(
    @{ N = 'null'; V = $null }
    @{ N = 'an empty string'; V = '' }
    @{ N = 'whitespace'; V = '   ' }
    @{ N = 'a non-numeric string'; V = 'abc' }
    @{ N = 'an int'; V = 7 }
    @{ N = 'a boolean'; V = $true }
    @{ N = 'a hashtable'; V = @{ x = 1 } }
    @{ N = 'an empty array'; V = @() }
    @{ N = 'an array of nulls'; V = @($null, $null) }
)
foreach ($list in $lists) {
    foreach ($shape in $shapes) {
        $threw = $false; $m = $null
        try { $m = Measure-Report (New-Report -Override @{ $list = $shape.V }) } catch { $threw = $true }
        Assert-That ("{0} as {1} does not throw" -f $list, $shape.N) (-not $threw)
        if (-not $threw) {
            $withinContract = (($m.Published -is [bool]) -and $m.Published -eq $true) -or
                              (($m.Published -is [string]) -and $m.Published -eq 'N/A')
            Assert-That ("{0} as {1} does not manufacture a proven False" -f $list, $shape.N) `
                $withinContract "(ready=$($m.Ready) unread=$($m.Unread) published=$(Format-Published $m.Published))"
        }
    }
}

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
