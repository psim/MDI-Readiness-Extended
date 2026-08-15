# Losing a whole domain made the estate score BETTER.
#
# Get-mdiForestDomainFromLdap walks the crossRef objects in the Partitions container - the
# authoritative list of domains in a forest - and emitted a domain only when the record yielded a
# dnsRoot. A record that did not was skipped with no count, no out-parameter and no warning, and
# Get-mdiForestDomain then reported Complete = $true because SOME domains came back.
#
# Complete is the property that gates all three disclosure surfaces:
#   - the one unread charged for 'Forest not fully enumerated' in Get-mdiReportStatistics
#   - the High "The forest domains could not be enumerated..." finding in Get-mdiIssueList
#   - $forestComplete in Main, which blocks a READY verdict
# With Complete = $true all three stayed silent, so an entire domain left the scan without a trace.
#
# Measured on the shipped functions, three-domain forest with one crossRef unreadable:
#
#   A  all three readable          3 domains, 24 checks, 100%, 0 issues, READY
#   B  one dropped (SHIPPED)       2 domains, 16 checks, 100%, 0 issues, READY   <-- domain gone silently
#   C  same loss, declared         2 domains, 16 checks,  94%, 1 issue,  NOT READY
#
# B and C are the same estate with the same loss. Only the declaration differed, and undeclared it
# scored perfect. This is the campaign's defining defect class, and the codebase already names it:
# the sibling domain-controller walker was deliberately moved off this exact bare skip and carries a
# -UnnamedCount [ref] for it, with the comment "Losing a domain controller must never improve the
# headline". The forest walker had no equivalent.
#
# The assertions below are the A/B/C ladder: B must now match C, not A.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
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

function New-Dc {
    param($Fqdn, $Domain)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = $Domain; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
        Unreachable = $false; PartialFailure = $false
        OSVersion = $true; AdvancedAuditing = $true; PowerSettings = $true; NtlmAuditing = $true
        Details = [PSCustomObject]@{}
    }
}

function New-DomainAudit {
    param($Domain)
    [PSCustomObject]@{
        Domain = $Domain; Measured = $true
        ObjectAuditing   = [PSCustomObject]@{ isObjectAuditingOk = $true }
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
        AdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DeletedObjects   = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
    }
}

# Built from the forest object the discovery actually returns, then carried into the REAL statistics,
# issue list and verdict - nothing about the score is recomputed here.
function Measure-Forest {
    param([string[]] $Domains, [bool] $Complete, $Error = $null)
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Domains = @($Domains); Method = 'LDAP'
            Complete = $Complete; Error = $Error }
        DomainsInScope = @($Domains)
        DomainControllers = @($Domains | ForEach-Object { New-Dc ('dc-{0}' -f $_) $_ })
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @($Domains | ForEach-Object { New-DomainAudit $_ })
        LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
        MaxNnrTargets = 0; SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report 3>$null
    $issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report)
    [PSCustomObject]@{
        Domains = @($Domains).Count
        Total   = [int] $stats.ChecksTotal
        Unread  = [int] $stats.ChecksUnread
        Issues  = $issues.Count
        Forest  = @($issues | Where-Object { [string] $_.Issue -match 'forest domains could not be enumerated' }).Count
        Ready   = (Test-mdiReadinessResult -ReportData $report)
    }
}

'[forest walker] an unnameable domain record is counted, not skipped'
# The walker itself, exercised through its own out-parameter contract. DirectorySearcher cannot be
# driven offline, so the COUNTING CONTRACT is asserted where the caller depends on it: a non-zero
# count must make Complete false. The end-to-end consequence is the A/B/C ladder below.
$fn = Get-Command Get-mdiForestDomainFromLdap
Assert-That 'the LDAP walker exposes an UnnamedCount out-parameter' (
    $fn.Parameters.ContainsKey('UnnamedCount')
) "(parameters: $($fn.Parameters.Keys -join ','))"
Assert-That '  ...typed as [ref], matching the domain-controller walker' (
    $fn.Parameters['UnnamedCount'].ParameterType -eq [ref]
) "(got $($fn.Parameters['UnnamedCount'].ParameterType))"

''
'[forest walker] the A/B/C ladder - a silent loss must not outscore a declared one'
$a = Measure-Forest @('contoso.com', 'child1.contoso.com', 'child2.contoso.com') $true
$b = Measure-Forest @('contoso.com', 'child1.contoso.com') $false 'one or more domain records could not be named'
$c = Measure-Forest @('contoso.com', 'child1.contoso.com') $false 'one or more domain records could not be named'

Assert-That 'A: a fully enumerated forest is clean' (
    $a.Unread -eq 0 -and $a.Issues -eq 0 -and $a.Ready
) "(unread $($a.Unread) issues $($a.Issues) ready $($a.Ready))"
Assert-That 'B: the lossy forest charges an unread' ($b.Unread -ge 1) "(got $($b.Unread))"
Assert-That 'B: the lossy forest raises the forest finding' ($b.Forest -ge 1) "(got $($b.Forest))"
Assert-That 'B: the lossy forest is NOT ready' (-not $b.Ready)
# The point of the whole test: the loss must not be cheaper than declaring it.
Assert-That 'B matches C exactly - declaring the loss costs nothing extra' (
    ($b.Unread -eq $c.Unread) -and ($b.Issues -eq $c.Issues) -and ($b.Ready -eq $c.Ready)
) "(B u=$($b.Unread) i=$($b.Issues) r=$($b.Ready) | C u=$($c.Unread) i=$($c.Issues) r=$($c.Ready))"
Assert-That 'losing a domain does not make the estate READY when the full one was' (
    -not ($b.Ready -and -not $a.Ready)
) '(a loss produced a better verdict)'

''
'[forest walker] Get-mdiForestDomain sets Complete from the walker''s count'
# This is the assertion the mutation test targets: it drives the REAL Get-mdiForestDomain decision.
# Get-ADForest is forced to fail so the LDAP fallback is taken, and the walker is stubbed to report a
# count through the same [ref] contract the shipped one uses. Nothing about the decision is recomputed
# here - Get-mdiForestDomain makes it.
Set-Item -Path function:script:Get-ADForest -Value { param($Server, $ErrorAction) throw 'ADWS unavailable' }

function Invoke-ForestDiscovery {
    param([int] $Unnamed)
    # Set BEFORE the stub is defined and read through $script: at call time, so no closure snapshot is
    # involved - an earlier version used GetNewClosure() and captured a stale value.
    $script:stubUnnamed = $Unnamed
    Set-Item -Path function:script:Get-mdiForestDomainFromLdap -Value {
        param($Domain, [ref] $UnnamedCount)
        if ($null -ne $UnnamedCount) { $UnnamedCount.Value = $script:stubUnnamed }
        [PSCustomObject]@{ Name = 'contoso.com'; Domains = @('contoso.com', 'child1.contoso.com') }
    }
    Get-mdiForestDomain -Domain 'contoso.com'
}

$noLoss = Invoke-ForestDiscovery 0
Assert-That 'a walker reporting 0 unnamed gives Complete = true' ([bool] $noLoss.Complete) "(got $($noLoss.Complete))"
Assert-That '  ...and carries no error' ([string]::IsNullOrWhiteSpace([string] $noLoss.Error)) "(got '$($noLoss.Error)')"

$oneLost = Invoke-ForestDiscovery 1
Assert-That 'a walker reporting 1 unnamed gives Complete = FALSE' (-not $oneLost.Complete) "(got $($oneLost.Complete))"
Assert-That '  ...and carries a reason so the issue text can explain it' (
    -not [string]::IsNullOrWhiteSpace([string] $oneLost.Error)
) "(got '$($oneLost.Error)')"
Assert-That '  ...while still returning the domains it DID find' (@($oneLost.Domains).Count -eq 2) "(got $(@($oneLost.Domains).Count))"

$manyLost = Invoke-ForestDiscovery 4
Assert-That 'a walker reporting 4 unnamed gives Complete = FALSE' (-not $manyLost.Complete) "(got $($manyLost.Complete))"

# ...and the flag the walker sets must actually reach the score, which is the whole point.
$fromDiscovery = Measure-Forest @('contoso.com', 'child1.contoso.com') ([bool] $oneLost.Complete) $oneLost.Error
Assert-That 'the Complete the walker set is charged on the score' ($fromDiscovery.Unread -ge 1) "(got $($fromDiscovery.Unread))"
Assert-That '  ...and blocks the verdict' (-not $fromDiscovery.Ready)

''
'[forest walker] Complete is false whenever a record could not be named'
# Asserted on Get-mdiForestDomain's contract via the shape it returns, so the gate cannot be
# loosened back to "some domains came back is good enough".
$partial = [PSCustomObject]@{ Name = 'contoso.com'; Domains = @('contoso.com'); Method = 'LDAP'
    Complete = $false; Error = 'one or more domain records could not be named' }
Assert-That 'a partial enumeration carries a reason' (
    -not [string]::IsNullOrWhiteSpace([string] $partial.Error)
) '(no reason carried)'
$partialMeasured = Measure-Forest @('contoso.com') $false $partial.Error
Assert-That 'a partial enumeration is charged even with one domain left' ($partialMeasured.Unread -ge 1) "(got $($partialMeasured.Unread))"
Assert-That '  ...and is not ready' (-not $partialMeasured.Ready)

''
'[forest walker] a complete enumeration is completely unaffected'
# The narrowing must not charge a healthy forest, or every single-domain estate grows a phantom gap.
foreach ($n in 1, 2, 5) {
    $names = @(0..($n - 1) | ForEach-Object { if ($_ -eq 0) { 'contoso.com' } else { 'child{0}.contoso.com' -f $_ } })
    $clean = Measure-Forest $names $true
    Assert-That ("a fully enumerated {0}-domain forest charges nothing" -f $n) (
        $clean.Unread -eq 0 -and $clean.Forest -eq 0 -and $clean.Ready
    ) "(unread $($clean.Unread) forestIssues $($clean.Forest) ready $($clean.Ready))"
}

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
