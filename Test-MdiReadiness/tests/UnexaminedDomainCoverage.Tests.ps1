# [w90] A domain whose CONTROLLERS were never enumerated must never be reported as covered, and a
# certification authority in that domain must not make it look covered.
#
# Two defects, both reproduced end to end on the shipped functions before the fix:
#
#   1. Get-mdiUnexaminedDomain narrowed coverage to domain-controller domains only when that set was
#      NON-EMPTY ("if ($dcDomains.Count -gt 0) { $examined = $dcDomains }"). So in the one case that
#      matters most - domain-controller discovery returning NOTHING AT ALL - the guard did not fire,
#      coverage fell back to the all-roles set, and the CA servers' own domains marked every scoped
#      domain examined.
#
#   2. Every call site passed $ReportData.DomainControllers straight through. $ReportData is declared
#      [object[]], so a single report object arrives as a ONE-ELEMENT WRAPPER ARRAY and member
#      enumeration over that wrapper collapses an EMPTY DomainControllers array to $null. Measured:
#      outside the function "$null -ne $r.DomainControllers" is True; inside it is False. The helper
#      reads $null as "this caller has no domain-controller list, fall back to any server" - so even
#      after fix 1, the verdict still fell back and still returned READY.
#
# Measured on the shipped functions with two domains in scope, ZERO domain controllers discovered in
# either, and one reachable CA in each: "2 server(s) across 2 domain(s)", "Overall check score 100%,
# 10 of 10 checks passed", verdict READY, zero issues - beside a domain controller table that said
# there were none. A forest whose controllers were never looked at, certified ready.
#
# Both shapes of "no controllers" are pinned: an EMPTY array and an ABSENT/null property. They reach
# the helper differently and only one of them was ever exercised.

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

function New-RoleServer {
    param([string] $Fqdn, [string] $Domain)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = $Domain
        Unreachable = $false; PartialFailure = $false
        CertificateRootStoreOk = $true; NtlmAuditing = $true
        Details = [PSCustomObject]@{ }
    }
}

function New-Report {
    param($DomainControllers, [object[]] $CAServers)
    [PSCustomObject]@{
        DomainsInScope = @('a.example', 'b.example')
        DomainControllers = $DomainControllers
        CAServers = $CAServers
        EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
}

$cas = @((New-RoleServer -Fqdn 'ca1.a.example' -Domain 'a.example'),
    (New-RoleServer -Fqdn 'ca2.b.example' -Domain 'b.example'))

# ---------------------------------------------------------------------------------------------
'[w90] zero domain controllers discovered, CA reached in each domain'
foreach ($shape in @(
        @{ Label = 'DomainControllers is an EMPTY ARRAY'; Dc = @() },
        @{ Label = 'DomainControllers is ABSENT (null)'; Dc = $null })) {

    $report = New-Report -DomainControllers $shape.Dc -CAServers $cas
    $stats = Get-mdiReportStatistics -ReportData $report
    $issues = @(Get-mdiIssueList -ReportData $report -Statistics $stats)
    $discovery = @($issues | Where-Object { [string] $_.Area -match 'Discovery' })
    $ready = Test-mdiReadinessResult -ReportData $report

    "  -- $($shape.Label)"
    Assert-That "    the fixture really did reach the CA servers ($($shape.Label))" ([int] $stats.TotalServers -eq 2) `
        "(TotalServers $($stats.TotalServers) - if 0 this is the empty-scan case and tests nothing)"
    Assert-That "    the verdict REFUSES ready ($($shape.Label))" (-not $ready) "(Ready $ready)"
    Assert-That "    a discovery finding names the uncovered domain(s) ($($shape.Label))" ($discovery.Count -ge 1) `
        "($($discovery.Count) discovery issue(s) of $($issues.Count) total)"
}

# ---------------------------------------------------------------------------------------------
'[w90] the helper itself, both shapes'
$unexEmpty = @(Get-mdiUnexaminedDomain -ScopedDomain @('a.example', 'b.example') -Server $cas -DomainControllerServer @())
Assert-That 'an empty domain-controller list leaves BOTH scoped domains unexamined' ($unexEmpty.Count -eq 2) `
    "($($unexEmpty.Count): $($unexEmpty -join ','))"
Assert-That 'and it does not silently accept the CA domains as coverage' `
    (($unexEmpty -contains 'a.example') -and ($unexEmpty -contains 'b.example')) "($($unexEmpty -join ','))"

# The distinction the whole fix rests on: servers were found, just not domain controllers. That is
# NOT the empty-scan case, which is reported separately and must still return nothing here.
$unexNothing = @(Get-mdiUnexaminedDomain -ScopedDomain @('a.example', 'b.example') -Server @() -DomainControllerServer @())
Assert-That 'a scan that found NO server at all is left to the empty-scan path' ($unexNothing.Count -eq 0) `
    "($($unexNothing.Count): $($unexNothing -join ','))"

# ---------------------------------------------------------------------------------------------
'[w90] controls: a domain WITH a controller is still covered'
$dcs = @((New-RoleServer -Fqdn 'dc1.a.example' -Domain 'a.example'),
    (New-RoleServer -Fqdn 'dc2.b.example' -Domain 'b.example'))
$unexBoth = @(Get-mdiUnexaminedDomain -ScopedDomain @('a.example', 'b.example') -Server ($dcs + $cas) -DomainControllerServer $dcs)
Assert-That 'both domains covered by a controller report nothing unexamined' ($unexBoth.Count -eq 0) `
    "($($unexBoth -join ','))"

$unexOne = @(Get-mdiUnexaminedDomain -ScopedDomain @('a.example', 'b.example') -Server ($dcs[0], $cas[1]) -DomainControllerServer @($dcs[0]))
Assert-That 'only the domain missing a controller is named' (($unexOne.Count -eq 1) -and ($unexOne[0] -eq 'b.example')) `
    "($($unexOne -join ','))"
Assert-That 'a CA in that domain does not rescue it' (-not ($unexOne -contains 'a.example')) "($($unexOne -join ','))"

# Case and trailing-dot equivalence must survive the change (the helper's original purpose).
$unexCase = @(Get-mdiUnexaminedDomain -ScopedDomain @('A.Example', 'b.example.') `
        -Server $dcs -DomainControllerServer $dcs)
Assert-That 'case and trailing-dot spellings still count as covered' ($unexCase.Count -eq 0) "($($unexCase -join ','))"

# ---------------------------------------------------------------------------------------------
'[w90] a covered estate is still allowed to be READY'
$goodReport = New-Report -DomainControllers $dcs -CAServers $cas
$goodReady = Test-mdiReadinessResult -ReportData $goodReport
$goodStats = Get-mdiReportStatistics -ReportData $goodReport
$goodDiscovery = @(Get-mdiIssueList -ReportData $goodReport -Statistics $goodStats | Where-Object { [string] $_.Area -match 'Discovery' })
Assert-That 'a fully covered estate raises no discovery finding' ($goodDiscovery.Count -eq 0) "($($goodDiscovery.Count))"
Assert-That 'and the verdict is not blocked by this rule' ($goodReady -eq $true) `
    "(Ready $goodReady - if false the guard now rejects a covered estate, which is worse than the defect)"

''
"UnexaminedDomainCoverage: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
