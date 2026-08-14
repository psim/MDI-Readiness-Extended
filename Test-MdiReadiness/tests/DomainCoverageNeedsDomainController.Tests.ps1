<#
    Behavioural regression test: a domain is only examined when a DOMAIN CONTROLLER in it was scanned.

    Coverage was computed from the merged union of all three role lists, so a certification authority
    or an Entra Connect server was enough to mark its domain covered. A child domain whose
    domain-controller discovery returned NOTHING therefore came back fully examined - no discovery
    finding, and a verdict of READY - because a CA in that domain had been reached.

    This tool exists to report domain controller readiness. Declaring an estate ready without having
    looked at a whole domain's controllers is the largest false green it can produce, so the three
    surfaces that judge coverage - the score, the issue list and the verdict - are all checked here.
#>

param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }

$text = [IO.File]::ReadAllText($scriptPath)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main'); if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:passed++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray }
    else { $script:failed++; Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red }
}

Write-Host 'DomainCoverageNeedsDomainController.Tests.ps1' -ForegroundColor Cyan

function New-Dc {
    param([string] $Fqdn, [string] $Domain)
    [PSCustomObject]@{ FQDN = $Fqdn; Domain = $Domain; Unreachable = $false
        OperatingSystem = 'Windows Server 2022'
        NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true
        Details = [ordered]@{} }
}
function New-Ca {
    param([string] $Fqdn, [string] $Domain)
    [PSCustomObject]@{ FQDN = $Fqdn; Domain = $Domain; Unreachable = $false
        OperatingSystem = 'Windows Server 2022'; CAAuditing = $true
        Details = [ordered]@{} }
}
function New-CoverageReport {
    param($DomainControllers, $CAServers)
    [PSCustomObject]@{
        Domain = 'root.example'; Forest = 'root.example'
        DomainsInScope = @('root.example', 'child.root.example')
        DomainControllers = @($DomainControllers); CAServers = @($CAServers); EntraConnectServers = @()
    }
}
function Get-Surfaces {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    [PSCustomObject]@{
        Stats  = $stats
        Issues = @(Get-mdiIssueList -Statistics $stats -ReportData $Report)
        Ready  = (Test-mdiReadinessResult -ReportData $Report)
    }
}

# --- The defect: a CA server standing in for a whole domain's controllers ----------------------
$masked = Get-Surfaces -Report (New-CoverageReport `
        -DomainControllers @((New-Dc 'dc1.root.example' 'root.example')) `
        -CAServers @((New-Ca 'ca1.child.root.example' 'child.root.example')))

$discoveryIssues = @($masked.Issues | Where-Object { [string] $_.Area -eq 'Discovery' })
Assert-True 'a domain with no domain controller scanned raises a discovery finding' `
    ($discoveryIssues.Count -ge 1) `
    ((@($masked.Issues | ForEach-Object { '{0}/{1}' -f $_.Area, $_.Server }) -join '; '))
Assert-True 'the finding names the domain that was missed' `
    (@($discoveryIssues | Where-Object { [string] $_.Server -like '*child.root.example*' }).Count -ge 1) `
    ((@($discoveryIssues | ForEach-Object { [string] $_.Server }) -join ', '))
Assert-True 'and the run is NOT ready' ($masked.Ready -eq $false) ("ready={0}" -f $masked.Ready)
# The wording must not be contradicted by the server table on the same page: a CA server in that
# domain WAS reached, so "no server could be enumerated" would be visibly false.
Assert-True 'the finding says no domain controller, not no server' `
    (@($discoveryIssues | Where-Object { [string] $_.Issue -match 'domain controller' }).Count -ge 1) `
    ((@($discoveryIssues | ForEach-Object { [string] $_.Issue }) -join ' | '))
Assert-True 'the unexamined domain is charged as unread in the score' `
    ($masked.Stats.ChecksUnread -ge 1) ("unread={0}" -f $masked.Stats.ChecksUnread)

# --- Control: both domains with a domain controller must stay clean ---------------------------
$covered = Get-Surfaces -Report (New-CoverageReport `
        -DomainControllers @((New-Dc 'dc1.root.example' 'root.example'), (New-Dc 'dc1.child.root.example' 'child.root.example')) `
        -CAServers @((New-Ca 'ca1.child.root.example' 'child.root.example')))
Assert-True 'control: every scoped domain with a domain controller raises no discovery finding' `
    (@($covered.Issues | Where-Object { [string] $_.Area -eq 'Discovery' }).Count -eq 0) `
    ((@($covered.Issues | ForEach-Object { '{0}/{1}' -f $_.Area, $_.Server }) -join '; '))
Assert-True 'control: and that run is ready' ($covered.Ready -eq $true) ("ready={0}" -f $covered.Ready)

# --- The predicate directly ---------------------------------------------------------------------
$dcOnly = @((New-Dc 'dc1.root.example' 'root.example'))
$allServers = @($dcOnly + (New-Ca 'ca1.child.root.example' 'child.root.example'))
Assert-True 'the predicate ignores a CA server when deciding coverage' `
    ((@(Get-mdiUnexaminedDomain -ScopedDomain @('root.example', 'child.root.example') -Server $allServers -DomainControllerServer $dcOnly) -join ',') -eq 'child.root.example') `
    ((@(Get-mdiUnexaminedDomain -ScopedDomain @('root.example', 'child.root.example') -Server $allServers -DomainControllerServer $dcOnly) -join ','))
Assert-True 'a domain WITH a domain controller is never reported unexamined' `
    (@(Get-mdiUnexaminedDomain -ScopedDomain @('root.example') -Server $allServers -DomainControllerServer $dcOnly).Count -eq 0)
# A trailing dot and a different case are the same DNS name, and that must survive the new path.
Assert-True 'coverage still ignores case and a trailing dot' `
    (@(Get-mdiUnexaminedDomain -ScopedDomain @('ROOT.EXAMPLE.') -Server $allServers -DomainControllerServer $dcOnly).Count -eq 0)
# A report that carries no domain-controller list AT ALL must not declare every domain missing.
#
# $null, not @(). The two are different facts and conflating them was itself a false green:
#   $null = the report has no domain-controller list (a legacy or hand-edited report) -> fall back
#   @()   = the list is present and EMPTY, i.e. domain-controller discovery returned NOTHING, which
#           is precisely the gap this rule exists to catch and must NOT fall back.
# These two cases passed @() and so pinned the old conflation; UnexaminedDomainCoverage.Tests.ps1
# now asserts the @() behaviour directly. Verified against the shipped function before editing
# (MDI-AB\live\w91-scope-semantics.ps1): $null and an omitted argument both yield [orphan.example],
# while @() yields [root.example,child.root.example,orphan.example].
Assert-True 'a report with no domain-controller list falls back to any server' `
    (@(Get-mdiUnexaminedDomain -ScopedDomain @('root.example') -Server $allServers -DomainControllerServer $null).Count -eq 0)
# ...and the fallback must still be DOING something: with no domain-controller list, a domain that no
# server of any kind reached is still a gap. Without this case the fallback could be deleted outright
# and nothing would notice, because an empty examined-set short-circuits to "no findings" anyway.
Assert-True 'and it still reports a domain that nothing reached at all' `
    ((@(Get-mdiUnexaminedDomain -ScopedDomain @('root.example', 'child.root.example', 'orphan.example') `
                -Server $allServers -DomainControllerServer $null) -join ',') -eq 'orphan.example') `
    ((@(Get-mdiUnexaminedDomain -ScopedDomain @('root.example', 'child.root.example', 'orphan.example') `
                -Server $allServers -DomainControllerServer $null) -join ','))
Assert-True 'and a scan that produced nothing anywhere reports no per-domain gaps' `
    (@(Get-mdiUnexaminedDomain -ScopedDomain @('root.example') -Server @() -DomainControllerServer @()).Count -eq 0)

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
