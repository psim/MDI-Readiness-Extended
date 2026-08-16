<#
    The issue raised for an incomplete forest enumeration must describe the scope actually covered.

    When discovery returns a partial domain list the run raises an issue explaining what happened. That
    text collapsed the partial result down to the forest root, so a scan that had in fact included two
    domains reported only one, and a scan whose root was the missing domain reported the root as though
    it were the domain examined. The issue therefore claimed an examination that never ran, on the one
    line an operator reads to find out what the scan missed.

    Pinned here: a root-omission issue names the child that was included rather than the root that was
    not; the issue does not claim the omitted root was the only domain examined; it reports the number
    of known scoped domains and names each of them; it does not collapse a multi-domain partial result
    to the root; and the corrected wording still does not weaken the incomplete-discovery verdict.
#>

$ErrorActionPreference = 'Stop'

$canonical = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $canonical)) { $canonical = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$canonical = [IO.Path]::GetFullPath($canonical)
$text = [IO.File]::ReadAllText($canonical)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main')
if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body

Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([bool] $Condition, [string] $Message, [string] $Detail = '')
    if ($Condition) {
        $script:passed++
        Write-Output "  PASS  $Message"
    }
    else {
        $script:failed++
        Write-Output "  FAIL  $Message$(if ($Detail) { ' -- ' + $Detail })"
    }
}
function New-Dc {
    param([string] $Domain)
    [PSCustomObject]@{
        FQDN = "dc.$Domain"; Domain = $Domain; Unreachable = $false; PartialFailure = $false
        OSVersion = $true; AdvancedAuditing = $true; PowerSettings = $true; NtlmAuditing = $true
        Details = [PSCustomObject]@{}
    }
}
function New-Audit {
    param([string] $Domain)
    [PSCustomObject]@{
        Domain = $Domain
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
    }
}
function Invoke-PartialForestReport {
    param([string[]] $Domains, [string] $Error)
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'root.test'; Forest = 'root.test'
        ForestDiscovery = [PSCustomObject]@{
            Name = 'root.test'; Domains = @($Domains); Method = 'LDAP'; Complete = $false; Error = $Error
        }
        DomainsInScope = @($Domains)
        DomainControllers = @($Domains | ForEach-Object { New-Dc $_ })
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @($Domains | ForEach-Object { New-Audit $_ })
        LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
        MaxNnrTargets = 0; SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report 3>$null
    [PSCustomObject]@{
        Issue = @(Get-mdiIssueList -Statistics $stats -ReportData $report |
                Where-Object { $_.Area -eq 'Forest discovery' })[0]
        Ready = [bool](Test-mdiReadinessResult -ReportData $report)
    }
}

Write-Output 'An incomplete forest issue names the domains actually included in scope'
$rootOmitted = Invoke-PartialForestReport -Domains @('child.root.test') `
    -Error 'the forest root domain root.test is absent from the returned domain list'
$rootText = [string]$rootOmitted.Issue.Issue
Write-Output "  RAW root-omitted=$rootText"
Assert-True ($rootText -match 'child\.root\.test') `
    'a root-omission issue names the child that was included' "Issue=$rootText"
Assert-True ($rootText -notmatch 'only root\.test was examined') `
    'the issue does not claim that the omitted root was the only domain examined' "Issue=$rootText"
Assert-True ($rootText -match 'discovered domain included in scope') `
    'the issue describes scope rather than claiming successful examination' "Issue=$rootText"
Assert-True (-not $rootOmitted.Ready) `
    'the corrected wording does not weaken the incomplete-discovery verdict'

Write-Output 'All known domains are named when discovery is partial'
$twoKnown = Invoke-PartialForestReport -Domains @('root.test', 'child.root.test') `
    -Error 'one directory record did not contain a usable DNS domain name'
$twoText = [string]$twoKnown.Issue.Issue
Write-Output "  RAW two-known=$twoText"
Assert-True ($twoText -match '2 discovered domains were included in scope') `
    'the issue reports the number of known scoped domains' "Issue=$twoText"
Assert-True ($twoText -match 'root\.test') `
    'the issue names the known forest root' "Issue=$twoText"
Assert-True ($twoText -match 'child\.root\.test') `
    'the issue names the known child' "Issue=$twoText"
Assert-True ($twoText -notmatch 'only root\.test was examined') `
    'the issue does not collapse a multi-domain partial result to the root' "Issue=$twoText"

Write-Output "RESULT: $script:passed passed / $script:failed failed"
if ($script:failed -gt 0) { exit 1 }
