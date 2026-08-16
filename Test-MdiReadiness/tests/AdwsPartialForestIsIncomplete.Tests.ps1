<#
    A partial ADWS forest enumeration must not be reported as a complete one.

    Forest discovery over ADWS returns a list of domains. When one of the returned directory records
    carries no usable DNS domain name, or when the list omits the very forest root it claims to
    describe, the enumeration did not cover the forest. The result was still marked Complete with no
    error, so everything downstream treated the shortened list as the whole estate: the missing scope
    was never examined and never charged, no issue was raised, and the run could still reach READY.

    The customer reads READY for a forest whose other domains were silently dropped from the scan.

    Pinned here: discovered rows are still retained, so the fix cannot simply throw the result away; an
    unnameable record or an omitted forest root makes the result incomplete and carries a reason; the
    operator is warned; the missing scope is charged unread; a forest-discovery issue is emitted; and
    READY is blocked. Controls confirm a genuinely complete result is left alone and raises nothing.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
# Sibling first: the suite copies the test and the product script into one flat isolated directory, so
# the copy beside this file is the one under test. A stale copy above that directory would otherwise be
# preferred to it. The parent fallback lets the file also run straight from the repository.
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = [IO.Path]::GetFullPath($target)
$text = [IO.File]::ReadAllText($target)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main')
if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body

$script:passed = 0
$script:failed = 0
$script:warnings = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value {
    param($Message)
    [void] $script:warnings.Add([string] $Message)
}
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:passed++
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray
    } else {
        $script:failed++
        Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red
    }
}

$script:adwsDomains = @()
$script:adwsName = 'contoso.com'
$script:adwsRootDomain = 'contoso.com'
Set-Item -Path function:script:Get-ADForest -Value {
    param($Server, $ErrorAction)
    [PSCustomObject]@{
        Name = $script:adwsName
        RootDomain = $script:adwsRootDomain
        Domains = @($script:adwsDomains)
    }
}
$script:ldapCalled = $false
Set-Item -Path function:script:Get-mdiForestDomainFromLdap -Value {
    param($Domain, [ref] $UnnamedCount)
    $script:ldapCalled = $true
    $null
}

function Invoke-Discovery {
    param(
        [AllowNull()] $Domains,
        [AllowNull()] [string] $Name = 'contoso.com',
        [AllowNull()] [string] $RootDomain = 'contoso.com'
    )
    $script:adwsDomains = @($Domains)
    $script:adwsName = $Name
    $script:adwsRootDomain = $RootDomain
    $script:ldapCalled = $false
    $script:warnings.Clear()
    Get-mdiForestDomain -Domain 'contoso.com'
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

Write-Host 'AdwsPartialForestIsIncomplete.Tests.ps1' -ForegroundColor Cyan

$partial = Invoke-Discovery -Domains @('contoso.com', $null, 'child.contoso.com', '   ')
Write-Host ('  RAW partial={0}' -f ($partial | ConvertTo-Json -Depth 4 -Compress))
Assert-True 'usable ADWS domains are retained' (
    (@($partial.Domains) -join ',') -eq 'contoso.com,child.contoso.com'
) ("domains={0}" -f (@($partial.Domains) -join '|'))
Assert-True 'blank ADWS domain records make forest discovery incomplete' (
    $partial.Complete -eq $false
) ("Complete={0}" -f $partial.Complete)
Assert-True 'partial ADWS discovery carries an error reason' (
    -not [string]::IsNullOrWhiteSpace([string] $partial.Error)
) ("Error={0}" -f $partial.Error)
Assert-True 'partial ADWS discovery warns the operator' (
    @($script:warnings | Where-Object { $_ -match 'incomplete forest list' }).Count -eq 1
) ("warnings={0}" -f ($script:warnings -join ' | '))
Assert-True 'LDAP is not needed to preserve the usable ADWS rows' (-not $script:ldapCalled)

$domains = @($partial.Domains)
$report = [PSCustomObject]@{
    ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
    ForestDiscovery = $partial; DomainsInScope = $domains
    DomainControllers = @($domains | ForEach-Object { New-Dc -Domain $_ })
    CAServers = @(); EntraConnectServers = @()
    DomainAuditing = @($domains | ForEach-Object { New-Audit -Domain $_ })
    LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
    MaxNnrTargets = 0; SkippedAreas = @()
}
$statistics = Get-mdiReportStatistics -ReportData $report 3>$null
$issues = @(Get-mdiIssueList -Statistics $statistics -ReportData $report)
$ready = Test-mdiReadinessResult -ReportData $report
Write-Host ('  RAW surface=passed:{0} total:{1} unread:{2} issues:{3} ready:{4}' -f
    $statistics.ChecksPassed, $statistics.ChecksTotal, $statistics.ChecksUnread, $issues.Count, $ready)
Assert-True 'the missing scope is charged unread' ($statistics.ChecksUnread -ge 1) ("Unread={0}" -f $statistics.ChecksUnread)
Assert-True 'a forest-discovery issue is emitted' (
    @($issues | Where-Object { $_.Area -eq 'Forest discovery' }).Count -eq 1
) ("issues={0}" -f (@($issues | ForEach-Object { $_.Area }) -join '|'))
Assert-True 'partial ADWS discovery blocks READY' ($ready -eq $false) ("Ready={0}" -f $ready)

$rootOmitted = Invoke-Discovery -Domains @('child.contoso.com')
Write-Host ('  RAW root-omitted={0}' -f ($rootOmitted | ConvertTo-Json -Depth 4 -Compress))
Assert-True 'a named list that omits its own forest root is incomplete' (
    $rootOmitted.Complete -eq $false
) ("Complete={0}" -f $rootOmitted.Complete)
Assert-True 'the root omission is explained' (
    [string] $rootOmitted.Error -match 'forest root domain contoso.com is absent'
) ("Error={0}" -f $rootOmitted.Error)

$clean = Invoke-Discovery -Domains @('contoso.com', 'child.contoso.com')
Write-Host ('  RAW clean={0}' -f ($clean | ConvertTo-Json -Depth 4 -Compress))
Assert-True 'control: a fully named ADWS result remains complete' ($clean.Complete -eq $true) ("Complete={0}" -f $clean.Complete)
Assert-True 'control: a complete result carries no error' (
    [string]::IsNullOrWhiteSpace([string] $clean.Error)
) ("Error={0}" -f $clean.Error)
Assert-True 'control: a complete result raises no warning' ($script:warnings.Count -eq 0) ("warnings={0}" -f ($script:warnings -join ' | '))

$nameRecovered = Invoke-Discovery -Domains @('contoso.com', 'child.contoso.com') -Name $null -RootDomain 'contoso.com'
Write-Host ('  RAW name-recovered={0}' -f ($nameRecovered | ConvertTo-Json -Depth 4 -Compress))
Assert-True 'control: RootDomain recovers an absent Name without inventing a gap' (
    $nameRecovered.Name -eq 'contoso.com' -and $nameRecovered.Complete -eq $true
) ("Name={0}; Complete={1}" -f $nameRecovered.Name, $nameRecovered.Complete)

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
