<#
    An LDAP crossRef list that omits its own forest root must not be reported as complete.

    Forest discovery over LDAP reads the crossRef container and returns the domains it finds. A list
    that comes back without the forest root is not a forest that has no root - it is an enumeration
    that did not finish. The result was nevertheless marked Complete with a null error, so the domains
    that were never examined disappeared from the estate without being counted anywhere.

    Pinned here: the domain that WAS discovered is still returned, the missing forest root makes the
    result incomplete and is named in the error text, the operator is warned, the unexamined scope is
    charged unread, the issue list reports forest discovery, and the run cannot reach READY. Controls
    confirm a list that does contain its root stays complete, error-free and silent.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
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
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value {
    param($Message)
    [void] $script:warnings.Add([string] $Message)
}
Set-Item -Path function:script:Get-ADForest -Value { param($Server, $ErrorAction) throw 'ADWS unavailable' }

function New-FakeDisposable {
    param($Properties)
    $object = [PSCustomObject]@{ Properties = $Properties }
    $object | Add-Member -MemberType ScriptMethod -Name Dispose -Value {} -Force
    $object
}
function New-CrossRef {
    param([string] $Domain)
    [PSCustomObject]@{ Properties = @{ dnsroot = @($Domain) } }
}
$script:crossRefs = @()
$script:directoryEntryCalls = 0
Set-Item -Path function:script:New-Object -Value {
    param(
        [Parameter(Position = 0)] $TypeName,
        [Parameter(Position = 1)] $ArgumentList,
        $Type,
        $Property
    )
    if ([string] $TypeName -eq 'System.DirectoryServices.DirectoryEntry') {
        $script:directoryEntryCalls++
        if ($script:directoryEntryCalls -eq 1) {
            return (New-FakeDisposable -Properties @{
                    configurationNamingContext = @('CN=Configuration,DC=root,DC=test')
                    rootDomainNamingContext = @('DC=root,DC=test')
                })
        }
        return (New-FakeDisposable -Properties @{})
    }
    if ([string] $TypeName -eq 'System.DirectoryServices.DirectorySearcher') {
        $searcher = [PSCustomObject]@{
            SearchRoot = $null; Filter = $null; PageSize = 0
            PropertiesToLoad = ([Collections.ArrayList]::new())
        }
        $searcher | Add-Member -MemberType ScriptMethod -Name FindAll -Value { $script:crossRefs } -Force
        $searcher | Add-Member -MemberType ScriptMethod -Name Dispose -Value {} -Force
        return $searcher
    }
    if ($PSBoundParameters.ContainsKey('ArgumentList')) {
        return Microsoft.PowerShell.Utility\New-Object -TypeName ([string] $TypeName) -ArgumentList $ArgumentList
    }
    Microsoft.PowerShell.Utility\New-Object -TypeName ([string] $TypeName)
}
function Invoke-Discovery {
    param([string[]] $Domains)
    $script:crossRefs = @($Domains | ForEach-Object { New-CrossRef $_ })
    $script:directoryEntryCalls = 0
    $script:warnings.Clear()
    Get-mdiForestDomain -Domain 'child.root.test'
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

Write-Host 'LdapRootOmissionIsIncomplete.Tests.ps1' -ForegroundColor Cyan

$partial = Invoke-Discovery -Domains @('child.root.test')
Write-Host ('  RAW partial={0}' -f ($partial | ConvertTo-Json -Depth 6 -Compress))
Assert-True 'LDAP returns the domain it did discover' (
    (@($partial.Domains) -join ',') -eq 'child.root.test'
) ("Domains={0}" -f (@($partial.Domains) -join '|'))
Assert-True 'a crossRef list missing the forest root is incomplete' (
    $partial.Complete -eq $false
) ("Complete={0}" -f $partial.Complete)
Assert-True 'the missing forest root is named in the error' (
    [string] $partial.Error -match 'forest root domain root.test is absent'
) ("Error={0}" -f $partial.Error)
Assert-True 'the operator is warned about the incomplete LDAP list' (
    @($script:warnings | Where-Object { $_ -match 'does not contain its root domain root.test' }).Count -eq 1
) ("Warnings={0}" -f ($script:warnings -join ' | '))

$domains = @($partial.Domains)
$report = [PSCustomObject]@{
    ScriptVersion = 'test'; Domain = 'root.test'; Forest = 'root.test'
    ForestDiscovery = $partial; DomainsInScope = $domains
    DomainControllers = @($domains | ForEach-Object { New-Dc $_ })
    CAServers = @(); EntraConnectServers = @()
    DomainAuditing = @($domains | ForEach-Object { New-Audit $_ })
    LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
    MaxNnrTargets = 0; SkippedAreas = @()
}
$stats = Get-mdiReportStatistics -ReportData $report 3>$null
$issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report)
$ready = Test-mdiReadinessResult -ReportData $report
Write-Host ('  RAW surface=passed:{0} total:{1} unread:{2} issues:{3} ready:{4}' -f
    $stats.ChecksPassed, $stats.ChecksTotal, $stats.ChecksUnread, $issues.Count, $ready)
Assert-True 'the incomplete LDAP scope is charged unread' ($stats.ChecksUnread -ge 1) ("Unread={0}" -f $stats.ChecksUnread)
Assert-True 'the issue list reports forest discovery' (
    @($issues | Where-Object { $_.Area -eq 'Forest discovery' }).Count -eq 1
) ("Areas={0}" -f (@($issues | ForEach-Object { $_.Area }) -join '|'))
Assert-True 'the incomplete LDAP scope blocks READY' ($ready -eq $false) ("Ready={0}" -f $ready)

$clean = Invoke-Discovery -Domains @('root.test', 'child.root.test')
Write-Host ('  RAW clean={0}' -f ($clean | ConvertTo-Json -Depth 6 -Compress))
Assert-True 'control: a list containing the root remains complete' ($clean.Complete -eq $true) ("Complete={0}" -f $clean.Complete)
Assert-True 'control: a complete LDAP list carries no error' (
    [string]::IsNullOrWhiteSpace([string] $clean.Error)
) ("Error={0}" -f $clean.Error)
Assert-True 'control: a complete LDAP list raises no warning' ($script:warnings.Count -eq 0) ("Warnings={0}" -f ($script:warnings -join ' | '))

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
