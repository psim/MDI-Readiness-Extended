<#
    A DOMAIN CONTROLLER FROM ANOTHER DOMAIN WAS CREDITED TO THE ONE THAT WAS ASKED ABOUT.

    Every scanned server records which domain it belongs to. That field is what
    Get-mdiUnexaminedDomain uses to decide whether a domain in scope was actually looked at, and what
    the verdict uses to refuse READY over a domain nothing reached.

    It was assigned unconditionally from the REQUESTED scope: `$dc['Domain'] = $Domain`. So a
    controller was filed under whatever domain the caller asked about, wherever it actually lived.
    Measured on the shipped functions with -Domain child.root.test and a target whose authoritative
    directory DN is CN=DC01,OU=Domain Controllers,DC=root,DC=test:

        authoritative_directory_domain=root.test
        produced_domain=child.root.test
        unexamined_count=0   ready=True   issues=0

    A root-domain controller filed under the child domain, the child therefore counted as covered,
    and the run certified READY over a domain nothing had examined. That is worse than reporting the
    child as unexamined: the operator is told the opposite of the truth rather than being told
    nothing.

    The domain is now DERIVED from the server's own fully qualified name - the name with its leftmost
    label removed, which is what an FQDN means - and falls back to the requested scope only for a
    dotless name, which genuinely carries no domain information.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

# Only the outermost readers are replaced; the attribution under test is the shipped code.
Set-Item -Path function:script:Test-mdiServerReachable -Value {
    param($ComputerName)
    [PSCustomObject]@{ Reachable = $false; Method = 'fixture'; Detail = 'not reachable in this fixture' }
}
Set-Item -Path function:script:Get-mdiDomainControllerInventory -Value { param($Domain) @() }

function Get-ProducedDomain {
    param([string] $Scope, [string] $Fqdn)
    # -DomainController takes plain strings, and an unreachable server short-circuits before any
    # network work - which is all this needs, because the attribution happens first.
    $result = Get-mdiDomainControllerReadiness -Domain $Scope -DomainController @($Fqdn) 3>$null 4>$null
    $server = @($result | Where-Object { $_ })[0]
    [string] $server.Domain
}

Write-Host 'A server is filed under the domain its own name says it is in' -ForegroundColor Cyan
# The defect: asked about the child, handed a ROOT-domain controller.
$crossDomain = Get-ProducedDomain -Scope 'child.root.test' -Fqdn 'dc01.root.test'
Assert-That 'a root-domain controller is not credited to the child domain' (
    $crossDomain -ne 'child.root.test') "produced=$crossDomain"
Assert-That 'and it is credited to the domain it actually belongs to' (
    $crossDomain -eq 'root.test') "produced=$crossDomain"

Write-Host ''
Write-Host 'CONTROLS - ordinary attribution is unchanged' -ForegroundColor Cyan
Assert-That 'CONTROL: a controller in the scoped domain keeps that domain' (
    (Get-ProducedDomain -Scope 'child.root.test' -Fqdn 'dc01.child.root.test') -eq 'child.root.test')
Assert-That 'CONTROL: a single-domain scan is unaffected' (
    (Get-ProducedDomain -Scope 'contoso.com' -Fqdn 'dc01.contoso.com') -eq 'contoso.com')
Assert-That 'CONTROL: a deep child domain is derived correctly' (
    (Get-ProducedDomain -Scope 'root.test' -Fqdn 'dc01.a.b.root.test') -eq 'a.b.root.test')
# A dotless name carries no domain information, so the requested scope is the only thing available -
# deriving anything from it would be inventing an identity.
Assert-That 'CONTROL: a short name falls back to the requested scope' (
    (Get-ProducedDomain -Scope 'contoso.com' -Fqdn 'DC01') -eq 'contoso.com')
# A trailing dot is the absolute spelling of the same name and must not leak into the domain.
Assert-That 'CONTROL: a trailing dot does not corrupt the derived domain' (
    (Get-ProducedDomain -Scope 'contoso.com' -Fqdn 'dc01.contoso.com.') -eq 'contoso.com')

Write-Host ''
Write-Host 'The consequence: an unexamined domain must be reported as unexamined' -ForegroundColor Cyan
# This is what the field is FOR. With the wrong attribution the child looked covered.
$rootDc = [PSCustomObject]@{
    FQDN = 'dc01.root.test'; Domain = 'root.test'; Unreachable = $false; PartialFailure = $false
    OSVersionOk = $true; Details = [PSCustomObject]@{}
}
$unexamined = @(Get-mdiUnexaminedDomain -ScopedDomain @('root.test', 'child.root.test') `
        -Server @($rootDc) -DomainControllerServer @($rootDc))
Assert-That 'the child domain is reported as unexamined' (
    $unexamined -contains 'child.root.test') "unexamined=[$($unexamined -join ', ')]"
Assert-That 'and the root domain is not' (
    $unexamined -notcontains 'root.test') "unexamined=[$($unexamined -join ', ')]"

# CONTROL: when both domains really were examined, neither is reported.
$childDc = [PSCustomObject]@{
    FQDN = 'dc01.child.root.test'; Domain = 'child.root.test'; Unreachable = $false; PartialFailure = $false
    OSVersionOk = $true; Details = [PSCustomObject]@{}
}
$bothExamined = @(Get-mdiUnexaminedDomain -ScopedDomain @('root.test', 'child.root.test') `
        -Server @($rootDc, $childDc) -DomainControllerServer @($rootDc, $childDc))
Assert-That 'CONTROL: two examined domains leave nothing unexamined' (
    $bothExamined.Count -eq 0) "unexamined=[$($bothExamined -join ', ')]"

Write-Host ''
Write-Host 'And the verdict must refuse READY over a domain nothing examined' -ForegroundColor Cyan
$reportData = [PSCustomObject]@{
    Domain = 'root.test'; Forest = 'root.test'; DomainsInScope = @('root.test', 'child.root.test')
    DomainControllers = @($rootDc); CAServers = @(); EntraConnectServers = @()
    DomainAuditing = @([PSCustomObject]@{
            Domain = 'root.test'
            AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
            ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
            ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
            DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
        })
}
Assert-That 'the run is NOT ready with a domain unexamined' (
    (Test-mdiReadinessResult -ReportData @($reportData) 3>$null) -eq $false)

# CONTROL: the same shape with both domains examined must still be able to reach READY, or the
# assertion above is just "the verdict is always false".
$bothData = [PSCustomObject]@{
    Domain = 'root.test'; Forest = 'root.test'; DomainsInScope = @('root.test', 'child.root.test')
    DomainControllers = @($rootDc, $childDc); CAServers = @(); EntraConnectServers = @()
    DomainAuditing = @(
        [PSCustomObject]@{ Domain = 'root.test'
            AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
            ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
            ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
            DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true } },
        [PSCustomObject]@{ Domain = 'child.root.test'
            AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
            ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
            ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
            DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true } })
}
Assert-That 'CONTROL: with both domains examined the run CAN be ready' (
    (Test-mdiReadinessResult -ReportData @($bothData) 3>$null) -eq $true)

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
