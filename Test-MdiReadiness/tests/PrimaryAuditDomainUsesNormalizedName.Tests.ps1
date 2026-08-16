<#
    A domain requested as an absolute DNS name must select that domain, not the first row in the forest.

    The requested domain is matched against the discovered forest scope by string equality. An operator
    who passes child.root.test. - with the trailing DNS root dot, or with surrounding whitespace -
    matched nothing, and the selection silently fell through to the first forest row. The report then
    answered for root.test while claiming to answer for child.root.test, including in the legacy JSON
    fields - the domain the operator actually requested was never examined, and nothing said so.

    Pinned here: an absolute DNS name is normalized before selection, the requested child row is chosen
    rather than the first forest row, the legacy JSON fields come from the requested child domain, and
    whitespace and the root dot normalize together. Controls confirm an already canonical name is
    untouched and that normalization does not alter the forest scope rows.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = [IO.Path]::GetFullPath($target)
$text = [IO.File]::ReadAllText($target)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$mainStart = $body.IndexOf('#region Main')
if ($mainStart -gt 0) { $body = $body.Substring(0, $mainStart) }
Invoke-Expression $body

$script:passed = 0
$script:failed = 0
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
function New-AuditRow {
    param([string] $Domain, [string] $Marker)
    [PSCustomObject]@{
        Domain = $Domain
        AdfsAuditing = [PSCustomObject]@{ Marker = "ADFS-$Marker" }
        ObjectAuditing = [PSCustomObject]@{ Marker = "OBJECT-$Marker" }
        ExchangeAuditing = [PSCustomObject]@{ Marker = "EXCHANGE-$Marker" }
        DeletedObjects = [PSCustomObject]@{ Marker = "DELETED-$Marker" }
        SchemaVersion = [PSCustomObject]@{ Marker = "SCHEMA-$Marker" }
    }
}
function Invoke-Selection {
    param([string] $RequestedDomain, [object[]] $Rows)
    $Domain = ConvertTo-mdiDomainScopeName -DomainName $RequestedDomain
    $domainAuditing = @($Rows)
    $primaryAuditing = Get-mdiPrimaryDomainAuditing -Domain $Domain -DomainAuditing $domainAuditing
    [PSCustomObject]@{
        Requested = $RequestedDomain
        Normalized = $Domain
        Selected = $primaryAuditing.Domain
        LegacyObject = $primaryAuditing.ObjectAuditing.Marker
        Scope = @($domainAuditing | ForEach-Object { $_.Domain })
    }
}

Write-Host 'PrimaryAuditDomainUsesNormalizedName.Tests.ps1' -ForegroundColor Cyan

$rows = @(
    (New-AuditRow 'root.test' 'ROOT')
    (New-AuditRow 'child.root.test' 'CHILD')
    (New-AuditRow 'other-tree.test' 'OTHER')
)
$absolute = Invoke-Selection -RequestedDomain 'child.root.test.' -Rows $rows
$spaced = Invoke-Selection -RequestedDomain '  child.root.test.  ' -Rows $rows
$exact = Invoke-Selection -RequestedDomain 'child.root.test' -Rows $rows
Write-Host ('  RAW absolute={0}' -f ($absolute | ConvertTo-Json -Depth 5 -Compress))
Write-Host ('  RAW spaced={0}' -f ($spaced | ConvertTo-Json -Depth 5 -Compress))
Write-Host ('  RAW exact={0}' -f ($exact | ConvertTo-Json -Depth 5 -Compress))

Assert-True 'an absolute DNS name is normalized to the scoped domain' (
    $absolute.Normalized -eq 'child.root.test'
) ("Normalized={0}" -f $absolute.Normalized)
Assert-True 'the requested child row is selected rather than the first forest row' (
    $absolute.Selected -eq 'child.root.test'
) ("Selected={0}" -f $absolute.Selected)
Assert-True 'legacy JSON fields come from the requested child domain' (
    $absolute.LegacyObject -eq 'OBJECT-CHILD'
) ("LegacyObject={0}" -f $absolute.LegacyObject)
Assert-True 'surrounding whitespace and the DNS root dot normalize together' (
    $spaced.Normalized -eq 'child.root.test' -and $spaced.Selected -eq 'child.root.test'
) ("Normalized={0}; Selected={1}" -f $spaced.Normalized, $spaced.Selected)
Assert-True 'control: an already canonical domain is unchanged' (
    $exact.Normalized -eq 'child.root.test' -and $exact.Selected -eq 'child.root.test'
) ("Normalized={0}; Selected={1}" -f $exact.Normalized, $exact.Selected)
Assert-True 'control: normalization does not alter forest scope rows' (
    (@($absolute.Scope) -join ',') -eq 'root.test,child.root.test,other-tree.test'
) ("Scope={0}" -f (@($absolute.Scope) -join '|'))

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
