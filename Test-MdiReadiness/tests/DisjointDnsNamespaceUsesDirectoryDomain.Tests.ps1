<#
    A domain controller's domain must come from its directory DN, not from its DNS suffix.

    In a disjoint DNS namespace a DC's FQDN does not match the AD domain it serves - dc01.corp.example
    can be a controller for child.ad.test. Attribution was taken from the DNS suffix, so such a DC was
    credited to whichever AD domain its hostname happened to resemble. Two wrong answers follow: a
    domain scores green on coverage supplied by a controller that does not belong to it, and the
    controller that genuinely covers it is not counted.

    Pinned here: the authoritative DN supplies the domain; the DN still wins when a DNS suffix
    misleadingly resembles the requested domain; a DC from another AD domain does not count as covering
    the requested one; the DN remains authoritative even when Get-ADComputer returns nothing; the DNS
    suffix is used only as a fallback when no directory DN exists; and the internal attribution value
    does not leak into the report JSON.
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
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param($ComputerName, $KnownAddress)
    '10.0.0.10'
}
Set-Item -Path function:script:Test-mdiServerReachable -Value {
    param($ComputerName)
    [PSCustomObject]@{ Reachable = $false; Method = 'test fixture' }
}

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
function Set-DirectoryComputer {
    param(
        [string] $DnsHostName,
        [AllowNull()] [string] $DistinguishedName,
        [bool] $ComputerLookupSucceeds = $true
    )
    $script:testDnsHostName = $DnsHostName
    $script:testDn = $DistinguishedName
    $script:testComputerLookupSucceeds = $ComputerLookupSucceeds
    Set-Item -Path function:script:Get-ADObject -Value {
        [PSCustomObject]@{ Name = 'DC01'; DistinguishedName = $script:testDn }
    }
    Set-Item -Path function:script:Get-ADComputer -Value {
        if (-not $script:testComputerLookupSucceeds) { return $null }
        [PSCustomObject]@{
            Name = 'DC01'; DNSHostName = $script:testDnsHostName
            DistinguishedName = $script:testDn; IPv4Address = '10.0.0.10'
            OperatingSystem = 'Windows Server'
        }
    }
}
function Get-DcRow {
    param([string] $Scope)
    @(Get-mdiDomainControllerReadiness -Domain $Scope `
            -DomainController @($script:testDnsHostName) 3>$null)[0]
}

Write-Output 'A disjoint DNS suffix does not change the DC AD-domain attribution'
Set-DirectoryComputer -DnsHostName 'dc01.corp.example' `
    -DistinguishedName 'CN=DC01,OU=Domain Controllers,DC=child,DC=ad,DC=test'
$disjoint = Get-DcRow -Scope 'child.ad.test'
Write-Output ('  RAW disjoint=' + ($disjoint | ConvertTo-Json -Depth 5 -Compress))
Assert-True ($disjoint.Domain -eq 'child.ad.test') `
    'the authoritative DN supplies the domain' "Domain=$($disjoint.Domain)"
Assert-True ($null -eq $disjoint.PSObject.Properties['DirectoryDomain']) `
    'the internal attribution value does not leak into report JSON'
$unexamined = @(Get-mdiUnexaminedDomain -ScopedDomain @('child.ad.test') `
        -Server @($disjoint) -DomainControllerServer @($disjoint))
Assert-True ($unexamined.Count -eq 0) `
    'the scanned disjoint-namespace DC covers its AD domain' "Unexamined=$($unexamined -join ',')"

Write-Output 'The authoritative AD-object DN survives a failed computer lookup'
Set-DirectoryComputer -DnsHostName 'dc01.corp.example' `
    -DistinguishedName 'CN=DC01,OU=Domain Controllers,DC=child,DC=ad,DC=test' `
    -ComputerLookupSucceeds $false
$objectOnly = Get-DcRow -Scope 'child.ad.test'
Write-Output ('  RAW object-only=' + ($objectOnly | ConvertTo-Json -Depth 5 -Compress))
Assert-True ($objectOnly.Domain -eq 'child.ad.test') `
    'the AD-object DN remains authoritative when Get-ADComputer returns nothing' "Domain=$($objectOnly.Domain)"

Write-Output 'A controller authoritatively in another domain does not receive scope credit'
Set-DirectoryComputer -DnsHostName 'dc01.child.ad.test' `
    -DistinguishedName 'CN=DC01,OU=Domain Controllers,DC=root,DC=ad,DC=test'
$wrongDomain = Get-DcRow -Scope 'child.ad.test'
Write-Output ('  RAW wrong-domain=' + ($wrongDomain | ConvertTo-Json -Depth 5 -Compress))
Assert-True ($wrongDomain.Domain -eq 'root.ad.test') `
    'the DN wins when a DNS suffix misleadingly resembles the requested domain' "Domain=$($wrongDomain.Domain)"
$unexaminedWrong = @(Get-mdiUnexaminedDomain -ScopedDomain @('child.ad.test') `
        -Server @($wrongDomain) -DomainControllerServer @($wrongDomain))
Assert-True ($unexaminedWrong -contains 'child.ad.test') `
    'a DC from another AD domain does not cover the requested domain' "Unexamined=$($unexaminedWrong -join ',')"

Write-Output 'Older directory rows without a DN retain the DNS-name fallback'
Set-DirectoryComputer -DnsHostName 'dc01.child.ad.test' -DistinguishedName $null
$legacy = Get-DcRow -Scope 'child.ad.test'
Write-Output ('  RAW no-dn=' + ($legacy | ConvertTo-Json -Depth 5 -Compress))
Assert-True ($legacy.Domain -eq 'child.ad.test') `
    'the DNS suffix remains the fallback when no directory DN is available' "Domain=$($legacy.Domain)"

Write-Output "RESULT: $script:passed passed / $script:failed failed"
if ($script:failed -gt 0) { exit 1 }
