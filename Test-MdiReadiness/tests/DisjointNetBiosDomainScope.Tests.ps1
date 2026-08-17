<#
    A domain is never reported UNEXAMINED because of how the operator SPELLED -Domain.

    -Domain is documented as "Domain Name or FQDN", and the name every Windows dialog shows an
    administrator of a DISJOINT namespace is the NetBIOS one: DNS fabrikam.local, NetBIOS FABCORP.
    That is not a case variant and not a trailing-dot variant - both of which the scope
    canonicalisation already handles - it is a different string, and no string rule turns one into
    the other.

    Everything that judges COVERAGE compares that string against a name that came from the
    DIRECTORY. A scanned domain controller's Domain is derived from its computer object's
    DistinguishedName - deliberately, so that a disjoint primary DNS suffix cannot file a controller
    under the wrong domain - while the scope, without -Forest, is the raw -Domain string, because
    Main builds Domains = @($Domain). Get-mdiUnexaminedDomain compares exactly those two.

    Measured on the shipped functions, one estate of two domain controllers, fully discovered and
    scanned under BOTH spellings, nothing else differing:

        -Domain fabrikam.local   scope fabrikam.local   rows fabrikam.local   unexamined: none
        -Domain FABCORP          scope FABCORP          rows fabrikam.local   unexamined: FABCORP

    The second charges the domain-level unread check, raises a Discovery issue and sets
    $domainsExamined = $false, so the run refuses READY over a domain whose every domain controller
    had just been examined. A false red produced by nothing but the spelling of a parameter, on the
    three surfaces that share Get-mdiUnexaminedDomain - and Get-mdiPrimaryDomainAuditing then
    reports the five domain-level auditing properties as unread through the same mismatch.

    Resolve-mdiDomainScopeDnsName resolves a DOTLESS -Domain to its DNS name once, before anything
    is measured against it.

    What is pinned here:
      1. The disjoint NetBIOS spelling produces the SAME coverage answer as the DNS spelling.
      2. A name that already carries a dot is returned untouched and the directory is NOT asked -
         this must not rewrite an FQDN, nor turn a domain controller name into its domain.
      3. A directory that cannot be asked, or that answers with an unreadable DNS name ($null, '',
         whitespace, a non-string), KEEPS the operator's spelling. A name nobody read must never be
         invented.
      4. A single-label DNS domain that resolves to itself is unchanged.
      5. A genuinely unexamined domain is STILL reported. The fix must not buy its false-red removal
         with a false green.
      6. Empty, null and whitespace input are returned unchanged without asking the directory.
      7. The mirror surface, Get-mdiPrimaryDomainAuditing, selects the right domain's row under the
         NetBIOS spelling instead of reporting it unread.

    The REAL functions are driven end to end: the shipped Get-mdiDomainControllerReadiness performs
    the directory attribution under test and the shipped Get-mdiUnexaminedDomain does the judging.
    Only the directory transport, DNS and reachability are modelled, because those are the network.
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

$script:warnings = New-Object System.Collections.ArrayList
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) [void] $script:warnings.Add([string] $Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# ----------------------------------------------------------------------------------------------
# The directory. Two domain controllers of fabrikam.local, whose NetBIOS domain name is FABCORP.
# Their computer objects are reachable by either spelling of -Server, as ADWS accepts both.
$script:dcObjects = @{
    'dcfab01.fabrikam.local' = 'CN=DCFAB01,OU=Domain Controllers,DC=fabrikam,DC=local'
    'dcfab02.fabrikam.local' = 'CN=DCFAB02,OU=Domain Controllers,DC=fabrikam,DC=local'
}
# What Get-ADDomain answers, keyed by the -Server value. $null models a cmdlet that returns
# nothing; a [scriptblock] models an answer whose DNSRoot could not be read as a name.
$script:domainAnswers = @{}
$script:domainCallCount = 0

function Get-ADDomainController {
    param($Server, $Filter, $ErrorAction)
    @(
        [PSCustomObject]@{ HostName = 'dcfab01.fabrikam.local'; Name = 'DCFAB01'; IPv4Address = '10.10.1.50'; IPv6Address = $null }
        [PSCustomObject]@{ HostName = 'dcfab02.fabrikam.local'; Name = 'DCFAB02'; IPv4Address = '10.10.1.52'; IPv6Address = $null }
    )
}
function Get-ADObject { param($Filter, $Server, $ErrorAction) $null }
function Get-ADComputer {
    param($Identity, $Server, $Properties, $Filter, $ErrorAction)
    $key = ([string] $Identity).ToLowerInvariant()
    if (-not $script:dcObjects.ContainsKey($key)) { return $null }
    [PSCustomObject]@{
        DNSHostName       = $key
        DistinguishedName = $script:dcObjects[$key]
        IPv4Address       = if ($key -like 'dcfab01*') { '10.10.1.50' } else { '10.10.1.52' }
        IPv6Address       = $null
        OperatingSystem   = 'Windows Server 2022 Datacenter'
    }
}
function Get-ADDomain {
    param($Server, $ErrorAction)
    $script:domainCallCount++
    $key = ([string] $Server).ToLowerInvariant()
    if (-not $script:domainAnswers.ContainsKey($key)) { throw "The domain '$Server' could not be contacted" }
    $answer = $script:domainAnswers[$key]
    if ($answer -is [scriptblock]) { return & $answer }
    [PSCustomObject]@{ DNSRoot = $answer; NetBIOSName = 'FABCORP' }
}
function Get-mdiComputerAddress {
    param($ComputerName, $KnownAddress)
    @(@($KnownAddress) | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
}
# Not contacted, so the test exercises attribution, scope and judging - not remote registry or WMI.
function Test-mdiServerReachable {
    param($ComputerName)
    [PSCustomObject]@{ Reachable = $false; Reason = 'test: not contacted' }
}

function Reset-Directory {
    $script:warnings.Clear()
    $script:domainCallCount = 0
    $script:domainAnswers = @{
        'fabcorp'        = 'fabrikam.local'
        'fabrikam.local' = 'fabrikam.local'
    }
}

# Exactly what Main does: canonicalise, resolve the scope name, then build $domainsInScope from
# $forestInfo.Domains, which without -Forest is @($Domain).
function Get-MainScope {
    param([string] $DomainParam)
    $d = ConvertTo-mdiDomainScopeName -DomainName $DomainParam
    $d = Resolve-mdiDomainScopeDnsName -DomainName $d
    $forestInfo = [PSCustomObject]@{ Name = $d; Domains = @($d); Method = 'Parameter'; Complete = $true; Error = $null }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    @(foreach ($n in @($forestInfo.Domains)) {
            $t = ([string] $n).Trim().TrimEnd('.')
            if ([string]::IsNullOrWhiteSpace($t)) { continue }
            if ($seen.Add($t)) { $t }
        })
}

function Get-Coverage {
    param([string] $DomainParam)
    $scope = @(Get-MainScope -DomainParam $DomainParam)
    $rows = @(foreach ($s in $scope) { Get-mdiDomainControllerReadiness -Domain $s })
    [PSCustomObject]@{
        Scope      = $scope
        Rows       = $rows
        Unexamined = @(Get-mdiUnexaminedDomain -ScopedDomain $scope -Server $rows -DomainControllerServer $rows)
    }
}

Write-Host 'Domain scope resolution across a disjoint NetBIOS namespace' -ForegroundColor Cyan

# ----------------------------------------------------------------------------------------------
# 1. The two spellings of one domain agree about coverage.
Reset-Directory
$byDns = Get-Coverage -DomainParam 'fabrikam.local'
Reset-Directory
$byNetBios = Get-Coverage -DomainParam 'FABCORP'

Assert-That 'the DNS spelling discovers two domain controllers' ($byDns.Rows.Count -eq 2) "got $($byDns.Rows.Count)"
Assert-That 'the NetBIOS spelling discovers two domain controllers' ($byNetBios.Rows.Count -eq 2) "got $($byNetBios.Rows.Count)"
Assert-That 'the DNS spelling reports no unexamined domain' ($byDns.Unexamined.Count -eq 0) "got [$($byDns.Unexamined -join ',')]"
Assert-That 'THE DEFECT: the NetBIOS spelling reports no unexamined domain either' `
    ($byNetBios.Unexamined.Count -eq 0) "got [$($byNetBios.Unexamined -join ',')]"
Assert-That 'the NetBIOS spelling is resolved to the DNS name for the scope' `
    (@($byNetBios.Scope)[0] -eq 'fabrikam.local') "got [$(@($byNetBios.Scope) -join ',')]"
Assert-That 'both spellings attribute every row to the directory domain' `
    ((@($byDns.Rows | ForEach-Object { [string] $_.Domain } | Select-Object -Unique) -join ',') -eq 'fabrikam.local' -and
     (@($byNetBios.Rows | ForEach-Object { [string] $_.Domain } | Select-Object -Unique) -join ',') -eq 'fabrikam.local')

# The case and trailing-dot variants were already correct and must stay correct.
foreach ($variant in 'FABRIKAM.LOCAL', 'fabrikam.local.', '  fabrikam.local  ') {
    Reset-Directory
    $v = Get-Coverage -DomainParam $variant
    Assert-That ("the variant '$variant' still reports no unexamined domain") ($v.Unexamined.Count -eq 0) "got [$($v.Unexamined -join ',')]"
}

# ----------------------------------------------------------------------------------------------
# 2. A dotted name is already a DNS name: it is returned untouched and the directory is not asked.
foreach ($dotted in 'fabrikam.local', 'FABRIKAM.LOCAL', 'dcfab01.fabrikam.local', 'child.fabrikam.local', '10.10.1.50') {
    Reset-Directory
    $out = Resolve-mdiDomainScopeDnsName -DomainName $dotted
    Assert-That ("a dotted name is returned unchanged: '$dotted'") ($out -eq ($dotted.Trim().TrimEnd('.'))) "got [$out]"
    Assert-That ("a dotted name does not query the directory: '$dotted'") ($script:domainCallCount -eq 0) "calls=$script:domainCallCount"
}
Reset-Directory
Assert-That 'a trailing dot is stripped before the dot test, and the name is still not resolved away' `
    ((Resolve-mdiDomainScopeDnsName -DomainName 'fabrikam.local.') -eq 'fabrikam.local')

# ----------------------------------------------------------------------------------------------
# 3. A directory that cannot answer keeps the operator's spelling. Nothing is invented.
Reset-Directory
$script:domainAnswers = @{}   # every lookup throws
Assert-That 'an unreachable directory keeps the supplied name' `
    ((Resolve-mdiDomainScopeDnsName -DomainName 'FABCORP') -eq 'FABCORP')
Assert-That 'an unreachable directory did ask before giving up' ($script:domainCallCount -eq 1) "calls=$script:domainCallCount"

# An answer whose DNS name could not be read. Every one of these must keep the supplied name.
$unreadable = @(
    @{ Label = '$null DNSRoot'; Value = $null }
    @{ Label = 'empty DNSRoot'; Value = '' }
    @{ Label = 'whitespace DNSRoot'; Value = '   ' }
    @{ Label = 'DNSRoot of a single dot'; Value = '.' }
    @{ Label = 'a number as DNSRoot'; Value = 12345 }
    @{ Label = 'an array as DNSRoot'; Value = @() }
    @{ Label = 'a cmdlet that returns nothing'; Value = [scriptblock]::Create('$null') }
    @{ Label = 'prose as DNSRoot'; Value = 'not a name!' }
    @{ Label = 'an IPv4 address as DNSRoot'; Value = '10.10.1.50' }
    @{ Label = 'a dotless answer that is not the request'; Value = 'fabrikam' }
    @{ Label = 'a name of a single hyphen'; Value = '-' }
)
foreach ($case in $unreadable) {
    Reset-Directory
    $script:domainAnswers['fabcorp'] = $case.Value
    $out = Resolve-mdiDomainScopeDnsName -DomainName 'FABCORP'
    Assert-That ("an unreadable answer keeps the supplied name: $($case.Label)") ($out -eq 'FABCORP') "got [$out]"
}

# A non-numeric string that IS a usable name is accepted - the guard rejects unreadable, not odd.
Reset-Directory
$script:domainAnswers['fabcorp'] = 'fabrikam.local.'
Assert-That 'an absolute DNS answer is canonicalised, not rejected' `
    ((Resolve-mdiDomainScopeDnsName -DomainName 'FABCORP') -eq 'fabrikam.local')

# ----------------------------------------------------------------------------------------------
# 4. A single-label DNS domain resolves to itself and is unaffected.
Reset-Directory
$script:domainAnswers['legacy'] = 'legacy'
Assert-That 'a single-label DNS domain is unchanged' ((Resolve-mdiDomainScopeDnsName -DomainName 'legacy') -eq 'legacy')

# ----------------------------------------------------------------------------------------------
# 5. A genuinely unexamined domain is still reported. No false green was bought with this fix.
Reset-Directory
$scope = @('fabrikam.local', 'apac.mdilab.local')
$rows = @(Get-mdiDomainControllerReadiness -Domain 'fabrikam.local')
$stillMissing = @(Get-mdiUnexaminedDomain -ScopedDomain $scope -Server $rows -DomainControllerServer $rows)
Assert-That 'a domain with no domain controller of its own is still reported unexamined' `
    ($stillMissing.Count -eq 1 -and $stillMissing[0] -eq 'apac.mdilab.local') "got [$($stillMissing -join ',')]"

# And a NetBIOS name whose directory lookup fails must not silently become covered.
Reset-Directory
$script:domainAnswers = @{ 'fabrikam.local' = 'fabrikam.local' }   # OTHERCORP cannot be resolved
$scope2 = @('fabrikam.local', (Resolve-mdiDomainScopeDnsName -DomainName 'OTHERCORP'))
$rows2 = @(Get-mdiDomainControllerReadiness -Domain 'fabrikam.local')
$missing2 = @(Get-mdiUnexaminedDomain -ScopedDomain $scope2 -Server $rows2 -DomainControllerServer $rows2)
Assert-That 'an unresolvable NetBIOS name is still charged as unexamined' `
    ($missing2.Count -eq 1 -and $missing2[0] -eq 'OTHERCORP') "got [$($missing2 -join ',')]"

# ----------------------------------------------------------------------------------------------
# 6. Nothing to resolve is returned unchanged, and asks the directory nothing.
foreach ($blank in @($null, '', '   ')) {
    Reset-Directory
    $out = Resolve-mdiDomainScopeDnsName -DomainName $blank
    Assert-That ("blank input is returned without a query: [$blank]") `
        ([string]::IsNullOrWhiteSpace($out) -and $script:domainCallCount -eq 0) "got [$out] calls=$script:domainCallCount"
}

# ----------------------------------------------------------------------------------------------
# 7. The mirror surface: the domain-level auditing row is selected, not reported unread.
Reset-Directory
$auditRows = @(
    [PSCustomObject]@{ Domain = 'mdilab.local'; SchemaVersion = 88; ObjectAuditing = $true }
    [PSCustomObject]@{ Domain = 'fabrikam.local'; SchemaVersion = 87; ObjectAuditing = $false }
)
$resolvedScope = Resolve-mdiDomainScopeDnsName -DomainName 'FABCORP'
$primary = Get-mdiPrimaryDomainAuditing -Domain $resolvedScope -DomainAuditing $auditRows
Assert-That 'the NetBIOS spelling selects its own domain-level auditing row' `
    ($null -ne $primary -and [string] $primary.Domain -eq 'fabrikam.local') "got [$($primary.Domain)]"
Assert-That 'and it is the row that was measured, not another domain''s' `
    ($null -ne $primary -and $primary.SchemaVersion -eq 87) "got [$($primary.SchemaVersion)]"

# ----------------------------------------------------------------------------------------------
Write-Host ''
Write-Host ("  passed {0}, failed {1}" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 }
exit 0
