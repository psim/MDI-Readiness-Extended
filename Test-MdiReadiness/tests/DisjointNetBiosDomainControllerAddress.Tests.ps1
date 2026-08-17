<#
    A domain controller is never reported unreachable because of how the OPERATOR SPELLED THE DOMAIN.

    Get-mdiDomainControllerInventory qualifies every bare domain-controller name with the scope
    domain (ConvertTo-mdiCanonicalComputerName appends it to any name carrying no dot) and then asks
    DNS for the qualified spelling. The scope domain is the operator's RAW -Domain string: without
    -Forest, Main builds Domains = @($Domain), so whatever was typed is what gets stapled on.

    -Domain is documented as "Domain Name or FQDN", and the name every Windows dialog shows an
    administrator of a DISJOINT namespace is the NetBIOS one - DNS fabrikam.local, NetBIOS FABCORP.
    That is not a case variant and not a trailing-dot variant; it is a different string that is not a
    DNS suffix at all. Qualifying with it produces a name that cannot exist in DNS, while the bare
    name still resolves through the client's suffix search list and NetBIOS.

    Before the fix, the inventory then wrote the server off:

        -Domain fabrikam.local   2 rows carrying addresses, 0 addressless
        -Domain FABCORP          0 rows carrying addresses, 2 ADDRESSLESS

    Same forest, same DNS, same directory - only the spelling of -Domain differed. The addressless
    rows feed the statistics, the issue list and the verdict, and each one printed "No usable IP
    address could be resolved ... so it cannot be probed". An estate nobody had failed to reach was
    reported as an estate that could not be probed: a value that was never read - no address was ever
    obtained for a name that does not exist - coming back looking like a measurement.

    Its sibling Resolve-mdiNnrTarget already carried the undo for exactly this case, and survives
    FABCORP, so the two halves of the same run disagreed about the same estate.

    What is pinned here:
      1. The disjoint NetBIOS spelling yields the SAME addressed inventory as the DNS spelling.
      2. The qualified spelling stays PREFERRED - it is tried first, and when it resolves the bare
         name is never asked for and never substituted.
      3. A server that resolves under NEITHER spelling is STILL reported addressless. The undo must
         not manufacture a target nobody can reach.
      4. A name that is already an FQDN is not re-qualified, and is not stripped when it resolves.
      5. The undo only ever strips the scope suffix that was actually appended - a name that does not
         end with it is left alone.

    The REAL functions are driven end to end: the shipped Merge-mdiDomainControllerEndpoint performs
    the qualification under test and the shipped Get-mdiAddresslessDomainController does the counting.
    Only the directory transport and DNS are modelled, because those are the network.
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
# The network. Bare names resolve through the suffix search list; the FQDN resolves; the NetBIOS
# spelling is not a DNS name and resolves to nothing. 'ghost' resolves under no spelling at all.
$script:dns = @{
    'dcfab01'                 = @('10.10.1.50')
    'dcfab01.fabrikam.local'  = @('10.10.1.50')
    'memfab01'                = @('10.10.1.51')
    'memfab01.fabrikam.local' = @('10.10.1.51')
}
$script:dnsAsked = New-Object System.Collections.ArrayList
function Get-mdiComputerAddress {
    param(
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $false)] [AllowNull()] [string[]] $KnownAddress = $null
    )
    [void] $script:dnsAsked.Add(([string] $ComputerName).ToLowerInvariant())
    $hit = @($script:dns[(([string] $ComputerName).Trim().TrimEnd('.').ToLowerInvariant())])
    @(@(@($KnownAddress) + $hit) | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } | Select-Object -Unique)
}

# The directory answered but carried no address - the ordinary cross-forest LDAP-fallback shape, and
# the one AddressResolutionComplete = $false exists for. The SHIPPED merge builds the server records,
# so the qualification under test is the product's own.
$script:enumeratedNames = @()
function Resolve-mdiDomainController {
    param([Parameter(Mandatory = $true)] [string] $Domain)
    $sources = @($script:enumeratedNames | ForEach-Object {
            [PSCustomObject]@{ Name = $_; IP = $null; Addresses = @(); AddressResolutionComplete = $false }
        })
    [PSCustomObject]@{
        Servers = @(Merge-mdiDomainControllerEndpoint -Server $sources -Domain $Domain)
        Unnamed = 0
        Error   = $null
    }
}

function Get-Inventory {
    param([string] $DomainArg, [string[]] $Names)
    $script:enumeratedNames = $Names
    $script:warnings.Clear()
    $script:dnsAsked.Clear()
    @(Get-mdiDomainControllerInventory -Domain @($DomainArg))
}

# ----------------------------------------------------------------------------------------------
Write-Host 'A disjoint NetBIOS -Domain does not turn a reachable estate into an unreachable one' -ForegroundColor Cyan

$estate = @('dcfab01', 'memfab01')

$byDns = Get-Inventory -DomainArg 'fabrikam.local' -Names $estate
$dnsAddressed = @($byDns | Where-Object { $_.IP })
$dnsAddressless = @(Get-mdiAddresslessDomainController -Inventory $byDns)
Assert-That 'baseline: the DNS spelling addresses both servers' ($dnsAddressed.Count -eq 2) "(got $($dnsAddressed.Count))"
Assert-That 'baseline: the DNS spelling reports nothing addressless' ($dnsAddressless.Count -eq 0) "(got $($dnsAddressless.Count))"

$byNetBios = Get-Inventory -DomainArg 'FABCORP' -Names $estate
$nbAddressed = @($byNetBios | Where-Object { $_.IP })
$nbAddressless = @(Get-mdiAddresslessDomainController -Inventory $byNetBios)
Assert-That 'the NetBIOS spelling addresses both servers too' ($nbAddressed.Count -eq 2) "(got $($nbAddressed.Count))"
Assert-That 'the NetBIOS spelling reports nothing addressless' ($nbAddressless.Count -eq 0) "(got: $($nbAddressless -join ', '))"
Assert-That 'no server is written off as unprobeable' (@($script:warnings | Where-Object { $_ -match 'cannot be probed' }).Count -eq 0) "(got: $($script:warnings -join ' | '))"
$nbIps = (@($nbAddressed | ForEach-Object { [string] $_.IP }) | Sort-Object) -join ','
Assert-That 'the addresses reported are the real ones' ($nbIps -eq '10.10.1.50,10.10.1.51') "(got: $nbIps)"
Assert-That 'the rows carry a name that actually resolves' (@($nbAddressed | Where-Object { $script:dns.ContainsKey(([string] $_.Name).ToLowerInvariant()) }).Count -eq 2) "(got: $(@($nbAddressed | ForEach-Object { $_.Name }) -join ', '))"

# Both spellings must agree about the SIZE of the estate as well as its reachability.
Assert-That 'both spellings enumerate the same number of servers' ($byDns.Count -eq $byNetBios.Count) "($($byDns.Count) vs $($byNetBios.Count))"

# ----------------------------------------------------------------------------------------------
Write-Host 'The qualified spelling stays preferred' -ForegroundColor Cyan

$null = Get-Inventory -DomainArg 'fabrikam.local' -Names @('dcfab01')
Assert-That 'the qualified name is asked for first' (@($script:dnsAsked)[0] -eq 'dcfab01.fabrikam.local') "(got: $(@($script:dnsAsked) -join ', '))"
Assert-That 'the bare name is never asked for when the qualified one resolves' (@($script:dnsAsked) -notcontains 'dcfab01') "(got: $(@($script:dnsAsked) -join ', '))"

$fqdnRows = Get-Inventory -DomainArg 'FABCORP' -Names @('dcfab01.fabrikam.local')
Assert-That 'a name that is already an FQDN is not re-qualified' (@($script:dnsAsked) -contains 'dcfab01.fabrikam.local') "(got: $(@($script:dnsAsked) -join ', '))"
Assert-That 'a resolving FQDN is kept exactly as enumerated' ((@($fqdnRows | ForEach-Object { $_.Name }) -join ',') -eq 'dcfab01.fabrikam.local') "(got: $(@($fqdnRows | ForEach-Object { $_.Name }) -join ','))"

# ----------------------------------------------------------------------------------------------
Write-Host 'The undo never manufactures a target nobody can reach' -ForegroundColor Cyan

$ghost = Get-Inventory -DomainArg 'FABCORP' -Names @('ghost')
$ghostAddressless = @(Get-mdiAddresslessDomainController -Inventory $ghost)
Assert-That 'a server resolving under NEITHER spelling is still addressless' ($ghostAddressless.Count -eq 1) "(got $($ghostAddressless.Count))"
Assert-That 'and it is still reported as not probeable' (@($script:warnings | Where-Object { $_ -match 'cannot be probed' }).Count -eq 1) "(got: $($script:warnings -join ' | '))"
Assert-That 'both spellings were tried before giving up' ((@($script:dnsAsked) -contains 'ghost.fabcorp') -and (@($script:dnsAsked) -contains 'ghost')) "(got: $(@($script:dnsAsked) -join ', '))"

$mixed = Get-Inventory -DomainArg 'FABCORP' -Names @('dcfab01', 'ghost')
$mixedAddressed = @($mixed | Where-Object { $_.IP })
$mixedAddressless = @(Get-mdiAddresslessDomainController -Inventory $mixed)
Assert-That 'one unreachable server does not hide the reachable one' ($mixedAddressed.Count -eq 1) "(got $($mixedAddressed.Count))"
Assert-That 'and the unreachable one is still counted' ($mixedAddressless.Count -eq 1) "(got $($mixedAddressless.Count))"

# ----------------------------------------------------------------------------------------------
Write-Host 'Only the suffix that was actually appended is ever stripped' -ForegroundColor Cyan

# The enumerated name ends in a DIFFERENT domain from the scope, so nothing may be stripped off it:
# stripping 'FABCORP' from a name that does not carry it would corrupt the host name.
$script:dns['other'] = @('10.10.1.99')
$foreign = Get-Inventory -DomainArg 'FABCORP' -Names @('other.contoso.com')
Assert-That 'a name carrying another suffix is not stripped' ((@($script:dnsAsked) -join ',') -eq 'other.contoso.com') "(got: $(@($script:dnsAsked) -join ', '))"
Assert-That 'and it is reported addressless rather than rewritten' (@(Get-mdiAddresslessDomainController -Inventory $foreign).Count -eq 1) "(got $(@($foreign | ForEach-Object { $_.Name }) -join ', '))"

# A whitespace-only scope appends nothing, so there is nothing to undo and nothing to strip.
$blank = Get-Inventory -DomainArg '   ' -Names @('dcfab01')
Assert-That 'a whitespace-only scope leaves the bare name alone' ((@($script:dnsAsked) -join ',') -eq 'dcfab01') "(got: $(@($script:dnsAsked) -join ', '))"
Assert-That 'and the bare name is still addressed' (@($blank | Where-Object { $_.IP }).Count -eq 1) "(got $(@($blank | Where-Object { $_.IP }).Count))"

# A trailing dot on the scope is the same domain, so it must behave exactly like the bare spelling.
$dotted = Get-Inventory -DomainArg 'FABCORP.' -Names @('dcfab01')
Assert-That 'a trailing dot on a NetBIOS scope behaves identically' (@($dotted | Where-Object { $_.IP }).Count -eq 1) "(got $(@($dotted | Where-Object { $_.IP }).Count))"

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
