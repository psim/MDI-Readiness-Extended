<#
    TWO READERS OF ONE INVENTORY MUST AGREE ON WHAT "HAS AN ADDRESS" MEANS.

    Three readers of the same domain-controller inventory decided it in two different ways:

        Resolve-mdiNnrTarget                  Where-Object { $_.IP }                  truthiness
        Resolve-mdiLdapTarget                 Where-Object { $_.IP }                  truthiness
        Get-mdiAddresslessDomainController    Test-mdiUsableComputerAddress           a real address

    Test-mdiUsableComputerAddress rejects 0.0.0.0, loopback, APIPA, multicast and the IPv6 any
    address. Every one of those is a NON-EMPTY STRING, so all of them passed the truthiness test.
    They are precisely the shapes an address takes when it was never really read: a stale A record,
    a hosts-file entry, a NIC that fell back to APIPA, a placeholder written where a lookup failed.

    Handed the same six rows - one reachable plus 0.0.0.0, 127.0.0.1, 169.254.10.5, '::' and $null -
    the shipped functions produced:

        Resolve-mdiLdapTarget                 5 targets   (4 of them unreachable placeholders)
        Resolve-mdiNnrTarget                  5 targets   (the same 4)
        Get-mdiAddresslessDomainController    5 addressless
        rows in BOTH lists at once            4

    One report that both PROBES a domain controller and DECLARES IT UNREACHABLE.

    HOW FAR THE CLAIM GOES, because it was measured rather than argued. Main has exactly one
    producer of this inventory, Get-mdiDomainControllerInventory, and it already strips unusable
    addresses: driven end to end with a directory answering 127.0.0.1, 0.0.0.0 and 169.254.10.5, it
    emitted ZERO rows carrying an unusable address and warned "No usable IP address could be
    resolved ... so it cannot be probed" for each. So this is NOT a live false green in the shipped
    pipeline, and this test does not pretend otherwise.

    What makes the guard load-bearing anyway is that THE PROBE CANNOT BE THE GUARD. Measured:
    Test-mdiTcpPort against 127.0.0.1 returns Success=True / 'Connected'. This script runs on a
    domain controller, where 389, 636, 3268 and 3269 are all listening locally, so a loopback row
    that ever reached the plan would be reported as a server successfully reached rather than as one
    never contacted. Any second producer - a cached inventory, an imported baseline, an
    operator-supplied list - lands exactly there. 0.0.0.0 and APIPA fail closed and classify as "Not
    tested", but they still consume the per-domain sampling budget: at MaxPerDomain=1 over three
    domains each holding a placeholder ahead of a reachable server, the unfixed resolvers probed
    THREE placeholders and ZERO reachable domain controllers.

    The extended lab is why the shapes matter now: domain controllers live in three sites and in a
    second forest, so a remote DC whose address is stale, unresolved or placeheld is an everyday row.

    What is pinned here:
      1. Neither resolver emits a target for 0.0.0.0, loopback, APIPA or the IPv6 any address.
      2. No row is ever probed AND declared addressless in the same run - the two readers agree.
      3. A genuinely reachable row is still probed. The fix must not empty the plan.
      4. Test-mdiTcpPort against loopback DOES answer 'Connected', which is why filtering at the
         resolver - rather than trusting the probe to fail - is the load-bearing part.
      5. The per-domain sampling budget is spent on reachable rows, not consumed by placeholders.
      6. A multi-homed row keeps its usable address while its unusable one is dropped.
      7. The shipped inventory producer does not emit an unusable address in the first place, so the
         two layers agree instead of relying on each other.

    The REAL shipped functions are driven. Only the directory transport is stubbed, and the local
    listening port used to prove the loopback answer is discovered from the running machine.
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

function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

function Row($name, $domain, $ip) {
    [PSCustomObject]@{ Name = $name; Domain = $domain; IP = $ip; Addresses = @($ip) }
}

# The estate: one reachable domain controller, then every shape an unread address arrives as.
$script:inventory = @(
    Row 'dc01.mdilab.local'        'mdilab.local'      '10.10.1.10'
    Row 'dcemea.emea.mdilab.local' 'emea.mdilab.local' '0.0.0.0'
    Row 'dcapac.apac.mdilab.local' 'apac.mdilab.local' '127.0.0.1'
    Row 'dcfab01.fabrikam.local'   'fabrikam.local'    '169.254.10.5'
    Row 'rodc01.mdilab.local'      'mdilab.local'      '::'
    Row 'dcnull.mdilab.local'      'mdilab.local'      $null
)

Write-Host ''
Write-Host 'An unreadable address never becomes a probe target'

$ldap = @(Resolve-mdiLdapTarget -DomainControllers $script:inventory -MaxPerDomain 5)
$nnr = @(Resolve-mdiNnrTarget -DomainControllers $script:inventory -Domain 'mdilab.local' -MaxTargets 10)

Assert-That 'the LDAP plan holds only the reachable domain controller' (
    $ldap.Count -eq 1 -and $ldap[0].IP -eq '10.10.1.10'
) "(got $($ldap.Count): $(@($ldap | ForEach-Object { $_.IP }) -join ', '))"

Assert-That 'the NNR plan holds only the reachable domain controller' (
    $nnr.Count -eq 1 -and $nnr[0].IP -eq '10.10.1.10'
) "(got $($nnr.Count): $(@($nnr | ForEach-Object { $_.IP }) -join ', '))"

foreach ($bad in '0.0.0.0', '127.0.0.1', '169.254.10.5', '::') {
    Assert-That "no LDAP target carries $bad" (@($ldap | Where-Object { [string] $_.IP -eq $bad }).Count -eq 0)
    Assert-That "no NNR target carries $bad" (@($nnr | Where-Object { [string] $_.IP -eq $bad }).Count -eq 0)
}

Write-Host ''
Write-Host 'The two readers of the inventory agree with each other'

$addressless = @(Get-mdiAddresslessDomainController -Inventory $script:inventory)
Assert-That 'every unreachable row is declared addressless' ($addressless.Count -eq 5) "(got $($addressless.Count))"

$contradiction = @($ldap + $nnr | Where-Object {
        $key = ConvertTo-mdiCanonicalComputerName -Value $_.Name -Domain ([string] $_.Domain)
        $addressless -contains $key
    })
Assert-That 'no row is probed AND declared addressless' ($contradiction.Count -eq 0) `
    "(got $($contradiction.Count): $(@($contradiction | ForEach-Object { $_.Name }) -join ', '))"

Assert-That 'the reachable domain controller is NOT declared addressless' (
    $addressless -notcontains 'dc01.mdilab.local'
) "(addressless: $($addressless -join ', '))"

Write-Host ''
Write-Host 'CONTROL - filtering at the resolver is load-bearing, because loopback answers'

# This is the whole reason the resolver must filter: the probe itself cannot tell that the machine
# answering is the local one. If this control ever fails, the machine has no listening port and the
# assertion below it is what carries the test.
$listening = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -in '0.0.0.0', '127.0.0.1', '::' } |
        Select-Object -ExpandProperty LocalPort -Unique)
$probePort = @($listening | Where-Object { $_ -gt 0 } | Sort-Object)[0]
if ($probePort) {
    $loopbackOutcome = Test-mdiTcpPort -ComputerName '127.0.0.1' -Port $probePort -TimeoutMs 1500
    Assert-That 'CONTROL: a loopback probe reports Connected, so the probe cannot be the guard' (
        $loopbackOutcome.Success -eq $true
    ) "(got Success=$($loopbackOutcome.Success) Detail=$($loopbackOutcome.Detail))"
} else {
    Assert-That 'CONTROL: skipped - no local listening port to prove the loopback answer' $true
}

Assert-That 'CONTROL: Test-mdiUsableComputerAddress rejects loopback' (
    (Test-mdiUsableComputerAddress -Value '127.0.0.1') -eq $false
)
Assert-That 'CONTROL: Test-mdiUsableComputerAddress accepts a real address' (
    (Test-mdiUsableComputerAddress -Value '10.10.1.10') -eq $true
)

Write-Host ''
Write-Host 'The sampling budget is not spent on placeholders'

# Three domains, each holding one placeholder ahead of a reachable server. At MaxPerDomain=1 the
# budget must reach the reachable row in every domain rather than being consumed by the placeholder
# that enumerated first.
$script:crowded = @(
    Row 'dcbad1.mdilab.local'      'mdilab.local'      '0.0.0.0'
    Row 'dc01.mdilab.local'        'mdilab.local'      '10.10.1.10'
    Row 'dcbad2.emea.mdilab.local' 'emea.mdilab.local' '127.0.0.1'
    Row 'dcemea.emea.mdilab.local' 'emea.mdilab.local' '10.10.2.20'
    Row 'dcbad3.fabrikam.local'    'fabrikam.local'    '169.254.10.5'
    Row 'dcfab01.fabrikam.local'   'fabrikam.local'    '10.10.1.50'
)
$sampled = @(Resolve-mdiLdapTarget -DomainControllers $script:crowded -MaxPerDomain 1)
Assert-That 'each domain contributes its REACHABLE server to the LDAP sample' (
    $sampled.Count -eq 3 -and
    (@($sampled | ForEach-Object { [string] $_.IP } | Sort-Object) -join ',') -eq '10.10.1.10,10.10.1.50,10.10.2.20'
) "(got $($sampled.Count): $(@($sampled | ForEach-Object { $_.IP }) -join ', '))"

$sampledNnr = @(Resolve-mdiNnrTarget -DomainControllers $script:crowded -Domain 'mdilab.local' -MaxTargets 3)
Assert-That 'the NNR sample likewise reaches three reachable servers' (
    $sampledNnr.Count -eq 3 -and
    (@($sampledNnr | ForEach-Object { [string] $_.IP } | Sort-Object) -join ',') -eq '10.10.1.10,10.10.1.50,10.10.2.20'
) "(got $($sampledNnr.Count): $(@($sampledNnr | ForEach-Object { $_.IP }) -join ', '))"

Write-Host ''
Write-Host 'A multi-homed server keeps the address that works'

# One host, two NICs: the usable address must survive and the placeholder must not be probed.
$script:multi = @(
    [PSCustomObject]@{ Name = 'dc02.mdilab.local'; Domain = 'mdilab.local'; IP = '0.0.0.0'; Addresses = @('0.0.0.0', '10.10.1.11') }
    [PSCustomObject]@{ Name = 'dc02.mdilab.local'; Domain = 'mdilab.local'; IP = '10.10.1.11'; Addresses = @('0.0.0.0', '10.10.1.11') }
)
$multiTargets = @(Resolve-mdiLdapTarget -DomainControllers $script:multi -MaxPerDomain 5)
Assert-That 'the multi-homed host is probed on its usable address only' (
    $multiTargets.Count -eq 1 -and $multiTargets[0].IP -eq '10.10.1.11'
) "(got $($multiTargets.Count): $(@($multiTargets | ForEach-Object { $_.IP }) -join ', '))"

Assert-That 'and it is NOT declared addressless, because one NIC does work' (
    @(Get-mdiAddresslessDomainController -Inventory $script:multi).Count -eq 0
) "(got $(@(Get-mdiAddresslessDomainController -Inventory $script:multi) -join ', '))"

Write-Host ''
Write-Host 'An empty estate is still empty, and a wholly unreachable one is not silently green'

Assert-That 'an estate of placeholders alone yields no targets at all' (
    @(Resolve-mdiLdapTarget -DomainControllers @($script:inventory | Where-Object { $_.IP -ne '10.10.1.10' }) -MaxPerDomain 5).Count -eq 0
)
Assert-That 'and every one of its rows is declared addressless instead' (
    @(Get-mdiAddresslessDomainController -Inventory @($script:inventory | Where-Object { $_.IP -ne '10.10.1.10' })).Count -eq 5
)

Write-Host ''
Write-Host 'The producer and the resolver agree, so neither relies on the other'

# The DIRECTORY answers with unusable addresses. This is the only stub; Get-mdiDomainControllerInventory
# below is the shipped code, and it is the single producer Main feeds to the resolvers.
function Resolve-mdiDomainController {
    param([Parameter(Mandatory = $true)] [string] $Domain)
    [PSCustomObject]@{
        Method  = 'ADWS'
        Error   = $null
        Unnamed = 0
        Servers = @(
            [PSCustomObject]@{ Name = 'dcloop.mdilab.local';  IP = '127.0.0.1';    Addresses = @('127.0.0.1');    AddressResolutionComplete = $true }
            [PSCustomObject]@{ Name = 'dczero.mdilab.local';  IP = '0.0.0.0';      Addresses = @('0.0.0.0');      AddressResolutionComplete = $true }
            [PSCustomObject]@{ Name = 'dcapipa.mdilab.local'; IP = '169.254.10.5'; Addresses = @('169.254.10.5'); AddressResolutionComplete = $true }
            [PSCustomObject]@{ Name = 'dcgood.mdilab.local';  IP = '10.10.1.10';   Addresses = @('10.10.1.10');   AddressResolutionComplete = $true }
        )
    }
}

$produced = @(Get-mdiDomainControllerInventory -Domain @('mdilab.local'))
$producedUnusable = @($produced | Where-Object { $_.IP -and -not (Test-mdiUsableComputerAddress -Value $_.IP) })
Assert-That 'the shipped inventory emits no row carrying an unusable address' ($producedUnusable.Count -eq 0) `
    "(got $($producedUnusable.Count): $(@($producedUnusable | ForEach-Object { $_.IP }) -join ', '))"

Assert-That 'the unreachable servers are KEPT as rows rather than dropped from the estate' (
    $produced.Count -eq 4
) "(got $($produced.Count))"

Assert-That 'and the reachable one keeps its address' (
    @($produced | Where-Object { $_.IP -eq '10.10.1.10' }).Count -eq 1
)

$producedTargets = @(Resolve-mdiLdapTarget -DomainControllers $produced -MaxPerDomain 5)
Assert-That 'so the plan built from the shipped inventory probes only the reachable server' (
    $producedTargets.Count -eq 1 -and $producedTargets[0].IP -eq '10.10.1.10'
) "(got $($producedTargets.Count): $(@($producedTargets | ForEach-Object { $_.IP }) -join ', '))"

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
