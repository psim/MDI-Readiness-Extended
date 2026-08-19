<#
    A DISJOINT NETBIOS SUFFIX IS NOT A DOMAIN ENTITLED TO TAKE ANOTHER DOMAIN'S PROBE SLOT.

    Resolve-mdiNnrTarget spends a bounded NNR budget - -MaxNnrTargets, default 5 - across the whole
    estate. Main hands it every domain of every forest in scope, so the budget is spread ROUND-ROBIN,
    one host per domain per pass, for the reason the function states itself: "A forest nobody probed
    is not a forest that passed."

    The queue order was: every NAMED domain first, in enumeration order, then the NAMELESS queue.
    That second rule was added because a host whose domain could not be read formed a queue of its
    own and took a slot ahead of a readable domain that had none yet - pinned by
    UnreadableDomainIsNotEntitledToAProbeSlot.Tests.ps1. This test pins the SAME harm arriving
    through a queue that is not nameless at all.

    WHERE THE EXTRA QUEUE COMES FROM. The operator-supplied branch tags each target's Domain from the
    DNS SUFFIX of the name that resolved:

        $dotIndex = ([string] $name).IndexOf('.')
        if ($dotIndex -gt 0 -and $dotIndex -lt (([string] $name).Length - 1)) {
            $suffix = ([string] $name).Substring($dotIndex + 1).Trim().TrimEnd('.')

    In a DISJOINT namespace that suffix is the NetBIOS name. fabrikam.local's NetBIOS name is
    FABCORP - not a case variant and not a trailing-dot variant, a different string entirely - and a
    member of a disjoint namespace is routinely written that way; Resolve-mdiDomainScopeDnsName uses
    ws4.FABCORP as its own example, and Get-mdiMatchingTrustee's header records that "the NetBIOS
    name frequently is not the DNS label at all". FABCORP and fabrikam.local ARE ONE DOMAIN. They
    key as two, because no string rule turns one into the other, and the second one then takes a
    share of a GLOBAL budget that the first was entitled to.

    Measured on the shipped function, five operator-named hosts across the extended lab's four
    domains - mdilab.local, emea.mdilab.local, apac.mdilab.local and the second forest
    fabrikam.local - at -MaxTargets 4, with stubbed name resolution, differing in NOTHING but where
    the FABCORP-suffixed host sat in the list:

        -NnrTargetComputer                                              fabrikam.local
        ws1.mdilab, ws2.emea, ws3.apac, ws4.fabrikam, ws5.FABCORP       reached
        ws1.mdilab, ws5.FABCORP, ws2.emea, ws3.apac, ws4.fabrikam       NO TARGET
        ws5.FABCORP, ws1.mdilab, ws2.emea, ws3.apac, ws4.fabrikam       NO TARGET

    The caller still received four targets and the NNR card still reported a result for the run, so
    the second forest - the one the cross-forest trust exists to cover - was never probed and no
    surface said so. Serving ORDER alone decided it, on the same five hosts and the same budget.

    THE RULE. A DOTLESS domain key is served after every QUALIFIED one, by the same rule the nameless
    queue already follows: a key that is not established to be a domain of its own must not cost a
    domain that WAS established the slot it was entitled to. Order only - never dropped, never
    merged.

    WHY IT IS NOT MERGED. The tool cannot know FABCORP is fabrikam.local without asking a directory,
    and inventing that mapping would be the worse failure this codebase exists to prevent. Ordering
    is safe in a way merging is not: it can only ever cost the AMBIGUOUS host its slot.

    WHAT MUST NOT REGRESS, pinned below alongside:
      * a SINGLE-LABEL DNS domain is legal - Resolve-mdiDomainScopeDnsName says so - so a dotless
        key must still be SERVED, merely last, and must still be probed when the budget allows;
      * an estate whose domains are ALL dotless must be ordered among itself exactly as before;
      * the spellings Get-mdiProbeDomainKey already folds - case, the trailing DNS root dot,
        surrounding whitespace - must starve nothing, before or after. This must not become a second
        copy of that rule;
      * a single-domain estate must select exactly the hosts it always did;
      * the nameless queue must still be served LAST OF ALL, after the dotless one;
      * the cap must still count HOSTS and keep every address of a multi-homed host;
      * Resolve-mdiLdapTarget, whose budget is PER DOMAIN and which therefore cannot lose a forest
        this way, must be unchanged.
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

Write-Host 'A disjoint NetBIOS suffix is not a domain entitled to another domain''s probe slot' -ForegroundColor Cyan

function New-Row ($Name, $Ip, $Domain) {
    [PSCustomObject]@{ Name = $Name; IP = $Ip; Domain = $Domain; MultiHomed = $false; Enumerated = $true }
}
function Get-Domains ($Targets) {
    @($Targets | ForEach-Object { Get-mdiProbeDomainKey -Domain $_.Domain } | Select-Object -Unique)
}
function Get-Names ($Targets) { (@($Targets | ForEach-Object { [string] $_.Name }) -join ', ') }

# The four domains the extended lab really has: the mdilab.local tree with its two children, and the
# SECOND FOREST across the cross-forest trust.
$REAL = @('mdilab.local', 'emea.mdilab.local', 'apac.mdilab.local', 'fabrikam.local')

# ---------------------------------------------------------------------------------------------------
# HALF ONE. THE ORIGIN. The operator-supplied branch really does produce a FABCORP queue from a name
# the operator wrote the way Windows shows it. Name resolution is stubbed - the behaviour under test
# is the DOMAIN QUEUEING of names that DID resolve, not resolution itself. -Domain is left empty so
# ConvertTo-mdiCanonicalComputerName cannot re-qualify the names and mask the suffix.
# ---------------------------------------------------------------------------------------------------
$script:hostAddress = @{}
$script:nextOctet = 10
function Get-mdiComputerAddress {
    param(
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $false)] [AllowNull()] [string[]] $KnownAddress = $null
    )
    $key = $ComputerName.ToLowerInvariant()
    if (-not $script:hostAddress.ContainsKey($key)) {
        $script:hostAddress[$key] = '10.20.0.{0}' -f $script:nextOctet
        $script:nextOctet++
    }
    , @($script:hostAddress[$key])
}

# THE CONTROL, first: every host qualified with its own DNS domain reaches all four. If this ever
# fails, nothing below means anything.
$control = @(Resolve-mdiNnrTarget -DomainControllers @() -MaxTargets 4 -NnrTargetComputer @(
        'ws1.mdilab.local', 'ws2.emea.mdilab.local', 'ws3.apac.mdilab.local',
        'ws4.fabrikam.local', 'ws5.fabrikam.local'))
$controlDomains = Get-Domains $control
Assert-That 'CONTROL: four qualified domains, budget 4, every domain reached' `
(@($REAL | Where-Object { $controlDomains -notcontains $_ }).Count -eq 0) `
("got {0}" -f ($controlDomains -join ', '))

# THE DEFECT. The same five hosts, one of them written with the DISJOINT NetBIOS suffix, at each of
# the three positions that used to decide the answer.
$positions = [ordered]@{
    'FABCORP host LAST'   = @('ws1.mdilab.local', 'ws2.emea.mdilab.local', 'ws3.apac.mdilab.local', 'ws4.fabrikam.local', 'ws5.FABCORP')
    'FABCORP host SECOND' = @('ws1.mdilab.local', 'ws5.FABCORP', 'ws2.emea.mdilab.local', 'ws3.apac.mdilab.local', 'ws4.fabrikam.local')
    'FABCORP host FIRST'  = @('ws5.FABCORP', 'ws1.mdilab.local', 'ws2.emea.mdilab.local', 'ws3.apac.mdilab.local', 'ws4.fabrikam.local')
}
foreach ($p in $positions.Keys) {
    $t = @(Resolve-mdiNnrTarget -DomainControllers @() -MaxTargets 4 -NnrTargetComputer $positions[$p])
    $d = Get-Domains $t
    $missing = @($REAL | Where-Object { $d -notcontains $_ })
    Assert-That ("{0}: no real domain loses its NNR slot" -f $p) ($missing.Count -eq 0) `
    ("{0} got no target; probed {1}" -f ($missing -join ', '), (Get-Names $t))
}

# The answer must not depend on serving order at all: all three positions probe the same hosts.
$sets = @($positions.Keys | ForEach-Object {
        $t = @(Resolve-mdiNnrTarget -DomainControllers @() -MaxTargets 4 -NnrTargetComputer $positions[$_])
        (@($t | ForEach-Object { ([string] $_.Name).ToLowerInvariant() }) | Sort-Object) -join ','
    } | Select-Object -Unique)
Assert-That 'the three orderings select the SAME hosts' (@($sets).Count -eq 1) `
("got {0} distinct outcomes: {1}" -f @($sets).Count, ($sets -join ' | '))

# ---------------------------------------------------------------------------------------------------
# HALF TWO. THE ORDERING ITSELF, driven through the domain-controller branch so nothing is stubbed.
# A dotless Domain must not take the slot of a qualified one, whatever order the rows arrive in.
# ---------------------------------------------------------------------------------------------------
function New-Estate ($DotlessFirst) {
    $dotless = New-Row 'memfab01.fabcorp' '10.10.1.51' 'FABCORP'
    $rest = @(
        (New-Row 'dc2022.mdilab.local' '10.0.1.10' 'mdilab.local')
        (New-Row 'dcemea.emea.mdilab.local' '10.0.2.10' 'emea.mdilab.local')
        (New-Row 'dcapac.apac.mdilab.local' '10.0.3.10' 'apac.mdilab.local')
        (New-Row 'dcfab01.fabrikam.local' '10.10.1.50' 'fabrikam.local')
    )
    if ($DotlessFirst) { @(@($dotless) + $rest) } else { @($rest + @($dotless)) }
}
foreach ($first in $true, $false) {
    $t = @(Resolve-mdiNnrTarget -DomainControllers (New-Estate $first) -MaxTargets 4)
    $d = Get-Domains $t
    $missing = @($REAL | Where-Object { $d -notcontains $_ })
    Assert-That ("a dotless Domain row placed {0} costs no qualified domain its slot" -f $(if ($first) { 'FIRST' } else { 'LAST' })) `
    ($missing.Count -eq 0) ("{0} got no target; probed {1}" -f ($missing -join ', '), (Get-Names $t))
}

# SERVED LAST, NOT DROPPED. A single-label DNS domain is legal, so when the budget can afford it the
# dotless host must still be probed. Refusing to probe it would be a different false green.
$roomy = @(Resolve-mdiNnrTarget -DomainControllers (New-Estate $true) -MaxTargets 5)
Assert-That 'a dotless-domain host is still probed when the budget allows' `
(@($roomy | Where-Object { $_.Name -eq 'memfab01.fabcorp' }).Count -eq 1) ("probed {0}" -f (Get-Names $roomy))

# AN ESTATE THAT IS ALL DOTLESS is ordered among itself exactly as before - the rule must not turn a
# legal single-label estate into an unserved one.
$allDotless = @(
    (New-Row 'h1.corpa' '10.30.0.1' 'CORPA')
    (New-Row 'h2.corpb' '10.30.0.2' 'CORPB')
    (New-Row 'h3.corpc' '10.30.0.3' 'CORPC')
)
$ad = @(Resolve-mdiNnrTarget -DomainControllers $allDotless -MaxTargets 2)
Assert-That 'an all-dotless estate still spreads across its own domains' `
((Get-Domains $ad).Count -eq 2) ("got {0}" -f ((Get-Domains $ad) -join ', '))

# THE NAMELESS QUEUE IS STILL LAST OF ALL - after the dotless one, not before it. A row whose domain
# could not be READ is a weaker claim than one that merely is not qualified.
$withBoth = @(
    (New-Row 'dcjunk.mdilab.local' '10.0.9.99' @{})
    (New-Row 'memfab01.fabcorp' '10.10.1.51' 'FABCORP')
    (New-Row 'dc2022.mdilab.local' '10.0.1.10' 'mdilab.local')
    (New-Row 'dcfab01.fabrikam.local' '10.10.1.50' 'fabrikam.local')
)
$b = @(Resolve-mdiNnrTarget -DomainControllers $withBoth -MaxTargets 2)
$bd = Get-Domains $b
Assert-That 'with a nameless AND a dotless row, the two QUALIFIED domains are served first' `
($bd -contains 'mdilab.local' -and $bd -contains 'fabrikam.local') ("probed {0}" -f (Get-Names $b))
$b3 = @(Resolve-mdiNnrTarget -DomainControllers $withBoth -MaxTargets 3)
Assert-That 'and the third slot goes to the DOTLESS row, not the nameless one' `
(@($b3 | Where-Object { $_.Name -eq 'memfab01.fabcorp' }).Count -eq 1) ("probed {0}" -f (Get-Names $b3))

# ---------------------------------------------------------------------------------------------------
# WHAT MUST NOT REGRESS.
# ---------------------------------------------------------------------------------------------------
# The spellings the KEY already folds must starve nothing. This rule must not become a second copy
# of that one.
foreach ($spelling in 'FABRIKAM.LOCAL', 'fabrikam.local.', '  fabrikam.local  ') {
    $rows = @(
        (New-Row 'dc2022.mdilab.local' '10.0.1.10' 'mdilab.local')
        (New-Row 'memfab01.fabrikam.local' '10.10.1.51' $spelling)
        (New-Row 'dcemea.emea.mdilab.local' '10.0.2.10' 'emea.mdilab.local')
        (New-Row 'dcfab01.fabrikam.local' '10.10.1.50' 'fabrikam.local')
    )
    $t = @(Resolve-mdiNnrTarget -DomainControllers $rows -MaxTargets 3)
    $d = Get-Domains $t
    $missing = @(@('mdilab.local', 'emea.mdilab.local', 'fabrikam.local') | Where-Object { $d -notcontains $_ })
    Assert-That ("a folded spelling ({0}) starves nothing and takes no extra queue" -f $spelling.Trim()) `
    ($missing.Count -eq 0) ("{0} got no target; probed {1}" -f ($missing -join ', '), (Get-Names $t))
}

# A single-domain estate still selects exactly the hosts it always did - the first N, in order.
$single = @(
    (New-Row 'dc2022.mdilab.local' '10.0.1.10' 'mdilab.local')
    (New-Row 'dc03.mdilab.local' '10.0.1.13' 'mdilab.local')
    (New-Row 'dc04.mdilab.local' '10.0.1.14' 'mdilab.local')
)
$s = @(Resolve-mdiNnrTarget -DomainControllers $single -MaxTargets 2)
Assert-That 'a single-domain estate still selects the first hosts in order' `
((Get-Names $s) -eq 'dc2022.mdilab.local, dc03.mdilab.local') ("got {0}" -f (Get-Names $s))

# The cap counts HOSTS, not addresses.
$multi = @(
    (New-Row 'dc2022.mdilab.local' '10.0.1.10' 'mdilab.local')
    (New-Row 'dc2022.mdilab.local' '10.0.1.11' 'mdilab.local')
    (New-Row 'memfab01.fabcorp' '10.10.1.51' 'FABCORP')
    (New-Row 'dcfab01.fabrikam.local' '10.10.1.50' 'fabrikam.local')
)
$m = @(Resolve-mdiNnrTarget -DomainControllers $multi -MaxTargets 2)
Assert-That 'both NICs of a selected multi-homed host survive the cap' `
(@($m | Where-Object { $_.Name -eq 'dc2022.mdilab.local' }).Count -eq 2) `
("got {0}" -f ((@($m | ForEach-Object { '{0}/{1}' -f $_.Name, $_.IP })) -join ', '))
Assert-That 'and fabrikam.local still got its slot past the dotless row' `
((Get-Domains $m) -contains 'fabrikam.local') ("got {0}" -f ((Get-Domains $m) -join ', '))

# MaxTargets <= 0 means no cap: nothing is spread, nothing is dropped.
$uncapped = @(Resolve-mdiNnrTarget -DomainControllers (New-Estate $true) -MaxTargets 0)
Assert-That 'MaxTargets 0 still returns the whole estate' ($uncapped.Count -eq 5) ("got {0}" -f $uncapped.Count)

# An empty estate is still zero targets.
$none = @(Resolve-mdiNnrTarget -DomainControllers @() -MaxTargets 5)
Assert-That 'an empty estate is zero targets' ($none.Count -eq 0) ("got {0}" -f $none.Count)

# Resolve-mdiLdapTarget's budget is PER DOMAIN, so it cannot lose a forest this way and must be
# unchanged - which is what proves the harm belongs to the GLOBAL budget and not to the key.
$ldap = @(Resolve-mdiLdapTarget -DomainControllers (New-Estate $true) -MaxPerDomain 1)
$ld = Get-Domains $ldap
Assert-That 'the LDAP sampler still reaches every qualified domain' `
(@($REAL | Where-Object { $ld -notcontains $_ }).Count -eq 0) ("got {0}" -f ($ld -join ', '))
Assert-That 'and the LDAP sampler still probes the dotless row too' `
(@($ldap | Where-Object { $_.Name -eq 'memfab01.fabcorp' }).Count -eq 1) ("probed {0}" -f (Get-Names $ldap))

Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 }
