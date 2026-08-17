<#
    The NNR sample budget must reach every domain in the estate even when the operator named the
    targets by hand.

    THE DEFECT THIS PINS. Resolve-mdiNnrTarget caps the NNR sample at -MaxTargets HOSTS, and the cap
    deliberately spreads that budget ACROSS DOMAINS - one host per domain per pass, in enumeration
    order - so that every domain is reached before any domain takes a second slot. The spreading key
    is read off the target objects themselves:

        Group-Object -Property { ([string] @($_.Group)[0].Domain).Trim().TrimEnd('.') }

    That works for the DEFAULT targets, which are domain controllers: Get-mdiDomainControllerInventory
    stamps every row it emits with the domain it was enumerated from. It did not work for the OTHER
    source of targets - the operator's own -NnrTargetComputer list - because that branch emitted

        [PSCustomObject]@{ Name = $name; IP = $address; MultiHomed = ($addresses.Count -gt 1) }

    with no Domain property at all. Every operator-supplied host therefore grouped under one empty
    key, the spreading loop had a single queue to walk, and the cap silently degraded back to "the
    first N hosts of a flat list" - precisely the behaviour the spreading was written to replace,
    still in force for whichever targets the operator chose by hand.

    This is the family every defect in this project has belonged to: a value that was never read
    coming back looking like a measurement. The absent property does not read as absent, it reads as
    the empty-string domain, and one queue keyed '' is indistinguishable to the loop from an estate
    that genuinely has one domain.

    WHY THE LAB REACHES IT NOW. It takes MORE THAN ONE DOMAIN in the target list to see any
    difference, and before 17 August the estate was a single forest whose hosts an operator would
    list from one domain. The lab now spans mdilab.local (plus two child domains) and fabrikam.local
    across a bidirectional forestTransitive trust, so naming a handful of representative hosts from
    both forests - which is the ordinary way to use -NnrTargetComputer - is what exposes it.

    MEASURED ON THE SHIPPED FUNCTION, an eight-host estate spanning mdilab.local and fabrikam.local
    at the default MaxTargets=5, with the six mdilab.local hosts listed first:

        domain-controller targets   5 sampled, 2 of them fabrikam.local
        operator-supplied targets   5 sampled, 0 of them fabrikam.local

    Same estate, same cap, same run. The second forest contributed no NNR target whatsoever and the
    NNR card still reported a result. A forest nobody probed is not a forest that passed.

    THE FIX. Operator-supplied targets are tagged with the domain they belong to, read off $name -
    the spelling that ACTUALLY RESOLVED. It is deliberately not read off -Domain: -Domain can name a
    different forest from the host being probed, and can be a DISJOINT NetBIOS name (fabrikam.local
    is NetBIOS FABCORP, a different string entirely and not a DNS suffix at all), and the bare-name
    undo immediately above may have just discarded the qualified spelling in favour of one carrying
    no suffix. A name with no dot, and a target supplied as a bare IP address, yield $null - unknown
    is what they are, and $null is what they already grouped as, so a single-domain estate selects
    exactly the hosts it always did.

    Pinned here:

    1. Operator-supplied targets carry a Domain, and it is the DNS suffix of the resolved name.
    2. With more hosts than the cap, spanning two forests and the second forest listed LAST, the
       second forest still contributes targets - the case that measured zero.
    3. The operator-supplied path and the domain-controller path sample the same estate the same way.
    4. A single-domain estate is UNCHANGED: same count, same hosts, same order as a flat first-N.
    5. The tag is a measurement, not a fabrication - a bare short name and a bare IP address get
       $null, and a NetBIOS-style -Domain is never welded on as a suffix.
    6. Child domains of one forest spread too - the key is the actual suffix, not the forest.
    7. Every address of a multi-homed target still carries the tag, and the cap still counts HOSTS.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Resolve-mdiNnrTarget') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The directory is not reachable from a test run. Stubbed explicitly rather than relied upon, so the
# test pins the behaviour even on a machine that is domain-joined.
Set-Item -Path function:script:Get-ADComputer -Value { param($Identity, $Properties, $Server, $ErrorAction) throw 'no directory in a test run' }

# Name resolution is stubbed so the test does not depend on this machine's DNS, its suffix search
# list, or the lab being up.
$script:resolvable = @{
    'dc2016.mdilab.local'     = @('10.10.1.11')
    'dc2019.mdilab.local'     = @('10.10.1.12')
    'dc2022.mdilab.local'     = @('10.10.1.13')
    'dc2025.mdilab.local'     = @('10.10.1.14')
    'mem01.mdilab.local'      = @('10.10.1.20')
    'mem03.mdilab.local'      = @('10.10.1.21')
    'dcfab01.fabrikam.local'  = @('10.10.1.50')
    'memfab01.fabrikam.local' = @('10.10.1.51')
    'dcemea.emea.mdilab.local' = @('10.10.2.10')
    'dcapac.apac.mdilab.local' = @('10.10.3.10')
    'wks01'                   = @('10.10.9.1', '10.10.9.2')
    '10.10.1.99'              = @('10.10.1.99')
}
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param($ComputerName, $KnownAddress)
    $key = ([string] $ComputerName).ToLowerInvariant()
    if ($script:resolvable.ContainsKey($key)) { return @($script:resolvable[$key]) }
    @()
}

function Get-Targets {
    param([string[]] $Requested, $Domain = $null, [int] $Max = 5)
    @(Resolve-mdiNnrTarget -DomainControllers @() -NnrTargetComputer $Requested -Domain $Domain -MaxTargets $Max)
}
function Count-In { param($Targets, [string] $Suffix) @($Targets | Where-Object { $_.Name -like "*$Suffix" }).Count }

# The estate, with the SIX mdilab.local hosts listed BEFORE the two fabrikam.local ones. That order
# is what made the shipped function sample zero fabrikam hosts: it is not incidental to the test.
$script:estate = @(
    'dc2016.mdilab.local', 'dc2019.mdilab.local', 'dc2022.mdilab.local', 'dc2025.mdilab.local',
    'mem01.mdilab.local', 'mem03.mdilab.local',
    'dcfab01.fabrikam.local', 'memfab01.fabrikam.local'
)

'--- 1. operator-supplied targets carry the domain of the name that resolved ---'
$t = Get-Targets -Requested @('dcfab01.fabrikam.local')
Assert-That 'the target has a Domain property' ($null -ne @($t)[0].PSObject.Properties['Domain']) 'the property is absent, so the cap groups every host under one key'
Assert-That 'and it is the DNS suffix of the resolved name' (@($t)[0].Domain -eq 'fabrikam.local') "got $(@($t)[0].Domain)"
$t = Get-Targets -Requested @('dc2016.mdilab.local')
Assert-That 'mdilab.local is tagged too' (@($t)[0].Domain -eq 'mdilab.local') "got $(@($t)[0].Domain)"

'--- 2. the second forest still contributes when it is listed LAST and the cap bites ---'
$t = Get-Targets -Requested $script:estate -Max 5
Assert-That 'the cap is honoured' (@($t).Count -eq 5) "got $(@($t).Count)"
Assert-That 'fabrikam.local is represented at all' ((Count-In $t 'fabrikam.local') -gt 0) 'the second forest contributed NO NNR target'
Assert-That 'and it gets its fair share of a 5-host budget' ((Count-In $t 'fabrikam.local') -eq 2) "got $(Count-In $t 'fabrikam.local')"
Assert-That 'mdilab.local keeps the rest' ((Count-In $t 'mdilab.local') -eq 3) "got $(Count-In $t 'mdilab.local')"

'--- 3. the operator path and the domain-controller path sample alike ---'
$dcs = @($script:estate | ForEach-Object {
        [PSCustomObject]@{
            Name = $_; IP = $script:resolvable[$_][0]; Addresses = @($script:resolvable[$_]); MultiHomed = $false
            Domain = $(if ($_ -like '*fabrikam.local') { 'fabrikam.local' } else { 'mdilab.local' })
            Enumerated = $true; Error = $null
        }
    })
$viaDc = @(Resolve-mdiNnrTarget -DomainControllers $dcs -MaxTargets 5)
$viaOp = Get-Targets -Requested $script:estate -Max 5
Assert-That 'both paths sample the same number of hosts' (@($viaDc).Count -eq @($viaOp).Count) "dc=$(@($viaDc).Count) op=$(@($viaOp).Count)"
Assert-That 'both paths reach fabrikam.local equally' ((Count-In $viaDc 'fabrikam.local') -eq (Count-In $viaOp 'fabrikam.local')) "dc=$(Count-In $viaDc 'fabrikam.local') op=$(Count-In $viaOp 'fabrikam.local')"

'--- 4. a single-domain estate is unchanged (same hosts, same order) ---'
$single = @('dc2016.mdilab.local', 'dc2019.mdilab.local', 'dc2022.mdilab.local', 'dc2025.mdilab.local', 'mem01.mdilab.local', 'mem03.mdilab.local')
$t = Get-Targets -Requested $single -Max 5
Assert-That 'five of six hosts are sampled' (@($t).Count -eq 5) "got $(@($t).Count)"
Assert-That 'and they are the first five, in the order supplied' ((@($t | ForEach-Object { $_.Name }) -join ',') -eq (($single | Select-Object -First 5) -join ',')) (@($t | ForEach-Object { $_.Name }) -join ',')
$uncapped = Get-Targets -Requested $single -Max 0
Assert-That 'an uncapped run returns every host' (@($uncapped).Count -eq 6) "got $(@($uncapped).Count)"

'--- 5. the tag is a measurement, never a fabrication ---'
$t = Get-Targets -Requested @('wks01') -Domain 'FABCORP'
Assert-That 'a bare short name that resolves is still kept' (@($t).Count -eq 2) "got $(@($t).Count)"
Assert-That 'and a NetBIOS -Domain is NOT welded on as a suffix' ($null -eq @($t)[0].Domain) "got $(@($t)[0].Domain)"
$t = Get-Targets -Requested @('wks01') -Domain 'fabrikam.local'
Assert-That 'nor is a DNS -Domain the host does not belong to' ($null -eq @($t)[0].Domain) "got $(@($t)[0].Domain)"
$t = Get-Targets -Requested @('10.10.1.99')
Assert-That 'a target given as a bare IP address is kept' (@($t).Count -eq 1) "got $(@($t).Count)"
Assert-That 'and its address octets are not read as a domain' ($null -eq @($t)[0].Domain) "got $(@($t)[0].Domain)"

'--- 6. child domains of one forest spread as well ---'
$tree = @('dc2016.mdilab.local', 'dc2019.mdilab.local', 'dc2022.mdilab.local', 'dc2025.mdilab.local', 'dcemea.emea.mdilab.local', 'dcapac.apac.mdilab.local')
$t = Get-Targets -Requested $tree -Max 3
Assert-That 'three hosts, one from each domain of the tree' (@($t).Count -eq 3) "got $(@($t).Count)"
$suffixes = @($t | ForEach-Object { $_.Domain }) | Sort-Object
Assert-That 'and the three domains are distinct' ((($suffixes | Select-Object -Unique).Count) -eq 3) ($suffixes -join ',')
Assert-That 'emea is not swallowed by its parent' ((($suffixes -join ',')) -match 'emea\.mdilab\.local') ($suffixes -join ',')

'--- 7. a multi-homed target keeps every address, and the cap counts HOSTS ---'
$t = Get-Targets -Requested @('wks01', 'dcfab01.fabrikam.local') -Max 2
Assert-That 'both NICs of the multi-homed host survive the cap' (@($t | Where-Object { $_.Name -eq 'wks01' }).Count -eq 2) "got $(@($t | Where-Object { $_.Name -eq 'wks01' }).Count)"
Assert-That 'the other host is sampled too' (@($t | Where-Object { $_.Name -eq 'dcfab01.fabrikam.local' }).Count -eq 1) "got $(@($t | Where-Object { $_.Name -eq 'dcfab01.fabrikam.local' }).Count)"
Assert-That 'every address row carries the tag' ((@($t | Where-Object { $_.Name -eq 'wks01' -and $null -eq $_.Domain }).Count) -eq 2) 'a NIC lost its tag'
Assert-That 'and MultiHomed is still right' ((@($t | Where-Object { $_.Name -eq 'wks01' })[0].MultiHomed) -eq $true)

''
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
