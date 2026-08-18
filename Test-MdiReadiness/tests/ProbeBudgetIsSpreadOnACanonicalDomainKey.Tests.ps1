<#
    THE DEFECT THIS TEST PINS

    Resolve-mdiLdapTarget and Resolve-mdiNnrTarget are siblings. Both spread a bounded probe budget
    ACROSS DOMAINS, and both exist for the reason the product states in their own comments after the
    second forest arrived: a forest nobody probed is not a forest that passed.

    They had drifted into two different spellings of "which domain is this":

        Resolve-mdiNnrTarget    Group-Object -Property { ([string] @($_.Group)[0].Domain).Trim().TrimEnd('.') }
        Resolve-mdiLdapTarget   Group-Object -Property Domain

    Group-Object given a BARE PROPERTY NAME compares the raw values rather than a string, and an
    inventory row can carry a Domain that is not a plain string. That shape is not hypothetical here:
    Get-mdiProbeTargetKey was written specifically because this estate produced "a six-row estate
    holding one row whose Domain was @('fabrikam.local')" - a domain enumerated into a one-element
    collection instead of a scalar.

    Measured on the shipped functions, four rows spanning mdilab.local and fabrikam.local whose
    Domain was a one-element array, at MaxPerDomain / MaxTargets = 1:

        Group-Object -Property Domain          1 group, named '{mdilab.local}'
        Resolve-mdiLdapTarget                  1 target,  domains: mdilab.local
        Resolve-mdiNnrTarget, IDENTICAL rows   2 targets, domains: mdilab.local, fabrikam.local

    Two different forests were ONE group. The whole of fabrikam.local therefore received no LDAP
    probe target at all, while the LDAP card still reported a result for the run - the cross-forest
    LDAPS and LDAPS-GC ports that -MultiForest promotes from Optional to REQUIRED were never measured
    against the forest that made them required, and nothing in the output said so. That is this
    project's defect family exactly: a value that was never read comes back looking like a
    measurement. It is also the very defect the per-domain spreading was written to fix,
    reintroduced one line below the fix by the spelling of the group key.

    The NNR sibling reaching both forests on the identical rows is what proves the rows are legible
    and the LDAP sampler is what was wrong, rather than the test feeding a shape nothing produces.

    The DNS ROOT DOT and whitespace failed the other way on the same function. 'fabrikam.local'
    beside 'fabrikam.local.' produced 2 LDAP targets for ONE domain, as did 'fabrikam.local' beside
    ' fabrikam.local ' - one domain taking double its budget, spent against the generated probe
    command line length limit and the port-probe time budget that this script already throws and
    warns on. The NNR sibling returned 1 for both.

    THE FIX

    Get-mdiProbeDomainKey now owns the domain key, and BOTH samplers group through it, so the two
    cannot drift apart again. It coerces with [string], trims whitespace and strips the DNS root dot,
    and keys an unreadable domain as the empty string rather than throwing - because an unreadable
    row must not cost a READABLE domain the slot it was entitled to. Case is left to Group-Object,
    which is case-insensitive by default, matching what both samplers already did.

    The tests below pin every one of those measurements, in both directions.
#>

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$script:target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $script:target)) {
    $script:target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
}
if (-not (Test-Path $script:target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$script:pass = 0
$script:fail = 0
function Assert-True {
    param([string] $What, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:pass++
        Write-Host ("  PASS  {0}" -f $What) -ForegroundColor Green
    } else {
        $script:fail++
        Write-Host ("  FAIL  {0} {1}" -f $What, $Detail) -ForegroundColor Red
    }
}

$text = Get-Content -LiteralPath $script:target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main')
if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body

function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

Write-Host 'The per-domain probe budget is spread on a CANONICAL domain key, in both samplers'

function New-Row {
    param([string] $Name, [object] $Domain, [string] $IP)
    [PSCustomObject]@{ Name = $Name; Domain = $Domain; IP = $IP; Addresses = @($IP) }
}

# Which domains actually received a target, judged by the SUFFIX OF THE NAME that came back - never
# by the Domain field the sampler grouped on, which is the thing under test.
function Get-SuffixSet {
    param([object[]] $Targets)
    @($Targets | ForEach-Object {
            $n = [string] $_.Name
            $d = $n.IndexOf('.')
            if ($d -gt 0) { $n.Substring($d + 1).Trim().TrimEnd('.').ToLowerInvariant() } else { '<none>' }
        } | Sort-Object -Unique)
}

# --- the shared key itself ----------------------------------------------------------------------
Assert-True 'a one-element collection keys as the domain it holds, not as a collection' `
    ((Get-mdiProbeDomainKey -Domain @('fabrikam.local')) -eq 'fabrikam.local') `
    ("keyed as [{0}]" -f (Get-mdiProbeDomainKey -Domain @('fabrikam.local')))

Assert-True 'two different forests in one-element collections do not key alike' `
    ((Get-mdiProbeDomainKey -Domain @('mdilab.local')) -ne (Get-mdiProbeDomainKey -Domain @('fabrikam.local'))) `
    ("both keyed as [{0}]" -f (Get-mdiProbeDomainKey -Domain @('mdilab.local')))

Assert-True 'the DNS root dot is stripped' `
    ((Get-mdiProbeDomainKey -Domain 'fabrikam.local.') -eq (Get-mdiProbeDomainKey -Domain 'fabrikam.local')) `
    'a trailing root dot produced a different domain'

Assert-True 'whitespace padding is stripped, including around the root dot' `
    ((Get-mdiProbeDomainKey -Domain ' fabrikam.local . ') -eq 'fabrikam.local') `
    ("keyed as [{0}]" -f (Get-mdiProbeDomainKey -Domain ' fabrikam.local . '))

Assert-True 'an unreadable domain keys as the empty string rather than throwing' `
    ((Get-mdiProbeDomainKey -Domain $null) -eq '' -and (Get-mdiProbeDomainKey -Domain '   ') -eq '') `
    'a null or whitespace domain did not key as the empty string'

# --- the estate that produced the header measurement --------------------------------------------
# Two forests, every Domain enumerated into a one-element collection, mdilab.local first.
$collectionDomains = @(
    (New-Row 'dc01.mdilab.local'      @('mdilab.local')   '10.10.1.10')
    (New-Row 'dc02.mdilab.local'      @('mdilab.local')   '10.10.1.11')
    (New-Row 'dcfab01.fabrikam.local' @('fabrikam.local') '10.10.1.50')
    (New-Row 'memfab01.fabrikam.local' @('fabrikam.local') '10.10.1.51')
)

$ldap = @(Resolve-mdiLdapTarget -DomainControllers $collectionDomains -MaxPerDomain 1)
$ldapDomains = Get-SuffixSet -Targets $ldap
Assert-True 'the trusted forest receives an LDAP target when Domain is a one-element collection' `
    ($ldapDomains -contains 'fabrikam.local') `
    ("domains probed: [{0}]" -f ($ldapDomains -join ','))

Assert-True 'both forests are reached, not one group holding both' `
    ($ldapDomains.Count -eq 2) `
    ("domains probed: [{0}]" -f ($ldapDomains -join ','))

$nnr = @(Resolve-mdiNnrTarget -DomainControllers $collectionDomains -MaxTargets 2)
$nnrDomains = Get-SuffixSet -Targets $nnr
Assert-True 'the NNR sibling reaches both forests on the identical rows' `
    ($nnrDomains.Count -eq 2) `
    ("domains probed: [{0}]" -f ($nnrDomains -join ','))

Assert-True 'the two samplers agree on the same estate' `
    (($ldapDomains -join ',') -eq ($nnrDomains -join ',')) `
    ("LDAP=[{0}] NNR=[{1}]" -f ($ldapDomains -join ','), ($nnrDomains -join ','))

# --- one domain spelled two ways must not take two budgets --------------------------------------
$rootDot = @(
    (New-Row 'dcfab01.fabrikam.local'  'fabrikam.local'  '10.10.1.50')
    (New-Row 'memfab01.fabrikam.local' 'fabrikam.local.' '10.10.1.51')
)
Assert-True "'fabrikam.local' and 'fabrikam.local.' are ONE domain to the LDAP sampler" `
    ((@(Resolve-mdiLdapTarget -DomainControllers $rootDot -MaxPerDomain 1)).Count -eq 1) `
    ("targets: {0}" -f (@(Resolve-mdiLdapTarget -DomainControllers $rootDot -MaxPerDomain 1)).Count)

Assert-True "'fabrikam.local' and 'fabrikam.local.' are ONE domain to the NNR sampler" `
    ((@(Resolve-mdiNnrTarget -DomainControllers $rootDot -MaxTargets 1)).Count -eq 1) `
    ("targets: {0}" -f (@(Resolve-mdiNnrTarget -DomainControllers $rootDot -MaxTargets 1)).Count)

# The NNR budget is spread by ROUND ROBIN over the domain queues, so a domain split into two queues
# does not merely take a second slot - it takes the slot belonging to a DIFFERENT domain further down
# the rotation. Two fabrikam.local hosts spelled with and without the root dot, enumerated ahead of
# mdilab.local, at MaxTargets=2: split into two queues, fabrikam.local consumes the whole budget at
# depth 0 and mdilab.local is never reached, while the NNR card still reports a result for the run.
$rotation = @(
    (New-Row 'dcfab01.fabrikam.local'  'fabrikam.local'  '10.10.1.50')
    (New-Row 'memfab01.fabrikam.local' 'fabrikam.local.' '10.10.1.51')
    (New-Row 'dc01.mdilab.local'       'mdilab.local'    '10.10.1.10')
)
$rotationDomains = Get-SuffixSet -Targets @(Resolve-mdiNnrTarget -DomainControllers $rotation -MaxTargets 2)
Assert-True 'a domain spelled two ways does not consume the NNR slot of another domain' `
    ($rotationDomains -contains 'mdilab.local' -and $rotationDomains -contains 'fabrikam.local') `
    ("domains probed: [{0}]" -f ($rotationDomains -join ','))

$padded = @(
    (New-Row 'dcfab01.fabrikam.local'  'fabrikam.local'   '10.10.1.50')
    (New-Row 'memfab01.fabrikam.local' ' fabrikam.local ' '10.10.1.51')
)
Assert-True 'a whitespace-padded domain is the same domain to the LDAP sampler' `
    ((@(Resolve-mdiLdapTarget -DomainControllers $padded -MaxPerDomain 1)).Count -eq 1) `
    ("targets: {0}" -f (@(Resolve-mdiLdapTarget -DomainControllers $padded -MaxPerDomain 1)).Count)

$cased = @(
    (New-Row 'dcfab01.fabrikam.local'  'fabrikam.local' '10.10.1.50')
    (New-Row 'memfab01.fabrikam.local' 'FABRIKAM.LOCAL' '10.10.1.51')
)
Assert-True 'DNS case does not split one domain into two budgets' `
    ((@(Resolve-mdiLdapTarget -DomainControllers $cased -MaxPerDomain 1)).Count -eq 1) `
    ("targets: {0}" -f (@(Resolve-mdiLdapTarget -DomainControllers $cased -MaxPerDomain 1)).Count)

# --- an unreadable domain must not cost a readable one its slot ---------------------------------
$unreadable = @(
    (New-Row 'dc01.mdilab.local'      $null            '10.10.1.10')
    (New-Row 'dc02.mdilab.local'      ''               '10.10.1.11')
    (New-Row 'dc03.mdilab.local'      '   '            '10.10.1.12')
    (New-Row 'dc04.mdilab.local'      12345            '10.10.1.13')
    (New-Row 'dcfab01.fabrikam.local' 'fabrikam.local' '10.10.1.50')
)
$threw = $null
try { $unreadableTargets = @(Resolve-mdiLdapTarget -DomainControllers $unreadable -MaxPerDomain 1) }
catch { $threw = $_.Exception.Message }
Assert-True 'an unreadable domain does not throw out of the LDAP sampler' `
    ($null -eq $threw) `
    ("threw: {0}" -f $threw)

Assert-True 'an unreadable domain does not cost the trusted forest its LDAP target' `
    ((Get-SuffixSet -Targets $unreadableTargets) -contains 'fabrikam.local') `
    ("domains probed: [{0}]" -f ((Get-SuffixSet -Targets $unreadableTargets) -join ','))

# --- nothing a single forest ever did may change -------------------------------------------------
$singleForest = @(
    (New-Row 'dc1.mdilab.local' 'mdilab.local' '10.10.1.10')
    (New-Row 'dc2.mdilab.local' 'mdilab.local' '10.10.1.11')
    (New-Row 'dc3.mdilab.local' 'mdilab.local' '10.10.1.12')
)
$single = @(Resolve-mdiLdapTarget -DomainControllers $singleForest -MaxPerDomain 2)
Assert-True 'a single-domain estate selects exactly the hosts it always did' `
    ($single.Count -eq 2 -and $single[0].Name -eq 'dc1.mdilab.local' -and $single[1].Name -eq 'dc2.mdilab.local') `
    ("selected: [{0}]" -f (($single | ForEach-Object { $_.Name }) -join ','))

$multiHomed = @(
    (New-Row 'dc1.mdilab.local' 'mdilab.local' '10.10.1.10')
    (New-Row 'dc1.mdilab.local' 'mdilab.local' '10.10.2.10')
    (New-Row 'dc2.mdilab.local' 'mdilab.local' '10.10.1.11')
)
$mh = @(Resolve-mdiLdapTarget -DomainControllers $multiHomed -MaxPerDomain 2)
Assert-True 'both addresses of a multi-homed domain controller are still probed' `
    (@($mh | Where-Object { $_.Name -eq 'dc1.mdilab.local' }).Count -eq 2) `
    ("dc1 addresses probed: {0}" -f @($mh | Where-Object { $_.Name -eq 'dc1.mdilab.local' }).Count)

Assert-True 'MaxPerDomain <= 0 still means every host, unsampled' `
    ((@(Resolve-mdiLdapTarget -DomainControllers $singleForest -MaxPerDomain 0)).Count -eq 3) `
    ("targets: {0}" -f (@(Resolve-mdiLdapTarget -DomainControllers $singleForest -MaxPerDomain 0)).Count)

Write-Host ''
Write-Host ("PASS={0} FAIL={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
