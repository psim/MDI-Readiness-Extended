<#
    A DOMAIN NOBODY COULD READ IS NOT A DOMAIN ENTITLED TO A PROBE SLOT.

    Resolve-mdiNnrTarget spends a bounded NNR budget - -MaxNnrTargets, default 5 - across the whole
    estate. Main hands it every domain of every forest in scope, so the budget is spread ROUND-ROBIN,
    one host per domain per pass, for a reason the function states itself: "A forest nobody probed is
    not a forest that passed."

    The queue list was built like this:

        $queues = @($byHost | Group-Object -Property { Get-mdiProbeDomainKey -Domain @($_.Group)[0].Domain } |
                ForEach-Object { , @($_.Group) })

    and served in that order. A host whose DOMAIN COULD NOT BE READ therefore formed a queue of its
    own and was served in enumeration order like any real domain - taking a slot ahead of a readable
    domain that had not yet been given one. Get-mdiProbeDomainKey's own header states the rule that
    breaks: "unknown is what it is, and an unreadable row must not cost a READABLE domain the slot it
    was entitled to."

    THE FUNCTION PRODUCES THAT QUEUE ITSELF. The operator-supplied branch tags each target from the
    name that actually resolved, and its comment says outright: "A name with no dot, and a target
    supplied as a bare IP address, both yield $null". So one dotless host name or one bare IP in
    -NnrTargetComputer - a workstation called by its short name, an appliance named by address - is
    enough. This is not an imported-inventory shape; it is the shipped code path.

    Measured on the shipped function, five operator-supplied hosts across the extended lab's two
    forests at MaxTargets=2, with stubbed name resolution, differing in NOTHING but where the dotless
    host sat in the list:

        -NnrTargetComputer                                        hosts probed               fabrikam.local
        ws1.mdilab, ws2.mdilab, ws3.fabrikam, ws4.fabrikam        ws1.mdilab, ws3.fabrikam   reached
        ws1.mdilab, WSFLAT, ws2.mdilab, ws3.fabrikam, ws4.fab     ws1.mdilab, WSFLAT         NO TARGET
        ws1.mdilab, ws2.mdilab, ws3.fabrikam, ws4.fab, WSFLAT     ws1.mdilab, ws3.fabrikam   reached

    The middle row is the defect. The second forest received no NNR target at all, the caller still
    got two targets back, and the NNR card still reported a result for the run - a forest nobody
    probed, reported as a forest that passed. Serving order alone decided it.

    THE SECOND HALF OF THE SAME DEFECT. Get-mdiProbeDomainKey did not even key unreadable domains as
    the empty string, which is what its header promised. It built the key with a bare [string] cast -
    a test of the RENDERING, not of the value, the identical mistake ConvertTo-mdiReadableDomainName
    was written for. Measured on the shipped function:

        $null / '' / '   ' / @()      ->  ''                                 (as documented)
        @('fabrikam.local')           ->  'fabrikam.local'                   (unwrapped, correct)
        12345                         ->  '12345'                <-- its own domain group
        $true                         ->  'True'                 <-- its own domain group
        @{}                           ->  'System.Collections.Hashtable'     <-- its own group
        [PSCustomObject]@{...}        ->  '@{Name=fabrikam.local}'           <-- its own group
        @('a','b')                    ->  'a b'                              <-- its own group

    Five of five unreadable shapes became DOMAINS. Serving the nameless queue last cannot help a
    queue that is not nameless, so both halves are pinned here: the key must refuse a value nobody
    read, and the sampler must serve what is left over last.

    This is the family every defect in this project has belonged to - a value that was NEVER READ
    coming back looking like a MEASUREMENT, here an uninterpretable Domain field looking like a
    domain with its own claim on a bounded probe budget.

    WHAT MUST NOT REGRESS, pinned below alongside: a one-element collection Domain must still unwrap
    (the shape this estate really produces, and the shape three functions were hardened for); the
    all-numeric single-label STRING '12345' that a directory really can return must still be
    accepted; a trailing DNS root dot and surrounding whitespace must still merge into one domain;
    a single-domain estate must select exactly the hosts it always did; the cap must still count
    HOSTS and keep every address of a multi-homed host; and an unreadable domain must still be
    PROBED when the budget can afford it - it is served last, never dropped.
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

Write-Host 'A domain nobody could read is not a domain entitled to a probe slot' -ForegroundColor Cyan

function New-Row ($Name, $Ip, $Domain) {
    [PSCustomObject]@{ Name = $Name; IP = $Ip; Domain = $Domain; MultiHomed = $false; Enumerated = $true }
}
function Get-Suffix ($Targets) {
    @($Targets | ForEach-Object {
            $n = [string] $_.Name
            if ($n -match '\.') { $n.Substring($n.IndexOf('.') + 1) } else { '<none>' }
        } | Select-Object -Unique)
}

# ---------------------------------------------------------------------------------------------------
# HALF ONE. A Domain nobody could read must key as the empty string, exactly as the header promises.
# The key is what decides how many DOMAINS the budget believes exist, so this is the measurement the
# whole spreading rests on.
# ---------------------------------------------------------------------------------------------------
$unreadable = [ordered]@{
    'null'                 = $null
    'empty string'         = ''
    'whitespace'           = '   '
    'empty array'          = @()
    'hashtable'            = @{}
    'populated hashtable'  = @{ DnsRoot = 'fabrikam.local' }
    'PSCustomObject'       = [PSCustomObject]@{ Name = 'fabrikam.local' }
    'number 12345'         = 12345
    'boolean true'         = $true
    'boolean false'        = $false
    'two-element array'    = @('a', 'b')
    'nested collection'    = @(@('fabrikam.local'), @('mdilab.local'))
}
foreach ($k in $unreadable.Keys) {
    $key = Get-mdiProbeDomainKey -Domain $unreadable[$k]
    Assert-That ("an unreadable Domain ({0}) keys as the empty string" -f $k) ([string]::IsNullOrEmpty($key)) `
    ("got '{0}'" -f $key)
}

# THE OTHER DIRECTION. Everything that IS a name must still key as that name - a blanket refusal
# would break the function instead of repairing it.
$readable = [ordered]@{
    'fabrikam.local'                = 'fabrikam.local'
    'trailing root dot'             = 'fabrikam.local.'
    'surrounding whitespace'        = '  fabrikam.local  '
    'one-element array'             = @('fabrikam.local')
    'one-element array, dotted'     = @('fabrikam.local.')
    'all-numeric single label'      = '12345'
}
foreach ($k in $readable.Keys) {
    $key = Get-mdiProbeDomainKey -Domain $readable[$k]
    $expected = if ($k -eq 'all-numeric single label') { '12345' } else { 'fabrikam.local' }
    Assert-That ("a readable Domain ({0}) still keys as its name" -f $k) ($key -eq $expected) `
    ("got '{0}', expected '{1}'" -f $key, $expected)
}

# One domain written three legal ways is still ONE domain, so it cannot take three shares of the
# budget - the merge this key already existed to perform.
$threeSpellings = @('fabrikam.local', 'fabrikam.local.', ' fabrikam.local ') |
    ForEach-Object { Get-mdiProbeDomainKey -Domain $_ } | Select-Object -Unique
Assert-That 'one domain spelled three legal ways is one key' (@($threeSpellings).Count -eq 1) `
("got {0}" -f (@($threeSpellings) -join ' | '))

# ---------------------------------------------------------------------------------------------------
# HALF TWO. The sampler. A host whose domain could not be read must not take the slot of a forest
# that has had none. The estate is the extended lab: mdilab.local first, fabrikam.local last, which
# is the order an enumeration walking the scope list produces.
# ---------------------------------------------------------------------------------------------------
function New-Estate ($JunkDomain, [switch] $NoJunk) {
    $rows = @(
        (New-Row 'dc2022.mdilab.local' '10.10.2.10' 'mdilab.local')
        (New-Row 'dc03.mdilab.local' '10.10.2.13' 'mdilab.local')
    )
    if (-not $NoJunk) { $rows += (New-Row 'dcjunk.mdilab.local' '10.10.2.99' $JunkDomain) }
    $rows += @(
        (New-Row 'dcfab01.fabrikam.local' '10.10.1.50' 'fabrikam.local')
        (New-Row 'memfab01.fabrikam.local' '10.10.1.51' 'fabrikam.local')
    )
    @($rows)
}

# THE CONTROL, first: with every Domain readable the budget already reaches both forests. If this
# ever fails, nothing below means anything.
$control = @(Resolve-mdiNnrTarget -DomainControllers (New-Estate -NoJunk) -MaxTargets 2)
Assert-That 'CONTROL: two readable domains, budget 2, both forests reached' `
((Get-Suffix $control) -contains 'fabrikam.local') ("got {0}" -f ((Get-Suffix $control) -join ', '))

foreach ($k in $unreadable.Keys) {
    $t = @(Resolve-mdiNnrTarget -DomainControllers (New-Estate $unreadable[$k]) -MaxTargets 2)
    $suffixes = Get-Suffix $t
    Assert-That ("an unreadable Domain ({0}) does not cost fabrikam.local its NNR slot" -f $k) `
    ($suffixes -contains 'fabrikam.local') ("probed {0}" -f (($t | ForEach-Object { $_.Name }) -join ', '))
}

# The same, one slot tighter: a budget of exactly ONE must go to a readable domain, never to the
# nameless queue, whatever order the rows arrive in.
foreach ($k in @('null', 'hashtable', 'number 12345', 'two-element array')) {
    $rows = @((New-Row 'dcjunk.mdilab.local' '10.10.2.99' $unreadable[$k])) + @(New-Estate -NoJunk)
    $t = @(Resolve-mdiNnrTarget -DomainControllers $rows -MaxTargets 1)
    Assert-That ("budget of 1 with the unreadable row FIRST ({0}) still probes a named domain" -f $k) `
    ((Get-Suffix $t) -notcontains '<none>' -and $t.Count -ge 1) `
    ("probed {0}" -f (($t | ForEach-Object { $_.Name }) -join ', '))
}

# SERVED LAST, NOT DROPPED. When the budget can afford it the unreadable host must still be probed:
# refusing to probe it would be a different false green - a host in the estate nobody looked at.
$estate = New-Estate $unreadable['hashtable']
$roomy = @(Resolve-mdiNnrTarget -DomainControllers $estate -MaxTargets 5)
Assert-That 'an unreadable-domain host is still probed when the budget allows' `
(@($roomy | Where-Object { $_.Name -eq 'dcjunk.mdilab.local' }).Count -eq 1) `
("probed {0}" -f (($roomy | ForEach-Object { $_.Name }) -join ', '))
Assert-That 'and both real forests are still reached alongside it' `
((Get-Suffix $roomy) -contains 'fabrikam.local' -and (Get-Suffix $roomy) -contains 'mdilab.local') `
("got {0}" -f ((Get-Suffix $roomy) -join ', '))

# ---------------------------------------------------------------------------------------------------
# WHAT MUST NOT REGRESS in the sampler itself.
# ---------------------------------------------------------------------------------------------------
# A single-domain estate must select exactly the hosts it always did - the first N, in order.
$single = @(
    (New-Row 'dc2022.mdilab.local' '10.10.2.10' 'mdilab.local')
    (New-Row 'dc03.mdilab.local' '10.10.2.13' 'mdilab.local')
    (New-Row 'dc04.mdilab.local' '10.10.2.14' 'mdilab.local')
)
$s = @(Resolve-mdiNnrTarget -DomainControllers $single -MaxTargets 2)
Assert-That 'a single-domain estate still selects the first hosts in order' `
((@($s | ForEach-Object { $_.Name }) -join ',') -eq 'dc2022.mdilab.local,dc03.mdilab.local') `
("got {0}" -f (($s | ForEach-Object { $_.Name }) -join ','))

# The cap counts HOSTS, not addresses: every address of a selected multi-homed host survives.
$multi = @(
    (New-Row 'dc2022.mdilab.local' '10.10.2.10' 'mdilab.local')
    (New-Row 'dc2022.mdilab.local' '10.10.2.11' 'mdilab.local')
    (New-Row 'dcjunk.mdilab.local' '10.10.2.99' @{})
    (New-Row 'dcfab01.fabrikam.local' '10.10.1.50' 'fabrikam.local')
)
$m = @(Resolve-mdiNnrTarget -DomainControllers $multi -MaxTargets 2)
Assert-That 'both NICs of a selected multi-homed host survive the cap' `
(@($m | Where-Object { $_.Name -eq 'dc2022.mdilab.local' }).Count -eq 2) `
("got {0}" -f (($m | ForEach-Object { '{0}/{1}' -f $_.Name, $_.IP }) -join ', '))
Assert-That 'and fabrikam.local still got its slot past the unreadable row' `
((Get-Suffix $m) -contains 'fabrikam.local') ("got {0}" -f ((Get-Suffix $m) -join ', '))

# MaxTargets <= 0 means no cap: nothing is spread, nothing is dropped.
$uncapped = @(Resolve-mdiNnrTarget -DomainControllers (New-Estate @{}) -MaxTargets 0)
Assert-That 'MaxTargets 0 still returns the whole estate' ($uncapped.Count -eq 5) `
("got {0}" -f $uncapped.Count)

# An empty estate is still zero targets, not one empty element.
$none = @(Resolve-mdiNnrTarget -DomainControllers @() -MaxTargets 5)
Assert-That 'an empty estate is zero targets' ($none.Count -eq 0) ("got {0}" -f $none.Count)

# Resolve-mdiLdapTarget shares the key. Its budget is PER DOMAIN so it cannot lose a forest, but an
# unreadable Domain must not be handed an allowance of its own either.
$ldap = @(Resolve-mdiLdapTarget -DomainControllers (New-Estate @{}) -MaxPerDomain 1)
Assert-That 'the LDAP sampler still reaches both forests' `
((Get-Suffix $ldap) -contains 'fabrikam.local' -and (Get-Suffix $ldap) -contains 'mdilab.local') `
("got {0}" -f ((Get-Suffix $ldap) -join ', '))
$ldapJunkGroups = @($ldap | Where-Object { $_.Name -eq 'dcjunk.mdilab.local' })
Assert-That 'the unreadable row does not take a second mdilab.local allowance' `
($ldapJunkGroups.Count -le 1) ("got {0}" -f $ldapJunkGroups.Count)

Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 }
