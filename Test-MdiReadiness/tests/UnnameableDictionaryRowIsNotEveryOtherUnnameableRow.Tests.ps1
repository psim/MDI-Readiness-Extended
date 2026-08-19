<#
    AN UNNAMEABLE ROW IS ITS OWN HOST ON A DICTIONARY-SHAPED ROW TOO, NOT EVERY OTHER UNNAMEABLE ROW.

    THE DEFECT THIS PINS. Get-mdiProbeTargetKey is the shared identity both probe samplers use to
    answer "which host is this". Its unnameable-row fallback - key the row by its ADDRESS IN ITS OWN
    DOMAIN, so that rows nobody could name are not all merged into each other - read the address as

        $Target.PSObject.Properties['IP']

    and treated a $null result as "this row carries no IP property at all". On an IDictionary that
    conclusion is wrong. PSObject.Properties over a hashtable or an [ordered] hashtable enumerates
    the .NET members of the dictionary - Count, Keys, Values, IsReadOnly - and NEVER the entries, so
    the lookup returns $null for a row whose IP entry is present and perfectly readable. This script
    states that fact itself, in Copy-mdiDetails, and every other reader of a possibly-dictionary row
    branches on [Collections.IDictionary] for it; this one reader did not.

    The inconsistency is what makes it a defect rather than a limitation: the two lines ABOVE the
    address read take Name and Domain off the same row by direct member access, which a dictionary
    answers correctly. So the function successfully read the row's name and its domain, then decided
    the row had no address - and fell through to the bare empty string, which is the exact collapse
    the '?unnamed?' key was introduced to stop, still in force for precisely these rows.

    Measured on the shipped functions before the fix, four unnameable rows spanning fabrikam.local,
    emea.mdilab.local and apac.mdilab.local plus one named mdilab.local domain controller:

        PSCustomObject rows   4 distinct host keys   Resolve-mdiNnrTarget -MaxTargets 1   1 target
        Hashtable rows        1 distinct host key    Resolve-mdiNnrTarget -MaxTargets 1   4 targets
        [ordered] rows        1 distinct host key    Resolve-mdiNnrTarget -MaxTargets 1   4 targets

    Both harms named by the sibling test, at once. THE CAP IS BLOWN - four targets returned for a
    budget of one, spent against the generated command line length limit and the port-probe time
    budget this script already throws and warns on. And A READABLE DOMAIN IS STARVED: mdilab.local,
    holding the one named, readable, reachable domain controller in the estate, received no NNR
    target at all, while the NNR card still reported a result for the run. A forest nobody probed is
    not a forest that passed.

    THE FIX. The address is read with Test-mdiDetailEntry / Get-mdiDetailValue - the shape-agnostic
    accessors this script already uses everywhere else a row may be a dictionary. A row that
    genuinely carries no IP entry, in either shape, still keys as the empty string and still does not
    throw; a named row, a null row and a PSCustomObject row are untouched.

    WHY THE SHAPE REACHES HERE. Stated no more strongly than it was measured: today's producer,
    Get-mdiDomainControllerInventory, emits PSCustomObject rows, and an -AsJson round trip returns
    PSCustomObject as well, so this was not a live false green in the shipped pipeline. It is one
    reader of an inventory disagreeing with the rest of the script about how a row is read - the same
    class of defect, and the same argument for fixing it on the key, that Resolve-mdiLdapTarget's own
    address and domain guards were fixed under.
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

Write-Host 'An unnameable row is its own host on a dictionary-shaped row too'

# The estate that produced the measurement in the header, built in each row shape. Four unnameable
# rows across two forests and three domains, plus one named, readable mdilab.local domain controller
# listed LAST - so that when the unnameable rows collapse into one host, mdilab.local is the domain
# that loses its slot.
$makers = [ordered] @{
    'PSCustomObject' = { param($n, $i, $d) [PSCustomObject]@{ Name = $n; IP = $i; Domain = $d } }
    'Hashtable'      = { param($n, $i, $d) @{ Name = $n; IP = $i; Domain = $d } }
    'Ordered'        = { param($n, $i, $d) ([ordered] @{ Name = $n; IP = $i; Domain = $d }) }
}

function New-Estate {
    param($Maker)
    @(
        (& $Maker $null '10.10.1.50' 'fabrikam.local')
        (& $Maker '' '10.10.1.51' 'fabrikam.local')
        (& $Maker '   ' '10.10.2.20' 'emea.mdilab.local')
        (& $Maker $null '10.10.3.30' 'apac.mdilab.local')
        (& $Maker 'dc2022.mdilab.local' '10.10.1.10' 'mdilab.local')
    )
}

foreach ($shape in @($makers.Keys)) {
    $maker = $makers[$shape]
    Write-Host ("  -- {0} --" -f $shape)

    # --- the identity itself ----------------------------------------------------------------------
    $a = & $maker $null '10.10.1.50' 'fabrikam.local'
    $b = & $maker '' '10.10.1.51' 'fabrikam.local'
    $c = & $maker '   ' '10.10.2.20' 'emea.mdilab.local'

    Assert-True ("{0}: an unnameable row with a readable address does not key as nothing" -f $shape) `
    (-not [string]::IsNullOrWhiteSpace((Get-mdiProbeTargetKey -Target $a))) `
        'the address on the row was never read, so the row keyed as the empty string'

    Assert-True ("{0}: the key carries the address that was read" -f $shape) `
    ((Get-mdiProbeTargetKey -Target $a) -like '*10.10.1.50') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target $a))

    Assert-True ("{0}: the key carries the row's own domain" -f $shape) `
    ((Get-mdiProbeTargetKey -Target $a) -like '*fabrikam.local*') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target $a))

    Assert-True ("{0}: two unnameable rows at different addresses are two hosts" -f $shape) `
    ((Get-mdiProbeTargetKey -Target $a) -ne (Get-mdiProbeTargetKey -Target $b)) `
    ("both keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target $a))

    Assert-True ("{0}: two unnameable rows in different forests are two hosts" -f $shape) `
    ((Get-mdiProbeTargetKey -Target $a) -ne (Get-mdiProbeTargetKey -Target $c)) `
    ("both keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target $a))

    Assert-True ("{0}: an unnameable key cannot collide with a named one" -f $shape) `
    ((Get-mdiProbeTargetKey -Target $a) -like '*?*') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target $a))

    Assert-True ("{0}: a named row keys by its name in its own domain" -f $shape) `
    ((Get-mdiProbeTargetKey -Target (& $maker 'dc01' '10.10.0.10' 'mdilab.local')) -eq 'dc01.mdilab.local') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target (& $maker 'dc01' '10.10.0.10' 'mdilab.local')))

    # --- four unnameable rows must stay four hosts -------------------------------------------------
    $estate = New-Estate $maker
    $unnameableKeys = @(@($estate | Select-Object -First 4) | ForEach-Object { Get-mdiProbeTargetKey -Target $_ })
    Assert-True ("{0}: four unnameable rows are four hosts, not one" -f $shape) `
    (@($unnameableKeys | Select-Object -Unique).Count -eq 4) `
    ("distinct keys: {0} [{1}]" -f @($unnameableKeys | Select-Object -Unique).Count, ($unnameableKeys -join ' | '))

    # --- the NNR cap must hold ---------------------------------------------------------------------
    $nnr1 = @(Resolve-mdiNnrTarget -DomainControllers $estate -MaxTargets 1)
    Assert-True ("{0}: -MaxTargets 1 returns at most one NNR target" -f $shape) `
    ($nnr1.Count -le 1) `
    ("returned {0} target(s): [{1}]" -f $nnr1.Count,
        (($nnr1 | ForEach-Object { '{0}@{1}' -f (Get-mdiProbeDomainKey -Domain $_.Domain), $_.IP }) -join ' '))

    # --- the readable domain must not be starved ---------------------------------------------------
    $nnr4 = @(Resolve-mdiNnrTarget -DomainControllers $estate -MaxTargets 4)
    $nnr4Domains = @($nnr4 | ForEach-Object { Get-mdiProbeDomainKey -Domain $_.Domain } | Select-Object -Unique)
    Assert-True ("{0}: the readable domain is not starved by unnameable rows" -f $shape) `
    ($nnr4Domains -contains 'mdilab.local') `
    ("domains probed: [{0}]" -f ($nnr4Domains -join ' '))

    Assert-True ("{0}: -MaxTargets 4 is not exceeded" -f $shape) `
    ($nnr4.Count -le 4) `
    ("returned {0} target(s)" -f $nnr4.Count)

    # --- the LDAP sampler: every domain reached, no domain over budget -----------------------------
    $ldap1 = @(Resolve-mdiLdapTarget -DomainControllers $estate -MaxPerDomain 1)
    $ldap1Domains = @($ldap1 | ForEach-Object { Get-mdiProbeDomainKey -Domain $_.Domain } | Select-Object -Unique | Sort-Object)
    Assert-True ("{0}: every domain of both forests receives an LDAP target" -f $shape) `
    (($ldap1Domains -join ',') -eq 'apac.mdilab.local,emea.mdilab.local,fabrikam.local,mdilab.local') `
    ("domains probed: [{0}]" -f ($ldap1Domains -join ' '))

    Assert-True ("{0}: at -MaxPerDomain 1 no domain exceeds its LDAP budget" -f $shape) `
    (@($ldap1 | Group-Object -Property { Get-mdiProbeDomainKey -Domain $_.Domain } |
                Where-Object { $_.Count -gt 1 }).Count -eq 0) `
    ("per-domain counts: [{0}]" -f ((@($ldap1 | Group-Object -Property { Get-mdiProbeDomainKey -Domain $_.Domain }) |
                ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ' '))

    # --- what must NOT have changed ----------------------------------------------------------------
    Assert-True ("{0}: a row carrying no IP entry at all still keys as nothing" -f $shape) `
    ((Get-mdiProbeTargetKey -Target (& { param($n, $d) if ($shape -eq 'PSCustomObject') { [PSCustomObject]@{ Name = $n; Domain = $d } }
                elseif ($shape -eq 'Hashtable') { @{ Name = $n; Domain = $d } }
                else { [ordered] @{ Name = $n; Domain = $d } } } '' 'fabrikam.local')) -eq '') `
        'a row with no IP entry did not key as the empty string'

    Assert-True ("{0}: a row with neither a readable name nor a readable address keys as nothing" -f $shape) `
    ((Get-mdiProbeTargetKey -Target (& $maker $null $null 'fabrikam.local')) -eq '') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target (& $maker $null $null 'fabrikam.local')))

    Assert-True ("{0}: an unreadable Domain on an unnameable row still does not throw" -f $shape) `
    ((Get-mdiProbeTargetKey -Target (& $maker $null '10.10.1.53' @('fabrikam.local'))) -like '*10.10.1.53') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target (& $maker $null '10.10.1.53' @('fabrikam.local'))))
}

# A null row is unchanged in every shape.
Assert-True 'a null row still keys as nothing rather than throwing' `
((Get-mdiProbeTargetKey -Target $null) -eq '') `
    'a null row did not key as the empty string'

# The three shapes must agree with each other, which is the invariant the defect broke.
$pso = Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = ''; IP = '10.10.1.50'; Domain = 'fabrikam.local' })
$hash = Get-mdiProbeTargetKey -Target @{ Name = ''; IP = '10.10.1.50'; Domain = 'fabrikam.local' }
$ord = Get-mdiProbeTargetKey -Target ([ordered] @{ Name = ''; IP = '10.10.1.50'; Domain = 'fabrikam.local' })

Assert-True 'a hashtable row keys identically to the same row as a PSCustomObject' `
($hash -eq $pso) `
("PSCustomObject=[{0}] Hashtable=[{1}]" -f $pso, $hash)

Assert-True 'an ordered-hashtable row keys identically to the same row as a PSCustomObject' `
($ord -eq $pso) `
("PSCustomObject=[{0}] Ordered=[{1}]" -f $pso, $ord)

Write-Host ''
Write-Host ("PASS={0} FAIL={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
