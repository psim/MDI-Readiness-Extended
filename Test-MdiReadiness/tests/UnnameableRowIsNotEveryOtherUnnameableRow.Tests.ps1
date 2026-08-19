<#
    AN UNNAMEABLE DOMAIN CONTROLLER ROW IS ITS OWN HOST, NOT EVERY OTHER UNNAMEABLE ROW.

    THE DEFECT THIS PINS. Get-mdiProbeTargetKey is the shared identity both probe samplers use to
    answer "which host is this". For a row it could not name it returned the BARE EMPTY STRING. That
    kept the row out of any NAMED host's group, which was the intent - but it merged every unnameable
    row into EVERY OTHER unnameable row, which is the exact collapse the function was written to
    stop, still in force for precisely the rows nobody could read. Rows in different domains, and in
    different FORESTS, were one host to both samplers.

    The extended lab is what makes it ordinary rather than contrived. mdilab.local (three domains)
    and fabrikam.local now sit either side of a bidirectional cross-forest trust, and a row arrives
    unnameable whenever its record carried no dNSHostName and no readable Name - an ADWS or LDAP call
    refused part-way across the trust is the everyday producer.

    Measured on the shipped functions before the fix, with an estate of one unnameable mdilab.local
    row, dc01.mdilab.local, dcfab01.fabrikam.local, THREE unnameable fabrikam.local rows and
    dc02.emea.mdilab.local:

        Resolve-mdiLdapTarget -MaxPerDomain 1    6 targets; fabrikam.local received FOUR
        Resolve-mdiLdapTarget -MaxPerDomain 2    7 targets; fabrikam.local received FOUR
        Resolve-mdiNnrTarget  -MaxTargets  2     5 targets; emea.mdilab.local received NONE

    Two harms, and the second is the one that matters.

    THE CAP IS BLOWN. Four targets for a per-domain budget of one; five for a global budget of two.
    In the LDAP sampler the budget is chosen and then the whole inventory is re-read and re-admitted
    by `$selectedKeys -contains <key>`; once ONE unnameable row won a slot the empty key sat in
    $selectedKeys and matched every other unnameable row in the estate, in any domain and either
    forest. That budget is spent against the generated command line length limit and the port-probe
    time budget this script already throws and warns on.

    A READABLE DOMAIN IS STARVED. This is the false green. In the NNR sampler the cap counts HOSTS,
    so the four unnameable rows counted as ONE host; that host was attributed to whichever domain
    enumerated first (mdilab.local), and the group was expanded back to all four rows AFTER being
    counted as one. At -MaxTargets 2 the budget was therefore consumed by two entries and
    emea.mdilab.local - a real domain holding a real, nameable, readable domain controller -
    received no NNR target at all, while the NNR card still reported a result for the run. A forest
    nobody probed is not a forest that passed, which is the reason the per-domain spreading exists.

    THE FIX. A row that cannot be NAMED is identified by its ADDRESS IN ITS OWN DOMAIN. The key
    carries a '?', which cannot occur in a DNS name or an IP address, so an unnameable key can never
    collide with a named one. Only a row with neither a readable name NOR a readable address still
    keys as the empty string - nothing whatever was read off it - and a null row is unchanged.

    Two addresses of one unnameable host now count as two hosts. That is deliberate: without a name,
    "which host is this" is genuinely unknowable, and erring this way can only probe that row's own
    domain more, never starve another domain of a slot it was entitled to.
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

Write-Host 'An unnameable domain controller row is its own host, not every other unnameable row'

# The estate that produced the measurement in the header. The unnameable mdilab.local row is listed
# FIRST so that it wins the empty-key representative slot, which is what put '' into $selectedKeys.
$estate = @(
    [PSCustomObject]@{ Name = $null; IP = '10.10.0.11'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc01.mdilab.local'; IP = '10.10.0.10'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; IP = '10.10.1.50'; Domain = 'fabrikam.local' }
    [PSCustomObject]@{ Name = ''; IP = '10.10.1.51'; Domain = 'fabrikam.local' }
    [PSCustomObject]@{ Name = '   '; IP = '10.10.1.52'; Domain = 'fabrikam.local' }
    [PSCustomObject]@{ Name = $null; IP = '10.10.1.53'; Domain = 'fabrikam.local' }
    [PSCustomObject]@{ Name = 'dc02.emea.mdilab.local'; IP = '10.10.2.10'; Domain = 'emea.mdilab.local' }
)

# --- the identity itself ------------------------------------------------------------------------
$unnameableA = [PSCustomObject]@{ Name = $null; IP = '10.10.1.51'; Domain = 'fabrikam.local' }
$unnameableB = [PSCustomObject]@{ Name = ''; IP = '10.10.1.52'; Domain = 'fabrikam.local' }
$unnameableC = [PSCustomObject]@{ Name = '   '; IP = '10.10.0.11'; Domain = 'mdilab.local' }

Assert-True 'two unnameable rows at different addresses are two different hosts' `
    ((Get-mdiProbeTargetKey -Target $unnameableA) -ne (Get-mdiProbeTargetKey -Target $unnameableB)) `
    ("both keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target $unnameableA))

Assert-True 'two unnameable rows in different forests are two different hosts' `
    ((Get-mdiProbeTargetKey -Target $unnameableA) -ne (Get-mdiProbeTargetKey -Target $unnameableC)) `
    ("both keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target $unnameableA))

Assert-True 'an unnameable row does not key as the empty string when its address was read' `
    (-not [string]::IsNullOrWhiteSpace((Get-mdiProbeTargetKey -Target $unnameableA))) `
    'an unnameable row with a readable address still keyed as nothing'

Assert-True 'an unnameable key cannot collide with a named one' `
    ((Get-mdiProbeTargetKey -Target $unnameableA) -like '*?*') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target $unnameableA))

# The same host reached twice from the same inventory must still be ONE key, or de-duplication of a
# repeated row breaks.
Assert-True 'the same unnameable row read twice keys identically' `
    ((Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = $null; IP = '10.10.1.51'; Domain = 'fabrikam.local' })) -eq
        (Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = ''; IP = '10.10.1.51'; Domain = 'fabrikam.local' }))) `
    'two reads of one unnameable row produced two different hosts'

# --- the LDAP sampler: the cap must hold ----------------------------------------------------------
$ldap1 = @(Resolve-mdiLdapTarget -DomainControllers $estate -MaxPerDomain 1)
$fab1 = @($ldap1 | Where-Object { [string] $_.Domain -eq 'fabrikam.local' })

Assert-True 'at -MaxPerDomain 1 the trusted forest receives exactly one LDAP target' `
    ($fab1.Count -eq 1) `
    ("fabrikam.local received {0}: [{1}]" -f $fab1.Count, (($fab1 | ForEach-Object { [string] $_.IP }) -join ' '))

Assert-True 'at -MaxPerDomain 1 no domain exceeds its LDAP budget' `
    (@($ldap1 | Group-Object -Property { [string] $_.Domain } | Where-Object { $_.Count -gt 1 }).Count -eq 0) `
    ("per-domain counts: [{0}]" -f ((@($ldap1 | Group-Object -Property { [string] $_.Domain }) |
                ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ' '))

$ldap2 = @(Resolve-mdiLdapTarget -DomainControllers $estate -MaxPerDomain 2)
Assert-True 'at -MaxPerDomain 2 no domain exceeds its LDAP budget either' `
    (@($ldap2 | Group-Object -Property { [string] $_.Domain } | Where-Object { $_.Count -gt 2 }).Count -eq 0) `
    ("per-domain counts: [{0}]" -f ((@($ldap2 | Group-Object -Property { [string] $_.Domain }) |
                ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ' '))

# Every domain of the estate must still be reached - the spreading exists for that and must not be
# traded away for the cap.
$ldap1Domains = @($ldap1 | ForEach-Object { [string] $_.Domain } | Select-Object -Unique | Sort-Object)
Assert-True 'every domain of both forests still receives an LDAP target' `
    (($ldap1Domains -join ',') -eq 'emea.mdilab.local,fabrikam.local,mdilab.local') `
    ("domains probed: [{0}]" -f ($ldap1Domains -join ' '))

# --- the NNR sampler: the readable domain must not be starved -------------------------------------
$nnr2 = @(Resolve-mdiNnrTarget -DomainControllers $estate -MaxTargets 2)

Assert-True 'the NNR cap counts unnameable rows as the separate hosts they are' `
    ($nnr2.Count -le 2) `
    ("-MaxTargets 2 returned {0} target(s): [{1}]" -f $nnr2.Count,
        (($nnr2 | ForEach-Object { '{0}@{1}' -f ([string] $_.Domain), $_.IP }) -join ' '))

$nnr4 = @(Resolve-mdiNnrTarget -DomainControllers $estate -MaxTargets 4)
$nnr4Domains = @($nnr4 | ForEach-Object { [string] $_.Domain } | Select-Object -Unique | Sort-Object)

Assert-True 'a readable domain is not starved by unnameable rows of another forest' `
    ($nnr4Domains -contains 'emea.mdilab.local') `
    ("domains probed: [{0}]" -f ($nnr4Domains -join ' '))

Assert-True 'the NNR budget still reaches every domain before any takes a second slot' `
    (($nnr4Domains -join ',') -eq 'emea.mdilab.local,fabrikam.local,mdilab.local') `
    ("domains probed: [{0}]" -f ($nnr4Domains -join ' '))

Assert-True 'the NNR cap is not exceeded at -MaxTargets 4 either' `
    ($nnr4.Count -le 4) `
    ("-MaxTargets 4 returned {0} target(s)" -f $nnr4.Count)

# --- what must NOT have changed -------------------------------------------------------------------
Assert-True 'a null row still keys as nothing rather than throwing' `
    ((Get-mdiProbeTargetKey -Target $null) -eq '') `
    'a null row did not key as the empty string'

Assert-True 'a row with neither a readable name nor a readable address still keys as nothing' `
    ((Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = $null; IP = $null; Domain = 'fabrikam.local' })) -eq '') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = $null; IP = $null; Domain = 'fabrikam.local' })))

Assert-True 'a row carrying no IP property at all keys as nothing rather than throwing' `
    ((Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = ''; Domain = 'fabrikam.local' })) -eq '') `
    'a row with no IP property did not key as the empty string'

Assert-True 'a named row is unaffected by the unnameable fallback' `
    ((Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = 'dc01'; IP = '10.10.0.10'; Domain = 'mdilab.local' })) -eq 'dc01.mdilab.local') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = 'dc01'; IP = '10.10.0.10'; Domain = 'mdilab.local' })))

Assert-True 'an unreadable Domain on an unnameable row still does not throw' `
    ((Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = $null; IP = '10.10.1.53'; Domain = @('fabrikam.local') })) -like '*10.10.1.53') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = $null; IP = '10.10.1.53'; Domain = @('fabrikam.local') })))

# A multi-homed NAMED host must still be one host with both of its NICs probed - the property the
# cap was written to protect and which this change must not trade away.
$multiHomed = @(
    [PSCustomObject]@{ Name = 'dc1.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc1.mdilab.local'; IP = '10.10.1.11'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc2.mdilab.local'; IP = '10.10.1.12'; Domain = 'mdilab.local' }
)
$mh = @(Resolve-mdiLdapTarget -DomainControllers $multiHomed -MaxPerDomain 1)
Assert-True 'a multi-homed named host still contributes both of its addresses' `
    (@($mh | Where-Object { $_.Name -eq 'dc1.mdilab.local' }).Count -eq 2) `
    ("dc1 addresses probed: {0}" -f @($mh | Where-Object { $_.Name -eq 'dc1.mdilab.local' }).Count)

# A single-domain estate holding no unnameable row must select exactly what it always did.
$singleForest = @(
    [PSCustomObject]@{ Name = 'dc1.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc2.mdilab.local'; IP = '10.10.1.11'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc3.mdilab.local'; IP = '10.10.1.12'; Domain = 'mdilab.local' }
)
$single = @(Resolve-mdiLdapTarget -DomainControllers $singleForest -MaxPerDomain 2)
Assert-True 'a single-domain estate selects exactly the hosts it always did' `
    ($single.Count -eq 2 -and $single[0].Name -eq 'dc1.mdilab.local' -and $single[1].Name -eq 'dc2.mdilab.local') `
    ("selected: [{0}]" -f (($single | ForEach-Object { $_.Name }) -join ','))

Write-Host ''
Write-Host ("PASS={0} FAIL={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
