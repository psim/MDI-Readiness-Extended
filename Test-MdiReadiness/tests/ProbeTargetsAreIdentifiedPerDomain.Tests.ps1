<#
    THE DEFECT THIS TEST PINS

    Resolve-mdiLdapTarget and Resolve-mdiNnrTarget both reduce the estate to "one entry per host"
    before spending a sampling budget across domains, and both did it with

        Group-Object -Property Name

    the bare spelling, with the row's own Domain discarded. Resolve-mdiLdapTarget then matched the
    chosen sample back against the estate with

        $selectedNames -contains $_.Name

    so the domain was used to CHOOSE the sample and never to MATCH it.

    Two domain controllers in different domains can carry the same Name, and across a forest trust
    that is ordinary rather than contrived: mdilab.local and fabrikam.local are separate namespaces
    that may each hold a "dc01". A row reaches these functions carrying a BARE name whenever the
    enumerated name did not resolve under its qualified spelling - Get-mdiDomainControllerInventory
    deliberately undoes the qualification in that case - or when the directory record had no
    dNSHostName, where Resolve-mdiDomainController falls back to Name.

    When that happened the colliding row was folded into the first domain's host and DISCARDED
    before the per-domain spreading those functions exist for ever ran. Measured on the shipped
    functions, a five-server mdilab.local estate plus a single fabrikam.local domain controller
    whose bare name collides with an mdilab.local one:

        Resolve-mdiLdapTarget -MaxPerDomain 2   2 targets, domains: mdilab.local
        Resolve-mdiNnrTarget  -MaxTargets 5     5 targets, domains: mdilab.local

    fabrikam.local received NO LDAP target and NO NNR target at all, while the LDAP and NNR cards
    still reported a result for the run. A forest nobody probed is not a forest that passed - which
    is the precise reason the per-domain spreading was written in the first place, and it was
    defeated by a name.

    The same collapse also broke the CAP: the host count under-counted, so an estate holding one
    colliding name returned SIX targets for -MaxTargets 5, the merged group being expanded back to
    both of its rows after having been counted as one.

    A value that was never read - no LDAP or NNR probe was ever issued against the second forest -
    came back looking like a measurement.

    The fix routes both samplers through Get-mdiProbeTargetKey, which identifies a host by its name
    IN ITS OWN DOMAIN via ConvertTo-mdiCanonicalComputerName. That helper must also survive an
    unreadable Domain: an inventory row can carry a wrong type, and -Domain is [string], so an
    Object[] raised a parameter-transformation error and turned a merely unreadable row into an
    exception that ended the whole resolution. The samplers previously never touched Domain, so such
    a row survived; the tests below pin that it still does.
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

Write-Host 'Cross-forest probe targets are identified by name IN THEIR OWN DOMAIN, not by a bare name'

# The estate that produced the measurement in the header: mdilab.local enumerates first and holds
# more domain controllers than the cap, and the single fabrikam.local domain controller carries a
# bare name that collides with an mdilab.local one.
$collidingEstate = @(
    [PSCustomObject]@{ Name = 'dcA.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dcB.mdilab.local'; IP = '10.10.1.11'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dcC.mdilab.local'; IP = '10.10.1.12'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dcD.mdilab.local'; IP = '10.10.1.14'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dcE.mdilab.local'; IP = '10.10.1.15'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc01'; IP = '10.10.1.13'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc01'; IP = '10.10.1.50'; Domain = 'fabrikam.local' }
)

# --- the LDAP sampler ---------------------------------------------------------------------------
$ldap = @(Resolve-mdiLdapTarget -DomainControllers $collidingEstate -MaxPerDomain 2)
$ldapDomains = @($ldap | ForEach-Object { [string] $_.Domain } | Select-Object -Unique)

Assert-True 'the trusted forest receives an LDAP probe target' `
    ($ldapDomains -contains 'fabrikam.local') `
    ("domains probed: [{0}]" -f ($ldapDomains -join ','))

Assert-True 'the LDAP target for the trusted forest is its own domain controller' `
    (@($ldap | Where-Object { [string] $_.Domain -eq 'fabrikam.local' -and $_.IP -eq '10.10.1.50' }).Count -eq 1) `
    ("targets: [{0}]" -f (($ldap | ForEach-Object { '{0}@{1}' -f $_.Name, $_.IP }) -join ' '))

Assert-True 'the local forest still receives its full LDAP sample' `
    (@($ldap | Where-Object { [string] $_.Domain -eq 'mdilab.local' }).Count -eq 2) `
    ("mdilab targets: {0}" -f @($ldap | Where-Object { [string] $_.Domain -eq 'mdilab.local' }).Count)

Assert-True 'no domain exceeds MaxPerDomain hosts' `
    (@($ldap | Group-Object -Property Domain | Where-Object {
                @($_.Group | Group-Object -Property Name).Count -gt 2
            }).Count -eq 0) `
    'a domain was given more hosts than the cap allows'

# --- the NNR sampler ----------------------------------------------------------------------------
$nnr = @(Resolve-mdiNnrTarget -DomainControllers $collidingEstate -MaxTargets 5)
$nnrDomains = @($nnr | ForEach-Object { [string] $_.Domain } | Select-Object -Unique)

Assert-True 'the trusted forest receives an NNR probe target' `
    ($nnrDomains -contains 'fabrikam.local') `
    ("domains probed: [{0}]" -f ($nnrDomains -join ','))

Assert-True 'the NNR target for the trusted forest is its own domain controller' `
    (@($nnr | Where-Object { [string] $_.Domain -eq 'fabrikam.local' -and $_.IP -eq '10.10.1.50' }).Count -eq 1) `
    ("targets: [{0}]" -f (($nnr | ForEach-Object { '{0}@{1}' -f $_.Name, $_.IP }) -join ' '))

# A tighter cap must still reach the second forest: this is the case where the budget is scarcest
# and the spreading matters most.
$nnrTight = @(Resolve-mdiNnrTarget -DomainControllers $collidingEstate -MaxTargets 3)
$nnrTightDomains = @($nnrTight | ForEach-Object { [string] $_.Domain } | Select-Object -Unique)
Assert-True 'the trusted forest is still reached under a tighter NNR cap' `
    ($nnrTightDomains -contains 'fabrikam.local') `
    ("domains probed: [{0}]" -f ($nnrTightDomains -join ','))

# The cap counts HOSTS. A colliding name must not let the sampler return more hosts than were asked
# for by expanding a group that was counted as one.
$nnrHosts = @($nnr | Group-Object -Property { '{0}|{1}' -f $_.Name, $_.Domain }).Count
Assert-True 'the NNR host cap is not exceeded by a colliding name' `
    ($nnrHosts -le 5) `
    ("hosts returned: {0} for MaxTargets 5" -f $nnrHosts)

$nnrTightHosts = @($nnrTight | Group-Object -Property { '{0}|{1}' -f $_.Name, $_.Domain }).Count
Assert-True 'the tighter NNR host cap is not exceeded either' `
    ($nnrTightHosts -le 3) `
    ("hosts returned: {0} for MaxTargets 3" -f $nnrTightHosts)

# --- the identity itself ------------------------------------------------------------------------
$mdilabRow = [PSCustomObject]@{ Name = 'dc01'; IP = '10.10.1.13'; Domain = 'mdilab.local' }
$fabRow = [PSCustomObject]@{ Name = 'dc01'; IP = '10.10.1.50'; Domain = 'fabrikam.local' }
Assert-True 'the same bare name in two domains is two identities' `
    ((Get-mdiProbeTargetKey -Target $mdilabRow) -ne (Get-mdiProbeTargetKey -Target $fabRow)) `
    ("both keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target $mdilabRow))

Assert-True 'a qualified name and its bare spelling in the same domain are one identity' `
    ((Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = 'DC01.MDILAB.LOCAL.'; Domain = 'mdilab.local' })) -eq
        (Get-mdiProbeTargetKey -Target $mdilabRow)) `
    'the two spellings of one host keyed differently'

Assert-True 'a bare IP address is not given a domain suffix' `
    ((Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = '10.10.1.50'; Domain = 'fabrikam.local' })) -eq '10.10.1.50') `
    ("keyed as [{0}]" -f (Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = '10.10.1.50'; Domain = 'fabrikam.local' })))

# --- shapes that were never read ----------------------------------------------------------------
# An unreadable row must stay unreadable, not become an exception that ends the resolution for the
# whole estate. Every one of these survived the bare-Name grouping the fix replaced.
$unreadable = @(
    [PSCustomObject]@{ Name = $null; IP = '10.0.0.1'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = ''; IP = '10.0.0.2'; Domain = 'fabrikam.local' }
    [PSCustomObject]@{ Name = '   '; IP = '10.0.0.3'; Domain = $null }
    [PSCustomObject]@{ Name = 'dc01'; IP = 'not-an-ip'; Domain = 12345 }
    [PSCustomObject]@{ Name = 'dc01'; IP = @('10.0.0.4'); Domain = @('fabrikam.local') }
    [PSCustomObject]@{ Name = 'dc01'; IP = $null; Domain = 'fabrikam.local' }
)

$threw = $null
$unreadableLdap = @()
try {
    $unreadableLdap = @(Resolve-mdiLdapTarget -DomainControllers $unreadable -MaxPerDomain 2)
} catch { $threw = $_.Exception.Message }
Assert-True 'an unreadable domain does not throw out of the LDAP sampler' `
    ($null -eq $threw) `
    ("threw: {0}" -f $threw)
Assert-True 'the readable rows of an unreadable estate are still returned' `
    ($unreadableLdap.Count -ge 5) `
    ("returned {0} target(s)" -f $unreadableLdap.Count)

$threwNnr = $null
try {
    [void] @(Resolve-mdiNnrTarget -DomainControllers $unreadable -MaxTargets 2)
} catch { $threwNnr = $_.Exception.Message }
Assert-True 'an unreadable domain does not throw out of the NNR sampler' `
    ($null -eq $threwNnr) `
    ("threw: {0}" -f $threwNnr)

Assert-True 'a null row keys as nothing rather than throwing' `
    ((Get-mdiProbeTargetKey -Target $null) -eq '') `
    'a null row did not key as the empty string'

# --- the single-forest estate is unchanged ------------------------------------------------------
# The spreading must not alter what a single-domain estate always selected.
$singleForest = @(
    [PSCustomObject]@{ Name = 'dc1.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc2.mdilab.local'; IP = '10.10.1.11'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc3.mdilab.local'; IP = '10.10.1.12'; Domain = 'mdilab.local' }
)
$single = @(Resolve-mdiLdapTarget -DomainControllers $singleForest -MaxPerDomain 2)
Assert-True 'a single-domain estate selects exactly the hosts it always did' `
    ($single.Count -eq 2 -and $single[0].Name -eq 'dc1.mdilab.local' -and $single[1].Name -eq 'dc2.mdilab.local') `
    ("selected: [{0}]" -f (($single | ForEach-Object { $_.Name }) -join ','))

# A multi-homed domain controller must still be probed on BOTH addresses.
$multiHomed = @(
    [PSCustomObject]@{ Name = 'dc1.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc1.mdilab.local'; IP = '10.10.2.10'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dc2.mdilab.local'; IP = '10.10.1.11'; Domain = 'mdilab.local' }
)
$mh = @(Resolve-mdiLdapTarget -DomainControllers $multiHomed -MaxPerDomain 2)
Assert-True 'both addresses of a multi-homed domain controller are still probed' `
    (@($mh | Where-Object { $_.Name -eq 'dc1.mdilab.local' }).Count -eq 2) `
    ("dc1 addresses probed: {0}" -f @($mh | Where-Object { $_.Name -eq 'dc1.mdilab.local' }).Count)

Assert-True 'a repeated (name, address) pair is still de-duplicated' `
    ((@(Resolve-mdiLdapTarget -DomainControllers @(
                    [PSCustomObject]@{ Name = 'dc1.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local' }
                    [PSCustomObject]@{ Name = 'dc1.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local' }
                ) -MaxPerDomain 2)).Count -eq 1) `
    'a duplicated inventory row produced two probe targets'

Write-Host ''
Write-Host ("PASS={0} FAIL={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
