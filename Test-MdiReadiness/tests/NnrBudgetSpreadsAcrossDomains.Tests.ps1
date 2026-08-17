# The NNR sample spent its whole budget on whichever domain enumerated first, so an entire forest
# could go unprobed while the NNR card still reported a result.
#
# Main hands Resolve-mdiNnrTarget the WHOLE estate - $dcInventory, every domain of every forest in
# scope - and the cap was `Group-Object Name | Select-Object -First $MaxTargets`: the first N hosts of
# a flat list, with no domain awareness at all. Its sibling Resolve-mdiLdapTarget has always sampled
# per domain (Group-Object Domain, then Select-Object -First $MaxPerDomain) for exactly this reason.
#
# Measured on the shipped functions with an eight-DC estate spanning mdilab.local (7 DCs) and
# fabrikam.local (1 DC) at the default MaxTargets=5:
#
#   Resolve-mdiNnrTarget   5 targets, ALL mdilab.local   fabrikam.local contributed 0
#   Resolve-mdiLdapTarget  3 targets                     both domains represented
#
# So the second forest was never asked to resolve anything, no NNR probe was issued anywhere in it,
# and nothing said so - the NNR result the report printed was produced entirely from the other
# forest. That is this project's recurring family: a value that was never read coming back looking
# like a measurement.
#
# Until 17 August this could not be seen. One forest, one site, every DC in Default-First-Site-Name
# meant the flat cap could never starve a domain of targets.
#
# The budget is now spread across domains one host per domain per pass. The cap itself is unchanged -
# it still counts HOSTS, not addresses, and still returns no more than $MaxTargets of them - and a
# single-domain estate still selects exactly the hosts it always did, which is asserted below so the
# fix cannot regress into changing single-forest behaviour.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$source = [IO.File]::ReadAllText($target)
$source = $source -replace '(?m)^\s*#Requires.*$', ''
$source = $source -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$main = $source.IndexOf('#region Main')
if ($main -lt 1) { throw 'Could not isolate the canonical function definitions.' }
Invoke-Expression $source.Substring(0, $main)
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-Dc {
    param([string] $Name, [string] $Ip, [string] $Domain, [string] $Site = 'HQ-Site')
    [PSCustomObject]@{ Name = $Name; IP = $Ip; Addresses = @($Ip); Domain = $Domain; SiteName = $Site }
}

function Get-DomainsOf {
    param([object[]] $Targets)
    @(@($Targets) | ForEach-Object { ([string] $_.Domain).Trim().TrimEnd('.') } |
        Where-Object { $_ } | Select-Object -Unique)
}

function Get-HostsOf {
    param([object[]] $Targets)
    @(@($Targets) | ForEach-Object { [string] $_.Name } | Select-Object -Unique)
}

# The estate the extended lab produces: a large first forest and a small second one.
$twoForest = @(
    New-Dc 'dc2016.mdilab.local' '10.10.1.10' 'mdilab.local' 'HQ-Site'
    New-Dc 'dc2019.mdilab.local' '10.10.1.11' 'mdilab.local' 'HQ-Site'
    New-Dc 'dc2022.mdilab.local' '10.10.1.12' 'mdilab.local' 'EMEA-Site'
    New-Dc 'dc2025.mdilab.local' '10.10.1.13' 'mdilab.local' 'EMEA-Site'
    New-Dc 'dcemea.mdilab.local' '10.10.1.14' 'mdilab.local' 'EMEA-Site'
    New-Dc 'dcapac.mdilab.local' '10.10.1.15' 'mdilab.local' 'Branch-Site'
    New-Dc 'rodc01.mdilab.local' '10.10.1.16' 'mdilab.local' 'Branch-Site'
    New-Dc 'dcfab01.fabrikam.local' '10.10.1.50' 'fabrikam.local' 'HQ-Site'
)

'[nnr budget] the defect: a second forest must not be starved of NNR targets'
$sample = @(Resolve-mdiNnrTarget -DomainControllers $twoForest -MaxTargets 5)
$sampleDomains = Get-DomainsOf $sample
"      selected: $((Get-HostsOf $sample) -join ', ')"
Assert-That 'the second forest contributes at least one NNR target' (
    $sampleDomains -contains 'fabrikam.local') "(domains: $($sampleDomains -join ', '))"
Assert-That 'the first forest still contributes targets' (
    $sampleDomains -contains 'mdilab.local') "(domains: $($sampleDomains -join ', '))"
Assert-That 'every domain in the estate is represented' (
    $sampleDomains.Count -eq 2) "(domains: $($sampleDomains -join ', '))"

'[nnr budget] the cap is still a cap, and still counts hosts'
Assert-That 'no more hosts than MaxTargets are selected' (
    (Get-HostsOf $sample).Count -le 5) "(selected $((Get-HostsOf $sample).Count) host(s))"
Assert-That 'the budget is spent in full when there are enough hosts' (
    (Get-HostsOf $sample).Count -eq 5) "(selected $((Get-HostsOf $sample).Count) host(s))"

# A multi-homed host must not have its second address dropped by the cap: the cap counts hosts, so
# every row of a selected host survives. This is the property the original comment protected and the
# round-robin must not break.
$multiHomed = @(
    [PSCustomObject]@{ Name = 'dcA.mdilab.local'; IP = '10.10.1.20'; Addresses = @('10.10.1.20', '10.10.1.21'); Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dcA.mdilab.local'; IP = '10.10.1.21'; Addresses = @('10.10.1.20', '10.10.1.21'); Domain = 'mdilab.local' }
    New-Dc 'dcB.mdilab.local' '10.10.1.22' 'mdilab.local'
    New-Dc 'dcfab01.fabrikam.local' '10.10.1.50' 'fabrikam.local'
)
$mhSample = @(Resolve-mdiNnrTarget -DomainControllers $multiHomed -MaxTargets 2)
'[nnr budget] a multi-homed host keeps every address inside its one slot'
Assert-That 'two hosts are selected' ((Get-HostsOf $mhSample).Count -eq 2) "(hosts: $((Get-HostsOf $mhSample) -join ', '))"
Assert-That 'both forests are still represented at MaxTargets=2' (
    (Get-DomainsOf $mhSample).Count -eq 2) "(domains: $((Get-DomainsOf $mhSample) -join ', '))"
Assert-That 'the multi-homed host keeps both of its addresses' (
    @($mhSample | Where-Object { $_.Name -eq 'dcA.mdilab.local' }).Count -eq 2 -or
    @($mhSample | Where-Object { $_.Name -eq 'dcA.mdilab.local' }).Count -eq 0) `
    "(rows: $(@($mhSample | Where-Object { $_.Name -eq 'dcA.mdilab.local' }).Count))"

# The single-forest estate is the shipped behaviour and must not move.
$oneForest = @(
    New-Dc 'dc1.contoso.test' '10.0.0.1' 'contoso.test'
    New-Dc 'dc2.contoso.test' '10.0.0.2' 'contoso.test'
    New-Dc 'dc3.contoso.test' '10.0.0.3' 'contoso.test'
    New-Dc 'dc4.contoso.test' '10.0.0.4' 'contoso.test'
)
$oneSample = @(Resolve-mdiNnrTarget -DomainControllers $oneForest -MaxTargets 2)
'[nnr budget] a single-domain estate is unchanged - the first N hosts, in order'
Assert-That 'the first two hosts are selected, in enumeration order' (
    ((Get-HostsOf $oneSample) -join ',') -eq 'dc1.contoso.test,dc2.contoso.test') `
    "(selected: $((Get-HostsOf $oneSample) -join ', '))"

# Fewer slots than domains: the cap still wins, and the domains that DO get a slot are distinct
# rather than all drawn from one place.
$threeForest = @($twoForest) + @(New-Dc 'dc.thirdcorp.test' '10.10.1.70' 'thirdcorp.test')
$tight = @(Resolve-mdiNnrTarget -DomainControllers $threeForest -MaxTargets 2)
'[nnr budget] fewer slots than domains still spreads them'
Assert-That 'exactly MaxTargets hosts are selected' ((Get-HostsOf $tight).Count -eq 2) "(hosts: $((Get-HostsOf $tight) -join ', '))"
Assert-That 'the two slots go to two different domains' (
    (Get-DomainsOf $tight).Count -eq 2) "(domains: $((Get-DomainsOf $tight) -join ', '))"

# An estate small enough to need no sampling must be returned whole.
$small = @(Resolve-mdiNnrTarget -DomainControllers @($twoForest[0], $twoForest[7]) -MaxTargets 5)
'[nnr budget] an estate under the cap is returned whole'
Assert-That 'both hosts are returned' ((Get-HostsOf $small).Count -eq 2) "(hosts: $((Get-HostsOf $small) -join ', '))"
Assert-That 'both domains are returned' ((Get-DomainsOf $small).Count -eq 2) "(domains: $((Get-DomainsOf $small) -join ', '))"

# Unreadable shapes must not throw and must not invent a target. A row with no Domain at all is the
# shape an LDAP-discovered DC has before attribution, and it must still be selectable.
'[nnr budget] unreadable shapes do not throw and do not invent targets'
foreach ($shape in @(
        @{ Label = 'null domain'; Rows = @([PSCustomObject]@{ Name = 'x.test'; IP = '10.0.0.9'; Domain = $null }) }
        @{ Label = 'empty domain'; Rows = @([PSCustomObject]@{ Name = 'x.test'; IP = '10.0.0.9'; Domain = '' }) }
        @{ Label = 'no domain prop'; Rows = @([PSCustomObject]@{ Name = 'x.test'; IP = '10.0.0.9' }) }
        @{ Label = 'wrong type domain'; Rows = @([PSCustomObject]@{ Name = 'x.test'; IP = '10.0.0.9'; Domain = @(1, 2) }) }
        @{ Label = 'null ip'; Rows = @([PSCustomObject]@{ Name = 'x.test'; IP = $null; Domain = 'a.test' }) }
        @{ Label = 'empty collection'; Rows = @() }
    )) {
    $threw = $false
    $result = @()
    try { $result = @(Resolve-mdiNnrTarget -DomainControllers $shape.Rows -MaxTargets 5) } catch { $threw = $true }
    Assert-That ("{0}: does not throw" -f $shape.Label) (-not $threw)
    if ($shape.Label -eq 'null ip' -or $shape.Label -eq 'empty collection') {
        Assert-That ("{0}: yields no target" -f $shape.Label) ($result.Count -eq 0) "(got $($result.Count))"
    }
}

# A mixed estate where one domain's rows are ALL addressless must not let that domain silently
# consume a slot - the slot has to go to a domain that can actually be probed.
$mixed = @(
    [PSCustomObject]@{ Name = 'dead1.fabrikam.local'; IP = $null; Addresses = @(); Domain = 'fabrikam.local' }
    [PSCustomObject]@{ Name = 'dead2.fabrikam.local'; IP = ''; Addresses = @(); Domain = 'fabrikam.local' }
    New-Dc 'dc1.mdilab.local' '10.10.1.10' 'mdilab.local'
    New-Dc 'dc2.mdilab.local' '10.10.1.11' 'mdilab.local'
)
$mixedSample = @(Resolve-mdiNnrTarget -DomainControllers $mixed -MaxTargets 1)
'[nnr budget] an addressless domain does not consume a probe slot'
Assert-That 'the single slot goes to an addressed host' (
    (Get-HostsOf $mixedSample).Count -eq 1 -and (Get-DomainsOf $mixedSample) -contains 'mdilab.local') `
    "(hosts: $((Get-HostsOf $mixedSample) -join ', '))"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
