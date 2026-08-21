# Regression test for defect 289: the two halves of the sampling disclosure were counted with two
# different rulers, so an estate that was genuinely sampled reported no sample at all.
#
# THE DEFECT. Get-mdiReportStatistics tells the operator whether the run probed the estate or only a
# sample of it, and both surfaces that say so - the ports card and the console run summary - decide
# it from the same ratio:
#
#     $portScope  = $Statistics.PortCandidateHostCount      how many hosts could have been probed
#     $portProbed = $Statistics.PortDistinctTargetCount     how many were
#     if ($portScope -gt $portProbed -and $portProbed -gt 0) { "ports N of M host(s), raise -Max..." }
#
# The DENOMINATOR was built by keying every candidate row through Get-mdiServerIdentityKey, which is
# case-insensitive, ignores a trailing dot and trims whitespace. The NUMERATOR was built by taking
# the raw Target string off each probe record - `[string] $_.Target`, falling back to TargetIP - and
# de-duplicating it with Select-Object -Unique, which is ORDINAL.
#
# So one machine probed once, but recorded under more than one spelling, counted as SEVERAL PROBED
# HOSTS. Enough of them and the numerator reaches the denominator, the comparison goes false, and
# every surface falls silent about a sample it did take.
#
# THE MEASUREMENT, on the shipped functions, over the extended lab's seven controllers across three
# AD sites and two forests, with the plan probing FOUR of the seven in both runs:
#
#     the same 4 hosts, spelled canonically   PortCandidateHostCount=7  PortDistinctTargetCount=4
#                                             -> "ports 4 of 7 host(s), raise -MaxLdapTargetsPerDomain"
#     the same 4 hosts, spelled twice each    PortCandidateHostCount=7  PortDistinctTargetCount=8
#                                             -> NOTHING SAID, on any surface
#
# Nothing about the scan differed between those two runs. dc2016, dcbr and memfab01 were not probed
# in either - and dcbr is the only controller in Branch-Site. The second run reported that estate as
# fully probed. A cross-site firewall is exactly the fault this tool exists to find, and it is found
# only if the controller behind it is either probed or NAMED AS UNPROBED.
#
# The spellings are not contrived. A multi-homed controller is recorded once by name and once by
# address; the fabrikam.local / FABCORP forest yields the directory's casing and the DNS answer's
# trailing dot for one host. Every one of those is one machine to the denominator and a separate
# probed host to the numerator.
#
# THE SECOND HALF OF THE SAME DEFECT. Because the numerator rendered its target with a bare
# [string] cast, a record whose Target was a hashtable, a boolean or a bare int rendered non-blank
# and counted as a host that had been probed. That is this codebase's one recurring fabrication -
# [string] tests the RENDERING, not the value - landing in the numerator of a coverage claim: a
# probe that measured nothing came back looking like a probe that measured something.
#
# THE FIX. Get-mdiProbeRecordTargetKey, the record-side counterpart of Get-mdiServerIdentityKey,
# keyed by the same ConvertTo-mdiCanonicalComputerName rules and lowercased the same way, and
# reading the target through ConvertTo-mdiReadableDomainName so an unreadable shape keys as the
# empty string and is dropped. BOTH numerators call it - the ports count and the NNR count are the
# identical construction - so the two halves of the ratio cannot drift apart again.
#
# WHAT THIS TEST PINS. Not just that the aliased run discloses again, but the OPPOSITE MISTAKE too:
# a numerator that merged genuinely distinct hosts would also make the disclosure fire, and would be
# just as wrong. So the canonically-spelled control must still count exactly four, four genuinely
# different machines must still count as four, and a target nobody could read must count as none.

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main')
if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
. ([scriptblock]::Create($body))

$script:pass = 0
$script:fail = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Got = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name" }
    else { $script:fail++; Write-Host "  FAIL  $Name $Got" }
}

# A server row of the shape the domain controller inventory emits, carrying the port-probe details
# the shipped Get-mdiPortResultRecord reads. $ProbeTargets is the list of target spellings this
# server's records name, which is the ONLY thing the runs below differ in.
function New-Dc {
    param($Fqdn, $Domain, $ProbeTargets = @())
    $results = @(foreach ($t in @($ProbeTargets)) {
            [PSCustomObject]@{
                Target      = $t
                TargetIP    = $null
                Port        = 389
                Requirement = 'Required'
                Success     = $true
                Applicable  = $true
                Detail      = 'open'
            }
        })
    [PSCustomObject]@{
        FQDN      = $Fqdn
        Name      = ($Fqdn -split '\.')[0]
        Domain    = $Domain
        Reachable = $true
        Details   = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = $results } }
    }
}

# The extended lab: seven controllers over three AD sites and two forests. dc2016, dcbr and
# memfab01 are never probed by any run in this file.
$estateSpec = @(
    @{ F = 'dc2022.mdilab.local'; D = 'mdilab.local' }
    @{ F = 'dc2019.mdilab.local'; D = 'mdilab.local' }
    @{ F = 'dc2016.mdilab.local'; D = 'mdilab.local' }
    @{ F = 'dcemea.emea.mdilab.local'; D = 'emea.mdilab.local' }
    @{ F = 'dcbr.mdilab.local'; D = 'mdilab.local' }
    @{ F = 'dcfab01.fabrikam.local'; D = 'fabrikam.local' }
    @{ F = 'memfab01.fabrikam.local'; D = 'fabrikam.local' }
)

# Every probe record is carried by the first controller, which is how a sensor-side plan records
# them: one sensor probing a list of targets.
function Get-Stats {
    param($ProbeTargets, $Estate = $estateSpec)
    $rows = @(foreach ($s in $Estate) {
            if ($s.F -eq @($Estate)[0].F) { New-Dc -Fqdn $s.F -Domain $s.D -ProbeTargets $ProbeTargets }
            else { New-Dc -Fqdn $s.F -Domain $s.D }
        })
    Get-mdiReportStatistics -ReportData ([PSCustomObject]@{
            DomainControllers   = $rows
            CAServers           = @()
            EntraConnectServers = @()
            NnrTargetComputer   = @()
            ScopedDomain        = @('mdilab.local', 'emea.mdilab.local', 'fabrikam.local')
        })
}

# The shipped comparison, replicated from Get-mdiReportSummary/Write-mdiConsoleSummary rather than
# described, so what is asserted is the rule the operator's surfaces really apply.
function Test-DisclosureFires {
    param($Stats)
    $scope = [int] $Stats.PortCandidateHostCount
    $probed = [int] $Stats.PortDistinctTargetCount
    ($scope -gt $probed -and $probed -gt 0)
}

$fourMachines = @('dc2022.mdilab.local', 'dc2019.mdilab.local', 'dcemea.emea.mdilab.local', 'dcfab01.fabrikam.local')

Write-Host "`nThe control: four of seven probed, every target spelled canonically"
$statsCanonical = Get-Stats -ProbeTargets $fourMachines
Assert-True 'seven candidate hosts are in scope' `
([int] $statsCanonical.PortCandidateHostCount -eq 7) ("got $($statsCanonical.PortCandidateHostCount)")
Assert-True 'four distinct hosts were probed' `
([int] $statsCanonical.PortDistinctTargetCount -eq 4) ("got $($statsCanonical.PortDistinctTargetCount)")
Assert-True 'and the sample IS disclosed' (Test-DisclosureFires -Stats $statsCanonical)

Write-Host "`nThe SAME four machines, spelled as a real cross-forest, multi-homed estate spells them"
$statsAliased = Get-Stats -ProbeTargets @(
    'dc2022.mdilab.local'
    'DC2022.MDILAB.LOCAL'
    'dc2019.mdilab.local'
    'dc2019.mdilab.local.'
    'dcemea.emea.mdilab.local'
    'DCEMEA.emea.mdilab.local'
    'dcfab01.fabrikam.local'
    'DCFAB01.FABRIKAM.LOCAL'
)
Assert-True 'eight spellings of four machines still count as FOUR probed hosts' `
([int] $statsAliased.PortDistinctTargetCount -eq 4) ("got $($statsAliased.PortDistinctTargetCount)")
Assert-True 'the numerator never exceeds the population it is drawn from' `
([int] $statsAliased.PortDistinctTargetCount -le [int] $statsAliased.PortCandidateHostCount) `
("got $($statsAliased.PortDistinctTargetCount) of $($statsAliased.PortCandidateHostCount)")
Assert-True 'and the three unprobed controllers are STILL disclosed' (Test-DisclosureFires -Stats $statsAliased)

Write-Host "`nOne machine, probed once, recorded four ways is ONE probed host"
$statsOne = Get-Stats -ProbeTargets @(
    'dcfab01.fabrikam.local'
    'DCFAB01.FABRIKAM.LOCAL'
    'dcfab01.fabrikam.local.'
    '  dcfab01.fabrikam.local  '
) -Estate @(@{ F = 'dcfab01.fabrikam.local'; D = 'fabrikam.local' })
Assert-True 'one candidate host is in scope' `
([int] $statsOne.PortCandidateHostCount -eq 1) ("got $($statsOne.PortCandidateHostCount)")
Assert-True 'and exactly one host was probed' `
([int] $statsOne.PortDistinctTargetCount -eq 1) ("got $($statsOne.PortDistinctTargetCount)")
Assert-True 'so a fully probed estate claims NO sample' (-not (Test-DisclosureFires -Stats $statsOne))

Write-Host "`nTHE OPPOSITE MISTAKE: genuinely different machines must not be merged"
# The estate is supplied explicitly here, and that is not incidental. The numerator is now drawn
# FROM the candidate population - a probe record only counts as a host that was visited if the host
# is one the run could have visited - so three targets that exist in no estate now count as zero,
# which is the point of that change and is pinned directly below. What THIS assertion is for is
# narrower and unchanged: that one short name living in three domains is three machines and not one.
# Putting the three in the estate keeps it measuring exactly that.
$statsDistinct = Get-Stats -ProbeTargets @(
    'dc1.mdilab.local'
    'dc1.fabrikam.local'
    'dc1.emea.mdilab.local'
) -Estate @(
    @{ F = 'dc1.mdilab.local'; D = 'mdilab.local' }
    @{ F = 'dc1.fabrikam.local'; D = 'fabrikam.local' }
    @{ F = 'dc1.emea.mdilab.local'; D = 'emea.mdilab.local' }
)
Assert-True 'one short name in three domains is three probed hosts' `
([int] $statsDistinct.PortDistinctTargetCount -eq 3) ("got $($statsDistinct.PortDistinctTargetCount)")

Write-Host "`nA host that is not in the candidate population was never a domain controller we probed"
# The residual left behind when the numerator was filtered on Scope alone. A record whose Scope is
# PRESENT BUT UNREADABLE is not equal to 'NetworkDevice', so it satisfied that exclusion and entered
# a domain-controller ratio on the strength of a value nobody could read - inflating the numerator
# and, with enough such rows, suppressing the sampling disclosure entirely. Drawing the numerator
# from the denominator's own population settles every unreadable spelling at once.
$statsOffEstate = Get-Stats -ProbeTargets @('wks001.mdilab.local', 'srv042.mdilab.local') `
    -Estate @(@{ F = 'dcfab01.fabrikam.local'; D = 'fabrikam.local' })
Assert-True 'two probed hosts that are not candidates count as none' `
([int] $statsOffEstate.PortDistinctTargetCount -eq 0) ("got $($statsOffEstate.PortDistinctTargetCount)")
Assert-True '  ...and the one real candidate is still in scope' `
([int] $statsOffEstate.PortCandidateHostCount -eq 1) ("got $($statsOffEstate.PortCandidateHostCount)")
Assert-True '  ...so the numerator can never exceed the denominator' `
([int] $statsOffEstate.PortDistinctTargetCount -le [int] $statsOffEstate.PortCandidateHostCount)

Write-Host "`nA target nobody could read is not a host that was probed"
foreach ($case in @(
        @{ L = 'a null target'; V = $null }
        @{ L = 'an empty string'; V = '' }
        @{ L = 'whitespace'; V = '   ' }
        @{ L = 'a bare int'; V = 12345 }
        @{ L = 'a boolean'; V = $true }
        @{ L = 'a hashtable'; V = @{ Name = 'dcfab01' } }
    )) {
    $statsOdd = Get-Stats -ProbeTargets @($case.V) -Estate @(@{ F = 'dcfab01.fabrikam.local'; D = 'fabrikam.local' })
    Assert-True ('{0} counts as no probed host' -f $case.L) `
    ([int] $statsOdd.PortDistinctTargetCount -eq 0) ("got $($statsOdd.PortDistinctTargetCount)")
}

Write-Host "`nA readable target still counts, so the guard did not simply refuse everything"
$statsWrapped = Get-Stats -ProbeTargets @(, @('dcfab01.fabrikam.local')) `
    -Estate @(@{ F = 'dcfab01.fabrikam.local'; D = 'fabrikam.local' })
Assert-True 'a one-element wrapped name is a probed host' `
([int] $statsWrapped.PortDistinctTargetCount -eq 1) ("got $($statsWrapped.PortDistinctTargetCount)")

Write-Host "`nThe key function itself, asked directly"
Assert-True 'a null record keys as the empty string' `
((Get-mdiProbeRecordTargetKey -Record $null) -eq '')
Assert-True 'casing and a trailing dot key identically' `
((Get-mdiProbeRecordTargetKey -Record ([PSCustomObject]@{ Target = 'DCFAB01.FABRIKAM.LOCAL.' })) -eq
    (Get-mdiProbeRecordTargetKey -Record ([PSCustomObject]@{ Target = 'dcfab01.fabrikam.local' })))
Assert-True 'a record with no Target falls back to its address' `
((Get-mdiProbeRecordTargetKey -Record ([PSCustomObject]@{ Target = ''; TargetIP = '10.10.1.50' })) -ne '')
Assert-True 'two different machines do not share a key' `
((Get-mdiProbeRecordTargetKey -Record ([PSCustomObject]@{ Target = 'dc1.mdilab.local' })) -ne
    (Get-mdiProbeRecordTargetKey -Record ([PSCustomObject]@{ Target = 'dc1.fabrikam.local' })))

Write-Host ''
Write-Host ("RESULT pass=$script:pass fail=$script:fail")
if ($script:fail -gt 0) { exit 1 }
exit 0
