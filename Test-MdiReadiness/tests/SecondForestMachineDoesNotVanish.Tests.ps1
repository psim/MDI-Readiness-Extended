<#
    A MACHINE IN THE SECOND FOREST MUST NOT VANISH BECAUSE ITS NAME WAS NEVER READ.

    Get-mdiServerIdentityKey is this script's single ruler for "which MACHINE is this server row",
    and its own header states why the answer has to be forest-aware:

        "A name is not a host once there is more than one forest in scope: mdilab.local and
         fabrikam.local may each legitimately hold a dc01, and they are different machines at
         different addresses."

    It separates them by routing the DOMAIN half through ConvertTo-mdiReadableDomainName and handing
    the result to ConvertTo-mdiCanonicalComputerName, which qualifies a DOTLESS name with it.

    THE DEFECT. The NAME half was read with a bare [string] cast:

        $key = ConvertTo-mdiCanonicalComputerName -Value ([string] $Server.FQDN) -Domain $readableDomain

    while its DOCUMENTED COUNTERPART - Get-mdiProbeRecordTargetKey, the NUMERATOR of the very ratio
    this key is the DENOMINATOR of - routes its own name half through ConvertTo-mdiReadableDomainName
    and states the rule in prose: "[string] tests the RENDERING, not the value". So the two halves of
    ONE disclosure ratio were counted by TWO rules - which is precisely the failure that function's
    header records as ALREADY having been made once, on this same pair.

    TWO LOSSES FOLLOWED, both measured on the shipped functions.

    1. A MACHINE LEFT A CROSS-FOREST ESTATE. Every unreadable value renders to a string CONTAINING
       DOTS - 'System.Collections.Hashtable' - and ConvertTo-mdiCanonicalComputerName appends the
       domain only to a name with NO dot. So for exactly the rows nobody could read, the forest
       separation this key exists for was switched off. Measured through Merge-mdiServerByFqdn on
       four rows, one unreadable FQDN in EACH forest:

           FQDN = @{}      4 rows in -> 3 rows out    the fabrikam.local machine VANISHED
           FQDN = $true    4 rows in -> 4 rows out    (rendered 'True', no dot, so it WAS qualified)

       The vanished row was never probed, never counted and never reported unreachable - what
       Get-mdiDomainControllerInventory calls "the most damaging outcome this tool has, because the
       report still reads as a complete scan of the estate".

    2. A NAME NOBODY READ BECAME A FULLY QUALIFIED HOST. The shapes that happened to render without
       a dot were QUALIFIED WITH THE DOMAIN and entered the estate as real hosts of that forest:

           $true            -> true.mdilab.local
           12345            -> 12345.mdilab.local
           @('dc01','dc02') -> dc01 dc02.fabrikam.local
           [pscustomobject] -> @{name=dc01}.fabrikam.local

       All four were counted in PortCandidateHostCount while Get-mdiProbeRecordTargetKey dropped all
       four from PortDistinctTargetCount, so the sampling disclosure compared a denominator holding
       fabricated hosts against a numerator that refuses them - and offered
       -MaxLdapTargetsPerDomain as the remedy for a host that cannot exist. That is this project's
       recurring family exactly: a value that was never read coming back looking like a measurement.

    THE FIX routes the name half through ConvertTo-mdiReadableDomainName as well, so an unreadable
    FQDN keys as the empty string. Both consumers already handled '' correctly and neither changed:
    Merge-mdiServerByFqdn keeps a blank-keyed row SEPARATE rather than merging it, and the statistics
    drop it with the IsNullOrWhiteSpace filter they already apply.

    WHAT THIS TEST ALSO REFUSES - the opposite mistakes, which are what make the fix worth pinning.

      * A READABLE name must key exactly as before, and must STILL be separated per forest. A fix
        that keyed everything blank would "pass" the merge assertions by destroying the estate.
      * A ONE-ELEMENT COLLECTION - @('dc01.mdilab.local') - is a shape this codebase has repeatedly
        been hardened FOR, and [string] already read it correctly. It must keep being read.
      * A row whose name is unreadable must still SURVIVE as its own row in the merge. Dropping it
        would replace a silent merge with a silent deletion, which is the worse failure of the two.
      * The all-numeric single-label STRING '12345' is a name a directory really returns and
        ConvertTo-mdiReadableDomainName deliberately accepts it; only the INT 12345 is refused.
#>

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

function New-Row {
    param($Fqdn, $Domain, $PowerOk = $true)
    [PSCustomObject]@{
        FQDN            = $Fqdn
        Domain          = $Domain
        Unreachable     = $false
        OperatingSystem = 'Windows Server 2022'
        isPowerSchemeOk = $PowerOk
    }
}

# The shapes an -AsJson round trip, another tool's inventory or a hand-edited report really produces.
# Named so a failure message says WHICH shape broke.
$unreadable = [ordered]@{
    'a hashtable'          = @{ Name = 'dc01' }
    'a PSCustomObject'     = [PSCustomObject]@{ Name = 'dc01' }
    'a two-element array'  = @('dc01', 'dc02')
    'a boolean'            = $true
    'an integer'           = 12345
}

Write-Host "`n1. An unreadable FQDN must not be a machine identity at all"
foreach ($name in $unreadable.Keys) {
    $k = Get-mdiServerIdentityKey -Server (New-Row -Fqdn $unreadable[$name] -Domain 'fabrikam.local')
    Assert-True "$name keys as the empty string" ($k -eq '') "got [$k]"
}

Write-Host "`n2. THE CROSS-FOREST LOSS - the same unreadable name in two forests is not one machine"
# Before the fix 'a hashtable' produced the IDENTICAL key in both forests, because
# 'System.Collections.Hashtable' carries dots and so was never qualified with the domain.
foreach ($name in $unreadable.Keys) {
    $a = Get-mdiServerIdentityKey -Server (New-Row -Fqdn $unreadable[$name] -Domain 'mdilab.local')
    $b = Get-mdiServerIdentityKey -Server (New-Row -Fqdn $unreadable[$name] -Domain 'fabrikam.local')
    # Either key blank (refused outright) or the two differ. What must NEVER happen is one non-blank
    # key shared by two forests, which silently declares them the same machine.
    $shared = ($a -eq $b) -and -not [string]::IsNullOrWhiteSpace($a)
    Assert-True "$name does not give mdilab.local and fabrikam.local one shared identity" (-not $shared) "both keyed [$a]"
}

Write-Host "`n3. A name nobody read must not be qualified into a host of a real forest"
foreach ($name in $unreadable.Keys) {
    $k = Get-mdiServerIdentityKey -Server (New-Row -Fqdn $unreadable[$name] -Domain 'mdilab.local')
    Assert-True "$name does not become a *.mdilab.local host" ($k -notlike '*mdilab.local') "got [$k]"
}

Write-Host "`n4. END TO END - Merge-mdiServerByFqdn must not lose a machine from the second forest"
foreach ($name in $unreadable.Keys) {
    $estate = @(
        (New-Row -Fqdn 'dc01.mdilab.local' -Domain 'mdilab.local' -PowerOk $true),
        (New-Row -Fqdn 'dcfab01.fabrikam.local' -Domain 'fabrikam.local' -PowerOk $true),
        (New-Row -Fqdn $unreadable[$name] -Domain 'mdilab.local' -PowerOk $false),
        (New-Row -Fqdn $unreadable[$name] -Domain 'fabrikam.local' -PowerOk $true)
    )
    $out = @(Merge-mdiServerByFqdn -Server $estate)
    Assert-True "$name : all 4 rows survive the merge" ($out.Count -eq 4) "got $($out.Count) row(s)"
}

Write-Host "`n5. ONE RATIO, ONE RULER - the denominator must agree with the numerator"
# Get-mdiServerIdentityKey feeds PortCandidateHostCount; Get-mdiProbeRecordTargetKey feeds
# PortDistinctTargetCount. Get-mdiProbeRecordTargetKey's header: the two counts "have to be measured
# with one ruler, because the disclosure is the RATIO between them".
foreach ($name in $unreadable.Keys) {
    $inDenominator = -not [string]::IsNullOrWhiteSpace(
        (Get-mdiServerIdentityKey -Server (New-Row -Fqdn $unreadable[$name] -Domain 'fabrikam.local')))
    $inNumerator = -not [string]::IsNullOrWhiteSpace(
        (Get-mdiProbeRecordTargetKey -Record ([PSCustomObject]@{ Target = $unreadable[$name]; TargetIP = $null })))
    Assert-True "$name is counted the same way by both halves of the ratio" ($inDenominator -eq $inNumerator) `
        "denominator=$inDenominator numerator=$inNumerator"
}

Write-Host "`n6. NOTHING THAT USED TO BE READ STOPS BEING READ"
$k1 = Get-mdiServerIdentityKey -Server (New-Row -Fqdn 'dc01.mdilab.local' -Domain 'mdilab.local')
Assert-True 'a fully qualified name keys unchanged' ($k1 -eq 'dc01.mdilab.local') "got [$k1]"

$k2 = Get-mdiServerIdentityKey -Server (New-Row -Fqdn 'dc01' -Domain 'mdilab.local')
$k3 = Get-mdiServerIdentityKey -Server (New-Row -Fqdn 'dc01' -Domain 'fabrikam.local')
Assert-True 'a SHORT name is still qualified with its own domain' ($k2 -eq 'dc01.mdilab.local') "got [$k2]"
Assert-True 'the same short name in two forests is still two machines' ($k2 -ne $k3) "both keyed [$k2]"

# The shape Get-mdiProbeTargetKey, Get-mdiProbeDomainKey and Get-mdiAddresslessDomainController were
# each hardened FOR. [string] already read it correctly and the fix must not lose it.
$k4 = Get-mdiServerIdentityKey -Server (New-Row -Fqdn @('dc01.mdilab.local') -Domain 'mdilab.local')
Assert-True 'a one-element collection is still unwrapped and read' ($k4 -eq 'dc01.mdilab.local') "got [$k4]"

$k5 = Get-mdiServerIdentityKey -Server (New-Row -Fqdn 'DC01.MDILAB.LOCAL.' -Domain 'mdilab.local')
Assert-True 'case and the trailing root dot still fold to one machine' ($k5 -eq 'dc01.mdilab.local') "got [$k5]"

# ConvertTo-mdiReadableDomainName deliberately accepts the all-numeric single-label STRING, because a
# directory really returns one. Only the INT is refused (section 1).
$k6 = Get-mdiServerIdentityKey -Server (New-Row -Fqdn '12345' -Domain 'mdilab.local')
Assert-True 'the all-numeric single-label STRING is still a readable name' ($k6 -eq '12345.mdilab.local') "got [$k6]"

$k7 = Get-mdiServerIdentityKey -Server (New-Row -Fqdn '  dc01.mdilab.local  ' -Domain 'mdilab.local')
Assert-True 'surrounding whitespace is still trimmed to one machine' ($k7 -eq 'dc01.mdilab.local') "got [$k7]"

Write-Host "`n7. A ROW WHOSE NAME NOBODY READ MUST STILL SURVIVE AS ITS OWN ROW"
# Refusing the name must not become deleting the server: that would swap a silent merge for a silent
# deletion, which is strictly worse. Merge-mdiServerByFqdn keeps a blank-keyed row separate.
$estate = @(
    (New-Row -Fqdn 'dc01.mdilab.local' -Domain 'mdilab.local'),
    (New-Row -Fqdn @{ Name = 'x' } -Domain 'mdilab.local'),
    (New-Row -Fqdn @{ Name = 'y' } -Domain 'fabrikam.local')
)
$out = @(Merge-mdiServerByFqdn -Server $estate)
Assert-True 'an unreadable row is kept, not dropped' ($out.Count -eq 3) "got $($out.Count) row(s)"

Write-Host ''
Write-Host ("RESULT  pass=$script:pass  fail=$script:fail")
if ($script:fail -gt 0) { exit 1 }
exit 0
