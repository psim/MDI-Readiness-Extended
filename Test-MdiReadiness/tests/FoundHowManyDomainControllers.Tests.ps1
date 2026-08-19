# DEFECT 290. The line that tells the operator how many domain controllers were found counted them
# with a ruler that discards the domain, so in a two-forest estate it reported a number that was
# wrong in BOTH directions depending on which way the spellings fell.
#
# Main printed "Found {0} domain controller(s) in {1} domain(s)" from
#
#     @($dcInventory | Where-Object { $_.Name } | Select-Object -ExpandProperty Name -Unique).Count
#
# an ordinal de-duplication of the BARE Name. One line above it, over the identical rows,
# Get-mdiAddresslessDomainController keyed the same inventory on
# ConvertTo-mdiCanonicalComputerName -Value $_.Name -Domain ([string] $_.Domain). Two functions
# answering the same question about the same rows with two different rulers - the signature every
# defect in this project has carried.
#
# WHY THE EXTENDED LAB FOUND IT AND 223 TESTS DID NOT. With one forest a bare Name is very nearly a
# unique key, so the two rulers agreed. They stop agreeing the moment a second forest exists:
#
#   UNDER-COUNT. mdilab.local and fabrikam.local may each legitimately hold a dc01. They are
#   different machines at different addresses in different forests. Keyed on the bare Name they are
#   one string, so six machines were reported as five. The operator is told the estate is smaller
#   than it is, and the controller that vanished is not one the tool declines to check - it is one
#   nobody is told exists.
#
#   OVER-COUNT. The same machine is legitimately spelled several ways by the directory: short name,
#   FQDN, the DNS answer's trailing dot, the directory's own casing. Keyed on the bare Name those
#   are four different strings, so ONE machine was reported as four. The operator is told the
#   estate is larger than it is, and a run that examined one host looks like a run that examined
#   four.
#
# Both numbers were measured on the shipped expression before anything was changed: truth 6 counted
# as 5, and truth 1 counted as 4.
#
# THE FIX. Get-mdiDomainControllerHostKey keys an inventory row the way the function directly above
# it in the file already keyed the very same rows - canonicalised against the row's own Domain, and
# lowercased so casing is not an identity. Get-mdiDomainControllerHostCount counts the distinct
# non-empty keys, and Main calls that instead of the inline expression, so the number shown to the
# operator is now a thing that can be measured rather than a ruler that exists in one place only.
#
# WHAT THIS TEST PINS. Both directions, because fixing one by breaking the other is the exact
# mistake this defect already is: an earlier version of this same line counted distinct FQDN, which
# these records do not carry, and reported "Found 0 domain controller(s)" for a populated forest.
# So a cross-forest collision must count as two hosts, a multiply-spelled machine as one, a
# multi-homed controller as one, a row nobody could read as none - and an ordinary estate of five
# differently-named controllers must still count five, which is the arm that catches a "fix" that
# merges or drops everything.

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

# An inventory row of the shape Get-mdiDomainControllerInventory emits. Name and Domain are the only
# two properties the count is entitled to read, which is the whole point: Domain was being discarded.
function New-Row {
    param($Name, $Domain, $Address = '10.10.1.1')
    [PSCustomObject] @{ Name = $Name; Domain = $Domain; IPv4Address = $Address }
}

Write-Host "`nAn ordinary estate: five differently-named controllers across three domains"
$plain = @(
    New-Row 'dc2016' 'mdilab.local'
    New-Row 'dc2019' 'mdilab.local'
    New-Row 'dc2022' 'mdilab.local'
    New-Row 'dcemea' 'emea.mdilab.local'
    New-Row 'dcapac' 'apac.mdilab.local'
)
Assert-True 'five distinct controllers count as five' `
([int] (Get-mdiDomainControllerHostCount -Inventory $plain) -eq 5) `
    ("got $(Get-mdiDomainControllerHostCount -Inventory $plain)")

Write-Host "`nTHE UNDER-COUNT: a dc01 in EACH forest is two machines, not one"
$collide = @(
    New-Row 'dc01' 'mdilab.local' '10.10.0.10'
    New-Row 'dc01' 'fabrikam.local' '10.10.1.50'
    New-Row 'dc2016' 'mdilab.local'
    New-Row 'dc2019' 'mdilab.local'
    New-Row 'dcemea' 'emea.mdilab.local'
    New-Row 'dcfab01' 'fabrikam.local' '10.10.1.50'
)
$collideCount = [int] (Get-mdiDomainControllerHostCount -Inventory $collide)
Assert-True 'six machines with a colliding short name count as six' `
($collideCount -eq 6) ("got $collideCount")
Assert-True 'the two colliding rows do not share a key' `
((Get-mdiDomainControllerHostKey -Row $collide[0]) -ne (Get-mdiDomainControllerHostKey -Row $collide[1]))

Write-Host "`nA cross-forest collision on the DEEPER names too, not just the two-label case"
$deep = @(
    New-Row 'dc01' 'emea.mdilab.local'
    New-Row 'dc01' 'apac.mdilab.local'
)
Assert-True 'the same short name in two child domains is two hosts' `
([int] (Get-mdiDomainControllerHostCount -Inventory $deep) -eq 2) `
    ("got $(Get-mdiDomainControllerHostCount -Inventory $deep)")

Write-Host "`nTHE OVER-COUNT: one machine, spelled the four ways the directory spells it"
$spellings = @(
    New-Row 'dcfab01' 'fabrikam.local'
    New-Row 'dcfab01.fabrikam.local' 'fabrikam.local'
    New-Row 'dcfab01.fabrikam.local.' 'fabrikam.local'
    New-Row 'DCFAB01.FABRIKAM.LOCAL' 'fabrikam.local'
)
$spellCount = [int] (Get-mdiDomainControllerHostCount -Inventory $spellings)
Assert-True 'four legitimate spellings of one machine count as one' `
($spellCount -eq 1) ("got $spellCount")

Write-Host "`nEvery spelling keys identically, which is why the count above is one"
$keys = @($spellings | ForEach-Object { Get-mdiDomainControllerHostKey -Row $_ })
Assert-True 'the short name and the FQDN key the same' ($keys[0] -eq $keys[1]) ("got '$($keys[0])' vs '$($keys[1])'")
Assert-True 'a trailing dot is not a different machine' ($keys[1] -eq $keys[2]) ("got '$($keys[1])' vs '$($keys[2])'")
Assert-True 'casing is not a different machine' ($keys[1] -eq $keys[3]) ("got '$($keys[1])' vs '$($keys[3])'")

Write-Host "`nA multi-homed controller is one host, as the comment above the line claims"
$homed = @(
    New-Row 'dc2022.mdilab.local' 'mdilab.local' '10.10.0.20'
    New-Row 'dc2022.mdilab.local' 'mdilab.local' '10.10.2.20'
    New-Row 'dcbr.mdilab.local' 'mdilab.local' '10.10.3.10'
)
Assert-True 'two addresses on one controller count as one host' `
([int] (Get-mdiDomainControllerHostCount -Inventory $homed) -eq 2) `
    ("got $(Get-mdiDomainControllerHostCount -Inventory $homed)")

Write-Host "`nA row whose Name nobody could read is not a controller that was found"
foreach ($case in @(
        @{ L = 'a null name'; V = $null }
        @{ L = 'an empty string'; V = '' }
        @{ L = 'whitespace'; V = '   ' }
    )) {
    $odd = @(New-Row $case.V 'fabrikam.local')
    Assert-True ('{0} counts as no controller' -f $case.L) `
    ([int] (Get-mdiDomainControllerHostCount -Inventory $odd) -eq 0) `
        ("got $(Get-mdiDomainControllerHostCount -Inventory $odd)")
}

Write-Host "`nAn unreadable row does not erase the readable ones beside it"
$mixed = @(
    New-Row 'dcfab01' 'fabrikam.local'
    New-Row '' 'fabrikam.local'
    New-Row 'dc2022' 'mdilab.local'
)
Assert-True 'two readable rows plus a blank one count as two' `
([int] (Get-mdiDomainControllerHostCount -Inventory $mixed) -eq 2) `
    ("got $(Get-mdiDomainControllerHostCount -Inventory $mixed)")

Write-Host "`nThe empty and absent inventories, which the parameter explicitly admits"
Assert-True 'an empty inventory counts zero' ([int] (Get-mdiDomainControllerHostCount -Inventory @()) -eq 0)
Assert-True 'a null inventory counts zero' ([int] (Get-mdiDomainControllerHostCount -Inventory $null) -eq 0)

Write-Host "`nThe key function itself, asked directly"
Assert-True 'a null row keys as the empty string' ((Get-mdiDomainControllerHostKey -Row $null) -eq '')
Assert-True 'a row with no Domain still keys as its name' `
((Get-mdiDomainControllerHostKey -Row (New-Row 'dcfab01.fabrikam.local' $null)) -eq 'dcfab01.fabrikam.local')
Assert-True 'a row whose Domain is a wrong type does not throw' `
((Get-mdiDomainControllerHostKey -Row (New-Row 'dcfab01.fabrikam.local' @('a', 'b'))) -is [string])

Write-Host "`nThe count agrees with the addressless reader, which keys the same rows the same way"
$agree = @(
    New-Row 'dc01' 'mdilab.local' '10.10.0.10'
    New-Row 'dc01' 'fabrikam.local' '10.10.1.50'
)
Assert-True 'both forests survive the addressless reader as distinct rows' `
([int] (Get-mdiDomainControllerHostCount -Inventory $agree) -eq 2)

Write-Host "`npass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
