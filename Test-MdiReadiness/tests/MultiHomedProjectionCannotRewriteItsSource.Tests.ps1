<#
    A copy that shares its source's store is not a copy, and the row it "projected" rewrote the
    domain controller it was projected from.

    Resolve-mdiLdapTarget expands one domain controller row into ONE ROW PER USABLE ADDRESS, so a
    DC that answers LDAP on one NIC and is filtered on another is probed on BOTH. Its own header
    states why: collapsing a host to a single arbitrary address "let DNS round-robin decide which
    NIC was tested and reported the DC healthy on the strength of the open interface while the
    blocked one went unprobed".

    It projected with $dc.PSObject.Copy(), which is SHALLOW. This file had already measured, twice,
    that PSObject.Copy() over an IDictionary returns the SAME underlying store - Copy-mdiDetails
    says "a 'copy' that is then written to still mutates the original", and Merge-mdiServerByFqdn
    clones its Details for the same reason. Two of the three sites were fixed; this one was left
    behind, and it is the one that decides which network paths get probed at all.

    Measured on the shipped function, one multi-homed dcfab01.fabrikam.local carrying 10.10.1.50
    and 10.10.1.60, the ONLY difference being the shape of the inventory row:

        PSCustomObject       2 targets   10.10.1.50, 10.10.1.60
        Hashtable            2 targets   10.10.1.50, 10.10.1.60
        OrderedDictionary    1 target                10.10.1.60   10.10.1.50 NEVER PROBED
        Generic.Dictionary   1 target                10.10.1.60   10.10.1.50 NEVER PROBED

    Every projection of the host wrote IP into one shared store, so they all ended up carrying the
    LAST address and the de-duplication at the foot of the function then collapsed them into one.
    The host still appears in the report with an LDAP result, so nothing discloses that half of its
    network paths were never tested - the report reads as a complete scan of the estate.

    It also rewrites the CALLER'S inventory: the row's IP went from 10.10.1.50 to 10.10.1.60 and
    stayed there. Get-mdiAddresslessDomainController and the domain-controller rows read that same
    inventory, so after sampling they describe the DC by an address discovery never assigned to it.

    The sibling site in Get-mdiRequiredPorts is fixed with it. There $Plan.PSObject.Copy() is
    written to three times to narrow the plan for the reverse-direction fallback; over a shared
    store that narrowing is permanent and applies to every server probed afterwards, which is
    precisely the shrinking denominator its own comment describes - "the denominator itself had
    shrunk, so every surface agreed on a complete pass over a population that had quietly lost four
    required members".

    Stated no more strongly than it was measured, exactly as the sibling guards in this function
    are: today's producer, Get-mdiDomainControllerInventory, emits PSCustomObject rows, so this is
    not a live false green in the shipped pipeline. It is a supplied inventory, another tool or a
    hand-edited report that reaches it - the same arrival vector every other guard there names, and
    a shape ConvertTo-mdiRecordObject already exists to accept.

    Pinned here: a dictionary-shaped multi-homed row yields a target on EVERY usable address; the
    source row is not rewritten; the four shapes agree with each other; and the plan copy taken by
    the reverse-direction fallback does not narrow the caller's plan.
#>

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
function Assert([string] $name, [bool] $ok) {
    if ($ok) { $script:pass++; Write-Host "  PASS  $name" }
    else { $script:fail++; Write-Host "  FAIL  $name" -ForegroundColor Red }
}
function Section([string] $name) { Write-Host ''; Write-Host $name }

$addrA = '10.10.1.50'
$addrB = '10.10.1.60'
$addrC = '10.10.1.70'

function New-Row {
    param([string] $Shape, [string[]] $Addresses)
    switch ($Shape) {
        'PSCustomObject' {
            [PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = $Addresses[0]; Addresses = @($Addresses) }
        }
        'Hashtable' {
            @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = $Addresses[0]; Addresses = @($Addresses) }
        }
        'OrderedDictionary' {
            [ordered]@{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = $Addresses[0]; Addresses = @($Addresses) }
        }
        'GenericDictionary' {
            $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'
            $d['Name'] = 'dcfab01.fabrikam.local'
            $d['Domain'] = 'fabrikam.local'
            $d['IP'] = $Addresses[0]
            $d['Addresses'] = @($Addresses)
            $d
        }
    }
}

function Get-RowIP {
    param($Row)
    if ($Row -is [Collections.IDictionary]) { return [string] $Row['IP'] }
    [string] $Row.IP
}

$shapes = @('PSCustomObject', 'Hashtable', 'OrderedDictionary', 'GenericDictionary')

Section '1. every usable address of a multi-homed domain controller gets an LDAP target'
foreach ($shape in $shapes) {
    $row = New-Row -Shape $shape -Addresses @($addrA, $addrB)
    $targets = @(Resolve-mdiLdapTarget -DomainControllers @($row) -MaxPerDomain 2)
    $probed = @(@($targets | ForEach-Object { [string] $_.IP }) | Sort-Object -Unique)
    Assert "$shape - both NICs are probed" ($probed.Count -eq 2)
    Assert "$shape - 10.10.1.50 is probed" ($probed -contains $addrA)
    Assert "$shape - 10.10.1.60 is probed" ($probed -contains $addrB)
}

Section '2. a three-homed controller keeps all three paths'
foreach ($shape in $shapes) {
    $row = New-Row -Shape $shape -Addresses @($addrA, $addrB, $addrC)
    $probed = @(@(Resolve-mdiLdapTarget -DomainControllers @($row) -MaxPerDomain 2 | ForEach-Object { [string] $_.IP }) | Sort-Object -Unique)
    Assert "$shape - three addresses give three targets" ($probed.Count -eq 3)
}

Section '3. the projection does not rewrite the row it was projected from'
foreach ($shape in $shapes) {
    $row = New-Row -Shape $shape -Addresses @($addrA, $addrB)
    $before = Get-RowIP -Row $row
    $null = Resolve-mdiLdapTarget -DomainControllers @($row) -MaxPerDomain 2
    $after = Get-RowIP -Row $row
    Assert "$shape - the caller's inventory row still carries $before" ($after -eq $before)
}

Section '4. the shapes agree with each other'
$byShape = @{}
foreach ($shape in $shapes) {
    $row = New-Row -Shape $shape -Addresses @($addrA, $addrB)
    $byShape[$shape] = (@(@(Resolve-mdiLdapTarget -DomainControllers @($row) -MaxPerDomain 2 | ForEach-Object { [string] $_.IP }) | Sort-Object -Unique) -join ',')
}
$distinct = @($byShape.Values | Sort-Object -Unique)
Assert 'all four inventory shapes produce the identical target set' ($distinct.Count -eq 1)
Assert 'and that set is both addresses' ($distinct[0] -eq ('{0},{1}' -f $addrA, $addrB))

Section '5. repeated sampling of one inventory is stable'
$row = New-Row -Shape 'OrderedDictionary' -Addresses @($addrA, $addrB)
$counts = @(1..3 | ForEach-Object {
        @(@(Resolve-mdiLdapTarget -DomainControllers @($row) -MaxPerDomain 2 | ForEach-Object { [string] $_.IP }) | Sort-Object -Unique).Count
    })
Assert 'three passes over the same row all return two targets' (@($counts | Where-Object { $_ -ne 2 }).Count -eq 0)

Section '6. a second host in the same call is unaffected'
$fab = New-Row -Shape 'OrderedDictionary' -Addresses @($addrA, $addrB)
$mdi = [ordered]@{ Name = 'dc01.mdilab.local'; Domain = 'mdilab.local'; IP = '10.0.1.10'; Addresses = @('10.0.1.10') }
$mixed = @(Resolve-mdiLdapTarget -DomainControllers @($fab, $mdi) -MaxPerDomain 2)
Assert 'both domains receive targets' ((@($mixed | Where-Object { $_.Name -like '*fabrikam*' }).Count -gt 0) -and (@($mixed | Where-Object { $_.Name -like '*mdilab*' }).Count -gt 0))
Assert 'fabrikam.local gets both of its NICs' (@(@($mixed | Where-Object { $_.Name -like '*fabrikam*' } | ForEach-Object { [string] $_.IP }) | Sort-Object -Unique).Count -eq 2)
Assert 'mdilab.local row was not rewritten' ([string] $mdi['IP'] -eq '10.0.1.10')

Section '7. the copy helper itself refuses to share a store'
foreach ($case in @(
        @{ N = 'PSCustomObject'; V = ([PSCustomObject]@{ IP = 'A' }) }
        @{ N = 'Hashtable'; V = @{ IP = 'A' } }
        @{ N = 'OrderedDictionary'; V = ([ordered]@{ IP = 'A' }) }
    )) {
    $orig = $case.V
    $copy = Copy-mdiWritableRecord -Record $orig
    $copy.IP = 'B'
    $origIP = if ($orig -is [Collections.IDictionary]) { [string] $orig['IP'] } else { [string] $orig.IP }
    Assert ('{0} - writing to the copy leaves the original at A' -f $case.N) ($origIP -eq 'A')
    $copyIP = if ($copy -is [Collections.IDictionary]) { [string] $copy['IP'] } else { [string] $copy.IP }
    Assert ('{0} - and the copy really took the write' -f $case.N) ($copyIP -eq 'B')
}
Assert 'a null record copies to null' ($null -eq (Copy-mdiWritableRecord -Record $null))

Section '8. the reverse-direction fallback does not narrow the caller''s plan'
# Get-mdiRequiredPorts copies the plan and overwrites NnrTargets, DomainControllers and Probes on
# the copy. Over a shared store that narrowing is permanent for every server probed afterwards.
$planShapes = @(
    @{ N = 'PSCustomObject'; V = ([PSCustomObject]@{ Probes = @(1, 2, 3, 4, 5, 6, 7); NnrTargets = @('a'); DomainControllers = @('b') }) }
    @{ N = 'OrderedDictionary'; V = ([ordered]@{ Probes = @(1, 2, 3, 4, 5, 6, 7); NnrTargets = @('a'); DomainControllers = @('b') }) }
)
foreach ($case in $planShapes) {
    $plan = $case.V
    $copy = Copy-mdiWritableRecord -Record $plan
    $copy.Probes = @(1, 2, 3)
    $copy.NnrTargets = @()
    $planProbes = if ($plan -is [Collections.IDictionary]) { @($plan['Probes']).Count } else { @($plan.Probes).Count }
    Assert ('{0} - the plan still carries all seven probes' -f $case.N) ($planProbes -eq 7)
}

Write-Host ''
Write-Host ('MultiHomedProjectionCannotRewriteItsSource: {0} passed, {1} failed' -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
