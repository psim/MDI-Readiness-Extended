<#
    Every network interface of a multi-homed domain controller must reach the LDAP probe plan, even
    when the inventory row carries its address in a wrapper rather than as a bare string.

    Resolve-mdiLdapTarget deliberately emits every unique (identity, IP) pair of the hosts it samples,
    and says why in its own comment: "a domain controller that answers LDAP on one NIC and is filtered
    on another must be tested on BOTH". Collapsing a host to one arbitrary address "let DNS round-robin
    decide which NIC was tested and reported the DC healthy on the strength of the open interface while
    the blocked one went unprobed".

    The de-duplication that produces those pairs was written as:

        Group-Object -Property { Get-mdiProbeTargetKey -Target $_ }, IP

    Two of the three fields in that statement had already been hardened for one specific mechanism:
    Group-Object given a BARE PROPERTY NAME compares the RAW values. Get-mdiProbeTargetKey exists
    because `Group-Object -Property Name` folded two same-named DCs in different domains into one host;
    Get-mdiProbeDomainKey exists because `Group-Object -Property Domain` put rows whose Domain was
    @('mdilab.local') and @('fabrikam.local') into ONE group named '{mdilab.local}'. IP was the last
    field in that statement still spelled bare, and it carries the identical exposure: under a raw
    comparison two DISTINCT single-element arrays compare EQUAL.

    Measured on the shipped function, one multi-homed domain controller whose two inventory rows
    carried IP = @('10.10.2.10') and IP = @('10.10.2.11'):

        bare  ..., IP        1 group named 'h, {10.10.2.10}'   ->  1 target, one NIC dropped
        coerced key          2 groups                          ->  2 targets, both NICs probed

    The dropped interface is worse than a failed probe because it produces NO RECORD AT ALL, and a
    fact with no record cannot be counted as missing by anything downstream: the LDAP card reports the
    controller on the strength of the interface that answered, with nothing anywhere saying the other
    was never tried. That is the false green this codebase exists to prevent.

    Stated no more strongly than it was measured, exactly as the sibling address guard in the same
    function is: today's producer, Get-mdiDomainControllerInventory, canonicalises each address and
    assigns a scalar, so this was not a live false green in the shipped pipeline. It is a disagreement
    between two readers of one inventory, reachable from a supplied inventory, an -AsJson round trip,
    another tool or a hand-edited report - and the guard belongs on the key, where its two sibling
    fields already are.

    Pinned here: two distinct array-wrapped addresses on one host stay two targets; mixed shapes on one
    host stay two targets; one address written two different ways still collapses to a single target,
    so the fix does not trade a dropped NIC for a duplicated probe; the cross-forest estate keeps its
    per-domain spread; and the unreadable shapes ($null, '', a non-numeric string, a wrong type, an
    empty collection) neither throw the estate away nor come back looking like a measurable address.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = [IO.Path]::GetFullPath($target)
$text = [IO.File]::ReadAllText($target)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main')
if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body

$script:passed = 0
$script:failed = 0
$script:warnings = New-Object System.Collections.ArrayList
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:passed++
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray
    } else {
        $script:failed++
        Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red
    }
}
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value {
    param($Message)
    [void] $script:warnings.Add([string] $Message)
}

function Get-TargetAddress {
    param($Targets, [string] $NameLike)
    @(@($Targets) | Where-Object { ([string] $_.Name) -like $NameLike } |
        ForEach-Object { [string] $_.IP } | Sort-Object)
}

Write-Host '--- the contract this file pins is on the shipped parameter names ---'
$cmd = Get-Command Resolve-mdiLdapTarget
Assert-True 'Resolve-mdiLdapTarget still takes -DomainControllers' ($cmd.Parameters.ContainsKey('DomainControllers'))
Assert-True 'Resolve-mdiLdapTarget still takes -MaxPerDomain' ($cmd.Parameters.ContainsKey('MaxPerDomain'))

Write-Host '--- control: a multi-homed DC with plain string addresses is probed on both NICs ---'
$plain = @(
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = '10.10.1.50' }
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = '10.10.1.60' }
)
$plainTargets = @(Resolve-mdiLdapTarget -DomainControllers $plain -MaxPerDomain 2)
Assert-True 'control: plain strings yield two targets' (@($plainTargets).Count -eq 2) (
    "count={0}" -f @($plainTargets).Count
)

Write-Host '--- the defect: two DISTINCT array-wrapped addresses must stay two targets ---'
$wrapped = @(
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = @('10.10.1.50') }
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = @('10.10.1.60') }
)
$wrappedTargets = @(Resolve-mdiLdapTarget -DomainControllers $wrapped -MaxPerDomain 2)
$wrappedAddresses = Get-TargetAddress -Targets $wrappedTargets -NameLike 'dcfab01*'
Assert-True 'an array-wrapped multi-homed DC keeps BOTH NICs' (@($wrappedTargets).Count -eq 2) (
    "count={0} addresses=[{1}]" -f @($wrappedTargets).Count, ($wrappedAddresses -join ',')
)
Assert-True 'the second NIC is the one that was being dropped' (
    $wrappedAddresses -contains '10.10.1.60'
) ("addresses=[{0}]" -f ($wrappedAddresses -join ','))
Assert-True 'the first NIC is still present' (
    $wrappedAddresses -contains '10.10.1.50'
) ("addresses=[{0}]" -f ($wrappedAddresses -join ','))

Write-Host '--- mixed shapes on one host (one row wrapped, one row plain) ---'
$mixed = @(
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = '10.10.1.50' }
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = @('10.10.1.60') }
)
$mixedTargets = @(Resolve-mdiLdapTarget -DomainControllers $mixed -MaxPerDomain 2)
Assert-True 'mixed shapes on one host still yield two targets' (@($mixedTargets).Count -eq 2) (
    "count={0}" -f @($mixedTargets).Count
)

Write-Host '--- the opposite direction: the fix must not turn one address into two probes ---'
$dupe = @(
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = '10.10.1.50' }
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = @('10.10.1.50') }
)
$dupeTargets = @(Resolve-mdiLdapTarget -DomainControllers $dupe -MaxPerDomain 2)
Assert-True 'one address written two ways collapses to a single target' (@($dupeTargets).Count -eq 1) (
    "count={0}" -f @($dupeTargets).Count
)

$dupeRows = @(
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = '10.10.1.50' }
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = '10.10.1.50' }
)
$dupeRowTargets = @(Resolve-mdiLdapTarget -DomainControllers $dupeRows -MaxPerDomain 2)
Assert-True 'a repeated inventory row is still de-duplicated' (@($dupeRowTargets).Count -eq 1) (
    "count={0}" -f @($dupeRowTargets).Count
)

Write-Host '--- the cross-forest estate: per-domain spread survives the coerced key ---'
$estate = @(
    [PSCustomObject] @{ Name = 'dc01.mdilab.local'; Domain = 'mdilab.local'; IP = '10.10.1.10' }
    [PSCustomObject] @{ Name = 'dc02.mdilab.local'; Domain = 'mdilab.local'; IP = @('10.10.2.10') }
    [PSCustomObject] @{ Name = 'dc02.mdilab.local'; Domain = 'mdilab.local'; IP = @('10.10.2.11') }
    [PSCustomObject] @{ Name = 'dc03.mdilab.local'; Domain = 'mdilab.local'; IP = '10.10.3.10' }
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = @('fabrikam.local'); IP = @('10.10.1.50') }
)
$allTargets = @(Resolve-mdiLdapTarget -DomainControllers $estate -MaxPerDomain 0)
$dc02Addresses = Get-TargetAddress -Targets $allTargets -NameLike 'dc02*'
Assert-True 'both NICs of the multi-homed dc02 are probed' (@($dc02Addresses).Count -eq 2) (
    "addresses=[{0}]" -f ($dc02Addresses -join ',')
)
Assert-True 'the cross-forest domain still receives an LDAP target' (
    @(Get-TargetAddress -Targets $allTargets -NameLike 'dcfab01*').Count -eq 1
)
Assert-True 'every host in the estate is represented' (
    @(@($allTargets) | ForEach-Object { [string] $_.Name } | Select-Object -Unique).Count -eq 4
) ("hosts={0}" -f (@(@($allTargets) | ForEach-Object { [string] $_.Name } | Select-Object -Unique) -join ','))

Write-Host '--- the per-domain budget is still spent per domain, not across the estate ---'
$capped = @(Resolve-mdiLdapTarget -DomainControllers $estate -MaxPerDomain 1)
Assert-True 'a cap of 1 still reaches BOTH domains' (
    @(@($capped) | ForEach-Object { [string] $_.Domain } | Select-Object -Unique).Count -eq 2
) ("domains={0}" -f (@(@($capped) | ForEach-Object { [string] $_.Domain } | Select-Object -Unique) -join ','))

Write-Host '--- unreadable shapes: nothing that was never read may look like an address ---'
$junk = @(
    [PSCustomObject] @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = '10.10.1.50' }
    [PSCustomObject] @{ Name = 'dcjunk1.fabrikam.local'; Domain = 'fabrikam.local'; IP = $null }
    [PSCustomObject] @{ Name = 'dcjunk2.fabrikam.local'; Domain = 'fabrikam.local'; IP = '' }
    [PSCustomObject] @{ Name = 'dcjunk3.fabrikam.local'; Domain = 'fabrikam.local'; IP = 'not-an-address' }
    [PSCustomObject] @{ Name = 'dcjunk4.fabrikam.local'; Domain = 'fabrikam.local'; IP = 12345 }
    [PSCustomObject] @{ Name = 'dcjunk5.fabrikam.local'; Domain = 'fabrikam.local'; IP = @() }
)
$junkThrew = $null
$junkTargets = @()
try { $junkTargets = @(Resolve-mdiLdapTarget -DomainControllers $junk -MaxPerDomain 0) }
catch { $junkThrew = $_.Exception.Message }
Assert-True 'an unreadable address does not throw the estate away' ($null -eq $junkThrew) ([string] $junkThrew)
Assert-True 'only the one genuinely readable address becomes a target' (@($junkTargets).Count -eq 1) (
    "count={0}" -f @($junkTargets).Count
)
Assert-True 'the surviving target is the real address' (
    (@($junkTargets).Count -eq 1) -and ([string] @($junkTargets)[0].IP -eq '10.10.1.50')
)

Write-Host '--- an empty estate is still zero targets, not one empty one ---'
Assert-True 'an empty inventory yields no targets' (
    @(Resolve-mdiLdapTarget -DomainControllers @() -MaxPerDomain 2).Count -eq 0
)

Write-Host '--- control: resolving targets raises no operator-facing warning ---'
Assert-True 'control: no warning was written while resolving' ($script:warnings.Count -eq 0) (
    "Warnings={0}" -f ($script:warnings -join ' | ')
)

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
