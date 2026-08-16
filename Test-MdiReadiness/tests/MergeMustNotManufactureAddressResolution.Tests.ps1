<#
    The domain-controller merge must not MANUFACTURE the claim that address resolution finished.

    Merge-mdiDomainControllerEndpoint folds every discovered spelling of one domain controller into a
    single entry. Alongside the name and addresses it publishes AddressResolutionComplete, and that
    flag is not decoration: Get-mdiDomainControllerInventory reads it to choose between two entirely
    different behaviours -

        $addresses = @(if ($dc.AddressResolutionComplete -eq $true) {
                <trust the addresses already attached to the record>
            } else {
                Get-mdiComputerAddress -ComputerName $dcName -KnownAddress $knownAddresses
            })

    The merge used to write that flag as a literal:

        AddressResolutionComplete = $true

    on every entry it created, whatever the source record said. A source carrying
    AddressResolutionComplete=$false - which means precisely "these addresses are NOT the resolved
    set, go and resolve them" - came out of the merge asserting the opposite. Measured before the
    fix: one record in with $false and no addresses, out with Complete=[True] and Addresses=[].

    That is this project's recurring defect in its purest form. Nothing was read, and a definite
    answer was published anyway.

    The damage is not confined to the flag. Resolve-mdiDomainController returns Servers from exactly
    three places - $viaAdws, $viaLdap and @() - and both non-empty ones are the OUTPUT OF THIS MERGE.
    So every server object that ever reaches the consumer above carried Complete=$true, the first
    branch was always taken, and the Get-mdiComputerAddress fallback in the else was UNREACHABLE CODE.
    A domain controller whose addresses failed to resolve during discovery was reported "No usable IP
    address could be resolved ... it cannot be probed" without the second attempt that branch exists
    to give it, and no producer could ever re-arm it because the merge erased the $false.

    Pinned here:

    1. An explicit $false SURVIVES the merge. This is the defect itself.
    2. The carry is PESSIMISTIC across copies of one host, in BOTH orders - complete-then-incomplete
       and incomplete-then-complete both yield incomplete. This matches Merge-mdiServerByFqdn, where
       a check that failed under any role is failed for the merged server. Flipping the -and to -or,
       or letting the last source win, turns these red.
    3. A source with NO such property is still complete. Both current producers (ADWS and LDAP) call
       Get-mdiComputerAddress before merging and never set the property, so their behaviour must not
       change. Without this assertion a "fix" could default everything to incomplete and re-resolve
       every address twice on every run.
    4. Only a real [bool] counts as complete. This one is narrower than it first looks, and the
       measurement matters more than the intuition. `-eq $true` does NOT mean "is truthy": PowerShell
       converts the RIGHT operand to the LEFT operand's type, so 'N/A' -eq $true compares 'N/A' with
       the string 'True' and is False. Measured, with the strict test replaced by a bare -eq $true,
       exactly two of the nine unreadable forms leak through as "complete": the STRING 'True' and the
       INTEGER 1. Both are real: a record read back through -AsJson carries booleans as the strings
       'True'/'False', and 1 is not a measurement of anything. The remaining forms are pinned anyway
       because they cost nothing to pin and they document the contract - a value that is not a
       boolean was not measured. Incomplete is the safe direction: it costs a DNS lookup, where the
       wrong direction costs a domain controller.
    5. Address union and de-duplication still work, so the fix cannot pass by disabling the merge.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# A discovery record. -Complete is only added when the caller supplies it, so the "property absent"
# case is a genuinely different object shape and not a $null-valued property.
function New-Src {
    param($Name, $IP = $null, $Addresses = @(), $Complete)
    $o = [ordered]@{ Name = $Name; IP = $IP; Addresses = @($Addresses) }
    if ($PSBoundParameters.ContainsKey('Complete')) { $o['AddressResolutionComplete'] = $Complete }
    [PSCustomObject] $o
}
function Merge-One {
    param([object[]] $Server, [string] $Domain = 'contoso.com')
    # Returned with the unary comma. A function returning a one-element array has it UNROLLED to a
    # scalar on the way out, so $r.Count was empty and every count assertion below failed while the
    # merge itself was perfectly correct - the wrong SHAPE in the harness, not a defect in the code.
    $out = @(Merge-mdiDomainControllerEndpoint -Server $Server -Domain $Domain)
    , $out
}

'1. An explicit incomplete resolution survives the merge'
$r = Merge-One @( (New-Src -Name 'dc2.contoso.com' -Complete $false) )
Assert-That 'one record in, one out' ($r.Count -eq 1) "got $($r.Count)"
Assert-That 'Complete=$false is NOT upgraded to $true' `
    ($r[0].AddressResolutionComplete -eq $false) "got [$($r[0].AddressResolutionComplete)]"

$r = Merge-One @( (New-Src -Name 'dc4.contoso.com' -IP '127.0.0.1' -Addresses @('169.254.1.1', '0.0.0.0') -Complete $false) )
Assert-That 'unusable addresses do not make a record complete' `
    ($r[0].AddressResolutionComplete -eq $false) "got [$($r[0].AddressResolutionComplete)]"
Assert-That 'and those addresses are still discarded as unusable' `
    (@($r[0].Addresses).Count -eq 0) "got [$(@($r[0].Addresses) -join ',')]"

'2. The carry is pessimistic, in both orders'
$r = Merge-One @(
    (New-Src -Name 'dc5.contoso.com' -IP '10.0.0.7' -Addresses @('10.0.0.7') -Complete $true),
    (New-Src -Name 'dc5.contoso.com' -Complete $false)
)
Assert-That 'complete then incomplete collapses to ONE host' ($r.Count -eq 1) "got $($r.Count)"
Assert-That 'complete then incomplete => incomplete' `
    ($r[0].AddressResolutionComplete -eq $false) "got [$($r[0].AddressResolutionComplete)]"
Assert-That 'the address measured by the complete copy is still kept' `
    ((@($r[0].Addresses) -join ',') -eq '10.0.0.7') "got [$(@($r[0].Addresses) -join ',')]"

$r = Merge-One @(
    (New-Src -Name 'dc5.contoso.com' -Complete $false),
    (New-Src -Name 'dc5.contoso.com' -IP '10.0.0.7' -Addresses @('10.0.0.7') -Complete $true)
)
Assert-That 'incomplete then complete => incomplete (last source must not win)' `
    ($r[0].AddressResolutionComplete -eq $false) "got [$($r[0].AddressResolutionComplete)]"

$r = Merge-One @(
    (New-Src -Name 'dc9.contoso.com' -IP '10.0.0.9' -Addresses @('10.0.0.9') -Complete $true),
    (New-Src -Name 'dc9.contoso.com' -IP '10.0.0.10' -Addresses @('10.0.0.10') -Complete $true)
)
Assert-That 'two complete copies stay complete' `
    ($r[0].AddressResolutionComplete -eq $true) "got [$($r[0].AddressResolutionComplete)]"

'3. A record that never carried the property is still complete (both live producers)'
$r = Merge-One @( (New-Src -Name 'dc3.contoso.com' -IP '10.0.0.3' -Addresses @('10.0.0.3')) )
Assert-That 'property absent => complete' `
    ($r[0].AddressResolutionComplete -eq $true) "got [$($r[0].AddressResolutionComplete)]"
$r = Merge-One @( (New-Src -Name 'dc3.contoso.com') )
Assert-That 'property absent and no addresses => still complete' `
    ($r[0].AddressResolutionComplete -eq $true) "got [$($r[0].AddressResolutionComplete)]"

'4. Only a real boolean counts as complete - no truthy coercion'
foreach ($bad in @('N/A', 'no', 'yes', 'True', '', '   ', 0, 1, $null)) {
    $label = if ($null -eq $bad) { '<null>' } else { "'$bad'" }
    $r = Merge-One @( (New-Src -Name 'dc8.contoso.com' -IP '10.0.0.8' -Addresses @('10.0.0.8') -Complete $bad) )
    Assert-That "AddressResolutionComplete=$label is not 'complete'" `
        ($r[0].AddressResolutionComplete -eq $false) "got [$($r[0].AddressResolutionComplete)]"
}
$r = Merge-One @( (New-Src -Name 'dc8.contoso.com' -IP '10.0.0.8' -Addresses @('10.0.0.8') -Complete $true) )
Assert-That 'a real $true still reads as complete' `
    ($r[0].AddressResolutionComplete -eq $true) "got [$($r[0].AddressResolutionComplete)]"

'5. The merge itself still merges (the fix cannot pass by breaking it)'
$r = Merge-One @(
    (New-Src -Name 'DC1.contoso.com'  -IP '10.0.0.1' -Addresses @('10.0.0.1')),
    (New-Src -Name 'dc1.contoso.com.' -IP '10.0.0.9' -Addresses @('10.0.0.9')),
    (New-Src -Name ' DC1 '            -IP '10.0.0.5' -Addresses @('10.0.0.5'))
)
Assert-That 'three spellings of one host merge to one entry' ($r.Count -eq 1) "got $($r.Count)"
Assert-That 'the merged name is the canonical FQDN' `
    ($r[0].Name -eq 'dc1.contoso.com') "got [$($r[0].Name)]"
Assert-That 'every address is kept, sorted and de-duplicated' `
    ((@($r[0].Addresses) -join ',') -eq '10.0.0.1,10.0.0.5,10.0.0.9') "got [$(@($r[0].Addresses) -join ',')]"
Assert-That 'IP is the first sorted address' ($r[0].IP -eq '10.0.0.1') "got [$($r[0].IP)]"

$r = Merge-One @()
Assert-That 'an empty collection merges to nothing' ($r.Count -eq 0) "got $($r.Count)"

''
"PASS: $script:pass  FAIL: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
