<#
    THE DEFECT THIS TEST PINS

    A domain controller that carried a usable address vanished from the estate entirely - it was
    neither probed nor reported as unreachable.

    Main builds $dcInventory once and hands it, one line apart, to two readers whose answers are
    COMPLEMENTS: Resolve-mdiLdapTarget says which controllers will be probed, and
    Get-mdiAddresslessDomainController says which have no usable address. A controller that is
    probed is not addressless, and one that is addressless cannot be probed.

    The two did not ask the same question. Resolve-mdiLdapTarget filtered on the row's .IP alone:

        Where-Object { Test-mdiUsableComputerAddress -Value $_.IP }

    while Get-mdiAddresslessDomainController asks it of @($_.Addresses) + @($_.IP). So a row whose
    .IP was unusable but which carried a usable address in .Addresses fell between them - excluded
    from the probe targets for having no usable IP, and excluded from the addressless list because
    it did, in fact, have a usable address. Measured on the shipped functions, one row
    Name=dcfab01.fabrikam.local IP=127.0.0.1 Addresses=@('127.0.0.1','10.10.1.50'):

        Resolve-mdiLdapTarget                 0 targets
        Get-mdiAddresslessDomainController    0 addressless

    The controller appeared in NEITHER list. That is strictly worse than the two disagreements this
    file has already fixed between these same readers, both of which put a row in BOTH lists: a row
    in neither produces NO RECORD AT ALL, and a fact with no record cannot be counted as missing by
    anything downstream - not by the statistics, not by the issue list, not by the verdict. It is the
    outcome Get-mdiDomainControllerInventory names as "the most damaging outcome this tool has,
    because the report still reads as a complete scan of the estate".

    THE FIX admits a row on ANY usable address it carries and PROJECTS it onto that address, so the
    two readers now agree on what "has a usable address" means. The projection cannot change a
    shipped run: rows are de-duplicated by (identity, address) at the bottom of the function, which
    is the same pair Get-mdiDomainControllerInventory already emits one row for - which is why the
    unchanged-estate cases below are asserted alongside the defect case.

    SCOPE OF THE CLAIM, stated no more strongly than it was measured. Today's producer emits one row
    per usable address and assigns that address to .IP, so this was not a live false green in the
    shipped pipeline. It is a disagreement between two readers of one inventory, reachable through a
    supplied inventory, an -AsJson round trip, another tool or a hand-edited report - the same
    arrival vector every other guard in this function names.
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
function Row {
    param($Name, $Domain, $IP, $Addresses)
    [PSCustomObject]@{ Name = $Name; Domain = $Domain; IP = $IP; Addresses = $Addresses }
}
function TargetNames { param($T) @($T | ForEach-Object { '{0}@{1}' -f $_.Name, $_.IP }) }

Write-Host "`nA row whose .IP is unusable but which carries a usable address is not lost"
$row = Row 'dcfab01.fabrikam.local' 'fabrikam.local' '127.0.0.1' @('127.0.0.1', '10.10.1.50')
$targets = @(Resolve-mdiLdapTarget -DomainControllers @($row) -MaxPerDomain 0)
$addressless = @(Get-mdiAddresslessDomainController -Inventory @($row))
Assert-True 'the controller is not in NEITHER list' (@($targets).Count -gt 0 -or @($addressless).Count -gt 0)
Assert-True 'it is probed' (@($targets).Count -eq 1) ("got $(@($targets).Count)")
Assert-True 'it is probed on the USABLE address, not the loopback one' (@($targets)[0].IP -eq '10.10.1.50') ("got '$(@($targets)[0].IP)'")
Assert-True 'it is not also declared addressless' (@($addressless).Count -eq 0) ("got $(@($addressless).Count)")

Write-Host "`nThe same row shaped as a dictionary behaves identically"
$ht = @{ Name = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; IP = '127.0.0.1'; Addresses = @('127.0.0.1', '10.10.1.50') }
$htTargets = @(Resolve-mdiLdapTarget -DomainControllers @($ht) -MaxPerDomain 0)
Assert-True 'a hashtable row is probed too' (@($htTargets).Count -eq 1) ("got $(@($htTargets).Count)")
Assert-True 'and on the usable address' (@($htTargets).Count -eq 1 -and @($htTargets)[0].IP -eq '10.10.1.50')

Write-Host "`nA row with NO usable address anywhere is still addressless and still not probed"
$dead = Row 'x.fabrikam.local' 'fabrikam.local' '127.0.0.1' @('127.0.0.1', '0.0.0.0', '169.254.10.5')
Assert-True 'not probed' (@(Resolve-mdiLdapTarget -DomainControllers @($dead) -MaxPerDomain 0).Count -eq 0)
Assert-True 'declared addressless' (@(Get-mdiAddresslessDomainController -Inventory @($dead)).Count -eq 1)

Write-Host "`nThe two readers are complements on a mixed cross-forest estate"
$estate = @(
    (Row 'dc2022.mdilab.local' 'mdilab.local' '10.10.1.62' @('10.10.1.62'))
    (Row 'dcfab01.fabrikam.local' 'fabrikam.local' '127.0.0.1' @('127.0.0.1', '10.10.1.50'))
    (Row 'dead.fabrikam.local' 'fabrikam.local' '0.0.0.0' @('0.0.0.0'))
)
$t = @(Resolve-mdiLdapTarget -DomainControllers $estate -MaxPerDomain 0)
$a = @(Get-mdiAddresslessDomainController -Inventory $estate)
$probedNames = @($t | ForEach-Object { ConvertTo-mdiCanonicalComputerName -Value $_.Name -Domain ([string] $_.Domain) } | Select-Object -Unique)
Assert-True 'the reachable mdilab controller is probed' ($probedNames -contains 'dc2022.mdilab.local')
Assert-True 'the recoverable fabrikam controller is probed' ($probedNames -contains 'dcfab01.fabrikam.local')
Assert-True 'the genuinely dead one is addressless' ($a -contains 'dead.fabrikam.local')
Assert-True 'no host is in BOTH lists' (@($probedNames | Where-Object { $a -contains $_ }).Count -eq 0)
Assert-True 'every row is accounted for in exactly one list' ((@($probedNames).Count + @($a).Count) -eq 3) ("got $(@($probedNames).Count)+$(@($a).Count)")

Write-Host "`nCONTROL - an unchanged shipped-shape estate is unaffected by the projection"
$shipped = @(
    (Row 'dc2022.mdilab.local' 'mdilab.local' '10.10.1.62' @('10.10.1.62'))
    (Row 'dc2016.mdilab.local' 'mdilab.local' '10.10.1.10' @('10.10.1.10'))
    (Row 'dcfab01.fabrikam.local' 'fabrikam.local' '10.10.1.50' @('10.10.1.50'))
)
Assert-True 'MaxPerDomain 0 probes all three' (@(Resolve-mdiLdapTarget -DomainControllers $shipped -MaxPerDomain 0).Count -eq 3)
Assert-True 'MaxPerDomain 1 probes one per domain' (@(Resolve-mdiLdapTarget -DomainControllers $shipped -MaxPerDomain 1).Count -eq 2)
Assert-True 'MaxPerDomain 2 probes both mdilab plus fabrikam' (@(Resolve-mdiLdapTarget -DomainControllers $shipped -MaxPerDomain 2).Count -eq 3)
Assert-True 'none of them is addressless' (@(Get-mdiAddresslessDomainController -Inventory $shipped).Count -eq 0)

Write-Host "`nCONTROL - a multi-homed controller emitted as one row per address still yields both NICs"
$mh = @(
    (Row 'dc.mdilab.local' 'mdilab.local' '10.10.1.10' @('10.10.1.10', '10.10.1.11'))
    (Row 'dc.mdilab.local' 'mdilab.local' '10.10.1.11' @('10.10.1.10', '10.10.1.11'))
)
$mhT = @(Resolve-mdiLdapTarget -DomainControllers $mh -MaxPerDomain 0)
Assert-True 'both NICs are probed, and only once each' (@($mhT).Count -eq 2) ("got $(@($mhT).Count): $((TargetNames $mhT) -join ', ')")

Write-Host "`nCONTROL - the projection does not invent a target for an empty estate"
Assert-True 'empty inventory yields no targets' (@(Resolve-mdiLdapTarget -DomainControllers @() -MaxPerDomain 0).Count -eq 0)
# A $null ELEMENT never reaches the projection: -DomainControllers is a mandatory [object[]], and
# PowerShell refuses a null element at binding time with
# ParameterArgumentValidationErrorNullNotAllowed. Asserted as a refusal rather than as a survivable
# input, because an earlier draft of this test asserted the opposite and was wrong.
$nullElementRefused = $false
try { [void] @(Resolve-mdiLdapTarget -DomainControllers @($null) -MaxPerDomain 0) }
catch { $nullElementRefused = $true }
Assert-True 'a $null element is refused at binding, not silently probed' $nullElementRefused

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
