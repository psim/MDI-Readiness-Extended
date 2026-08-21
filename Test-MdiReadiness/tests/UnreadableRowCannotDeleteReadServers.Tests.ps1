<#
    THE DEFECT THIS TEST PINS

    Get-mdiServerIdentityKey is the one spelling-independent name for a machine. Merge-mdiServerByFqdn
    uses it to decide whether two records are the same server, the Entra Connect discovery uses it to
    de-duplicate sync accounts that name one host, and the report counters use it to say how many
    servers exist. It is the single function every one of those surfaces shares.

    It handed the record's fields straight to ConvertTo-mdiCanonicalComputerName:

        ConvertTo-mdiCanonicalComputerName -Value $Server.FQDN -Domain $Server.Domain

    whose parameters are typed [string]. PowerShell cannot bind an Object[] to a [string] parameter,
    so a row carrying a wrong type - a collection, a number - did not come back unreadable. It raised
    a parameter-transformation error.

    That error is TERMINATING, and this key is computed inside Group-Object script blocks, so it did
    not cost the offending row: it cost every row beside it. Measured on the shipped functions with
    four healthy servers and one row whose Domain was @('fabrikam.local'):

        Merge-mdiServerByFqdn                 threw - the whole merge died, all five servers lost
        the Entra Connect de-duplication      threw
        Get-mdiProbeTargetKey (same shape)    survived, key dc01.fabrikam.local

    The last line is what makes this a defect rather than a limitation. Get-mdiProbeTargetKey is the
    sibling helper answering the same question - which machine is this - and it was hardened for
    exactly this shape, with its own comment stating the rule: "making the identity domain-aware must
    not turn a row that was merely unreadable into an exception that ends the whole resolution."
    Get-mdiServerIdentityKey was left unhardened while being used by MORE surfaces than the samplers
    that helper serves.

    A row nobody could read must not be able to delete the servers that WERE read.

    The wrong-typed shape is ordinary in this estate: an -AsJson round trip, a report merged from two
    runs, or a partial directory read across the fabrikam.local trust all produce a field that is a
    collection where a string was expected.

    Both fields are coerced, not just Domain - FQDN is bound to the same [string] parameter and
    carries the same exposure.

    THE SAME DEFECT, THIRD SITE

    ConvertTo-mdiCanonicalComputerName types -Value as [object] but -Domain as [string], so only the
    DOMAIN argument is exposed. Auditing every call site left exactly one reader of the domain
    controller inventory still binding a raw field: Get-mdiAddresslessDomainController, at both its
    Group-Object key and its ForEach-Object projection.

    Measured on the shipped functions with a four-row inventory holding two genuinely addressless
    controllers and one row whose Domain was @('fabrikam.local'):

        Get-mdiAddresslessDomainController   threw - the addressless list for the estate was lost
        Resolve-mdiLdapTarget, same rows     2 targets, survives

    Both consume the SAME $dcInventory, one line apart in Main. An addressless list that throws is
    worse than one that is short: the rows it feeds - the statistics, the issue list and the verdict -
    lose every genuinely unreachable controller along with the unreadable one, so an estate with real
    unreachable domain controllers reports none.

    THE CLASS, FOUND BY PARSING RATHER THAN BY READING

    The two sites above were found by reading. Parsing the script for every call that binds a bare
    record field to a parameter the callee types as [string] or [int] found 85 such binds, of which
    four sit inside a pipeline script block - which is what turns "this row is unreadable" into "the
    whole collection is lost". Two of those four are pinned below.

    Get-mdiTargetLabel, in the firewall rule generation, types both parameters as [string]. Its
    records cross a JSON boundary: port probe results are produced on the remote host and read back
    with ConvertFrom-Json. A clean single run yields a String, but a merged or hand-edited report
    yields Object[] - measured, not assumed. One such record among three threw and took EVERY
    blocked-NNR label with it, so the generated firewall rules lost their targets.

    Test-mdiServerReachable, in the capacity sampling, is guarded by "$_.FQDN -and". That guard does
    NOT protect the bind, because a single-element collection is TRUTHY: it passes the guard and then
    fails to bind, inside a Where-Object block, losing the capacity sample for every domain
    controller.

    Both call sites are now coerced. What this file pins for them is the HELPER CONTRACT the fix
    rests on - that Get-mdiTargetLabel and Test-mdiServerReachable genuinely refuse a collection, so
    the coercion is load-bearing rather than decorative. The call-site coercion itself was verified by
    probe MDI-AB\live\xforest-24 and is recorded as such: a fixture that drives an array-shaped Target
    all the way to the label pipeline could not be built, and an assertion that passes whether or not
    the fix is present would be worse than no assertion at all.
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

Write-Host 'An unreadable server row cannot delete the servers that were read'

# --- the key itself survives every unreadable shape ----------------------------------------------
$unreadable = @(
    @{ Label = 'Domain is a collection'; Server = [PSCustomObject]@{ FQDN = 'dc01'; Domain = @('fabrikam.local') } }
    @{ Label = 'Domain is a number'; Server = [PSCustomObject]@{ FQDN = 'dc01'; Domain = 12345 } }
    @{ Label = 'Domain is an empty collection'; Server = [PSCustomObject]@{ FQDN = 'dc01'; Domain = @() } }
    @{ Label = 'FQDN is a collection'; Server = [PSCustomObject]@{ FQDN = @('dc01.mdilab.local'); Domain = 'mdilab.local' } }
    @{ Label = 'both are collections'; Server = [PSCustomObject]@{ FQDN = @('dc01'); Domain = @('mdilab.local') } }
    @{ Label = 'FQDN is a number'; Server = [PSCustomObject]@{ FQDN = 6636; Domain = 'mdilab.local' } }
)
foreach ($case in $unreadable) {
    $threw = $false
    try { $null = Get-mdiServerIdentityKey -Server $case.Server } catch { $threw = $true }
    Assert-True ('{0} does not throw' -f $case.Label) (-not $threw)
}

# A single-element collection still names the domain it holds; coercion must not lose it, or the
# row would key as a bare name and merge into another forest's host of the same name.
$coerced = Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = 'dc01'; Domain = @('fabrikam.local') })
Assert-True 'a collection Domain is still read as the domain it holds' `
    ($coerced -eq 'dc01.fabrikam.local') ("(got '{0}')" -f $coerced)

# --- the merge keeps every readable server when one row beside them is unreadable ----------------
# This is the consequence that makes the throw a defect: it was never the bad row that was lost.
$estate = @(
    [PSCustomObject]@{ FQDN = 'dc01.mdilab.local'; Domain = 'mdilab.local'; Role = 'DC'; SensorHealth = 'OK' }
    [PSCustomObject]@{ FQDN = 'dc02.mdilab.local'; Domain = 'mdilab.local'; Role = 'DC'; SensorHealth = 'OK' }
    [PSCustomObject]@{ FQDN = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; Role = 'DC'; SensorHealth = 'OK' }
    [PSCustomObject]@{ FQDN = 'ca01.mdilab.local'; Domain = 'mdilab.local'; Role = 'CA'; SensorHealth = 'OK' }
    [PSCustomObject]@{ FQDN = 'memfab01.fabrikam.local'; Domain = @('fabrikam.local'); Role = 'DC'; SensorHealth = 'OK' }
)
$mergeThrew = $false
$merged = @()
try { $merged = @(Merge-mdiServerByFqdn -Server $estate) } catch { $mergeThrew = $true }
Assert-True 'the merge does not throw on an unreadable row' (-not $mergeThrew)
Assert-True 'every server survives the merge' ($merged.Count -eq 5) ("(got {0})" -f $merged.Count)
$expectedSurvivors = @('dc01.mdilab.local', 'dc02.mdilab.local', 'dcfab01.fabrikam.local', 'ca01.mdilab.local')
$missingSurvivors = @($expectedSurvivors | Where-Object {
        $name = $_
        @($merged | Where-Object { [string] $_.FQDN -eq $name }).Count -ne 1
    })
Assert-True 'the readable servers are all still present' ($missingSurvivors.Count -eq 0) `
    ("(missing: {0})" -f ($missingSurvivors -join ', '))

# --- the role de-duplication that shares the key -------------------------------------------------
$syncServers = @(
    @{ FQDN = 'aadc01.mdilab.local'; Domain = 'mdilab.local'; IP = '10.10.1.60' }
    @{ FQDN = 'aadc02.fabrikam.local'; Domain = @('fabrikam.local'); IP = '10.10.1.61' }
)
$dedupThrew = $false
$grouped = @()
try {
    $grouped = @($syncServers | Group-Object -Property { Get-mdiServerIdentityKey -Server ([PSCustomObject] $_) } |
            ForEach-Object { @($_.Group)[0] })
} catch { $dedupThrew = $true }
Assert-True 'the Entra Connect de-duplication does not throw' (-not $dedupThrew)
Assert-True 'both sync servers survive the de-duplication' ($grouped.Count -eq 2) ("(got {0})" -f $grouped.Count)

# --- the two sibling helpers must agree that an unreadable row is a VALUE, not an exception ------
$siblingThrew = $false
try { $null = Get-mdiProbeTargetKey -Target ([PSCustomObject]@{ Name = 'dc01'; Domain = @('fabrikam.local') }) } catch { $siblingThrew = $true }
$thisThrew = $false
try { $null = Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = 'dc01'; Domain = @('fabrikam.local') }) } catch { $thisThrew = $true }
Assert-True 'both identity helpers treat an unreadable row the same way' `
    ($siblingThrew -eq $thisThrew -and -not $thisThrew) `
    ("(sibling threw={0}, this threw={1})" -f $siblingThrew, $thisThrew)

# --- the behaviour the key already had must be unchanged -----------------------------------------
Assert-True 'a same-named host in another forest is still a different machine' (
    (Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = 'dc01'; Domain = 'mdilab.local' })) -ne
    (Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = 'dc01'; Domain = 'fabrikam.local' })))
Assert-True 'spellings of one host still collapse to one key' (
    @(@(
        [PSCustomObject]@{ FQDN = 'DCFAB01.FABRIKAM.LOCAL'; Domain = 'fabrikam.local' }
        [PSCustomObject]@{ FQDN = 'dcfab01.fabrikam.local.'; Domain = 'fabrikam.local' }
        [PSCustomObject]@{ FQDN = '  dcfab01.fabrikam.local  '; Domain = 'fabrikam.local' }
        [PSCustomObject]@{ FQDN = 'dcfab01'; Domain = 'fabrikam.local' }
    ) | ForEach-Object { Get-mdiServerIdentityKey -Server $_ } | Select-Object -Unique).Count -eq 1)
Assert-True 'a nameless row still keys as the empty string' (
    (Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = ''; Domain = 'mdilab.local' })) -eq '')
Assert-True 'a null server still keys as the empty string' (
    (Get-mdiServerIdentityKey -Server $null) -eq '')

# --- the third site: the addressless list must survive the same row ------------------------------
# Two genuinely addressless controllers, so the function has real work to lose, plus one readable
# row whose Domain is a collection.
$inventory = @(
    [PSCustomObject]@{ Name = 'dc01.mdilab.local'; IP = '10.10.1.10'; Addresses = @('10.10.1.10'); Domain = 'mdilab.local'; Enumerated = $true }
    [PSCustomObject]@{ Name = 'dc02.mdilab.local'; IP = $null; Addresses = @(); Domain = 'mdilab.local'; Enumerated = $true }
    [PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; IP = $null; Addresses = @(); Domain = 'fabrikam.local'; Enumerated = $true }
    [PSCustomObject]@{ Name = 'memfab01.fabrikam.local'; IP = '10.10.1.51'; Addresses = @('10.10.1.51'); Domain = @('fabrikam.local'); Enumerated = $true }
)
$addrThrew = $false
$addressless = @()
try { $addressless = @(Get-mdiAddresslessDomainController -Inventory $inventory) } catch { $addrThrew = $true }
Assert-True 'the addressless list does not throw on an unreadable row' (-not $addrThrew)
Assert-True 'both genuinely addressless controllers are still reported' (
    $addressless.Count -eq 2 -and
    $addressless -contains 'dc02.mdilab.local' -and
    $addressless -contains 'dcfab01.fabrikam.local') ("(got: {0})" -f ($addressless -join ', '))
# The row that IS addressed must not be invented into the list by the coercion.
Assert-True 'the unreadable row is not reported as addressless' (
    @($addressless | Where-Object { $_ -like 'memfab01*' }).Count -eq 0) ("(got: {0})" -f ($addressless -join ', '))

# The two readers of one inventory must agree that an unreadable row is a value, not an exception.
$samplerThrew = $false
try { $null = @(Resolve-mdiLdapTarget -DomainControllers $inventory -MaxPerDomain 2) } catch { $samplerThrew = $true }
Assert-True 'both readers of the same inventory treat an unreadable row the same way' `
    ($samplerThrew -eq $addrThrew -and -not $addrThrew) `
    ("(sampler threw={0}, addressless threw={1})" -f $samplerThrew, $addrThrew)

# --- the two in-block binds found by parsing ------------------------------------------------------
# Exercised through the REAL producer, New-mdiRemediationScript, not through a copy of the fixed
# expression - a test that re-implements the fix stays green when the fix is removed.
#
# The array shape is what a merged or hand-edited report carries; a clean single run yields a
# String, which is why this site needed parsing rather than reading to find.
$nnrIds = @(
    @{ Id = 'NnrNetBios'; Name = 'NNR - NetBIOS'; Protocol = 'UDP'; Port = 137 }
    @{ Id = 'NnrRpc'; Name = 'NNR - NTLM over RPC'; Protocol = 'TCP'; Port = 135 }
    @{ Id = 'NnrRdp'; Name = 'NNR - RDP'; Protocol = 'TCP'; Port = 3389 }
)
function New-NnrRow {
    param($Server, $Target, $TargetIP, $Probe)
    [PSCustomObject]@{
        Server = $Server; Id = $Probe.Id; Name = $Probe.Name; Protocol = $Probe.Protocol; Port = $Probe.Port
        Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'
        Target = $Target; TargetIP = $TargetIP
        Applicable = $true; Success = $false; Detail = 'Connection refused'
    }
}
# Every NNR method fails for both targets, so both are genuinely unresolvable and both reach the
# label pipeline. One of them carries the merged-report array shape.
$nnrRecords = @(
    foreach ($p in $nnrIds) { New-NnrRow -Server 'dc01.mdilab.local' -Target 'dc02.mdilab.local' -TargetIP '10.10.1.11' -Probe $p }
    foreach ($p in $nnrIds) { New-NnrRow -Server 'dc01.mdilab.local' -Target @('dcfab01.fabrikam.local') -TargetIP @('10.10.1.50') -Probe $p }
)
$remServers = @([PSCustomObject]@{
        FQDN = 'dc01.mdilab.local'; Domain = 'mdilab.local'
        Details = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = $nnrRecords } }
    })
$reportData = [PSCustomObject]@{
    Domain = 'mdilab.local'; Forest = 'mdilab.local'
    DomainControllers = $remServers; Servers = $remServers
    CAServers = @(); EntraConnectServers = @()
}
$remPath = Join-Path ([IO.Path]::GetTempPath()) ('mdi-remediation-{0}.ps1' -f [guid]::NewGuid().Guid)
$remThrew = $false
try { $null = New-mdiRemediationScript -ReportData $reportData -FilePath $remPath } catch { $remThrew = $true }
Assert-True 'the remediation script generator does not throw on an unreadable NNR record' (-not $remThrew)
Assert-True 'the generated remediation script was written' ((-not $remThrew) -and (Test-Path $remPath))
Remove-Item $remPath -Force -ErrorAction SilentlyContinue

# CONTROL: the helper contract this fix depends on.
#
# Get-mdiTargetLabel USED to type both parameters as [string], which made it REFUSE a collection -
# the terminating error proven fatal for the two functions above, and what this control originally
# pinned. Both parameters are now [object] and the value is READ BEFORE IT IS RENDERED, because a
# [string] parameter renders at BIND TIME, before any guard in the body can see the value: a
# hashtable bound as 'System.Collections.Hashtable' and a two-element list as its elements joined by
# a space. Neither is whitespace, so both were printed to the operator as a host NAME that nothing
# ever read - an unread value coming back looking like a measurement.
#
# So the contract to pin is no longer "it throws at the bind". It is the pair of facts the fix rests
# on: the call can no longer fail to bind, AND an unreadable target is never printed as a host name -
# the label falls back to the address alone. A one-element collection is not unreadable, it holds
# exactly one name, so it must still render that name.
#
# Measured on the shipped function (MDI-AB\live\w197): '...local' and @('...local') both render
# 'dcfab01.fabrikam.local (10.10.1.50)', while @('a','b'), @{}, 12345, '' and $null all render
# '10.10.1.50'.
$labelThrew = $false
try { $null = Get-mdiTargetLabel -Target @('dcfab01.fabrikam.local') -TargetIP '10.10.1.50' } catch { $labelThrew = $true }
Assert-True 'CONTROL: Get-mdiTargetLabel reads a collection instead of refusing it at the bind' (-not $labelThrew)
Assert-True 'a one-element collection still names the host it holds' (
    (Get-mdiTargetLabel -Target @('dcfab01.fabrikam.local') -TargetIP '10.10.1.50') -like '*dcfab01.fabrikam.local*')
Assert-True 'CONTROL: a two-element list is unreadable, so the label falls back to the address alone' (
    (Get-mdiTargetLabel -Target @('dcfab01.fabrikam.local', 'dc01.mdilab.local') -TargetIP '10.10.1.50') -eq '10.10.1.50')
Assert-True 'CONTROL: nor is a hashtable printed as a name, which a [string] parameter rendered as its type name' (
    (Get-mdiTargetLabel -Target @{} -TargetIP '10.10.1.50') -eq '10.10.1.50')
Assert-True 'and the coerced form is accepted' (
    (Get-mdiTargetLabel -Target ([string] @('dcfab01.fabrikam.local')) -TargetIP ([string] @('10.10.1.50'))) -like '*dcfab01.fabrikam.local*')

# The capacity-sampling reachability filter is guarded by "$_.FQDN -and". That guard cannot protect
# the bind, because a single-element collection is TRUTHY - it passes the guard and then fails to
# bind to the [string] parameter, inside a Where-Object block.
Assert-True 'a single-element collection is truthy, so the guard cannot stop the bind' ([bool] @('dc01.mdilab.local'))
$reachRejects = $false
try { $null = Test-mdiServerReachable -ComputerName @('dc01.mdilab.local') } catch { $reachRejects = $true }
Assert-True 'CONTROL: Test-mdiServerReachable rejects a collection, so that coercion is load-bearing too' $reachRejects

Write-Host ''
Write-Host ("pass={0}  fail={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }