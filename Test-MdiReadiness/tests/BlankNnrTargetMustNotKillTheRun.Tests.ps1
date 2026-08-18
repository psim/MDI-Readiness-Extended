<#
    THE DEFECT THIS TEST PINS

    ONE BLANK ENTRY IN -NnrTargetComputer KILLED THE ENTIRE RUN.

    Resolve-mdiNnrTarget decides whether to probe the hosts the operator named or to fall back to a
    sample of domain controllers. It asked:

        $targets = if ($NnrTargetComputer) { ...the operator's list... } else { ...the DC fallback... }

    -NnrTargetComputer is declared [string[]]. `if (<array>)` is not the question "did the caller name
    a host": for a MULTI-element array PowerShell tests the array itself, which is true whatever the
    elements are. So a list carrying no usable name took the trust-the-caller branch.

    That alone would be the familiar silent-skip defect. Here it was worse, because a blank name
    cannot merely fail to resolve - it cannot be PASSED. Two lines into that branch:

        $addresses = @(Get-mdiComputerAddress -ComputerName $name -KnownAddress $knownIp)

    and Get-mdiComputerAddress types -ComputerName as a MANDATORY [string]. A mandatory string
    parameter REJECTS the empty string at BIND time:

        Cannot bind argument to parameter 'ComputerName' because it is an empty string.

    That is a TERMINATING error, and it is raised inside the ForEach-Object whose output becomes
    $targets - so, exactly like the Group-Object throw already pinned for
    Get-mdiAddresslessDomainController, it does not cost the offending entry: it costs every host
    beside it.

    Measured on the shipped function, five domain-controller rows across mdilab.local,
    emea.mdilab.local, apac.mdilab.local and fabrikam.local available as the fallback:

        -NnrTargetComputer $null                         5 targets  (fallback ran)
        -NnrTargetComputer @('')                         5 targets  (fallback ran)
        -NnrTargetComputer @('','')                      THREW
        -NnrTargetComputer @($null,$null)                THREW
        -NnrTargetComputer @(' ')                        THREW
        -NnrTargetComputer @(' ',' ')                    THREW
        -NnrTargetComputer @('','dc2022.mdilab.local')   THREW

    The last line is the one that matters. The operator named a REAL domain controller and put one
    blank beside it - a trailing comma, an empty line in a file read with Get-Content, an empty cell
    in a CSV - and the run died. Not a degraded scan, and not a scan that reported less: no scan.
    Main calls Resolve-mdiNnrTarget at the top level and that call is inside NO try block (confirmed
    from the abstract syntax tree, not from indentation), so the exception propagates out of the
    script and no report is written at all.

    @('') is the one blank shape anybody would think to type, and it is the one shape that already
    worked, because a SINGLE-element array is truthy according to its element. That is why this
    survived every earlier probe: the obvious test passes.

    THE FIX

    Two parts, and BOTH are required:

      * the branch asks Test-mdiNoNameSupplied - the same per-element question the three role
        scanners ask of their own [string[]] lists - so a list that names nothing falls back to
        domain-controller discovery instead of "trusting" a list of blanks;

      * the loop runs over the NAMES ONLY, so a blank sitting beside a real name costs nothing.

    Filtering alone would leave a blank-only list taking the caller branch, resolving nothing, and
    skipping the fallback in silence - the clean-looking report of nothing this project keeps
    removing. Get-mdiUnresolvedNnrTarget would not disclose it either: it skips blank requests,
    correctly, because a blank was never a host anyone asked about.

    WHAT MUST NOT REGRESS IN THE OTHER DIRECTION

    A list that DOES name a host must still suppress the domain-controller fallback. If a genuine
    -NnrTargetComputer run quietly reverted to probing domain controllers, the operator would be
    told that name resolution was verified against the workstations they named when it never was.
#>

$ErrorActionPreference = 'Stop'

# SIBLING FIRST, then parent. The suite stages the product script and the tests flat in one folder,
# while the repository keeps the tests in a subfolder - and a stray copy in a PARENT directory must
# never win, or the test silently exercises old code.
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

# Shaped exactly like Get-mdiDomainControllerInventory's output for the lab as it now stands: two
# forests, three domains in the first, every row carrying a usable address and its own domain. The
# fallback must yield one target per row, so "did the fallback run" is a count, not a guess.
$inventory = @(
    [PSCustomObject]@{ Name = 'dc2022.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local'; Addresses = @('10.10.1.10') }
    [PSCustomObject]@{ Name = 'dc2019.mdilab.local'; IP = '10.10.1.11'; Domain = 'mdilab.local'; Addresses = @('10.10.1.11') }
    [PSCustomObject]@{ Name = 'dcemea.emea.mdilab.local'; IP = '10.10.2.10'; Domain = 'emea.mdilab.local'; Addresses = @('10.10.2.10') }
    [PSCustomObject]@{ Name = 'dcapac.apac.mdilab.local'; IP = '10.10.2.11'; Domain = 'apac.mdilab.local'; Addresses = @('10.10.2.11') }
    [PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; IP = '10.10.1.50'; Domain = 'fabrikam.local'; Addresses = @('10.10.1.50') }
)
$fallbackCount = $inventory.Count

# .invalid is reserved by RFC 2606 and can never resolve, so "the caller branch ran and found no
# address" is deterministic on any network, with or without a DNS search suffix.
$unresolvable = 'nnr-target-probe.invalid'

# The parameter typing is reproduced exactly, because the [string[]] coercion is part of the defect:
# asserting against a bare array would test a shape the product never sees.
function Invoke-Resolver {
    param (
        [Parameter(Mandatory = $false)] [string[]] $List = $null,
        [Parameter(Mandatory = $false)] [object[]] $Rows = $null
    )
    @(Resolve-mdiNnrTarget -DomainControllers $Rows -NnrTargetComputer $List -Domain 'fabrikam.local' -MaxTargets 5)
}

Write-Host 'A list that names nothing must fall back to the domain controllers, not throw'

$namesNothing = @(
    @{ L = '$null';            V = $null }
    @{ L = '@()';              V = @() }
    @{ L = "@('')";            V = @('') }
    @{ L = "@('','')";         V = @('', '') }
    @{ L = "@(`$null,`$null)"; V = @($null, $null) }
    @{ L = "@(' ')";           V = @(' ') }
    @{ L = "@(' ',' ')";       V = @(' ', ' ') }
    @{ L = "@('','','')";      V = @('', '', '') }
    @{ L = "@(`"`t`")";        V = @("`t") }
)
foreach ($c in $namesNothing) {
    $threw = $false
    $count = -1
    try {
        $count = (Invoke-Resolver -List $c.V -Rows $inventory).Count
    } catch {
        $threw = $true
    }
    Assert-True ("a blank-only list does not throw: {0}" -f $c.L) (-not $threw) `
        'a mandatory [string] parameter rejects the empty string at bind time, and that error is terminating'
    Assert-True ("a blank-only list falls back to the domain controllers: {0}" -f $c.L) `
        ($count -eq $fallbackCount) `
        ("expected {0} fallback target(s), got {1} - filtering the blanks without fixing the branch gives 0" -f $fallbackCount, $count)
}

Write-Host ''
Write-Host 'A blank BESIDE a real name must cost nothing but itself'

$mixed = @(
    @{ L = "@('',<name>)";         V = @('', $unresolvable) }
    @{ L = "@(<name>,'')";         V = @($unresolvable, '') }
    @{ L = "@(' ',<name>)";        V = @(' ', $unresolvable) }
    @{ L = "@(`$null,<name>)";     V = @($null, $unresolvable) }
    @{ L = "@('',<name>,'')";      V = @('', $unresolvable, '') }
)
foreach ($c in $mixed) {
    $threw = $false
    $count = -1
    try {
        $count = (Invoke-Resolver -List $c.V -Rows $inventory).Count
    } catch {
        $threw = $true
    }
    Assert-True ("a blank beside a real name does not throw: {0}" -f $c.L) (-not $threw) `
        'this is the shape that killed the whole run: the operator named a real host and one blank sat beside it'
    # NOT the fallback count. The operator named a host, so the caller branch must run - a silent
    # revert to probing domain controllers would report name resolution as verified against hosts
    # nobody asked about.
    Assert-True ("a named host still suppresses the fallback: {0}" -f $c.L) `
        ($count -ne $fallbackCount) `
        ("got exactly the {0} fallback target(s), so the operator's list was ignored" -f $fallbackCount)
}

Write-Host ''
Write-Host 'A list that names a host is still trusted'

$threw = $false
$count = -1
try { $count = (Invoke-Resolver -List @($unresolvable) -Rows $inventory).Count } catch { $threw = $true }
Assert-True 'a single named host does not throw' (-not $threw) ''
Assert-True 'a single named host suppresses the domain-controller fallback' `
    ($count -ne $fallbackCount) `
    'the caller named a host, so the fallback must not run'

Write-Host ''
Write-Host 'The root cause is pinned directly'

# This is the fact that makes a blank UNPASSABLE rather than merely unresolvable, and it is what
# turns a skipped entry into a dead run. If Get-mdiComputerAddress is ever relaxed to accept an
# empty name, this assertion fails and the header above needs revisiting - it must not silently
# become "the filter is no longer load bearing".
$bindThrew = $false
try { [void] (Get-mdiComputerAddress -ComputerName '') } catch { $bindThrew = $true }
Assert-True 'Get-mdiComputerAddress rejects an empty name at bind time' $bindThrew `
    'if this no longer throws, the blank filter is still correct but the stated consequence has changed'

# The branch predicate itself, so a "simplification" back to raw truthiness is caught at the source
# and not only through its downstream effect.
Assert-True 'raw array truthiness is NOT the question the branch needs' `
    ([bool] ([string[]] @('', '')) -and (Test-mdiNoNameSupplied -Name ([string[]] @('', '')))) `
    'a multi-element blank array is truthy, yet names nothing - which is exactly why if(<array>) was wrong'

Write-Host ''
Write-Host ("pass={0}  fail={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
