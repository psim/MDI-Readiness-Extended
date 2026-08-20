# =====================================================================================
# THE ADWS FOREST WALK COULD CERTIFY A FOREST BIGGER THAN THE DIRECTORY HOLDS
# =====================================================================================
#
# THE DEFECT THIS PINS, IN PROSE
#
# Get-mdiForestDomain has two transports over the SAME directory: Active Directory Web
# Services, and an LDAP fallback for when ADWS on TCP 9389 does not answer. The
# function's own comments forbid the two disagreeing - "a fallback that accepts what
# the primary rejects reintroduces the failure" (~4237), and "accepting a mixed ADWS
# result as complete let Main discard its blank entries while the report still
# certified that the whole forest had been enumerated" (~4307).
#
# They disagreed anyway, about forest SIZE.
#
# The LDAP walker ends its enumeration (~4245) with
#
#     ... | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
#
# The ADWS branch (~4311-4320) has no such collapse. It emits every row it could name,
# in order, and returns that list verbatim as .Domains (~4347). Worse, it .Trim()s each
# value at ~4319 - so it MANUFACTURES exact duplicates out of entries that differed
# only by surrounding whitespace, and then keeps both copies.
#
# Measured on the shipped function with Get-ADForest stubbed, one directory:
#
#     domain list handed to the walker                    n  Complete  emitted
#     ------------------------------------------------- --- --------- --------------------
#     mdilab / emea / apac            (control)           3   True     all three, once each
#     mdilab / emea / mdilab          (exact duplicate)   3   True     mdilab.local TWICE
#     mdilab / emea / MDILAB.LOCAL    (case variant)      3   True     both spellings
#     mdilab / emea / mdilab.local.   (absolute form)     3   True     both spellings
#     mdilab / emea / '  mdilab.local  '  (whitespace)    3   True     mdilab.local TWICE
#
# The same content through the LDAP sibling's shipped collapse answers 2 for the exact
# duplicate. So on one directory the two transports say 3 and 2, and which answer the
# customer gets is decided by whether ADWS happened to respond - not by anything they
# chose. Complete stays $true throughout, so none of the three disclosure surfaces that
# Complete gates - the unread charge, the "forest domains could not be enumerated"
# issue, and the READY verdict - says anything at all.
#
# WHAT THE DUPLICATE COSTS, MEASURED
#
# Get-mdiDomainControllerInventory types -Domain as [string[]] and iterates it, so a
# domain named twice is enumerated twice. With two real controllers already resolved:
#
#     domain named ONCE  (control)             rows=2  named=2  distinct=2
#     domain named TWICE (the ADWS duplicate)  rows=4  named=4  distinct=2
#
# The estate doubles. Every row is a probe target, a coverage denominator and a
# statistics contributor, and both copies are the same machine - so this is this
# project's own family once more: a domain nobody enumerated separately comes back
# looking like a measurement of forest size.
#
# WHY THE 17 AUGUST TOPOLOGY IS WHERE IT BITES
#
# v1.1.5 shipped against a single forest, where a duplicate cannot change any count. A
# second forest reached across a trust, and a disjoint NetBIOS name (DNS
# fabrikam.local, NetBIOS FABCORP), are precisely the estates where one domain arrives
# under two spellings, and multi-domain forests are the only ones where this branch
# emits more than one row at all.
#
# THE RULE COMPARISON MUST FOLLOW
#
# Get-mdiUnexaminedDomain - THE definition of coverage, shared by the statistics, the
# issue list and the verdict - already settled this question for this codebase at
# ~15136: "Comparison is case-insensitive and ignores a trailing dot, which is what DNS
# itself does." It records that the ORDINAL Select-Object -Unique is what let
# "contoso.com", "CONTOSO.COM" and "contoso.com." survive as three entries for one
# domain. The forest walk must not repeat the mistake its own coverage reader was fixed
# for, and must not swap one transport divergence for another: BOTH transports must
# collapse these spellings the same way.
#
# What this file pins:
#   * the control forest of three genuinely distinct domains is still returned intact,
#     once each, Complete=True - so the dedup did not eat a real domain;
#   * a domain repeated exactly is named ONCE;
#   * a domain repeated in a different CASE is named once;
#   * a domain repeated in absolute (trailing dot) form is named once;
#   * a domain repeated with surrounding whitespace - the duplicate the product's own
#     .Trim() manufactures - is named once;
#   * the surviving spelling still satisfies the forest-root presence check, so
#     Complete stays True and the dedup cannot invent an incompleteness;
#   * the UNREADABLE family is still charged, never certified - the dedup must not
#     become a new way for an unnamed record to disappear quietly.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
Write-Host "PRODUCT: $target"
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:said = New-Object System.Collections.Generic.List[string]
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) [void] $script:said.Add([string] $Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:said.Add([string] $Message) }

$script:pass = 0; $script:fail = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name" }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" }
}

# The ADWS transport is reached by making Get-ADForest answer. Its result carries the forest
# Name and RootDomain (both read at ~4322-4323) and the Domains collection the walk enumerates.
$script:forestDomains = @()
Set-Item -Path function:script:Get-ADForest -Value {
    param($Server, $ErrorAction)
    [PSCustomObject]@{
        Name       = 'mdilab.local'
        RootDomain = 'mdilab.local'
        Domains    = $script:forestDomains
    }
}

function Measure-Walk {
    <#  Runs the real Get-mdiForestDomain over one stubbed directory and reports what the
        ADWS branch returned: how many domains, whether it called itself Complete, which
        transport answered, and the spellings themselves. #>
    param([object[]] $Domains)
    $script:forestDomains = $Domains
    $script:said.Clear()
    $r = Get-mdiForestDomain
    [PSCustomObject]@{
        N        = @($r.Domains).Count
        Complete = [bool] $r.Complete
        Method   = [string] $r.Method
        Names    = @($r.Domains)
        Joined   = (@($r.Domains) -join '|')
        Error    = [string] $r.Error
    }
}

# How many entries of the returned list normalise - case-insensitively, trailing dot ignored,
# which is what DNS does and what Get-mdiUnexaminedDomain already settled - onto one name.
function Count-Spelling {
    param([object[]] $Names, [string] $Of)
    $want = $Of.Trim().TrimEnd('.')
    @($Names | Where-Object { ([string] $_).Trim().TrimEnd('.') -eq $want }).Count
}

Write-Host ''
Write-Host 'CONTROL - three genuinely distinct domains must survive intact'
$control = Measure-Walk @('mdilab.local', 'emea.mdilab.local', 'apac.mdilab.local')
Assert-True 'the control forest is answered over ADWS' ($control.Method -eq 'ADWS') "method=$($control.Method)"
Assert-True 'the control forest still returns all three distinct domains' ($control.N -eq 3) "n=$($control.N) [$($control.Joined)]"
Assert-True 'the control forest is Complete' ($control.Complete) "err=$($control.Error)"

Write-Host ''
Write-Host 'THE DEFECT - one domain, five spellings, must never be counted twice'
$cases = @(
    @{ Label = 'repeated exactly'; Third = 'mdilab.local' }
    @{ Label = 'repeated in a different case'; Third = 'MDILAB.LOCAL' }
    @{ Label = 'repeated in absolute form'; Third = 'mdilab.local.' }
    @{ Label = 'repeated with surrounding whitespace'; Third = '  mdilab.local  ' }
)
foreach ($c in $cases) {
    $r = Measure-Walk @('mdilab.local', 'emea.mdilab.local', $c.Third)
    Assert-True ('a domain {0} is named ONCE, not twice' -f $c.Label) `
    ((Count-Spelling -Names $r.Names -Of 'mdilab.local') -eq 1) "n=$($r.N) [$($r.Joined)]"
    Assert-True ('a domain {0} leaves a two-domain forest' -f $c.Label) `
    ($r.N -eq 2) "n=$($r.N) [$($r.Joined)]"
    Assert-True ('a domain {0} does not cost the forest its Complete flag' -f $c.Label) `
    ($r.Complete) "err=$($r.Error)"
    Assert-True ('the other domain survives when one is {0}' -f $c.Label) `
    ((Count-Spelling -Names $r.Names -Of 'emea.mdilab.local') -eq 1) "[$($r.Joined)]"
}

Write-Host ''
Write-Host 'THE UNREADABLE FAMILY - still charged, never quietly dropped'
# A value nobody could name must keep costing the forest its Complete flag. If a dedup ever
# swallowed these instead, an unnamed record would vanish silently - the failure this whole
# project exists to catch - so they are pinned here alongside the collapse.
$unreadable = @(
    @{ Label = '$null'; Value = $null }
    @{ Label = 'an empty string'; Value = '' }
    @{ Label = 'whitespace'; Value = '   ' }
    @{ Label = 'a number'; Value = 12345 }
    @{ Label = 'a hashtable'; Value = @{ DnsRoot = 'fabrikam.local' } }
    @{ Label = 'a boolean'; Value = $true }
)
foreach ($u in $unreadable) {
    $r = Measure-Walk @('mdilab.local', 'emea.mdilab.local', $u.Value)
    Assert-True ('a domain record that is {0} is charged, not certified' -f $u.Label) `
    ((-not $r.Complete) -and $r.N -eq 2) "n=$($r.N) complete=$($r.Complete) [$($r.Joined)]"
}

# A one-element collection is the shape a pipeline really produces, and
# ConvertTo-mdiReadableDomainName's contract is to UNWRAP it rather than refuse it. The dedup
# must not turn that contract into a loss.
$r = Measure-Walk @('mdilab.local', @('emea.mdilab.local'), 'apac.mdilab.local')
Assert-True 'a one-element collection is still unwrapped and kept' `
($r.N -eq 3 -and $r.Complete) "n=$($r.N) complete=$($r.Complete) [$($r.Joined)]"

Write-Host ''
Write-Host ("RESULT  pass={0}  fail={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
