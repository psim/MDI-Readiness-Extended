<#
    A TOTAL DISCOVERY FAILURE MUST NOT REPORT AS FULL DOMAIN COVERAGE.

    Get-mdiUnexaminedDomain is THE definition of "which domains in scope produced no servers", and it
    gates all three of this tool's disclosure surfaces at once, at three separate call sites:

        the statistics    a 'Domain not examined - <name>' row charged as an unread check
        the issue list    a High / Discovery finding
        the verdict       $domainsExamined = ($unexaminedDomains.Count -eq 0)

    so whatever it declines to return is a gap that appears NOWHERE - not in the score, not in the
    findings, not in READY.

    It ends with an escape hatch for the empty scan:

        if (-not $anyServerSeen) { return @() }

    whose own comment states the contract in prose: "Whether ANY server at all was seen ... This is
    what distinguishes 'nothing was found anywhere' ... from 'servers were found but not one of them
    was a domain controller' - which is the case this function has to catch."

    THE DEFECT: the value did not count servers. It read

        $anyServerSeen = $examined.Count -gt 0

    which is the number of distinct DOMAIN NAMES collected - and $examined is deliberately built with
    discovery placeholders EXCLUDED, because a placeholder proves nothing about a domain's coverage.
    So an estate in which every row is a placeholder collected no names, "no names" was read as "no
    servers", and the hatch fired over an estate the run had in fact enumerated and rendered.

    This is the identical mistake, one variable over, to the `if ($dcDomains.Count -gt 0)` guard that
    was already removed from this same function for defeating the rule it was meant to protect.

    THE SHAPE THAT REACHES IT IS ONE THE PRODUCT EMITS ITSELF. The domain controller pass emits, for
    every directory record it cannot name, a row with a real Domain, an FQDN of
    "Domain controller (not named) n of m - <domain>" and IsPlaceholder = $true; Get-mdiCAReadiness
    and Get-mdiEntraConnectReadiness emit the same contract when their role cannot be enumerated. An
    ordinary low-privilege cross-forest run reaches it: -Forest over mdilab.local + fabrikam.local
    where the domain controller computer objects carry no dNSHostName and AD CS enumeration is denied.

    MEASURED ON THE SHIPPED FUNCTION, scope mdilab.local + fabrikam.local:

        3 unnamed-record placeholders, no other row      unexamined: NONE   -> READY
        the SAME 3 rows plus one reached CA              unexamined: BOTH   -> NOT READY
        zero domain controllers, all rows placeholders   unexamined: NONE   -> READY
        zero domain controllers, one reached CA          unexamined: BOTH   -> NOT READY

    Adding a healthy server to a broken estate made the verdict WORSE, and the completely broken
    estate - the one where not a single machine in either forest was named - got the best verdict of
    the four. The function's header calls reporting an estate ready without having looked at a whole
    domain's controllers "the largest false green it can produce"; this produced it for EVERY domain
    in scope simultaneously.

    THE SAME GATE ALSO SWALLOWED THE BLANK CASE: real, reached, non-placeholder servers whose Domain
    came back blank collected no names either, so two domains in scope with two scanned servers
    charged nothing - while the same two servers carrying an UNREADABLE domain (@{}) charged both.
    Blank is the ordinary "could not be read" value everywhere else in this codebase, so the more
    honest signal produced the quieter report.

    THE FIX counts ROWS, before the placeholder narrowing, because the hatch asks a question about
    the REPORT ("did this run produce anything at all?") and not about coverage.

    WHAT THIS TEST ALSO PINS, so the fix cannot be "improved" into a new defect:
      - a genuinely empty scan must STILL return nothing, or the empty-scan report is buried under
        one per-domain finding for every domain in scope;
      - placeholders must STILL contribute nothing to coverage - the fix changes only the empty-scan
        test, never what counts as examined;
      - every healthy estate must be unchanged, including the half-broken estate the function's own
        header already measured.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Write-Host 'A total discovery failure is not full domain coverage' -ForegroundColor Cyan

$scope = @('mdilab.local', 'fabrikam.local')

# The EXACT row the domain controller pass emits for a directory record it could not name.
function New-Unnamed ($Domain, $I, $N) {
    [PSCustomObject]@{
        FQDN           = 'Domain controller (not named) {0} of {1} - {2}' -f $I, $N, $Domain
        Domain         = $Domain
        SensorHealth   = 'N/A'
        Unreachable    = $false
        PartialFailure = $false
        IsPlaceholder  = $true
        Details        = [ordered]@{}
    }
}
function New-Real ($Fqdn, $Domain) {
    [PSCustomObject]@{ FQDN = $Fqdn; Domain = $Domain; Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false; Details = [ordered]@{} }
}
function Get-Unexamined ($Rows, $DcRows) {
    @(Get-mdiUnexaminedDomain -ScopedDomain $scope -Server $Rows -DomainControllerServer $DcRows)
}

# ---------------------------------------------------------------------------------------------------
# THE DEFECT ITSELF. Rows exist, they are rendered and charged as unread checks, and not one of them
# named a machine. Every domain in scope must be reported unexamined.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'An estate of nothing but discovery placeholders charges every domain' -ForegroundColor Cyan

$allPlaceholder = @(
    New-Unnamed 'mdilab.local' 1 2
    New-Unnamed 'mdilab.local' 2 2
    New-Unnamed 'fabrikam.local' 1 1
)
$un = Get-Unexamined $allPlaceholder $allPlaceholder
Assert-That 'both domains are charged' ($un.Count -eq 2) ("got $($un.Count): $($un -join ', ')")
Assert-That 'mdilab.local is charged' ($un -contains 'mdilab.local') ("got '$($un -join ', ')'")
Assert-That 'fabrikam.local is charged' ($un -contains 'fabrikam.local') ("got '$($un -join ', ')'")
Assert-That 'the verdict is NOT READY' (($un.Count -eq 0) -eq $false)

# The same estate with no domain-controller list at all - the case the header calls the largest
# false green this tool can produce.
$un = Get-Unexamined $allPlaceholder @()
Assert-That 'zero domain controllers still charges both' ($un.Count -eq 2) ("got $($un.Count): $($un -join ', ')")

# One forest entirely placeholders, the other not discovered at all.
$un = Get-Unexamined @(New-Unnamed 'fabrikam.local' 1 1) @(New-Unnamed 'fabrikam.local' 1 1)
Assert-That 'a single placeholder charges both domains' ($un.Count -eq 2) ("got $($un.Count): $($un -join ', ')")

# ---------------------------------------------------------------------------------------------------
# THE INVERSION. Adding a healthy server must never make the report WORSE. Before the fix the
# all-placeholder estate charged nothing and the same estate plus one reached CA charged both.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'Adding a healthy server never increases the number of findings' -ForegroundColor Cyan

$broken = (Get-Unexamined $allPlaceholder $allPlaceholder).Count
$plusCa = (Get-Unexamined (@($allPlaceholder) + @(New-Real 'ca01.mdilab.local' 'mdilab.local')) $allPlaceholder).Count
Assert-That 'one reached CA does not add a finding' ($plusCa -le $broken) ("broken=$broken plusCa=$plusCa")
Assert-That 'the broken estate is not the quieter report' ($broken -ge $plusCa) ("broken=$broken plusCa=$plusCa")

# ---------------------------------------------------------------------------------------------------
# THE BLANK CASE, swallowed by the same gate. Real servers that were reached and scanned, whose
# Domain came back blank, are not evidence that any domain was examined.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'Servers whose domain could not be read do not certify coverage' -ForegroundColor Cyan

foreach ($shape in @{ 'blank' = ''; 'null' = $null; 'whitespace' = '   ' }.GetEnumerator()) {
    $rows = @(New-Real 'dc01.mdilab.local' $shape.Value; New-Real 'dcfab01.fabrikam.local' $shape.Value)
    $un = Get-Unexamined $rows $rows
    Assert-That ("a {0} Domain on every server charges both domains" -f $shape.Key) ($un.Count -eq 2) ("got $($un.Count): $($un -join ', ')")
}
# The unreadable shapes always charged; pinned so the two halves cannot drift apart again.
foreach ($shape in @{ 'a hashtable' = @{}; 'the number 12345' = 12345; 'the boolean $true' = $true }.GetEnumerator()) {
    $rows = @(New-Real 'dc01.mdilab.local' $shape.Value; New-Real 'dcfab01.fabrikam.local' $shape.Value)
    $un = Get-Unexamined $rows $rows
    Assert-That ("{0} as a Domain charges both domains" -f $shape.Key) ($un.Count -eq 2) ("got $($un.Count): $($un -join ', ')")
}

# ---------------------------------------------------------------------------------------------------
# THE OTHER DIRECTION. The empty-scan hatch must survive, and no healthy estate may change.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'The empty scan is still the empty scan' -ForegroundColor Cyan

Assert-That 'no rows at all returns nothing' ((Get-Unexamined @() @()).Count -eq 0)
Assert-That 'a null server list returns nothing' ((@(Get-mdiUnexaminedDomain -ScopedDomain $scope -Server $null -DomainControllerServer $null)).Count -eq 0)
Assert-That 'an empty scope returns nothing' ((@(Get-mdiUnexaminedDomain -ScopedDomain @() -Server $allPlaceholder -DomainControllerServer $allPlaceholder)).Count -eq 0)

Write-Host ''
Write-Host 'Every healthy estate is unchanged' -ForegroundColor Cyan

$bothScanned = @(New-Real 'dc01.mdilab.local' 'mdilab.local'; New-Real 'dcfab01.fabrikam.local' 'fabrikam.local')
Assert-That 'both forests scanned charges nothing' ((Get-Unexamined $bothScanned $bothScanned).Count -eq 0)

$onlyMdilab = @(New-Real 'dc01.mdilab.local' 'mdilab.local')
$un = Get-Unexamined $onlyMdilab $onlyMdilab
Assert-That 'a genuinely missing domain is still charged' (($un.Count -eq 1) -and ($un -contains 'fabrikam.local')) ("got '$($un -join ', ')'")

# The half-broken estate the function's own header already measured: one domain scanned normally,
# the other contributing only unnamed-record placeholders.
$halfBroken = @(New-Real 'dc01.mdilab.local' 'mdilab.local'; New-Unnamed 'fabrikam.local' 1 2; New-Unnamed 'fabrikam.local' 2 2)
$un = Get-Unexamined $halfBroken $halfBroken
Assert-That 'the half-broken estate still charges only fabrikam.local' (($un.Count -eq 1) -and ($un -contains 'fabrikam.local')) ("got '$($un -join ', ')'")

# Spelling equivalence must be untouched by the change.
$dotted = @(New-Real 'dc01.mdilab.local' 'mdilab.local.'; New-Real 'dcfab01' 'FABRIKAM.LOCAL')
Assert-That 'a trailing dot and a case difference still match' ((Get-Unexamined $dotted $dotted).Count -eq 0) ("got '$((Get-Unexamined $dotted $dotted) -join ', ')'")

# A placeholder must still contribute NOTHING to coverage even when real servers exist beside it.
$mixed = @(New-Real 'dc01.mdilab.local' 'mdilab.local'; New-Unnamed 'fabrikam.local' 1 1)
$un = Get-Unexamined $mixed $mixed
Assert-That 'a placeholder never marks its own domain examined' ($un -contains 'fabrikam.local') ("got '$($un -join ', ')'")

Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 }
