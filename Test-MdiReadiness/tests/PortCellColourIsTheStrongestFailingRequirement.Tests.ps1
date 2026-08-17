<#
    Pins: a port cell in the required-ports matrix must take its colour from the STRONGEST
    requirement among that server's FAILING records, not from whichever record sorts first.

    THE DEFECT THIS TEST PINS

    Get-mdiRequiredPortsHtml painted each per-server cell with:

        $rowRequirement = @($failed.Requirement | Where-Object { $_ }) + @($srvRecords.Requirement | Where-Object { $_ })
        $class = if (@($rowRequirement)[0] -eq 'Required') { 'red' } else { 'amber' }

    That line was already once fixed: the colour used to come from $probeRecords[0] - the first
    record across EVERY server - and was narrowed to this server's own records. The narrowing fixed
    half of the defect and left the other half on the same line, because [0] is still whichever
    record happens to sort first. One SERVER holding two requirements for one probe id therefore
    reproduces the original symptom one scope down.

    A cross-forest estate produces exactly that state. LdapsTcp and LdapsGcTcp ship as Optional and
    are promoted to Required in a -MultiForest plan, so a report carrying both a same-forest and a
    cross-forest result set for one sensor - a merged estate, a re-run, a report from another tool -
    carries both spellings under one server.

    Measured on the shipped function before the fix: one sensor, two REFUSED LDAPS probes, Optional
    to dc01.mdilab.local and Required to dcfab01.fabrikam.local, the only difference being the order
    the records arrive in:

        Optional record first   label=Required   cell=amber
        Required record first   label=Required   cell=red

    So a REQUIRED port proven refused was painted amber - advisory - underneath a row heading that
    correctly read Required. The colour is what an operator reads first; it said do not bother while
    the label said act. That is the inverse of the row-label defect fixed immediately below it in the
    same function, and it is the more dangerous half, because amber is the colour that gets skipped.

    The same [0] also let an UNREADABLE requirement outrank a readable one. A failing record whose
    Requirement was whitespace, the number 636, or 'Required.' - shapes an -AsJson round trip or a
    hand-edited report produces - painted the cell amber even with a readable Required failure beside
    it, because [0] picked the unreadable record and it is not equal to 'Required'.

    WHAT MUST NOT REGRESS IN THE OTHER DIRECTION

    'Optional' is a RECOGNISED requirement even though it ranks 0, and must not be treated as
    unreadable. A first attempt at this fix kept only rank > 0 and fell back to the server's other
    records when nothing survived - which turned "the Optional probe failed, the Required one is
    open" from amber into red by borrowing the requirement of a probe that PASSED. That case is
    pinned here too.

    AtLeastOne must stay amber: only rank 3 (Required / All) blocks, and a failed NNR method is
    judged per target elsewhere in the same function.
#>

$ErrorActionPreference = 'Stop'

# The product script is resolved from $PSScriptRoot, SIBLING FIRST and only then the parent chain.
# A machine-specific path would fail for anyone who clones the repository, and a parent-first search
# silently loads a stale copy left in a working directory above the tests.
function Resolve-ProductScript {
    $dir = $PSScriptRoot
    while ($dir) {
        $sibling = Join-Path $dir 'Test-MdiReadiness.ps1'
        if (Test-Path -LiteralPath $sibling) { return $sibling }
        $nested = Join-Path $dir 'Test-MdiReadiness\Test-MdiReadiness.ps1'
        if (Test-Path -LiteralPath $nested) { return $nested }
        $parent = Split-Path -Parent $dir
        if ($parent -eq $dir) { break }
        $dir = $parent
    }
    throw 'Could not resolve Test-MdiReadiness.ps1 from $PSScriptRoot upwards'
}

$productScript = Resolve-ProductScript
$text = [IO.File]::ReadAllText($productScript)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$mainIndex = $body.IndexOf('#region Main')
if ($mainIndex -gt 0) { $body = $body.Substring(0, $mainIndex) }
Invoke-Expression $body
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:failures = 0
$script:assertions = 0
function Assert-Equal {
    param($Expected, $Actual, [string] $Because)
    $script:assertions++
    if ([string] $Expected -ne [string] $Actual) {
        $script:failures++
        Write-Host ("  FAIL {0}`n       expected [{1}] but got [{2}]" -f $Because, $Expected, $Actual) -ForegroundColor Red
    } else {
        # Emitted on SUCCESS too, and in the "  PASS <text>" shape every other test in this tree
        # uses. The suite runner counts assertions by matching ^\s*PASS\s / ^\s*FAIL\s in a test's
        # output, and treats a file that produced NEITHER as one that threw before it reached its
        # assertions (Broke). Printing only on failure therefore made a fully passing file
        # indistinguishable from a crashed one: it reported "18 assertion(s), 0 failure(s)" to a
        # human reader while the gate recorded no-assert=1 and turned the whole tree RED with zero
        # failures. A test whose passing assertions the gate cannot see is exactly the silently
        # worthless test the Broke check exists to catch.
        Write-Host ("  PASS {0}" -f $Because)
    }
}

function New-Server {
    param([string] $Fqdn, [object[]] $Results)
    [PSCustomObject]@{
        FQDN    = $Fqdn
        Domain  = ($Fqdn -replace '^[^.]+\.', '')
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = $Results } }
    }
}

function New-PortResult {
    param([string] $Id, [string] $Name, [string] $Protocol, $Port, [string] $Scope, $Requirement,
        $Success, [string] $Target, [string] $TargetIP, [string] $Detail)
    [PSCustomObject]@{
        Id = $Id; Name = $Name; Protocol = $Protocol; Port = $Port; Scope = $Scope
        Requirement = $Requirement; Success = $Success; Applicable = $true
        Target = $Target; TargetIP = $TargetIP; Detail = $Detail
    }
}

# The row template is
#   <td title="Notes">Name<br/><small>Requirement</small></td><td>Protocol</td><td>Port</td><td>Scope</td>{per-server cells}
# so the first four cells are the description and everything after them is a server cell.
function Get-RowFacts {
    param([string] $Html, [string] $RowMatch)
    $rows = [regex]::Matches($Html, '(?s)<tr>(?<cells>.*?)</tr>')
    foreach ($r in $rows) {
        $cells = $r.Groups['cells'].Value
        if ($cells -notmatch [regex]::Escape($RowMatch)) { continue }
        $tds = [regex]::Matches($cells, '(?s)<td[^>]*>.*?</td>')
        $label = if ($cells -match '(?s)<small>(?<req>.*?)</small>') {
            ($matches['req'] -replace '<[^>]+>', '').Trim()
        } else { '<no small>' }
        $serverCells = @(for ($i = 4; $i -lt $tds.Count; $i++) {
                if ($tds[$i].Value -match 'class="([^"]+)"') { $matches[1] } else { '-' }
            })
        return [PSCustomObject]@{ Label = $label; Cells = ($serverCells -join ',') }
    }
    [PSCustomObject]@{ Label = '<row not found>'; Cells = '<row not found>' }
}

function New-Ldaps {
    param($Requirement, $Success, [string] $Target, [string] $TargetIP)
    New-PortResult -Id 'LdapsTcp' -Name 'Secure LDAP (LDAPS)' -Protocol 'TCP' -Port 636 `
        -Scope 'DomainController' -Requirement $Requirement -Success $Success `
        -Target $Target -TargetIP $TargetIP -Detail $(if ($Success -eq $true) { 'Connected' } else { 'Closed - connection refused' })
}

Write-Host 'Port cell colour takes the strongest failing requirement, not the first record'

$optionalBlocked = New-Ldaps -Requirement 'Optional' -Success $false -Target 'dc01.mdilab.local' -TargetIP '10.10.1.10'
$requiredBlocked = New-Ldaps -Requirement 'Required' -Success $false -Target 'dcfab01.fabrikam.local' -TargetIP '10.10.1.50'
$requiredOpen = New-Ldaps -Requirement 'Required' -Success $true -Target 'dcfab01.fabrikam.local' -TargetIP '10.10.1.50'

# --- The defect itself: one server, two blocked probes, requirements disagree ----------------------
# Both orders must give the same answer, and that answer must be red: a Required port is refused.
foreach ($case in @(
        @{ Name = 'Optional record first'; Results = @($optionalBlocked, $requiredBlocked) }
        @{ Name = 'Required record first'; Results = @($requiredBlocked, $optionalBlocked) }
    )) {
    $facts = Get-RowFacts -RowMatch 'Secure LDAP' -Html (
        Get-mdiRequiredPortsHtml -Server @(New-Server -Fqdn 'sensor01.mdilab.local' -Results $case.Results))
    Assert-Equal -Expected 'red' -Actual $facts.Cells `
        -Because ('a refused Required LDAPS probe must paint the cell red ({0})' -f $case.Name)
    Assert-Equal -Expected 'Required' -Actual $facts.Label `
        -Because ('the row label must read Required ({0})' -f $case.Name)
}

# --- The honest amber that must survive the fix ---------------------------------------------------
# The Optional probe failed and the Required one is open. Nothing required is blocked, so the cell is
# advisory. A fix that treats 'Optional' as unreadable borrows the passing probe's Required here.
$weakOnly = Get-RowFacts -RowMatch 'Secure LDAP' -Html (
    Get-mdiRequiredPortsHtml -Server @(New-Server -Fqdn 'sensor01.mdilab.local' -Results @($optionalBlocked, $requiredOpen)))
Assert-Equal -Expected 'amber' -Actual $weakOnly.Cells `
    -Because 'only the Optional probe failed, so the cell is advisory and must not borrow the open Required probe'

# --- An unreadable requirement must never downgrade a measured Required failure beside it ----------
foreach ($shape in @(
        @{ Name = 'null'; Value = $null }
        @{ Name = 'empty string'; Value = '' }
        @{ Name = 'whitespace'; Value = '   ' }
        @{ Name = 'a number'; Value = 636 }
        @{ Name = 'a boolean'; Value = $true }
        @{ Name = 'wrong case'; Value = 'REQUIRED' }
        @{ Name = 'trailing dot'; Value = 'Required.' }
    )) {
    $odd = New-Ldaps -Requirement $shape.Value -Success $false -Target 'dc02.mdilab.local' -TargetIP '10.10.1.11'
    $facts = Get-RowFacts -RowMatch 'Secure LDAP' -Html (
        Get-mdiRequiredPortsHtml -Server @(New-Server -Fqdn 'sensor01.mdilab.local' -Results @($odd, $requiredBlocked)))
    Assert-Equal -Expected 'red' -Actual $facts.Cells `
        -Because ('a failing record whose Requirement is {0} must not downgrade the refused Required probe beside it' -f $shape.Name)
}

# --- Controls: a server whose records all agree is unaffected --------------------------------------
foreach ($case in @(
        @{ Requirement = 'Optional'; Class = 'amber' }
        @{ Requirement = 'Required'; Class = 'red' }
        @{ Requirement = 'Recommended'; Class = 'amber' }
    )) {
    $a = New-Ldaps -Requirement $case.Requirement -Success $false -Target 'dc01.mdilab.local' -TargetIP '10.10.1.10'
    $b = New-Ldaps -Requirement $case.Requirement -Success $false -Target 'dc02.mdilab.local' -TargetIP '10.10.1.11'
    $facts = Get-RowFacts -RowMatch 'Secure LDAP' -Html (
        Get-mdiRequiredPortsHtml -Server @(New-Server -Fqdn 'sensor01.mdilab.local' -Results @($a, $b)))
    Assert-Equal -Expected $case.Class -Actual $facts.Cells `
        -Because ('a server whose records all say {0} keeps its shipped colour' -f $case.Requirement)
}

# AtLeastOne is the NNR group: a failed method is advisory here and judged per target elsewhere.
$nnrA = New-PortResult -Id 'NnrNetBios' -Name 'NNR - NetBIOS' -Protocol 'UDP' -Port 137 -Scope 'NetworkDevice' `
    -Requirement 'AtLeastOne' -Success $false -Target 'wks1.mdilab.local' -TargetIP '10.10.2.30' -Detail 'No response'
$nnrFacts = Get-RowFacts -RowMatch 'NNR - NetBIOS' -Html (
    Get-mdiRequiredPortsHtml -Server @(New-Server -Fqdn 'sensor01.mdilab.local' -Results @($nnrA)))
Assert-Equal -Expected 'amber' -Actual $nnrFacts.Cells `
    -Because 'a failed AtLeastOne NNR method stays advisory; only Required and All block'

# --- The per-server scope the earlier fix established must still hold ------------------------------
# Two servers, each with its own single record. The cross-forest server's refused Required probe is
# red; the same-forest server's refused Optional probe stays amber. Neither may take the other's.
$twoServers = @(
    New-Server -Fqdn 'dc01.mdilab.local' -Results @($optionalBlocked)
    New-Server -Fqdn 'dcfab01.fabrikam.local' -Results @($requiredBlocked)
)
$perServer = Get-RowFacts -RowMatch 'Secure LDAP' -Html (Get-mdiRequiredPortsHtml -Server $twoServers)
Assert-Equal -Expected 'amber,red' -Actual $perServer.Cells `
    -Because 'each server keeps its own requirement; the columns are sorted by server name'
Assert-Equal -Expected 'Required' -Actual $perServer.Label `
    -Because 'the row label is the strongest requirement any server reported'

Write-Host ('  {0} assertion(s), {1} failure(s)' -f $script:assertions, $script:failures)
if ($script:failures -gt 0) { exit 1 }
exit 0
