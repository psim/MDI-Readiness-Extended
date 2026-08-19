<#
    AN UNREADABLE DOMAIN MUST NOT BECOME A DNS SUFFIX.

    Get-mdiServerIdentityKey is, in its own words, "the one spelling-independent name for a server,
    used by everything that has to decide whether two records are the same machine" - the merge, the
    role de-duplication and every server counter share it.

    It built the key like this:

        $key = ConvertTo-mdiCanonicalComputerName -Value ([string] $Server.FQDN) -Domain ([string] $Server.Domain)

    The [string] casts were added deliberately, and for a real defect: ConvertTo-mdiCanonicalComputerName
    types both parameters [string], so a row whose Domain was @('fabrikam.local') raised a
    parameter-transformation error, and because this key is computed inside Group-Object script
    blocks that TERMINATING error did not cost the offending row - it cost every row beside it.

    But the cast traded a crash for a FABRICATION, which is the failure this codebase keeps naming:
    a loud failure replaced by a quiet one is not a fix. [string] tests the RENDERING, not the value.
    The Domain half of this key is only ever used to QUALIFY a dotless name - the canonicaliser
    appends it verbatim to any name carrying no dot - so every non-string rendered non-blank and
    became a DNS SUFFIX.

    THE ROW THAT REACHES IT IS A SHIPPED ONE, not a contrived shape. A certification authority row
    keeps a SHORT name as its FQDN (`$caFqdn = if (...) { $caDnsName } else { $caName }`), and the
    comment above that line says an operator-supplied -CAServer "stays probeable exactly as before
    even when the directory cannot confirm it - that is the case -CAServer exists for". The CA loop
    then stamps the raw scope onto it unconditionally (`$ca['Domain'] = $Domain`), as does the Entra
    Connect loop. Measured on the shipped function with `-CAServer CAFAB01`:

        Domain value          key produced
        $null / '' / '   '    'cafab01'                              left bare, correct
        @('fabrikam.local')   'cafab01.fabrikam.local'               unwrapped, correct
        12345                 'cafab01.12345'              <-- a suffix nobody read
        $true                 'cafab01.true'               <-- a suffix nobody read
        @{}                   'cafab01.system.collections.hashtable' <-- a suffix nobody read

    Those are not merely wrong keys, they are keys that LOOK RESOLVED. A fully qualified name is this
    codebase's evidence that a host's domain was learned, so a value nobody read came back wearing
    the shape of a measurement - the family every defect in this project has belonged to. The
    consequence is the one Get-mdiServerIdentityKey's own header already states: "one physical server
    was counted twice and its two halves could carry different verdicts. The healthy-looking half
    then appeared in the ready count."

    The key now routes the domain through ConvertTo-mdiReadableDomainName, exactly as
    Get-mdiProbeDomainKey and Get-mdiProbeTargetKey already do. That function tests the TYPE rather
    than the spelling, which is the only test that can work here - 'System.Collections.Hashtable' is
    legal DNS characters throughout - and it still accepts the all-numeric single-label STRING
    '12345' a directory really can return.

    WHAT THIS TEST ALSO PINS, so the fix cannot be "improved" into a new defect: an unreadable domain
    must leave the name BARE rather than drop the row, because a nameless row must stay separate from
    named hosts instead of merging into one; a readable domain must still qualify a short name, which
    is the behaviour every non-disjoint estate depends on; an ALREADY DOTTED name must never be
    rewritten by the scope; and the merge must still throw nothing on the unreadable shapes that
    used to kill it.

    NOT PINNED, DELIBERATELY: telling a disjoint NetBIOS name from a single-label DNS domain.
    'FABCORP' is a string a directory or an operator really supplied, and a single-label DNS domain
    is legal, so the two are indistinguishable at this layer without asking the directory.
    Resolve-mdiDomainScopeDnsName is where that resolution belongs, and where it deliberately keeps
    the operator's spelling when the directory cannot be asked.
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

Write-Host 'An unreadable domain must not become a DNS suffix' -ForegroundColor Cyan

function New-Ca ($Fqdn, $Domain) { [PSCustomObject]@{ FQDN = $Fqdn; Domain = $Domain; Unreachable = $false } }

# ---------------------------------------------------------------------------------------------------
# THE DEFECT ITSELF. A Domain nobody could read must not be appended to a dotless name.
# Every one of these rendered non-blank under the old [string] cast and became a DNS suffix.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'An unreadable Domain leaves a short name bare, never qualified' -ForegroundColor Cyan

$unreadable = [ordered]@{
    'the number 12345'                  = 12345
    'the number 0'                      = 0
    'the boolean $true'                 = $true
    'the boolean $false'                = $false
    'an empty hashtable'                = @{}
    'a populated hashtable'             = @{ Name = 'fabrikam.local' }
    'a PSCustomObject'                  = [PSCustomObject]@{ Name = 'fabrikam.local' }
    'a two-element collection'          = @('a', 'b')
    'an empty collection'               = @()
    'a scriptblock'                     = { 'fabrikam.local' }
    'a DateTime'                        = [datetime]'2026-08-19'
}
foreach ($label in $unreadable.Keys) {
    $key = Get-mdiServerIdentityKey -Server (New-Ca 'CAFAB01' $unreadable[$label])
    Assert-That ("{0} does not become a suffix" -f $label) ($key -eq 'cafab01') ("got '$key'")
    Assert-That ("{0} produces no dot at all" -f $label) ($key -notmatch '\.') ("got '$key'")
}

# The three that already behaved, pinned so the fix cannot regress them.
foreach ($blank in @{ '$null' = $null; 'the empty string' = ''; 'whitespace' = '   ' }.GetEnumerator()) {
    $key = Get-mdiServerIdentityKey -Server (New-Ca 'CAFAB01' $blank.Value)
    Assert-That ("{0} still leaves the name bare" -f $blank.Key) ($key -eq 'cafab01') ("got '$key'")
}

# ---------------------------------------------------------------------------------------------------
# THE OTHER DIRECTION. Nothing that used to be read may stop being read. If these fail the fix has
# been "improved" into a new defect - a short name that no longer gets its domain.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'A READABLE domain still qualifies a short name' -ForegroundColor Cyan

$readable = [ordered]@{
    'a plain DNS name'                      = 'fabrikam.local'
    'a one-element collection'              = @('fabrikam.local')
    'a name with a trailing root dot'       = 'fabrikam.local.'
    'a name with surrounding whitespace'    = '  fabrikam.local  '
    'an upper-case spelling'                = 'FABRIKAM.LOCAL'
}
foreach ($label in $readable.Keys) {
    $key = Get-mdiServerIdentityKey -Server (New-Ca 'CAFAB01' $readable[$label])
    Assert-That ("{0} still qualifies" -f $label) ($key -eq 'cafab01.fabrikam.local') ("got '$key'")
}

# An all-numeric single-label STRING is a name a directory really can return, and
# ConvertTo-mdiReadableDomainName accepts it deliberately. It must keep qualifying, or this fix has
# silently narrowed what counts as a domain.
$numericString = Get-mdiServerIdentityKey -Server (New-Ca 'CAFAB01' '12345')
Assert-That 'the all-numeric single-label STRING still qualifies' `
($numericString -eq 'cafab01.12345') ("got '$numericString'")

# A single-label DNS domain is legal and is not distinguishable from a NetBIOS name here.
$singleLabel = Get-mdiServerIdentityKey -Server (New-Ca 'CAFAB01' 'FABCORP')
Assert-That 'a single-label string is still treated as a domain' `
($singleLabel -eq 'cafab01.fabcorp') ("got '$singleLabel'")

# ---------------------------------------------------------------------------------------------------
# AN ALREADY QUALIFIED NAME IS NEVER REWRITTEN, whatever the Domain says. The canonicaliser only
# appends to a dotless name, and that must remain true for readable and unreadable domains alike.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'An already qualified name is never rewritten by the scope' -ForegroundColor Cyan

foreach ($label in @('the number 12345', 'an empty hashtable', 'the boolean $true')) {
    $key = Get-mdiServerIdentityKey -Server (New-Ca 'dcfab01.fabrikam.local' $unreadable[$label])
    Assert-That ("a dotted name survives {0}" -f $label) ($key -eq 'dcfab01.fabrikam.local') ("got '$key'")
}
$dottedNetbios = Get-mdiServerIdentityKey -Server (New-Ca 'dcfab01.fabrikam.local' 'FABCORP')
Assert-That 'a dotted name survives a disjoint NetBIOS scope' `
($dottedNetbios -eq 'dcfab01.fabrikam.local') ("got '$dottedNetbios'")

# ---------------------------------------------------------------------------------------------------
# THE CONSEQUENCE THE KEY EXISTS TO PREVENT. Two rows for one machine must not survive the merge as
# two machines. This is what "counted twice, and its two halves could carry different verdicts" means
# in practice, and it is measured on the real merge rather than on the key alone.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'The merge is not split, and is not killed, by an unreadable domain' -ForegroundColor Cyan

# A readable estate: the short spelling and the qualified spelling of ONE machine must merge.
$mergedReadable = @(Merge-mdiServerByFqdn -Server @(
        (New-Ca 'CAFAB01' 'fabrikam.local')
        (New-Ca 'cafab01.fabrikam.local' 'fabrikam.local')
    ))
Assert-That 'one machine under two readable spellings merges to one row' `
($mergedReadable.Count -eq 1) ("got {0}" -f $mergedReadable.Count)

# The shape that used to kill the whole merge - a collection Domain - must cost nothing.
$mergedCollection = @(Merge-mdiServerByFqdn -Server @(
        (New-Ca 'dc01.mdilab.local' 'mdilab.local')
        (New-Ca 'dc02.mdilab.local' 'mdilab.local')
        (New-Ca 'dcfab01.fabrikam.local' @('fabrikam.local'))
        (New-Ca 'dc03.mdilab.local' 'mdilab.local')
    ))
Assert-That 'a collection Domain does not delete the rows beside it' `
($mergedCollection.Count -eq 4) ("got {0}" -f $mergedCollection.Count)

# An unreadable domain on a SHORT name must not merge that row into a named host, and must not throw.
$mergedUnreadable = @(Merge-mdiServerByFqdn -Server @(
        (New-Ca 'cafab01.fabrikam.local' 'fabrikam.local')
        (New-Ca 'CAFAB01' @{})
    ))
Assert-That 'a row whose domain nobody read stays its own row' `
($mergedUnreadable.Count -eq 2) ("got {0}" -f $mergedUnreadable.Count)

# Every unreadable shape must survive the merge without a terminating error, which is the defect the
# [string] cast was originally added for and which must stay fixed.
foreach ($label in $unreadable.Keys) {
    $threw = $false
    try { $null = @(Merge-mdiServerByFqdn -Server @((New-Ca 'dc01.mdilab.local' 'mdilab.local'), (New-Ca 'CAFAB01' $unreadable[$label]))) }
    catch { $threw = $true }
    Assert-That ("the merge survives {0}" -f $label) (-not $threw)
}

# ---------------------------------------------------------------------------------------------------
# A NAMELESS ROW STILL KEYS AS THE EMPTY STRING, which callers rely on to keep such rows separate.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'A row with no usable name still keys as the empty string' -ForegroundColor Cyan

Assert-That 'a null server keys empty' ((Get-mdiServerIdentityKey -Server $null) -eq '')
foreach ($label in @('the number 12345', 'an empty hashtable')) {
    $key = Get-mdiServerIdentityKey -Server (New-Ca '' $unreadable[$label])
    Assert-That ("a blank FQDN with {0} keys empty" -f $label) ($key -eq '') ("got '$key'")
}

Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 }
