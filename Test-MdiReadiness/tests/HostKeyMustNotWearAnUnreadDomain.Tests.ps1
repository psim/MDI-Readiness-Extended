<#
    A HOST KEY MUST NOT WEAR A DOMAIN NOBODY READ.

    Three rulers decide which MACHINE an inventory row is, and all three qualified a dotless name
    with the row's raw Domain field cast to a string:

        Get-mdiProbeTargetKey              $named = ConvertTo-mdiCanonicalComputerName -Value $Target.Name -Domain ([string] $Target.Domain)
        Get-mdiDomainControllerHostKey     $key   = ConvertTo-mdiCanonicalComputerName -Value $Row.Name    -Domain ([string] $Row.Domain)
        Get-mdiAddresslessDomainController  the same expression again, twice, inline

    [string] tests the RENDERING, not the value, and the domain half of these keys exists only to
    QUALIFY a dotless name - ConvertTo-mdiCanonicalComputerName appends whatever it is handed,
    verbatim, to any name carrying no dot. A short name is not a contrived shape: it is exactly what
    Resolve-mdiDomainController and Get-mdiDomainControllerFromLdap emit when dNSHostName is empty
    and Name is used instead, which is the RODC / replication-gap case both of them are written for.

    Measured on the shipped functions, a row named dc01:

        Domain value            key produced
        $null / '' / '   '      'dc01'                                    left bare, correct
        @('fabrikam.local')     'dc01.fabrikam.local'                     unwrapped, correct
        12345                   'dc01.12345'                   <-- a suffix nobody read
        $true                   'dc01.true'                    <-- a suffix nobody read
        @{}                     'dc01.system.collections.hashtable'       <-- a suffix nobody read
        [PSCustomObject]        'dc01.@{dnsroot=fabrikam.local}'          <-- a suffix nobody read
        @('a','b')              'dc01.a b'                     <-- not even a DNS name

    Get-mdiProbeTargetKey DISAGREED WITH ITSELF about that field. Its unnameable half keys the
    domain through Get-mdiProbeDomainKey, which routes through ConvertTo-mdiReadableDomainName and
    correctly returned the EMPTY domain key for every one of those values - so one value was read as
    unread by one branch of the function and as a resolved DNS suffix by the other, three lines
    apart. Get-mdiServerIdentityKey, reading the SAME field on the SAME row, returned the bare
    'dc01' for all of them, because UnreadableDomainIsNotADnsSuffix.Tests.ps1 already pins that fix
    there. These three rulers were left behind by it.

    A fully qualified name is this codebase's evidence that a host's domain was learned, so a value
    nobody read came back wearing the shape of a measurement - the family every defect in this
    project has belonged to. Two consequences were measured, both on surfaces the operator sees:

      THE KEY ITSELF. Get-mdiDomainControllerHostCount is Get-mdiDomainControllerHostKey's only
      consumer and is the number of controllers the report states. The count did not change here -
      an unreadable domain deliberately leaves the name BARE, which keeps such a row separate from
      named hosts rather than merging it into one, exactly as Get-mdiServerIdentityKey does - but
      the SPELLING of the key did, and it is that spelling every other reader compares against.
      A key of 'dc01.12345' claims a domain was learned; 'dc01' says only what was read.

      THE REPAIR LIST. Get-mdiAddresslessDomainController returns NAMES that are printed to the
      operator as domain controllers to go and fix. Measured with three addressless controllers
      whose Domain nobody could read, it returned 'dc01.system.collections.hashtable', 'dc02.a b'
      and 'dc03.@{dnsroot=fabrikam.local}' - none of them a name any directory returned, one of them
      not a DNS name at all, all three presented as fully qualified.

    All three now route the domain through ConvertTo-mdiReadableDomainName, this codebase's single
    definition of "is this a domain name anybody read", and Get-mdiAddresslessDomainController uses
    the ruler itself rather than a fourth inline copy of its expression - three copies of one rule
    being how the copies drifted in the first place.

    WHAT THIS TEST ALSO PINS, so the fix cannot be "improved" into a new defect:

      * a DISJOINT NETBIOS name must still qualify. FABCORP is the NetBIOS name of fabrikam.local
        and carries no dot, and ConvertTo-mdiReadableDomainName accepts it, so dcfab01 + FABCORP
        must still key as 'dcfab01.fabcorp'. A fix that refused dotless domains would silently stop
        qualifying every short controller name in the disjoint estate - a worse defect than the one
        being fixed, and one this lab's second forest is the only place that shows it.
      * the all-numeric single-label STRING '12345' is a domain a directory really can return and
        must still qualify, while the NUMBER 12345 must not.
      * an already-dotted name must never be rewritten by the row's domain.
      * a bare IP address must never have a domain stapled onto it.
      * the unreadable shapes must not THROW. The [string] cast they replaced was itself added to
        stop a terminating parameter-transformation error, raised inside Group-Object script blocks
        where it cost every row beside the offending one - so a row that is merely unreadable must
        stay merely unreadable.
      * the three rulers and Get-mdiServerIdentityKey must AGREE on every shape, which is the
        property that was actually broken: four readers of one field, one of them hardened.
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

function New-Row ($Name, $Domain, $IP = $null) {
    [PSCustomObject]@{
        Name      = $Name
        Domain    = $Domain
        IP        = $IP
        Addresses = @(if ($null -ne $IP) { $IP })
    }
}

Write-Host 'A host key must not wear a domain nobody read' -ForegroundColor Cyan

$unreadable = [ordered]@{
    'the number 12345'         = 12345
    'the number 0'             = 0
    'the boolean $true'        = $true
    'the boolean $false'       = $false
    'an empty hashtable'       = @{}
    'a populated hashtable'    = @{ DnsRoot = 'fabrikam.local' }
    'an ordered hashtable'     = ([ordered]@{ DnsRoot = 'fabrikam.local' })
    'a PSCustomObject'         = [PSCustomObject]@{ DnsRoot = 'fabrikam.local' }
    'a two-element collection' = @('fabrikam.local', 'mdilab.local')
    'a scriptblock'            = { 'fabrikam.local' }
    'a DateTime'               = [datetime]'2026-08-17'
}

# ---------------------------------------------------------------------------------------------------
# THE DEFECT. A Domain nobody could read must not be appended to a dotless name, on any of the
# three rulers. Every one of these rendered non-blank under the old [string] cast.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'An unreadable Domain leaves a short controller name bare' -ForegroundColor Cyan

foreach ($label in $unreadable.Keys) {
    $row = New-Row 'dc01' $unreadable[$label] '10.10.1.50'
    $probeKey = Get-mdiProbeTargetKey -Target $row
    $hostKey = Get-mdiDomainControllerHostKey -Row $row
    Assert-That ("Get-mdiProbeTargetKey: {0} is not a suffix" -f $label) ($probeKey -eq 'dc01') ("got '$probeKey'")
    Assert-That ("Get-mdiDomainControllerHostKey: {0} is not a suffix" -f $label) ($hostKey -eq 'dc01') ("got '$hostKey'")

    $addressless = @(Get-mdiAddresslessDomainController -Inventory @((New-Row 'dc01' $unreadable[$label])))
    Assert-That ("Get-mdiAddresslessDomainController: {0} is not a suffix" -f $label) `
    ($addressless.Count -eq 1 -and $addressless[0] -eq 'dc01') ("got '$($addressless -join ',')'")
}

# ---------------------------------------------------------------------------------------------------
# THE FOUR RULERS MUST AGREE. This is the property that was actually broken: Get-mdiServerIdentityKey
# was hardened and the other three were not, so four readers of one field gave two answers.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'The four readers of Domain agree on every shape' -ForegroundColor Cyan

$allShapes = [ordered]@{ '$null' = $null; "the empty string" = ''; 'whitespace' = '   ';
    "'fabrikam.local'" = 'fabrikam.local'; "@('fabrikam.local')" = @('fabrikam.local')
}
foreach ($label in $unreadable.Keys) { $allShapes[$label] = $unreadable[$label] }

foreach ($label in $allShapes.Keys) {
    $row = New-Row 'dc01' $allShapes[$label] '10.10.1.50'
    $identity = Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = 'dc01'; Domain = $allShapes[$label] })
    $probeKey = Get-mdiProbeTargetKey -Target $row
    $hostKey = Get-mdiDomainControllerHostKey -Row $row
    Assert-That ("{0}: probe key agrees with the identity key" -f $label) ($probeKey -eq $identity) ("probe '$probeKey' vs identity '$identity'")
    Assert-That ("{0}: host key agrees with the identity key" -f $label) ($hostKey -eq $identity) ("host '$hostKey' vs identity '$identity'")
}

# ---------------------------------------------------------------------------------------------------
# THE SAME FUNCTION MUST NOT DISAGREE WITH ITSELF. Get-mdiProbeTargetKey's unnameable half already
# read this field correctly, through Get-mdiProbeDomainKey.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'Both halves of Get-mdiProbeTargetKey read Domain the same way' -ForegroundColor Cyan

foreach ($label in $unreadable.Keys) {
    $unnamed = Get-mdiProbeTargetKey -Target (New-Row '' $unreadable[$label] '10.10.1.50')
    Assert-That ("{0}: the unnameable half records no domain" -f $label) `
    ($unnamed -eq '?unnamed??10.10.1.50') ("got '$unnamed'")
    $named = Get-mdiProbeTargetKey -Target (New-Row 'dc01' $unreadable[$label] '10.10.1.50')
    Assert-That ("{0}: the named half records no domain either" -f $label) `
    ($named -notmatch '\.') ("got '$named'")
}

# ---------------------------------------------------------------------------------------------------
# THE DISJOINT NETBIOS NAME MUST STILL QUALIFY. FABCORP is the NetBIOS name of fabrikam.local and
# carries no dot; a fix that refused dotless domains would stop qualifying every short controller
# name in that estate.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'A readable domain still qualifies a short name' -ForegroundColor Cyan

$readable = [ordered]@{
    'FABCORP (disjoint NetBIOS)'    = @{ Domain = 'FABCORP'; Expect = 'dcfab01.fabcorp' }
    'fabrikam.local'                = @{ Domain = 'fabrikam.local'; Expect = 'dcfab01.fabrikam.local' }
    'fabrikam.local. (root dot)'    = @{ Domain = 'fabrikam.local.'; Expect = 'dcfab01.fabrikam.local' }
    'emea.mdilab.local'             = @{ Domain = 'emea.mdilab.local'; Expect = 'dcfab01.emea.mdilab.local' }
    'apac.mdilab.local'             = @{ Domain = 'apac.mdilab.local'; Expect = 'dcfab01.apac.mdilab.local' }
    "the STRING '12345'"            = @{ Domain = '12345'; Expect = 'dcfab01.12345' }
    "a one-element collection"      = @{ Domain = @('fabrikam.local'); Expect = 'dcfab01.fabrikam.local' }
    'MDILAB (NetBIOS, other trust)' = @{ Domain = 'MDILAB'; Expect = 'dcfab01.mdilab' }
}
foreach ($label in $readable.Keys) {
    $d = $readable[$label].Domain
    $expect = $readable[$label].Expect
    $row = New-Row 'dcfab01' $d '10.10.1.50'
    Assert-That ("{0}: probe key qualifies" -f $label) ((Get-mdiProbeTargetKey -Target $row) -eq $expect) ("got '$(Get-mdiProbeTargetKey -Target $row)'")
    Assert-That ("{0}: host key qualifies" -f $label) ((Get-mdiDomainControllerHostKey -Row $row) -eq $expect) ("got '$(Get-mdiDomainControllerHostKey -Row $row)'")
    $addressless = @(Get-mdiAddresslessDomainController -Inventory @((New-Row 'dcfab01' $d)))
    Assert-That ("{0}: addressless list qualifies" -f $label) `
    ($addressless.Count -eq 1 -and $addressless[0] -eq $expect) ("got '$($addressless -join ',')'")
}

# ---------------------------------------------------------------------------------------------------
# AN ALREADY-QUALIFIED NAME, AND AN ADDRESS, ARE NEVER REWRITTEN.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'A dotted name and a bare address are left alone' -ForegroundColor Cyan

foreach ($label in $allShapes.Keys) {
    $dotted = New-Row 'dcfab01.fabrikam.local' $allShapes[$label] '10.10.1.50'
    Assert-That ("{0}: a dotted name is not rewritten" -f $label) `
    ((Get-mdiProbeTargetKey -Target $dotted) -eq 'dcfab01.fabrikam.local') ("got '$(Get-mdiProbeTargetKey -Target $dotted)'")
    Assert-That ("{0}: a dotted name keeps its host key" -f $label) `
    ((Get-mdiDomainControllerHostKey -Row $dotted) -eq 'dcfab01.fabrikam.local') ("got '$(Get-mdiDomainControllerHostKey -Row $dotted)'")
    $addressRow = New-Row '10.10.1.50' $allShapes[$label] '10.10.1.50'
    Assert-That ("{0}: an address gets no domain stapled on" -f $label) `
    ((Get-mdiDomainControllerHostKey -Row $addressRow) -eq '10.10.1.50') ("got '$(Get-mdiDomainControllerHostKey -Row $addressRow)'")
}

# ---------------------------------------------------------------------------------------------------
# THE COUNT THE OPERATOR IS SHOWN. An unreadable copy of a named host keys BARE and therefore stays
# a separate row - deliberately, so a row nobody could read never merges into a named host. What
# must not happen is the reverse: a genuinely different machine in the OTHER forest collapsing into
# one, which is the UNDER-COUNT half of the pair Get-mdiDomainControllerHostKey exists to prevent.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'The controller count still separates the two forests' -ForegroundColor Cyan

$twoForests = @(
    New-Row 'dc01' 'mdilab.local' '10.0.0.10'
    New-Row 'dc01' 'fabrikam.local' '10.10.1.50'
)
Assert-That 'a dc01 in each forest is still two controllers' `
((Get-mdiDomainControllerHostCount -Inventory $twoForests) -eq 2) `
("got $(Get-mdiDomainControllerHostCount -Inventory $twoForests)")

# One machine, four legitimate spellings of the same qualified name, is still ONE controller.
$oneMachine = @(
    New-Row 'dcfab01' 'fabrikam.local' '10.10.1.50'
    New-Row 'DCFAB01' 'fabrikam.local' '10.10.1.50'
    New-Row 'dcfab01.fabrikam.local' 'fabrikam.local' '10.10.1.50'
    New-Row 'dcfab01.fabrikam.local.' 'fabrikam.local' '10.10.1.50'
)
Assert-That 'four spellings of one controller are still one' `
((Get-mdiDomainControllerHostCount -Inventory $oneMachine) -eq 1) `
("got $(Get-mdiDomainControllerHostCount -Inventory $oneMachine)")

# And a row whose domain nobody read must not be silently merged INTO a named host, which is what
# leaving the name bare is for.
foreach ($label in $unreadable.Keys) {
    $inventory = @(
        New-Row 'dc01' 'mdilab.local' '10.0.0.10'
        New-Row 'dc01' $unreadable[$label] '10.0.0.10'
    )
    $keys = @(@($inventory) | ForEach-Object { Get-mdiDomainControllerHostKey -Row $_ })
    Assert-That ("{0}: the unread copy keys bare, not into the named host" -f $label) `
    ($keys[0] -eq 'dc01.mdilab.local' -and $keys[1] -eq 'dc01') ("got '$($keys -join ',')'")
}

# ---------------------------------------------------------------------------------------------------
# NOTHING MAY THROW. The [string] cast this replaced was itself added to stop a terminating
# parameter-transformation error inside a Group-Object script block.
# ---------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host 'An unreadable row stays merely unreadable' -ForegroundColor Cyan

foreach ($label in $allShapes.Keys) {
    $threw = $false
    try {
        $inv = @(
            New-Row 'dc01' $allShapes[$label]
            New-Row 'dc02' 'mdilab.local'
            New-Row 'dc03' $allShapes[$label] '10.0.0.30'
        )
        [void] (Get-mdiAddresslessDomainController -Inventory $inv)
        [void] (Get-mdiDomainControllerHostCount -Inventory $inv)
        [void] (Resolve-mdiNnrTarget -DomainControllers $inv -MaxTargets 2)
    } catch { $threw = $true; $msg = $_.Exception.Message }
    Assert-That ("{0}: the whole estate survives it" -f $label) (-not $threw) ("threw: $msg")
}

# A null row, and a row carrying no Name at all, key as the empty string rather than throwing.
Assert-That 'a null row keys empty' ((Get-mdiDomainControllerHostKey -Row $null) -eq '') 'expected empty'
Assert-That 'a nameless row keys empty' ((Get-mdiDomainControllerHostKey -Row ([PSCustomObject]@{ Domain = 'mdilab.local' })) -eq '') 'expected empty'

Write-Host ''
Write-Host ("RESULT: {0} passed / {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
