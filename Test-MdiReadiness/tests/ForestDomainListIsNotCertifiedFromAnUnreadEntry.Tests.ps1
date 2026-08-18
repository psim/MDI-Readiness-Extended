<#
    A forest domain list that was NEVER READ came back looking like a complete enumeration.

    Get-mdiForestDomain is the gate on "did this run look at every domain in this forest". Its own
    comment states the stake: "A -Forest run that quietly examined one domain out of five and then
    reported READY is a false green over four domains nobody looked at". It therefore carries a
    Complete flag and an Error string, and Complete gates all three disclosure surfaces - the unread
    charge, the "forest domains could not be enumerated" issue, and the READY verdict.

    THE DEFECT. Both forest walkers named a domain with a bare [string] cast and then tested that cast
    with IsNullOrWhiteSpace alone:

        $domainName = [string] $entry                                   (the ADWS branch)
        if ([string]::IsNullOrWhiteSpace($domainName)) { $adwsUnnamed++; continue }

        $dnsRoot = [string] $entry.Properties['dnsroot'][0]             (the LDAP fallback)
        if ([string]::IsNullOrWhiteSpace($dnsRoot)) { $unnamed++; continue }

    IsNullOrWhiteSpace tests the RENDERING, not the value, and every non-string renders to something
    non-blank: a hashtable to 'System.Collections.Hashtable', a nested collection to
    'System.Object[]', a PSCustomObject to '@{DnsRoot=emea.mdilab.local}', $true to 'True', 12345 to
    '12345'. So an entry nobody could name was counted as a NAMED DOMAIN, the unnamed counter stayed
    0, and Complete stayed $true.

    Measured on the shipped function against the extended lab's real three-domain mdilab.local list -
    mdilab.local, emea.mdilab.local, apac.mdilab.local - with only the emea entry replaced:

        @('mdilab.local', '',                     'apac.mdilab.local')   Complete=False  n=2  CHARGED
        @('mdilab.local', '   ',                  'apac.mdilab.local')   Complete=False  n=2  CHARGED
        @('mdilab.local', $null,                  'apac.mdilab.local')   Complete=False  n=2  CHARGED
        @('mdilab.local', 12345,                  'apac.mdilab.local')   Complete=True   n=3  ['12345']
        @('mdilab.local', @{Name='emea...'},      'apac.mdilab.local')   Complete=True   n=3  ['System.Collections.Hashtable']
        @('mdilab.local', [pscustomobject]@{...}, 'apac.mdilab.local')   Complete=True   n=3  ['@{DnsRoot=emea.mdilab.local}']
        @('mdilab.local', $true,                  'apac.mdilab.local')   Complete=True   n=3  ['True']

    A blank entry was charged and an unreadable one was certified, on the same list, one element
    apart. In the certified rows emea.mdilab.local - a real domain of this estate - left the scan
    under a name that is a .NET type, and NOTHING recorded that it had gone: the run reported a
    three-domain forest it had never enumerated, and every later comparison (the coverage key, the
    unexamined-domain charge, the report identity) was made against a string no directory ever
    returned. That is strictly worse than the blank case, which at least declares the loss.

    The extended lab is what makes the shapes ordinary rather than theoretical. The estate is now
    three domains in mdilab.local plus a SECOND FOREST, fabrikam.local, across a bidirectional
    cross-forest trust with the disjoint NetBIOS name FABCORP; the codebase already documents having
    met a row whose Domain was @('fabrikam.local') in this very estate, and Get-mdiProbeTargetKey,
    Get-mdiProbeDomainKey and Get-mdiAddresslessDomainController were each hardened for it.

    THE FIX routes both walkers through ConvertTo-mdiReadableDomainName, which tests the TYPE rather
    than the spelling. A charset or shape rule cannot do this job - 'System.Collections.Hashtable' is
    legal DNS characters throughout - while an all-numeric single-label domain arrives from a
    directory as the STRING '12345' and must still be accepted. A ONE-ELEMENT collection is unwrapped
    rather than refused, because [string] @('fabrikam.local') is 'fabrikam.local' and that shape was
    already being read correctly; nothing that used to be read stops being read.

    This test pins both directions on both walkers: every unreadable shape is CHARGED and never
    certified, and every readable shape - including the real topology, a one-element collection, an
    all-numeric name and a single-label forest - is still enumerated exactly as before.
#>

$ErrorActionPreference = 'Stop'
$script:pass = 0
$script:fail = 0

# The suite runner counts assertions by matching lines that BEGIN with PASS or FAIL, so every
# assertion has to emit one.
function Assert-Equal {
    param($Expected, $Actual, [string] $Because)
    if ([string] $Expected -eq [string] $Actual) {
        $script:pass++
        "  PASS  $Because"
    } else {
        $script:fail++
        "  FAIL  $Because (expected '$Expected', got '$Actual')"
    }
}

function Resolve-ProductScript {
    $dir = $PSScriptRoot
    while ($dir) {
        $sibling = Join-Path $dir 'Test-MdiReadiness.ps1'
        if (Test-Path -LiteralPath $sibling) { return (Resolve-Path -LiteralPath $sibling).Path }
        $nested = Join-Path $dir 'Test-MdiReadiness\Test-MdiReadiness.ps1'
        if (Test-Path -LiteralPath $nested) { return (Resolve-Path -LiteralPath $nested).Path }
        $parent = Split-Path -Parent $dir
        if ($parent -eq $dir) { break }
        $dir = $parent
    }
    throw 'Could not resolve Test-MdiReadiness.ps1 from $PSScriptRoot (sibling first, then parent).'
}

$product = Resolve-ProductScript
$text = Get-Content -LiteralPath $product -Raw
$cut = $text.IndexOf('#region Main')
if ($cut -lt 0) { throw 'Could not find #region Main' }
. ([scriptblock]::Create($text.Substring(0, $cut)))

# --------------------------------------------------------------------------------------------
# The ADWS branch. Get-ADForest is shadowed WITHOUT [CmdletBinding()]: the product splats
# @{ ErrorAction = 'Stop'; Server = ... }, and an advanced function already declares ErrorAction as a
# common parameter, so declaring it again makes every call throw "a parameter with the name
# 'ErrorAction' was defined multiple times". The product catches that as an ADWS failure and falls
# through to LDAP, and the test would then measure the fallback while appearing to measure ADWS.
# --------------------------------------------------------------------------------------------
$script:forestToReturn = $null
function Get-ADForest {
    param($Server, $ErrorAction)
    if ($script:forestToReturn -is [string]) { throw $script:forestToReturn }
    $script:forestToReturn
}

# The LDAP fallback is shadowed too, so a fall-through can never reach a real directory and can never
# accidentally satisfy an assertion about the ADWS branch.
function Get-mdiForestDomainFromLdap {
    param([string] $Domain = $null, [ref] $UnnamedCount = $null)
    if ($null -ne $UnnamedCount) { $UnnamedCount.Value = 0 }
    $null
}

function Invoke-Adws {
    param($Domains, $Name = 'mdilab.local', $RootDomain = 'mdilab.local')
    $script:forestToReturn = [PSCustomObject]@{ Name = $Name; RootDomain = $RootDomain; Domains = $Domains }
    Get-mdiForestDomain -Domain 'mdilab.local' -WarningAction SilentlyContinue
}

Write-Output '=== the real extended-lab topology must still enumerate exactly as before ==='

$real = Invoke-Adws -Domains @('mdilab.local', 'emea.mdilab.local', 'apac.mdilab.local')
Assert-Equal -Expected 'True' -Actual $real.Complete -Because 'the real three-domain mdilab.local list is a complete enumeration'
Assert-Equal -Expected 3 -Actual @($real.Domains).Count -Because 'the real three-domain mdilab.local list yields three domains'
Assert-Equal -Expected 'mdilab.local, emea.mdilab.local, apac.mdilab.local' -Actual (@($real.Domains) -join ', ') `
    -Because 'the real three-domain list is returned unchanged'
Assert-Equal -Expected 'ADWS' -Actual $real.Method -Because 'the real list is enumerated over ADWS, not over the fallback'
Assert-Equal -Expected '' -Actual ([string] $real.Error) -Because 'a complete real enumeration carries no error'

$fab = Invoke-Adws -Domains @('fabrikam.local') -Name 'fabrikam.local' -RootDomain 'fabrikam.local'
Assert-Equal -Expected 'True' -Actual $fab.Complete -Because 'the trusted second forest fabrikam.local is a complete one-domain enumeration'
Assert-Equal -Expected 'fabrikam.local' -Actual (@($fab.Domains) -join ', ') -Because 'the trusted second forest returns its single domain'

Write-Output ''
Write-Output '=== an entry nobody could name must be CHARGED, never certified ==='

# Each case replaces ONLY the emea.mdilab.local entry, so any difference is the entry and nothing
# else. Every one of these renders to a non-blank string under a bare [string] cast, which is what
# let them be counted as named domains.
$unreadable = [ordered]@{
    "a blank ''"                   = ''
    "a whitespace '   '"           = '   '
    'a $null'                      = $null
    'a NUMBER 12345'               = 12345
    'a NUMBER 0'                   = 0
    'a $true'                      = $true
    'a $false'                     = $false
    'a HASHTABLE'                  = @{ Name = 'emea.mdilab.local' }
    'a PSCustomObject'             = ([PSCustomObject]@{ DnsRoot = 'emea.mdilab.local' })
    'a NESTED collection'          = (, @('emea.mdilab.local'))
    'a TWO-element collection'     = @('emea.mdilab.local', 'apac.mdilab.local')
    'a DateTime'                   = ([datetime] '2026-08-17')
    'a GUID'                       = ([guid] '00000000-0000-0000-0000-000000000001')
    'a ScriptBlock'                = ([scriptblock]::Create('"emea.mdilab.local"'))
}
foreach ($label in $unreadable.Keys) {
    $result = Invoke-Adws -Domains @('mdilab.local', $unreadable[$label], 'apac.mdilab.local')
    Assert-Equal -Expected 'False' -Actual $result.Complete `
        -Because ("{0} in the forest domain list must leave the enumeration INCOMPLETE" -f $label)
    Assert-Equal -Expected 2 -Actual @($result.Domains).Count `
        -Because ("{0} must not be counted as a named domain" -f $label)
    Assert-Equal -Expected 'one or more domain records could not be named' -Actual ([string] $result.Error) `
        -Because ("{0} must be charged as a record that could not be named" -f $label)
    Assert-Equal -Expected 'False' -Actual (@($result.Domains) -contains 'System.Collections.Hashtable').ToString() `
        -Because ("{0} must never reach the domain list as a .NET type name" -f $label)
}

Write-Output ''
Write-Output '=== a readable entry must still be read, whatever container it arrives in ==='

# [string] @('fabrikam.local') is 'fabrikam.local'. This shape is documented in this estate and three
# other functions were hardened to READ it, so the fix must unwrap it rather than refuse it.
$oneElement = New-Object 'System.Collections.ArrayList'
[void] $oneElement.Add('mdilab.local')
[void] $oneElement.Add((, 'emea.mdilab.local'))
[void] $oneElement.Add('apac.mdilab.local')
$wrapped = Invoke-Adws -Domains $oneElement
Assert-Equal -Expected 'True' -Actual $wrapped.Complete `
    -Because 'a ONE-ELEMENT collection holding a real domain name is readable and must not be charged'
Assert-Equal -Expected 3 -Actual @($wrapped.Domains).Count `
    -Because 'a ONE-ELEMENT collection holding a real domain name still yields its domain'
Assert-Equal -Expected 'mdilab.local, emea.mdilab.local, apac.mdilab.local' -Actual (@($wrapped.Domains) -join ', ') `
    -Because 'a ONE-ELEMENT collection is unwrapped to the name it carries'

# An all-numeric single-label domain arrives from a directory as a STRING and is a legitimate name.
# The rule must reject the INT 12345 and accept the STRING '12345', which is exactly why it tests the
# type rather than the spelling.
$numericName = Invoke-Adws -Domains @('12345') -Name '12345' -RootDomain '12345'
Assert-Equal -Expected 'True' -Actual $numericName.Complete `
    -Because "the STRING '12345' is a legitimate single-label domain name and must be accepted"
Assert-Equal -Expected '12345' -Actual (@($numericName.Domains) -join ', ') `
    -Because "the STRING '12345' is returned as the domain it names"

# A name that only LOOKS like a type is still a string somebody read.
$typeLike = Invoke-Adws -Domains @('mdilab.local', 'System.Collections.Hashtable') -Name 'mdilab.local' -RootDomain 'mdilab.local'
Assert-Equal -Expected 'True' -Actual $typeLike.Complete `
    -Because 'a STRING that happens to spell a .NET type name was still read and must be accepted'
Assert-Equal -Expected 2 -Actual @($typeLike.Domains).Count `
    -Because 'a STRING that happens to spell a .NET type name is still one domain'

Write-Output ''
Write-Output '=== the LDAP fallback applies the identical rule ==='

# ConvertTo-mdiReadableDomainName is the one place the rule lives, and Get-mdiForestDomainFromLdap
# calls it on the same values, so pinning the shared rule pins both walkers. A fallback that accepted
# what the primary rejects would reintroduce the defect one function away from the fix.
#
# The LDAP walker's own call site is pinned at SOURCE level as well. Its body cannot be driven from a
# test without standing up a DirectorySearcher, so a behavioural assertion alone would stay green if
# only that half were reverted to the bare cast - and a test that stays green when the bug returns is
# worthless. These two assertions fail the moment the fallback stops asking the shared rule.
$ldapStart = $text.IndexOf('function Get-mdiForestDomainFromLdap')
$ldapEnd = $text.IndexOf('function Get-mdiForestDomain {')
if ($ldapStart -lt 0 -or $ldapEnd -le $ldapStart) { throw 'Could not isolate Get-mdiForestDomainFromLdap in the product source' }
$ldapBody = $text.Substring($ldapStart, $ldapEnd - $ldapStart)
Assert-Equal -Expected 'True' -Actual ($ldapBody -match 'ConvertTo-mdiReadableDomainName\s+-Value\s+\$entry\.Properties\[''dnsroot''\]').ToString() `
    -Because 'the LDAP fallback must name a crossRef through the shared readability rule'
Assert-Equal -Expected 'False' -Actual ($ldapBody -match '\[string\]\s*\$entry\.Properties\[''dnsroot''\]').ToString() `
    -Because 'the LDAP fallback must not name a crossRef with a bare [string] cast'

Assert-Equal -Expected '' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value $null)) `
    -Because 'the shared rule refuses $null'
Assert-Equal -Expected '' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value '')) `
    -Because 'the shared rule refuses a blank string'
Assert-Equal -Expected '' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value '   ')) `
    -Because 'the shared rule refuses a whitespace string'
Assert-Equal -Expected '' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value 12345)) `
    -Because 'the shared rule refuses the NUMBER 12345'
Assert-Equal -Expected '' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value @{ Name = 'x' })) `
    -Because 'the shared rule refuses a hashtable'
Assert-Equal -Expected '' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value ([PSCustomObject]@{ DnsRoot = 'x' }))) `
    -Because 'the shared rule refuses a PSCustomObject'
Assert-Equal -Expected '' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value $true)) `
    -Because 'the shared rule refuses a boolean'
Assert-Equal -Expected '' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value (, @('fabrikam.local')))) `
    -Because 'the shared rule refuses a NESTED collection'
Assert-Equal -Expected '' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value @('fabrikam.local', 'mdilab.local'))) `
    -Because 'the shared rule refuses a TWO-element collection, which is not one domain name'
Assert-Equal -Expected 'fabrikam.local' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value 'fabrikam.local')) `
    -Because 'the shared rule reads a plain string'
Assert-Equal -Expected 'fabrikam.local' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value @('fabrikam.local'))) `
    -Because 'the shared rule unwraps a ONE-element collection, the shape this estate really produces'
Assert-Equal -Expected 'FABCORP' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value 'FABCORP')) `
    -Because 'the shared rule reads the DISJOINT NetBIOS name unchanged and does not require a dot'
Assert-Equal -Expected '12345' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value '12345')) `
    -Because "the shared rule reads the STRING '12345', which is a legitimate single-label name"
Assert-Equal -Expected ' fabrikam.local. ' -Actual ([string] (ConvertTo-mdiReadableDomainName -Value ' fabrikam.local. ')) `
    -Because 'the shared rule decides READABILITY only and must not re-spell a name its callers normalise'

Write-Host ("assertions passed={0} failed={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
