<#
    A domain controller named by IP address must not have a domain invented from that address.

    THE DEFECT THIS PINS. Get-mdiDomainControllerReadiness stamps a Domain on every domain
    controller row it produces, from a three-step ladder:

        1. the authoritative directory DN   -> DirectoryDomain
        2. the FQDN suffix                  -> $dcFqdn.Substring($dcFqdn.IndexOf('.') + 1)
        3. the requested scope              -> $Domain

    Step 2 asked one question - does the text contain a dot - and then performed string surgery on
    whatever it found. An IPv4 literal contains dots. So a controller named 10.10.1.50 had its
    leftmost octet stripped and the remainder, "10.1.50", stamped on the row as its Active Directory
    domain. Nothing had been read: no directory answered, and an address carries no domain
    information at all. Measured on the shipped function with -Domain fabrikam.local:

        -DomainController 10.10.1.50              Domain=10.1.50          INVENTED
        -DomainController 10.10.1.51.             Domain=10.1.51          INVENTED
        -DomainController fd00::50                Domain=fabrikam.local   correct
        -DomainController DCFAB01                 Domain=fabrikam.local   correct
        -DomainController dcfab01.fabrikam.local  Domain=fabrikam.local   correct

    The two address families disagreed about the same host for an accidental reason: an IPv6 literal
    carries no dots, so it fell through to the scope and was right by luck, while its IPv4 equivalent
    was wrong. That asymmetry is the proof this was never a deliberate rule.

    WHY THAT IS DESTRUCTIVE. Get-mdiUnexaminedDomain decides domain COVERAGE on exactly this field,
    and the verdict, the issue list and the statistics all share that one definition. Fed the
    10.1.50 row it reported fabrikam.local as a domain in scope that produced no servers, so the
    domain whose controller had JUST been scanned was charged as never examined: readiness lost, a
    High Discovery finding raised, and the operator sent to investigate a gap that is not there.
    The report simultaneously gained a per-domain heading for "10.1.50", a domain that does not
    exist anywhere in the estate. A false red and a fabricated domain from one string operation.

    WHY THE LAB REACHES IT NOW. Naming a controller by address is the ORDINARY way to reach one
    across the bidirectional fabrikam.local trust added on 17 August: this forest's DNS holds no
    record for a host in the other forest, so -DomainController takes an IP. ConvertTo-mdiCanonicalComputerName
    is deliberately built to pass an address through unchanged - it asks "is this an address?"
    before it would qualify a short name - so the address arrives at the attribution ladder intact.
    Against the single forest v1.1.5 shipped for, a controller was reached by name and step 2 always
    had a real DNS suffix to read.

    THE FIX. Ask the existing strict address test, ConvertTo-mdiCanonicalIPAddress, before treating
    the text as a DNS name. An address is not a name, so it contributes no domain and the requested
    scope remains the fallback - the same answer a short name already got.

    The strictness matters and is pinned below. ConvertTo-mdiCanonicalIPAddress deliberately rejects
    the legacy inet_addr forms ('10.1.50', '2019') because those are host NAMES that happen to be
    numeric. A looser "does it look numeric" guard would have taken their suffix away too.

    Pinned here:

    1. An IPv4-named controller keeps the requested scope; "10.1.50" is never produced.
    2. So does one written with a trailing dot, which is the same address absolutely spelled.
    3. IPv6 still keeps the requested scope - the case that was right by accident must stay right.
    4. A real FQDN still yields its own suffix: the fix must not buy safety by refusing to answer.
    5. A controller whose suffix DIFFERS from the requested scope still reports its own suffix, so
       the DN-less compatibility fallback survives intact.
    6. The authoritative directory DN still outranks both.
    7. A numeric HOST NAME that is not a valid address keeps its suffix, pinning the strict test.
    8. The consequence: the scanned domain is not charged as unexamined, and no fabricated domain
       reaches the coverage surface.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiDomainControllerReadiness') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# What the directory returns for a given identity. Empty by default: a host reached across the trust
# by address is exactly the case where this forest's directory cannot answer, which is why the
# operator supplied an address in the first place.
$script:adcomputers = @{}
Set-Item -Path function:script:Get-ADObject -Value {
    param($Filter, $Server, $ErrorAction)
    $null
}
Set-Item -Path function:script:Get-ADComputer -Value {
    param($Identity, $Server, $Properties, $ErrorAction)
    $key = [string] $Identity
    if ($script:adcomputers.ContainsKey($key)) { return $script:adcomputers[$key] }
    $null
}
# The Domain stamp happens BEFORE the reachability branch - the reachability call is the next
# statement - so short-circuiting here measures the attribution and nothing else.
Set-Item -Path function:script:Test-mdiServerReachable -Value {
    param($ComputerName)
    [PSCustomObject]@{ Reachable = $false; Method = 'stubbed for this test' }
}
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param($ComputerName, $KnownAddress)
    @()
}

function Get-DcDomain {
    param([string] $Scope, [string] $Dc)
    $rows = @(Get-mdiDomainControllerReadiness -Domain $Scope -DomainController $Dc)
    if ($rows.Count -eq 0) { return '<no row>' }
    [string] $rows[0].Domain
}

'--- 1. an IPv4-named controller keeps the requested scope ---'
$ipv4 = Get-DcDomain -Scope 'fabrikam.local' -Dc '10.10.1.50'
Assert-That 'an IPv4 address does not become a domain' ($ipv4 -eq 'fabrikam.local') "got '$ipv4'"
Assert-That 'the octet-stripped string 10.1.50 is never produced' ($ipv4 -ne '10.1.50') "got '$ipv4'"

'--- 2. the same address written absolutely ---'
$ipv4Dot = Get-DcDomain -Scope 'fabrikam.local' -Dc '10.10.1.51.'
Assert-That 'a trailing-dot IPv4 address does not become a domain' ($ipv4Dot -eq 'fabrikam.local') "got '$ipv4Dot'"

'--- 3. IPv6 was right by accident and must stay right ---'
$ipv6 = Get-DcDomain -Scope 'fabrikam.local' -Dc 'fd00::50'
Assert-That 'an IPv6 address keeps the requested scope' ($ipv6 -eq 'fabrikam.local') "got '$ipv6'"
Assert-That 'both address families now agree about the same host' ($ipv6 -eq $ipv4) "v4='$ipv4' v6='$ipv6'"

'--- 4. a real name still yields a real suffix ---'
$named = Get-DcDomain -Scope 'fabrikam.local' -Dc 'dcfab01.fabrikam.local'
Assert-That 'a properly named controller reports its own suffix' ($named -eq 'fabrikam.local') "got '$named'"
$short = Get-DcDomain -Scope 'fabrikam.local' -Dc 'DCFAB01'
Assert-That 'a short name is qualified into the requested scope' ($short -eq 'fabrikam.local') "got '$short'"

'--- 5. the DN-less suffix fallback must survive the fix ---'
# A controller whose DNS suffix disagrees with the requested scope: the suffix is the only evidence
# there is, so it must still outrank the scope. This is the branch the fix narrows, and narrowing it
# too far would silently refile every such controller under the domain the caller asked about.
$other = Get-DcDomain -Scope 'fabrikam.local' -Dc 'dc01.emea.mdilab.local'
Assert-That 'a differing DNS suffix still beats the requested scope' ($other -eq 'emea.mdilab.local') "got '$other'"

'--- 6. the authoritative directory DN still outranks everything ---'
$script:adcomputers = @{
    '10.10.1.50' = [PSCustomObject]@{
        DNSHostName       = 'dcfab01.fabrikam.local'
        DistinguishedName = 'CN=DCFAB01,OU=Domain Controllers,DC=fabrikam,DC=local'
        IPv4Address       = '10.10.1.50'
        IPv6Address       = $null
        OperatingSystem   = 'Windows Server 2022 Standard'
    }
}
$fromDn = Get-DcDomain -Scope 'mdilab.local' -Dc '10.10.1.50'
Assert-That 'the directory DN decides the domain when it can be read' ($fromDn -eq 'fabrikam.local') "got '$fromDn'"
$script:adcomputers = @{}

'--- 7. a numeric HOST NAME is a name, not an address ---'
# ConvertTo-mdiCanonicalIPAddress deliberately rejects the legacy inet_addr forms, because they are
# names that happen to be numeric. The fix must consult that strict test and not a loose numeric
# guess, or these lose the only domain evidence they carry.
Assert-That '10.1.50 is not a valid address' ($null -eq (ConvertTo-mdiCanonicalIPAddress -Value '10.1.50'))
Assert-That '10.10.1.50 IS a valid address' ('10.10.1.50' -eq (ConvertTo-mdiCanonicalIPAddress -Value '10.10.1.50'))
$numericName = Get-DcDomain -Scope 'fabrikam.local' -Dc '2019.fabrikam.local'
Assert-That 'a host named 2019 keeps its real suffix' ($numericName -eq 'fabrikam.local') "got '$numericName'"

'--- 8. the consequence: coverage, which shares one definition with the verdict ---'
$row = [PSCustomObject]@{
    FQDN = '10.10.1.50'; Domain = $ipv4; Unreachable = $false; IsPlaceholder = $false
}
$unexamined = @(Get-mdiUnexaminedDomain -ScopedDomain @('fabrikam.local') -Server @($row) -DomainControllerServer @($row))
Assert-That 'the domain whose controller was scanned is not charged as unexamined' ($unexamined.Count -eq 0) "got: $($unexamined -join ', ')"

# And the fabricated name must not reach the coverage surface under any spelling.
$fabricated = @('10.1.50', '10.1.51', '1.50')
$leaked = @($fabricated | Where-Object { $ipv4 -eq $_ -or $ipv4Dot -eq $_ })
Assert-That 'no fabricated domain reaches the report' ($leaked.Count -eq 0) "these did: $($leaked -join ', ')"

''
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
