<#
    A host NAME must never be accepted as an ADDRESS.

    ConvertTo-mdiCanonicalComputerName decides what a domain controller IS. Its first question is
    "is this value an address?", asked of ConvertTo-mdiCanonicalIPAddress, and only if the answer is
    no does it qualify a short name with its domain:

        $address = ConvertTo-mdiCanonicalIPAddress -Value $name
        if ($null -ne $address) { return $address }
        ...
        if ($name -notmatch '\.') { $name = $name + '.' + $domainName }

    That question used to be answered by [Net.IPAddress]::TryParse alone. TryParse is the legacy
    inet_addr parser, and it is far more permissive than "is this an IPv4 literal". Measured on
    Windows PowerShell 5.1, all of the following returned TRUE:

        '2019'       -> 0.0.7.227      a bare integer, read as a packed 32-bit address
        '12345'      -> 0.0.48.57
        '1'          -> 0.0.0.1
        '10.1'       -> 10.0.0.1       an abbreviated form: last part fills the remaining octets
        '1.2.3'      -> 1.2.0.3
        '010.1.2.3'  -> 8.1.2.3        a leading zero is read as OCTAL
        '0x0a010203' -> 10.1.2.3       a hexadecimal literal

    So a domain controller named 2019 - passed to -DomainController, or read out of the inventory -
    was canonicalised to the address 0.0.7.227 instead of 2019.contoso.com. Two consequences, both
    silent:

    1. A NAME became a fabricated ADDRESS. The domain suffix was never applied, so the host never
       keyed the same as itself discovered elsewhere as 2019.contoso.com. Get-mdiServerKey and
       Get-mdiAddresslessDomainController both group on this value, so one physical server became
       two half-populated rows, either of which could carry the healthy verdict into the ready count.
       Every port probe for it was then aimed at 0.0.7.227, an address nobody owns.

    2. One ADDRESS became a DIFFERENT address. '010.1.2.3' is a real spelling - octets get zero
       padded by tools that align columns - and it silently became 8.1.2.3. Test-mdiTcpPort
       canonicalises through the same function and connects to the parsed address, so the probe
       measured a host that was never in scope and reported the result against the one that was.

    This is this project's recurring defect once more: nothing was measured, and a well-formed,
    confident answer was published anyway. There is no error to notice because the parse SUCCEEDED.

    The fix requires a strict four-part dotted-decimal literal before a value without a colon is
    treated as IPv4. Anything else is a name, and DNS decides what it means.

    Pinned here:

    1. The numeric, abbreviated, octal and hexadecimal forms are all rejected as addresses. This is
       the defect itself. Reinstating the bare TryParse turns these red.
    2. A numeric short name is domain-qualified like any other name - the behaviour the rejection
       exists to restore, asserted end to end through ConvertTo-mdiCanonicalComputerName.
    3. Real addresses still canonicalise: IPv4 including the 0 and 255 boundary octets, IPv6, an
       IPv4-mapped IPv6 address, a padded/whitespaced value, and a [Net.IPAddress] object. Without
       these the fix could pass by rejecting everything, which would strand every genuine address.
    4. The consuming surfaces agree. A rejected value must sort into the NAME bucket rather than the
       address bucket, and must not be reported as a usable computer address.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

'1. inet_addr spellings are NOT addresses'
# Each value is paired with what the legacy parser used to make of it, so a failure message says
# exactly which fabricated address leaked through.
$notAddresses = [ordered]@{
    '2019'        = '0.0.7.227'
    '12345'       = '0.0.48.57'
    '1'           = '0.0.0.1'
    '0'           = '0.0.0.0'
    '10.1'        = '10.0.0.1'
    '1.2.3'       = '1.2.0.3'
    '010.1.2.3'   = '8.1.2.3'
    '0x0a010203'  = '10.1.2.3'
}
foreach ($k in $notAddresses.Keys) {
    $got = ConvertTo-mdiCanonicalIPAddress -Value $k
    Assert-That "'$k' is not an address" ($null -eq $got) "got [$got], the inet_addr reading is $($notAddresses[$k])"
}

# Malformed values that the strict test must also refuse, and that TryParse already refused. These
# guard the regex itself: an over-wide octet, too many parts, and a name.
foreach ($k in '256.1.1.1', '1.2.3.4.5', '1.2.3.', 'dc1', 'dc1.contoso.com', '', '   ') {
    Assert-That "'$k' is not an address" ($null -eq (ConvertTo-mdiCanonicalIPAddress -Value $k))
}
Assert-That 'a null value is not an address' ($null -eq (ConvertTo-mdiCanonicalIPAddress -Value $null))

'2. A numeric short name is domain-qualified, like any other name'
Assert-That "'2019' + contoso.com => 2019.contoso.com" `
    ((ConvertTo-mdiCanonicalComputerName -Value '2019' -Domain 'contoso.com') -eq '2019.contoso.com') `
    "got [$(ConvertTo-mdiCanonicalComputerName -Value '2019' -Domain 'contoso.com')]"
Assert-That "'12345' + contoso.com => 12345.contoso.com" `
    ((ConvertTo-mdiCanonicalComputerName -Value '12345' -Domain 'contoso.com') -eq '12345.contoso.com')
Assert-That 'a numeric name and its own FQDN key IDENTICALLY' `
    ((ConvertTo-mdiCanonicalComputerName -Value '2019' -Domain 'contoso.com') -eq
        (ConvertTo-mdiCanonicalComputerName -Value '2019.contoso.com' -Domain 'contoso.com'))
Assert-That 'an ordinary short name is unaffected' `
    ((ConvertTo-mdiCanonicalComputerName -Value 'dc1' -Domain 'contoso.com') -eq 'dc1.contoso.com')
Assert-That 'a real address is still returned as an address, not suffixed' `
    ((ConvertTo-mdiCanonicalComputerName -Value '10.1.2.3' -Domain 'contoso.com') -eq '10.1.2.3')
Assert-That 'an unreadable name stays unread' `
    ($null -eq (ConvertTo-mdiCanonicalComputerName -Value '' -Domain 'contoso.com'))

'3. Genuine addresses still canonicalise'
$addresses = [ordered]@{
    '10.1.2.3'        = '10.1.2.3'
    '0.0.0.0'         = '0.0.0.0'
    '255.255.255.255' = '255.255.255.255'
    '192.168.0.1'     = '192.168.0.1'
    '  10.1.2.3  '    = '10.1.2.3'
    'fe80::1'         = 'fe80::1'
    '2001:db8::1'     = '2001:db8::1'
    '::1'             = '::1'
    '::ffff:10.1.2.3' = '10.1.2.3'
    '2001:0db8:0000:0000:0000:0000:0000:0001' = '2001:db8::1'
}
foreach ($k in $addresses.Keys) {
    $got = ConvertTo-mdiCanonicalIPAddress -Value $k
    Assert-That "'$k' canonicalises to $($addresses[$k])" ($got -eq $addresses[$k]) "got [$got]"
}
Assert-That 'a [Net.IPAddress] object is accepted unparsed' `
    ((ConvertTo-mdiCanonicalIPAddress -Value ([Net.IPAddress]::Parse('10.9.8.7'))) -eq '10.9.8.7')

'4. The consuming surfaces agree'
Assert-That 'a real address is a usable computer address' (Test-mdiUsableComputerAddress -Value '10.1.2.3')
Assert-That 'a numeric NAME is not a usable computer address' (-not (Test-mdiUsableComputerAddress -Value '2019'))
Assert-That 'a real address sorts in the address bucket' `
    ((Get-mdiIPAddressSortKey -Value '10.1.2.3') -like '0|*')
Assert-That 'a numeric name sorts in the NAME bucket' `
    ((Get-mdiIPAddressSortKey -Value '2019') -eq '9|2019') "got [$(Get-mdiIPAddressSortKey -Value '2019')]"

''
"PASS: $script:pass  FAIL: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
