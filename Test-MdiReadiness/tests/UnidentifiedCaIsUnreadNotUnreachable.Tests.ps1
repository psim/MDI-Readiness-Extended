<#
    THE DEFECT THIS TEST PINS

    A certification authority that was DISCOVERED but never IDENTIFIED was reported as a machine
    that had been contacted and found unavailable.

    Get-mdiCAReadiness discovers certification authorities with two directory reads: the Cert
    Publishers group of the domain, then Get-ADComputer on each member to turn it into a host name.
    Only the FIRST of those had a not-measured path. $caNotMeasured is set in the catch around the
    group read, and produces an 'AD CS (not enumerated)' row carrying SensorHealth 'N/A' and
    IsPlaceholder, so a domain whose CAs could not be enumerated is scored as unread rather than as
    a domain with nothing to check.

    The SECOND read had none, and its failure was silently converted into a fake measurement.

    The mechanism is the parameter type. The function declares

        [Parameter(Mandatory = $false)] [string[]] $CAServer = $null

    and then assigns the discovery result straight back into that same variable:

        $CAServer = Get-ADGroupMember -Server $Domain -Identity $CertPublishersSID ... | Where-Object ...

    A param-block type constraint stays attached to the variable for the whole function, so every
    member is COERCED TO A STRING at that assignment - and an ADPrincipal stringifies to its
    distinguishedName. Discovered members therefore arrive at the naming loop as
    'CN=ca01,OU=CAs,DC=fabrikam,DC=local', never as objects and never as host names.

    Get-ADComputer is then called with -ErrorAction SilentlyContinue, so a permission denial, a
    replication gap or a cross-forest reference simply yields $null, and the fallback was

        $caFqdn = if ($caComputer -and $caComputer.DNSHostName) { [string] $caComputer.DNSHostName } else { $caName }

    - the distinguished name. That DN was handed to Test-mdiServerReachable as a -ComputerName, could
    not possibly resolve, and the row was emitted as

        FQDN 'CN=ca01,OU=CAs,DC=fabrikam,DC=local'   Unreachable=True
        Comment 'Server is not available: ICMP'

    with IsPlaceholder unset. Nothing was ever contacted: the name was a directory path. A server the
    tool never identified was presented as a server it had probed and found down - counted in the
    server KPIs as a machine, charged as a FAILURE rather than as an unread check, and sending the
    operator to investigate name resolution or a firewall for a host whose name the tool never
    learned.

    Measured on the shipped function, fabrikam.local with two Cert Publishers members whose computer
    objects could not be read:

        rows 2, both carrying a DN as their FQDN, both Unreachable=True, neither IsPlaceholder

    while the SAME function, one block away, already reports a failed group read as not-measured.

    This is ordinary rather than contrived across the 17 August forest trust: dNSHostName is not
    always readable across a trust, which is the same condition the domain-controller path already
    handles with its 'Domain controller (not named) N of M' placeholder, and the same condition
    Get-mdiEntraConnectReadiness handles with $unreadableSyncAccount for accounts "whose server name
    could not be READ". Get-mdiCAReadiness's second read was the only one of the four without it.

    Whitespace is the same fact spelled differently: the old guard `if ($caComputer.DNSHostName)`
    accepted '   ' as a host name, because a non-empty string is truthy.

    WHAT MUST NOT REGRESS IN THE OTHER DIRECTION

    A name the operator passed to -CAServer is a host name they chose, not a distinguished name, and
    it must stay probeable exactly as before even when the directory cannot confirm it - that is the
    case -CAServer exists for. Only DISCOVERED members are diverted to a placeholder. A domain that
    genuinely runs no AD CS must also stay silent, because a placeholder there would charge an unread
    check against a domain with nothing to read.
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

# Reachability is decided BY NAME, so nothing fails unconditionally: a real host name is reachable, a
# distinguished name is not. That is what makes the false red visible instead of assumed.
function Test-mdiServerReachable {
    param($ComputerName)
    if ([string] $ComputerName -match '^[A-Za-z0-9][A-Za-z0-9\.\-]*$') { @{ Reachable = $true; Method = 'ICMP' } }
    else { @{ Reachable = $false; Method = 'ICMP' } }
}
function Get-mdiComputerAddress { param($ComputerName, $KnownAddress) @($KnownAddress | Where-Object { $_ }) }

# Every per-server check, so a REACHABLE server yields a complete passing row. Only identification is
# under test here.
function Get-mdiServerRequirements { param($ComputerName) @{ isMinHwRequirementsOk = $true; details = @{} } }
function Get-mdiPowerScheme { param($ComputerName) @{ isPowerSchemeOk = $true; details = @{} } }
function Get-mdiAdvancedAuditing { param($ComputerName, $ExpectedAuditing) @{ isAdvancedAuditingOk = $true; details = @{} } }
function Get-mdiCAAuditing { param($ComputerName) @{ isCaAuditingOk = $true; details = @{} } }
function Get-mdiCertReadiness { param($ComputerName) @{ isRootCertificatesOk = $true; details = @{} } }
function Get-mdiSensorVersion { param($ComputerName) '2.0.0.0' }
function Get-mdiCaptureComponent { param($ComputerName) 'Npcap' }
function Get-mdiMachineType { param($ComputerName) 'Virtual' }
function Get-mdiOSVersion { param($ComputerName) @{ isOsVerOk = $true; details = @{} } }
function Get-mdiSensorHealth { param($ComputerName) @{ isSensorHealthOk = $true; details = @{ Installed = $true } } }
function Get-mdiTimeSync { param($ComputerName, $MaxSkewMinutes) @{ isTimeSyncOk = $true; details = @{} } }

$script:scenario = ''

# An ADPrincipal stringifies to its distinguishedName. Reproduced exactly, because the [string[]]
# coercion described in the header means this ToString IS what the function ends up working with.
function New-CaMember {
    param($Name)
    $o = [PSCustomObject]@{ objectClass = 'computer'; Name = $Name; distinguishedName = "CN=$Name,OU=CAs,DC=fabrikam,DC=local" }
    $o | Add-Member -MemberType ScriptMethod -Name ToString -Value { $this.distinguishedName } -Force
    $o
}

function Get-ADDomain {
    param($Server, $ErrorAction)
    [PSCustomObject]@{ DNSRoot = $Server; DomainSID = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3' } }
}

function Get-ADGroupMember {
    param($Server, $Identity, $ErrorAction)
    switch ($script:scenario) {
        'throws' { throw 'Access is denied' }
        'none' { @() }
        default { New-CaMember 'cafab01'; New-CaMember 'cafab02' }
    }
}

function Get-ADComputer {
    param($Identity, $Server, $Properties, $ErrorAction)
    $isFirst = ([string] $Identity) -like 'CN=cafab01,*'
    switch ($script:scenario) {
        'readable' {
            $n = if ($isFirst) { 'cafab01' } else { 'cafab02' }
            [PSCustomObject]@{ DNSHostName = "$n.fabrikam.local"; IPv4Address = '10.10.1.60'; IPv6Address = $null; OperatingSystem = 'Windows Server 2022' }
        }
        'unreadable' { $null }
        'mixed' {
            if ($isFirst) { [PSCustomObject]@{ DNSHostName = 'cafab01.fabrikam.local'; IPv4Address = '10.10.1.60'; IPv6Address = $null; OperatingSystem = 'Windows Server 2022' } }
            else { $null }
        }
        'blank' { [PSCustomObject]@{ DNSHostName = '   '; IPv4Address = $null; IPv6Address = $null; OperatingSystem = $null } }
        # -CAServer supplied by the operator: the directory cannot confirm the name.
        'supplied' { $null }
        default { $null }
    }
}

Write-Host 'A discovered certification authority that could not be identified is reported unread, not unreachable'

# --- the shape this whole defect rests on --------------------------------------------------------
# Asserted rather than assumed: if a member ever stopped arriving as its DN, every scenario below
# would be testing something other than the product's real input.
$member = New-CaMember 'cafab01'
Assert-True 'a Cert Publishers member reaches the naming loop as its distinguished name' `
    (([string] $member) -eq 'CN=cafab01,OU=CAs,DC=fabrikam,DC=local') ("got '{0}'" -f ([string] $member))

# --- controls: the paths that were already correct and must stay correct -------------------------
$script:scenario = 'readable'
$readable = @(Get-mdiCAReadiness -Domain 'fabrikam.local')
Assert-True 'CONTROL: two readable CAs are reported as two real servers' `
    (($readable.Count -eq 2) -and (@($readable | Where-Object { $_.IsPlaceholder }).Count -eq 0)) `
    ("rows={0}" -f $readable.Count)
Assert-True 'CONTROL: a readable CA carries its DNS host name, not a distinguished name' `
    ($readable[0].FQDN -eq 'cafab01.fabrikam.local') ("got '{0}'" -f $readable[0].FQDN)

$script:scenario = 'throws'
$threw = @(Get-mdiCAReadiness -Domain 'fabrikam.local')
Assert-True 'CONTROL: a failed GROUP read still reports not-enumerated as an unread check' `
    (($threw.Count -eq 1) -and ($threw[0].SensorHealth -eq 'N/A') -and [bool] $threw[0].IsPlaceholder)

$script:scenario = 'none'
$none = @(Get-mdiCAReadiness -Domain 'fabrikam.local')
Assert-True 'CONTROL: a domain that genuinely runs no AD CS stays silent' ($none.Count -eq 0) `
    ("rows={0}" -f $none.Count)

# --- the defect: every discovered member unidentifiable ------------------------------------------
$script:scenario = 'unreadable'
$unread = @(Get-mdiCAReadiness -Domain 'fabrikam.local')

Assert-True 'both unidentifiable members are still accounted for, one row each' ($unread.Count -eq 2) `
    ("rows={0}" -f $unread.Count)

$dnRows = @($unread | Where-Object { [string] $_.FQDN -like '*CN=*' -and -not $_.IsPlaceholder })
Assert-True 'no row is emitted as a MACHINE whose FQDN is a distinguished name' ($dnRows.Count -eq 0) `
    ("rows carrying a DN as a real host: {0}" -f $dnRows.Count)

$falseReds = @($unread | Where-Object { $_.Unreachable })
Assert-True 'a CA that was never identified is NOT reported unreachable - nothing was contacted' `
    ($falseReds.Count -eq 0) ("rows marked Unreachable: {0}" -f $falseReds.Count)

Assert-True 'each unidentified CA is marked not-measured (N/A) so it is charged as an unread check' `
    ((@($unread | Where-Object { $_.SensorHealth -eq 'N/A' }).Count -eq 2))

Assert-True 'each unidentified CA is a placeholder, so it is not counted in the server KPIs as a machine' `
    ((@($unread | Where-Object { $_.IsPlaceholder }).Count -eq 2))

Assert-True 'the comment names the member so the operator can act on it' `
    ([string] $unread[0].Comment -like '*CN=cafab01,OU=CAs,DC=fabrikam,DC=local*')

Assert-True 'the unidentified rows are distinguishable from the not-enumerated row' `
    (([string] $unread[0].FQDN -like 'AD CS (not identified)*') -and ([string] $threw[0].FQDN -like 'AD CS (not enumerated)*'))

# --- partial loss: the readable one must not be lost, the unreadable one must not vanish ---------
$script:scenario = 'mixed'
$mixed = @(Get-mdiCAReadiness -Domain 'fabrikam.local')
Assert-True 'a partial loss keeps BOTH rows: one real server and one unread placeholder' `
    (($mixed.Count -eq 2) -and
        (@($mixed | Where-Object { -not $_.IsPlaceholder -and $_.FQDN -eq 'cafab01.fabrikam.local' }).Count -eq 1) -and
        (@($mixed | Where-Object { $_.IsPlaceholder }).Count -eq 1)) `
    ("rows={0}" -f $mixed.Count)

# One row per lost member, not one row for the group: discovering less of the estate must not
# improve the headline by shrinking the denominator.
Assert-True 'the loss costs one row per member, so the denominator reflects what was missed' `
    ((@($unread | Where-Object { $_.IsPlaceholder }).Count -eq 2) -and (@($mixed | Where-Object { $_.IsPlaceholder }).Count -eq 1))

# --- whitespace is the same fact as null ---------------------------------------------------------
$script:scenario = 'blank'
$blank = @(Get-mdiCAReadiness -Domain 'fabrikam.local')
Assert-True 'a dNSHostName of blanks is unreadable, not a host name (a non-empty string is truthy)' `
    ((@($blank | Where-Object { $_.IsPlaceholder }).Count -eq 2) -and (@($blank | Where-Object { $_.Unreachable }).Count -eq 0)) `
    ("placeholders={0}" -f (@($blank | Where-Object { $_.IsPlaceholder }).Count))

# --- the other direction: an operator-supplied name must stay probeable --------------------------
# This is what stops the fix from becoming its own defect. -CAServer is a host name the operator
# chose; a directory that cannot confirm it is not a reason to refuse to probe it.
$script:scenario = 'supplied'
$supplied = @(Get-mdiCAReadiness -Domain 'fabrikam.local' -CAServer 'ca-manual.fabrikam.local')
Assert-True 'an operator-supplied CA is still probed by name when the directory cannot confirm it' `
    (($supplied.Count -eq 1) -and ($supplied[0].FQDN -eq 'ca-manual.fabrikam.local') -and (-not $supplied[0].IsPlaceholder)) `
    ("rows={0} fqdn='{1}'" -f $supplied.Count, $supplied[0].FQDN)

Write-Host ''
Write-Host ("pass={0}  fail={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
