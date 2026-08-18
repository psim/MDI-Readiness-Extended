<#
    A disjoint NetBIOS domain name must not be left unresolved just because Active Directory Web
    Services could not answer.

    Resolve-mdiDomainScopeDnsName turns the NetBIOS spelling an administrator of a disjoint namespace
    is shown - DNS fabrikam.local, NetBIOS FABCORP - into the DNS name every comparison downstream is
    made against. Left unresolved, the run charges the domain-level unread check, raises a Discovery
    issue and refuses READY over a domain whose every domain controller was just examined and passed:
    a false red produced by nothing but the spelling of a parameter.

    It resolved that name through ONE reader, Get-ADDomain, which talks to Active Directory Web
    Services on TCP 9389. Get-mdiForestDomain has a whole LDAP fallback written because ADWS is "an
    optional service that can be stopped, firewalled, or refuse a restricted caller"; this function
    had none. It caught, kept the operator's spelling and returned. Measured with -Domain FABCORP on
    a fully scanned two-controller fabrikam.local estate: ADWS refusing the caller, ADWS filtered,
    ADWS stopped, and the AD module not being installed at all each produced scope FABCORP against
    rows spelled fabrikam.local, and Get-mdiUnexaminedDomain then reported FABCORP as unexamined. On
    a domain-joined workstation without RSAT - the ordinary case for a tool documented as runnable
    before any sensor exists - the disjoint namespace ALWAYS took that path, whatever the directory
    would have said.

    Pinned here: a second reader is tried whenever the first cannot answer OR answers with something
    unusable; the identical usability rule governs both readers, so a blank, whitespace, an IP
    address, a number or a dotless name that is not the request can never become the scope; the
    operator's spelling is still kept when no reader can answer; an already-qualified name is not
    read at all; and the disjoint NetBIOS spelling, once resolved, costs no unexamined domain.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = [IO.Path]::GetFullPath($target)
$text = [IO.File]::ReadAllText($target)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$mainStart = $body.IndexOf('#region Main')
if ($mainStart -gt 0) { $body = $body.Substring(0, $mainStart) }
Invoke-Expression $body

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:passed++
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray
    } else {
        $script:failed++
        Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red
    }
}

$script:said = @()
function Write-mdiVerbose { param($Message) $script:said += [string] $Message }
function Write-mdiWarning { param($Message) $script:said += 'WARN: ' + [string] $Message }

$script:adwsCalls = 0
$script:adwsBehaviour = $null
# Function:\global: is required. A function created by Set-Item inside a FUNCTION lands in that
# function's own scope and vanishes when it returns, so the shim would never be in place and every
# case below would silently measure the real Get-ADDomain.
function Set-Adws {
    param($Behaviour)
    $script:adwsBehaviour = $Behaviour
    Set-Item -Path Function:\global:Get-ADDomain -Value {
        param($Server, $ErrorAction)
        $script:adwsCalls++
        $b = $script:adwsBehaviour
        if ($b -is [string] -and $b -eq 'THROW') { throw 'Unable to contact the server (ADWS)' }
        [PSCustomObject]@{ DNSRoot = $b }
    }
}

# The second reader is a STATIC .NET call, which no shim function can replace, so it is observed
# through what it says rather than by interception: the message naming it can only be written if a
# second reader was actually tried. 'FABCORP' is not a domain this machine can contact, so that
# reader always fails here - which is the point. What is measured is whether it is REACHED.
function Invoke-Scope {
    param($Adws, [string] $Requested)
    Set-Adws -Behaviour $Adws
    $script:adwsCalls = 0
    $script:said = @()
    $result = Resolve-mdiDomainScopeDnsName -DomainName $Requested
    [PSCustomObject]@{
        Result       = $result
        AdwsCalls    = $script:adwsCalls
        SecondReader = @($script:said | Where-Object { $_ -match 'domain locator' }).Count -gt 0
    }
}

$answered = Invoke-Scope -Adws 'fabrikam.local' -Requested 'FABCORP'
$threw = Invoke-Scope -Adws 'THROW' -Requested 'FABCORP'
$blank = Invoke-Scope -Adws '' -Requested 'FABCORP'
$nullRoot = Invoke-Scope -Adws $null -Requested 'FABCORP'
$spaces = Invoke-Scope -Adws '   ' -Requested 'FABCORP'
$address = Invoke-Scope -Adws '10.10.1.50' -Requested 'FABCORP'
$number = Invoke-Scope -Adws 12345 -Requested 'FABCORP'
$otherNb = Invoke-Scope -Adws 'WRONGNB' -Requested 'FABCORP'
$echoed = Invoke-Scope -Adws 'FABCORP' -Requested 'FABCORP'
$collection = Invoke-Scope -Adws @('fabrikam.local') -Requested 'FABCORP'
$rootDot = Invoke-Scope -Adws 'fabrikam.local.' -Requested 'FABCORP'
$qualified = Invoke-Scope -Adws 'somethingelse.local' -Requested 'fabrikam.local'
$emptyName = Invoke-Scope -Adws 'THROW' -Requested ''
$nullName = Invoke-Scope -Adws 'THROW' -Requested $null

# What the unresolved spelling costs, on the definition three surfaces share.
$dcRows = @(
    [PSCustomObject]@{ FQDN = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; OperatingSystem = 'Windows Server 2022' }
    [PSCustomObject]@{ FQDN = 'dcfab02.fabrikam.local'; Domain = 'fabrikam.local'; OperatingSystem = 'Windows Server 2022' }
)
$unexaminedWhenResolved = @(Get-mdiUnexaminedDomain -ScopedDomain @($answered.Result) -Server $dcRows -DomainControllerServer $dcRows)
$unexaminedWhenKept = @(Get-mdiUnexaminedDomain -ScopedDomain @('FABCORP') -Server $dcRows -DomainControllerServer $dcRows)

Assert-True 'the function declares a reader that does not depend on Active Directory Web Services' (
    (Get-Command Resolve-mdiDomainScopeDnsName).Definition -match 'ActiveDirectory\.Domain'
) 'no ADWS-free reader is present'

Assert-True 'a first reader that answers resolves the disjoint NetBIOS name' (
    $answered.Result -eq 'fabrikam.local'
) ("Result={0}" -f $answered.Result)
Assert-True 'a first reader that answers is not second-guessed' (
    -not $answered.SecondReader
) 'a second reader ran even though the first answered'

Assert-True 'a first reader that throws falls through to a second reader' (
    $threw.SecondReader -and $threw.AdwsCalls -eq 1
) ("SecondReader={0}; AdwsCalls={1}" -f $threw.SecondReader, $threw.AdwsCalls)
Assert-True 'an answer of blank falls through rather than ending the search' (
    $blank.SecondReader
) 'a blank answer ended the search'
Assert-True 'an answer of $null falls through rather than ending the search' (
    $nullRoot.SecondReader
) 'a null answer ended the search'
Assert-True 'an answer of whitespace falls through rather than ending the search' (
    $spaces.SecondReader
) 'a whitespace answer ended the search'
Assert-True 'an answer that is an IP address falls through rather than ending the search' (
    $address.SecondReader
) 'an address ended the search'
Assert-True 'an answer that is a number falls through rather than ending the search' (
    $number.SecondReader
) 'a number ended the search'
Assert-True 'a dotless answer that is not the requested name falls through' (
    $otherNb.SecondReader
) 'a dotless answer that is not the request ended the search'

Assert-True 'nothing unusable can become the scope - the operator spelling is kept' (
    $threw.Result -eq 'FABCORP' -and $blank.Result -eq 'FABCORP' -and $nullRoot.Result -eq 'FABCORP' -and
    $spaces.Result -eq 'FABCORP' -and $address.Result -eq 'FABCORP' -and $number.Result -eq 'FABCORP' -and
    $otherNb.Result -eq 'FABCORP'
) ("threw={0}; blank={1}; null={2}; spaces={3}; address={4}; number={5}; otherNb={6}" -f
    $threw.Result, $blank.Result, $nullRoot.Result, $spaces.Result, $address.Result, $number.Result, $otherNb.Result)

Assert-True 'an answer equal to the request is accepted, as a single-label DNS forest requires' (
    $echoed.Result -eq 'FABCORP' -and -not $echoed.SecondReader
) ("Result={0}; SecondReader={1}" -f $echoed.Result, $echoed.SecondReader)
Assert-True 'an answer arriving as a collection is still read' (
    $collection.Result -eq 'fabrikam.local' -and -not $collection.SecondReader
) ("Result={0}" -f $collection.Result)
Assert-True 'an answer carrying the DNS root dot is normalised, not rejected' (
    $rootDot.Result -eq 'fabrikam.local' -and -not $rootDot.SecondReader
) ("Result={0}" -f $rootDot.Result)

Assert-True 'an already-qualified name is not read from any directory' (
    $qualified.Result -eq 'fabrikam.local' -and $qualified.AdwsCalls -eq 0 -and -not $qualified.SecondReader
) ("Result={0}; AdwsCalls={1}; SecondReader={2}" -f $qualified.Result, $qualified.AdwsCalls, $qualified.SecondReader)
Assert-True 'control: an unreadable domain name reads nothing and returns nothing' (
    $emptyName.Result -eq '' -and $emptyName.AdwsCalls -eq 0 -and
    $nullName.Result -eq '' -and $nullName.AdwsCalls -eq 0
) ("empty={0}/{1}; null={2}/{3}" -f $emptyName.Result, $emptyName.AdwsCalls, $nullName.Result, $nullName.AdwsCalls)

Assert-True 'the resolved scope costs no unexamined domain over a fully scanned estate' (
    $unexaminedWhenResolved.Count -eq 0
) ("unexamined={0}" -f (@($unexaminedWhenResolved) -join ','))
Assert-True 'control: the unresolved NetBIOS spelling is what produces the false red' (
    $unexaminedWhenKept.Count -eq 1 -and $unexaminedWhenKept[0] -eq 'FABCORP'
) ("unexamined={0}" -f (@($unexaminedWhenKept) -join ','))

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
