<#
    An NNR target the operator named must not be dropped because the run qualified it with the
    wrong domain.

    THE DEFECT THIS PINS. Resolve-mdiNnrTarget takes the hosts the operator listed in
    -NnrTargetComputer, tries to find each one in the directory, and then qualified the name
    unconditionally:

        $name = ConvertTo-mdiCanonicalComputerName -Value $name -Domain $Domain

    That line appends -Domain to any name carrying no dot. It can only CHANGE the name in two
    situations:

      (a) the Get-ADComputer lookup THREW - so there is positive evidence the host is not findable
          in $Domain - and the operator's name carries no dot. $Domain is stapled on anyway.
      (b) the lookup SUCCEEDED but DNSHostName was blank, so $computer.Name (a short name) is used.
          Qualifying is CORRECT here: the directory just confirmed the host is in that domain.

    In case (a) the result is a name that cannot exist in DNS. Get-mdiComputerAddress then resolves
    nothing, the target is dropped from the probe plan with only a warning, and
    Get-mdiUnresolvedNnrTarget reports it "unverified rather than ready". The operator asked "can
    the sensor resolve this host?" and the run never tried - and NNR is the feature whose failures
    this tool exists to explain.

    WHY IT SURVIVED, AND WHY THE LAB REACHES IT NOW. Resolve-mdiNnrTarget is the ONE call site that
    passes the operator's raw -Domain into that helper; every other call site passes a DNS domain
    name taken from discovery, where qualification is always right. In a single-forest run the
    operator's -Domain is the domain their targets live in, so the AD lookup succeeds and the
    qualification is a no-op. It takes a target that is NOT in -Domain to reach case (a), which is
    ordinary in the estate the lab gained on 17 August: -NnrTargetComputer names a workstation while
    -Domain names the other forest, or names a domain by its DISJOINT NetBIOS name - DNS
    fabrikam.local, NetBIOS FABCORP, which is not a case or trailing-dot variant of the DNS name but
    a different string entirely, and not a DNS suffix at all. -Domain is documented as accepting
    "Domain Name or FQDN", and Get-mdiPrimaryDomainAuditing was fixed earlier for exactly the
    -Domain FABCORP input, so a NetBIOS -Domain is already treated as legitimate operator input.

    MEASURED ON THE SHIPPED FUNCTION, one host whose bare name resolves to two addresses:

        -Domain <empty>          2 targets
        -Domain fabrikam.local   DROPPED   (name.fabrikam.local resolves to nothing)
        -Domain FABCORP          DROPPED   (name.fabcorp cannot exist in DNS)

    A bare short name still resolves through the client's DNS suffix search list and through
    NetBIOS. Qualifying it therefore DESTROYED a name that would have resolved.

    THE FIX. The qualified spelling stays PREFERRED, so case (b) and every single-forest run are
    unchanged. Only a qualification that resolved to NOTHING is reconsidered: the name as the
    operator supplied it is tried once before the target is dropped. A target that resolves under
    NEITHER spelling is still dropped - inventing a target nobody can reach would be the worse
    failure, and this must not manufacture one.

    Pinned here:

    1. A resolvable short name is kept as a target when -Domain names a domain it is not in,
       including the disjoint NetBIOS spelling FABCORP.
    2. Its ADDRESSES are the real ones, and every address is kept (a multi-homed target must not
       silently lose a NIC through this path).
    3. A host that resolves under neither spelling is STILL dropped - the fix must not invent a
       target.
    4. The no-qualification case (-Domain empty/null) is unchanged.
    5. When the qualified name DOES resolve, that is what is used - the preference order is not
       reversed, so the blank-DNSHostName path and every single-forest run keep today's behaviour.
    6. Unreadable -Domain shapes (a number, a boolean, whitespace) cannot drop a resolvable target
       either.
    7. The domain-controller fallback path (no -NnrTargetComputer) is untouched by this change.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Resolve-mdiNnrTarget') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

# The directory is not reachable from a test run, so Get-ADComputer throws - which IS the branch
# this defect lives in (case (a) above). Stubbed explicitly rather than relied upon, so the test
# pins the behaviour even on a machine that is domain-joined.
Set-Item -Path function:script:Get-ADComputer -Value { param($Identity, $Properties, $Server, $ErrorAction) throw 'no directory in a test run' }

# Name resolution is stubbed so the test does not depend on this machine's DNS, its suffix search
# list, or the lab being up. 'wks01' is the resolvable short name; nothing else resolves.
$script:resolvable = @{
    'wks01'      = @('10.10.1.51', '10.10.9.51')
    'single01'   = @('10.10.1.60')
    'wks02.mdilab.local' = @('10.10.1.70')
}
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param($ComputerName, $KnownAddress)
    $key = ([string] $ComputerName).ToLowerInvariant()
    if ($script:resolvable.ContainsKey($key)) { return @($script:resolvable[$key]) }
    @()
}

function Get-Targets {
    param([string[]] $Requested, $Domain)
    @(Resolve-mdiNnrTarget -DomainControllers @() -NnrTargetComputer $Requested -Domain $Domain -MaxTargets 5)
}

'--- 1. a resolvable short name survives a -Domain it does not belong to ---'
foreach ($d in @('fabrikam.local', 'FABCORP', 'mdilab.local', 'emea.mdilab.local')) {
    $t = Get-Targets -Requested @('wks01') -Domain $d
    Assert-That "-Domain $d keeps the target" (@($t).Count -gt 0) 'the target was dropped from the probe plan'
    Assert-That "-Domain $d reports the name the operator supplied" (@($t)[0].Name -eq 'wks01') "got $(@($t)[0].Name)"
}

'--- 2. every address is kept, and MultiHomed is right ---'
$t = Get-Targets -Requested @('wks01') -Domain 'FABCORP'
Assert-That 'both addresses of a multi-homed target are kept' (@($t).Count -eq 2) "got $(@($t).Count)"
$ips = @($t | ForEach-Object { $_.IP })
Assert-That 'the addresses are the real ones' ((($ips | Sort-Object) -join ',') -eq '10.10.1.51,10.10.9.51') ($ips -join ',')
Assert-That 'MultiHomed is true for a two-address target' (@($t)[0].MultiHomed -eq $true)
$single = Get-Targets -Requested @('single01') -Domain 'FABCORP'
Assert-That 'a single-address target is not marked MultiHomed' (@($single)[0].MultiHomed -eq $false)

'--- 3. a genuinely unresolvable target is STILL dropped (no invention) ---'
foreach ($d in @('fabrikam.local', 'FABCORP', $null)) {
    $shown = if ($null -eq $d) { '<null>' } else { $d }
    $t = Get-Targets -Requested @('does-not-exist') -Domain $d
    Assert-That "-Domain $shown drops an unresolvable target" (@($t).Count -eq 0) "invented $(@($t).Count) target(s)"
}

'--- 4. the no-qualification case is unchanged ---'
foreach ($d in @($null, '', '   ')) {
    $shown = if ($null -eq $d) { '<null>' } elseif ("$d" -eq '') { "''" } else { '<ws>' }
    $t = Get-Targets -Requested @('wks01') -Domain $d
    Assert-That "-Domain $shown keeps the target" (@($t).Count -eq 2) "got $(@($t).Count)"
    Assert-That "-Domain $shown uses the bare name" (@($t)[0].Name -eq 'wks01')
}

'--- 5. when the QUALIFIED name resolves, it is the one used ---'
# wks02.mdilab.local resolves; the bare wks02 does not. The qualified spelling must win, so the
# blank-DNSHostName path and every single-forest run keep today's behaviour.
$t = Get-Targets -Requested @('wks02') -Domain 'mdilab.local'
Assert-That 'the qualified name is preferred when it resolves' (@($t).Count -eq 1) "got $(@($t).Count)"
Assert-That 'and it is the qualified spelling that is reported' (@($t)[0].Name -eq 'wks02.mdilab.local') "got $(@($t)[0].Name)"
Assert-That 'with its address' (@($t)[0].IP -eq '10.10.1.70')

'--- 6. unreadable -Domain shapes cannot drop a resolvable target ---'
foreach ($d in @(636, $true, 'not a domain')) {
    $t = Get-Targets -Requested @('wks01') -Domain $d
    Assert-That "-Domain '$d' keeps the target" (@($t).Count -eq 2) "got $(@($t).Count)"
}

'--- 7. the domain-controller fallback path is untouched ---'
$dcs = @(
    [PSCustomObject]@{ Name = 'dc01.mdilab.local'; IP = '10.10.1.10'; Domain = 'mdilab.local' }
    [PSCustomObject]@{ Name = 'dcfab01.fabrikam.local'; IP = '10.10.1.50'; Domain = 'fabrikam.local' }
)
$t = @(Resolve-mdiNnrTarget -DomainControllers $dcs -Domain 'FABCORP' -MaxTargets 5)
Assert-That 'without -NnrTargetComputer the DC list is used verbatim' (@($t).Count -eq 2) "got $(@($t).Count)"
Assert-That 'and both forests are represented' (((@($t | ForEach-Object { $_.Domain }) | Sort-Object) -join ',') -eq 'fabrikam.local,mdilab.local')

''
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
