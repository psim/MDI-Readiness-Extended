# THE SELF-PROBE GUARD MUST NOT COLLAPSE WHEN NAME RESOLUTION FAILS, BECAUSE A COLLAPSED GUARD
# FABRICATES A PASS ON PORTS THAT WERE NEVER PROBED.
#
# Get-mdiLocalProbeAddress is what keeps Invoke-mdiPortProbePlan from aiming a probe at the machine
# it is running on. A probe aimed at one of this host's own addresses never leaves the host - the
# local stack serves it - and on a domain controller 389, 636, 3268 and 3269 are all listening
# locally, so it succeeds whatever a firewall between hosts would have done to the same packet.
#
# THE DEFECT. The guard built its list from [Net.Dns]::GetHostAddresses([Net.Dns]::GetHostName())
# inside a try whose catch was EMPTY, then appended 127.0.0.1 and ::1 unconditionally. "Which
# addresses are mine" is a fact the local IP stack HOLDS and DNS only reports second-hand, so any
# resolver fault - a SocketException while the DNS service restarts, a scavenged host record, a
# resolver refusing this caller - silently reduced the guard to loopback alone. Every routable
# address the machine owns then looked REMOTE and was probed.
#
# Its docstring defended that as the safe direction: "a fault in this helper must never be able to
# suppress probes that would otherwise have run." It is the wrong way round. The self target is not
# suppressed into nothing when the guard works - it is reported "Not tested - this domain controller
# is the server running the probe", and Get-mdiRequiredPorts turns that into N/A. When the guard
# fails, that honest N/A becomes a measured PASS. The fault does not lose a measurement, it invents
# one, and it moves the verdict towards ready.
#
# MEASURED END TO END on the shipped functions, one all-self DomainController plan with -MultiForest,
# the two runs differing in nothing but whether the lookup threw:
#
#     resolver answers   isRequiredPortsOk = N/A    rows 4   measured 0   succeeded 0
#     resolver throws    isRequiredPortsOk = True   rows 4   measured 4   succeeded 4
#
# The four are LdapTcp, LdapGcTcp, LdapsTcp and LdapsGcTcp, every one Required - LdapsTcp and
# LdapsGcTcp because -MultiForest promotes 636 and 3269 - and every one "Connected" to the machine
# that issued the probe.
#
# WHY IT IS AN ORDINARY ESTATE, NOT A CONTRIVED ONE. The LDAP sample is spread per DOMAIN, so a
# domain holding ONE domain controller gives that controller only ITSELF as a target. fabrikam.local,
# the second forest, holds exactly one. Run on it, the whole DomainController sample is the machine
# itself - the all-self plan this test builds.
#
# THE FIX. The interface list is asked FIRST and the resolver second, and the two are unioned. The
# IP stack does not depend on name resolution, so a resolver fault can no longer collapse the guard.
# Get-mdiHostNameAddress exists as the seam that lets this test make the resolver fail; a static
# .NET call cannot be made to throw from a test, which is why the failure could never be pinned
# while it was inlined.
#
# WHAT IS PINNED:
#   1. with the resolver throwing, the guard still reports this machine's own routable addresses
#   2. with the resolver throwing, an all-self plan still yields ZERO measured and ZERO successful
#      probes, and isRequiredPortsOk stays 'N/A'
#   3. the honest "this is the server running the probe" detail still reaches the operator
#   4. the seam travels to the remote sensor - omitting it from the shipped function list would make
#      every port probe on every server fail with a command-not-found

param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $scriptPath)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$text = [IO.File]::ReadAllText($scriptPath)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main'); if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([bool] $Condition, [string] $Message)
    if ($Condition) { $script:passed++; Write-Host ("  PASS  {0}" -f $Message) }
    else { $script:failed++; Write-Host ("  FAIL  {0}" -f $Message) -ForegroundColor Red }
}

Write-Host 'SelfProbeGuardSurvivesResolverFailure'

# The addresses this machine really owns, read the way the fix reads them. Loopback is excluded so
# the assertions below cannot be satisfied by the unconditional loopback pair.
$ownRoutable = @(
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        try {
            foreach ($unicast in $nic.GetIPProperties().UnicastAddresses) {
                $canonical = ConvertTo-mdiCanonicalIPAddress -Value $unicast.Address
                if ($null -ne $canonical -and (Test-mdiUsableComputerAddress -Value $canonical)) { $canonical }
            }
        } catch {
        }
    }
) | Select-Object -Unique

if (@($ownRoutable).Count -eq 0) {
    Write-Host '  SKIP  this host has no usable routable address of its own to guard'
    Write-Host ("RESULT passed={0} failed={1}" -f $script:passed, $script:failed)
    exit 0
}
$selfIp = @($ownRoutable)[0]

# ---------------------------------------------------------------------------------------------
# The resolver fault. This is the ONLY thing that changes.
Set-Item -Path function:script:Get-mdiHostNameAddress -Value {
    throw (New-Object System.Net.Sockets.SocketException 11001)
}

$guard = @(Get-mdiLocalProbeAddress)
Assert-True ($guard -contains $selfIp) `
    ("1. with the resolver throwing, the guard still holds this machine's own address {0}" -f $selfIp)
Assert-True (@($guard | Where-Object { Test-mdiUsableComputerAddress -Value $_ }).Count -gt 0) `
    '1b. the guard did not collapse to the loopback pair'

# ---------------------------------------------------------------------------------------------
# End to end: the all-self DomainController plan a single-controller domain produces, with the
# probes pointed at a port that is genuinely listening so "the local stack answers" is measured and
# not assumed. A domain controller has 389/636/3268/3269 open locally for the same reason.
$listenPort = 39390
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $listenPort)
$listener.Start()
try {
    $selfAsDc = [PSCustomObject]@{ Name = $env:COMPUTERNAME; Domain = 'fabrikam.local'; IP = $selfIp; Addresses = @($selfIp) }
    $plan = New-mdiPortProbePlan -Domain 'fabrikam.local' -DomainController @($selfAsDc) -TimeoutMs 400 -MultiForest
    $plan.Probes = @($plan.Probes | Where-Object { $_.Scope -eq 'DomainController' -and $_.Protocol -eq 'TCP' } |
            ForEach-Object { $copy = $_.PSObject.Copy(); $copy.Port = $listenPort; $copy })

    Assert-True (@($plan.Probes).Count -gt 0) '2a. the plan carries DomainController TCP probes to judge'
    Assert-True (@($plan.Probes | Where-Object { $_.Id -eq 'LdapsTcp' -and $_.Requirement -eq 'Required' }).Count -eq 1) `
        '2b. -MultiForest promoted LDAPS 636 to Required, so this is the multi-forest path'

    $verdict = Get-mdiRequiredPorts -ComputerName $env:COMPUTERNAME -Plan $plan -IsDomainController
    $rows = @($verdict.details.Results)
    $succeeded = @($rows | Where-Object { $_.Success -eq $true })
    $measured = @($rows | Where-Object { Test-mdiProbeWasMeasured -Record $_ })

    Assert-True ($succeeded.Count -eq 0) `
        ('2c. no probe aimed at this machine reported success (got {0})' -f $succeeded.Count)
    Assert-True ($measured.Count -eq 0) `
        ('2d. no probe aimed at this machine counted as measured (got {0})' -f $measured.Count)
    Assert-True ([string] $verdict.isRequiredPortsOk -eq 'N/A') `
        ("2e. isRequiredPortsOk stays 'N/A' rather than becoming a pass (got '{0}')" -f [string] $verdict.isRequiredPortsOk)
    Assert-True (@($verdict.details.FailedRequired).Count -eq 0) `
        '2f. and it is not reported as a failure either - nothing was measured'

    $honest = @($rows | Where-Object { [string] $_.Detail -like '*the server running the probe*' })
    Assert-True ($honest.Count -eq $rows.Count) `
        ('3. every row says it was not tested because it is the probing host ({0} of {1})' -f $honest.Count, $rows.Count)
} finally {
    $listener.Stop()
}

# ---------------------------------------------------------------------------------------------
# The seam has to reach the sensor. This script runs there with nothing but the named functions.
$shipped = [regex]::Match($text, "(?s)\`$functionNames\s*=\s*@\((.*?)\n\s*\)")
if (-not $shipped.Success) {
    # Fall back to a plain containment test over the whole file rather than failing on the shape of
    # a list this test does not own.
    Assert-True ($text -match "'Get-mdiHostNameAddress'") '4. Get-mdiHostNameAddress is named in the shipped function list'
} else {
    Assert-True ($shipped.Groups[1].Value -match "'Get-mdiHostNameAddress'") `
        '4. Get-mdiHostNameAddress travels to the remote sensor with Get-mdiLocalProbeAddress'
}

Write-Host ("RESULT passed={0} failed={1}" -f $script:passed, $script:failed)
if ($script:failed -gt 0) { exit 1 }
exit 0
