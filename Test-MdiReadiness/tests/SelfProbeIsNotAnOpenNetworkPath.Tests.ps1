# A DOMAIN CONTROLLER MUST NOT PROBE ITSELF AND REPORT THE RESULT AS AN OPEN NETWORK PATH.
#
# Invoke-mdiPortProbePlan runs ON the sensor server and walked $Plan.DomainControllers and
# $Plan.NnrTargets with no exclusion of the machine it was running on. A TCP or UDP probe aimed at
# one of the host's OWN addresses never leaves the host - the local stack serves it - and on a
# domain controller 389, 636, 3268 and 3269 are all listening locally. So that probe succeeded
# whatever a firewall between hosts would have done to the same packet: a value nobody measured,
# wearing the shape of a measurement.
#
# The script already made this exact argument about 127.0.0.1, in Resolve-mdiLdapTarget's own
# comment ("the probe cannot be the guard - measured, Test-mdiTcpPort against 127.0.0.1 returns
# Success=True / 'Connected'"), and Test-mdiUsableComputerAddress duly rejects loopback, APIPA,
# 0.0.0.0 and the IPv6 any address. It does NOT reject a domain controller's own routable address,
# because that address is perfectly usable - for everybody except the machine that owns it.
#
# WHY IT DECIDED A VERDICT RATHER THAN JUST WASTING A PROBE. The LDAP sample is spread per DOMAIN
# (-MaxLdapTargetsPerDomain, default 2), so a domain holding ONE domain controller gives that
# controller only ITSELF as a target. Measured on dc2022 with exactly the plan the product builds
# for a single-controller domain: LdapTcp, LdapUdp, LdapGcTcp, LdapsTcp and LdapsGcTcp all reported
# open, mandatory failures 0, unmeasured 0, and isRequiredPortsOk came back True. -MultiForest
# promotes LDAPS 636 and LDAPS-GC 3269 from Optional to Required, so the two ports a multi-forest
# deployment turns on were certified the same way - and fabrikam.local, the second forest the lab
# gained on 17 August, holds exactly one domain controller.
#
# Proven blocked at the same time, same address and ports, two source hosts:
#     from dc2022 (which owns 10.10.1.12):  10.10.1.12:389 connected=True   :636 connected=True
#     from dc2016:                          10.10.1.12:389 connected=False  :636 connected=False
# The path is shut. The self-probe reported it open.
#
# The fix must ALSO not overcorrect. A self target sitting beside a genuinely remote one must be
# dropped silently - the remote target carries the measurement - and must not drag a real result to
# 'N/A'. Turning good measurements into "not tested" would be a worse regression than the defect,
# so that case is pinned here just as hard as the defect itself.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The host's own addresses are FIXED for this test rather than read from the machine, so the test
# asserts the same thing on a laptop, a build agent and a domain controller.
$script:selfIp = '10.10.1.12'
$script:remoteIp = '10.10.1.99'
function Get-mdiLocalProbeAddress { @($script:selfIp, '127.0.0.1', '::1') }

# Every transport answers SUCCESS. That is precisely what a connection to the machine's own address
# does on a domain controller, and it is what makes the defect invisible: with these shadows in
# place, any probe that is actually ISSUED comes back open. A record that is open therefore proves
# the probe was issued, and a record that is "Not tested" proves it was not.
function Test-mdiTcpPort { param($ComputerName, $Port, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'Connected'; LatencyMs = 1 } }
function Test-mdiUdpPort { param($ComputerName, $Port, $TimeoutMs, $Payload, $ResponseValidator, $ExpectedTransactionId) [PSCustomObject]@{ Success = $true; Detail = 'Replied'; LatencyMs = 1 } }
function Test-mdiNnrNetBios { param($ComputerName, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'Resolved to: DC'; LatencyMs = 1 } }
function Test-mdiReverseDns { param($IPAddress, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'Resolved'; LatencyMs = 1 } }
function Get-mdiConfiguredDnsServer { [PSCustomObject]@{ Servers = @(); Measured = $true; Detail = $null } }
function Test-mdiLocalTcpListener { param($Port) @() }
function Test-mdiLocalUdpListener { param($Port) [PSCustomObject]@{ Success = $true; Detail = 'Listening' } }
function Test-mdiCloudConnectivity { param($Url, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'Connected' } }

function New-Target {
    param([string] $Name, [string] $Ip)
    [PSCustomObject]@{ Name = $Name; IP = $Ip; MultiHomed = $false; Domain = 'fabrikam.local' }
}

function Get-PlanDetail {
    param($DcTargets, $NnrTargets)
    $plan = New-mdiPortProbePlan -Domain 'fabrikam.local' -DomainController $DcTargets -NnrTarget $NnrTargets `
        -TimeoutMs 500 -MultiForest
    # ASSIGN BEFORE WRAPPING: Invoke-mdiPortProbePlan returns ", $results.ToArray()", so the pipeline
    # emits ONE object that IS the record array and @(...) would count it as a single element.
    $raw = Invoke-mdiPortProbePlan -Plan $plan
    @($raw)
}

$selfOnly = @(New-Target -Name 'dcfab01.fabrikam.local' -Ip $script:selfIp)
$bothTargets = @((New-Target -Name 'dcfab01.fabrikam.local' -Ip $script:selfIp), (New-Target -Name 'dcfab02.fabrikam.local' -Ip $script:remoteIp))

'[self-only plan] the single-controller domain - nothing was really probed'
$selfDetails = Get-PlanDetail -DcTargets $selfOnly -NnrTargets $selfOnly
$selfDc = @($selfDetails | Where-Object { $_.Scope -eq 'DomainController' })
$selfNnr = @($selfDetails | Where-Object { $_.Scope -eq 'NetworkDevice' })

Assert-That 'the DomainController scope still produces records' ($selfDc.Count -gt 0) "(got $($selfDc.Count))"
Assert-That 'no required LDAP/GC/LDAPS port is reported open against the host itself' (
    @($selfDc | Where-Object { $_.Success -eq $true }).Count -eq 0
) "($(@($selfDc | Where-Object { $_.Success -eq $true }).Count) reported open)"
Assert-That '  ...they are recorded as NOT TESTED, not as blocked' (
    @($selfDc | Where-Object { [string] $_.Detail -match '^Not tested' }).Count -eq $selfDc.Count
)
Assert-That '  ...so Test-mdiProbeWasMeasured treats none of them as a measurement' (
    @($selfDc | Where-Object { Test-mdiProbeWasMeasured -Record $_ }).Count -eq 0
)
# The two ports -MultiForest promotes to Required are named explicitly: they are the whole reason a
# multi-forest deployment runs this check, and a general assertion would not notice losing just them.
foreach ($promoted in 'LdapsTcp', 'LdapsGcTcp') {
    $row = @($selfDc | Where-Object { $_.Id -eq $promoted })
    Assert-That ("  ...including {0}, which -MultiForest promotes to Required" -f $promoted) (
        $row.Count -gt 0 -and @($row | Where-Object { $_.Success -eq $true }).Count -eq 0
    )
}
Assert-That 'the NNR scope is not resolved by the host answering itself either' (
    @($selfNnr | Where-Object { $_.Success -eq $true }).Count -eq 0
) "($(@($selfNnr | Where-Object { $_.Success -eq $true }).Count) reported resolved)"

# The verdict the report actually carries, assembled with the shipped predicates.
$applicable = @($selfDetails | Where-Object { $_.Applicable -eq $true })
$mandatory = @($applicable | Where-Object { Test-mdiRequirementIsMandatory -Requirement $_.Requirement })
$measured = @($mandatory | Where-Object { Test-mdiProbeWasMeasured -Record $_ })
$failures = @($measured | Where-Object { -not $_.Success })
$unmeasured = @($mandatory | Where-Object { -not (Test-mdiProbeWasMeasured -Record $_) })
Assert-That 'a plan whose only target was the host itself has unmeasured required probes' ($unmeasured.Count -gt 0)
Assert-That '  ...and no required probe is counted as a measured failure' ($failures.Count -eq 0) "($($failures.Count) failures)"

'[mixed plan] a self target beside a real one must not cost the real measurement'
$bothDetails = Get-PlanDetail -DcTargets $bothTargets -NnrTargets $bothTargets
$bothDc = @($bothDetails | Where-Object { $_.Scope -eq 'DomainController' })
Assert-That 'the remote domain controller is still probed' (
    @($bothDc | Where-Object { [string] $_.TargetIP -eq $script:remoteIp -and $_.Success -eq $true }).Count -gt 0
)
Assert-That '  ...and the host itself contributes no record at all' (
    @($bothDc | Where-Object { [string] $_.TargetIP -eq $script:selfIp }).Count -eq 0
) "($(@($bothDc | Where-Object { [string] $_.TargetIP -eq $script:selfIp }).Count) self records)"
Assert-That '  ...so nothing is left unmeasured by the presence of a self target' (
    @($bothDc | Where-Object { -not (Test-mdiProbeWasMeasured -Record $_) }).Count -eq 0
)

'[unreadable target shapes] must not be mistaken for the host, and must not read as reached'
foreach ($shape in @(
        @{ Label = 'null'; Ip = $null }
        @{ Label = 'empty string'; Ip = '' }
        @{ Label = 'non-numeric string'; Ip = 'not-an-ip' }
    )) {
    $t = @([PSCustomObject]@{ Name = 'shape'; IP = $shape.Ip; MultiHomed = $false; Domain = 'fabrikam.local' })
    $d = @((Get-PlanDetail -DcTargets $t -NnrTargets @()) | Where-Object { $_.Scope -eq 'DomainController' })
    # An unreadable address is NOT this machine, so the probe must still be attempted rather than
    # silently suppressed by the self-target guard - suppressing it would lose the estate quietly,
    # which is the failure this whole family is about.
    Assert-That ("a target whose IP is {0} is not treated as the host itself" -f $shape.Label) (
        @($d | Where-Object { [string] $_.Detail -match 'server running the probe' }).Count -eq 0
    )
}

# A row whose IP is the host's own address wrapped in an array is still the host. It must not be
# probed - ConvertTo-mdiCanonicalIPAddress reads through the wrapper, and the guard must use it.
$wrapped = @([PSCustomObject]@{ Name = 'shape'; IP = @($script:selfIp); MultiHomed = $false; Domain = 'fabrikam.local' })
$wrappedDc = @((Get-PlanDetail -DcTargets $wrapped -NnrTargets @()) | Where-Object { $_.Scope -eq 'DomainController' })
Assert-That 'the host address wrapped in an array is still recognised as the host' (
    @($wrappedDc | Where-Object { $_.Success -eq $true }).Count -eq 0
)

# The helper is shipped to the sensor inside the generated command line. If it is missing from that
# list the remote script cannot resolve it and EVERY port probe on EVERY server fails with a
# command-not-found - a far worse outcome than the defect this test pins.
$scriptText = Get-Content -LiteralPath $target -Raw
$fnListMatch = [regex]::Match($scriptText, '(?s)\$functionNames = @\((.*?)\)\r?\n')
Assert-That 'Get-mdiLocalProbeAddress is shipped to the sensor with the other probe primitives' (
    $fnListMatch.Success -and $fnListMatch.Groups[1].Value -match "'Get-mdiLocalProbeAddress'"
)

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
