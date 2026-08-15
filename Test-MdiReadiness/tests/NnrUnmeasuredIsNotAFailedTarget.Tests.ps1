# An NNR target whose probes never RAN was stored as a MEASURED required-ports failure.
#
# Get-mdiRequiredPorts builds two failure lists from the same $applicable set, fourteen lines apart.
# The mandatory one is guarded, with a comment saying exactly why:
#
#     # Failure means a probe RAN and the port did not answer. Routed through the shared predicate
#     # rather than a bare "-not $_.Success", which is truthy for the $null of a probe that never
#     # produced a result ...
#     $mandatoryMeasured = @($mandatory | Where-Object { Test-mdiProbeWasMeasured -Record $_ })
#
# The NNR one asked only "did any member report success". A probe that never ran reports no success,
# so a target whose every method was unmeasured landed in $nnrFailedTargets beside a target that
# answered and refused - and because the 'N/A' branch of the verdict requires that list to be empty,
# the check stored False rather than "not tested".
#
# Measured on the shipped function, the two adjacent filters given the IDENTICAL condition:
#
#     required probes never ran -> isRequiredPortsOk = N/A   , FailedRequired   empty   (guarded)
#     NNR probes never ran      -> isRequiredPortsOk = False , NnrFailedTargets 'wks1.contoso.com (::1)'
#
# It needs nothing unusual to reach: an NNR target that resolves to IPv6 only cannot be probed, and
# the socket exception is exactly the "Not tested - ..." detail those records carry. The consequence is
# a false RED - an operator sent to open TCP 135, UDP 137 and TCP 3389 on a device nobody could test.
#
# The fix has TWO halves and the second is the one that matters. Excluding unmeasured probes from the
# failure list ALONE turns the false red into the "empty-scan false green" the mandatory comment warns
# about - measured while making this change, the first attempt produced isRequiredPortsOk = True on a
# run where no NNR probe ran at all. Nothing blocked and nothing tested is 'N/A'.
#
# NOTE ON METHOD. These assertions drive the SHIPPED Get-mdiRequiredPorts and stub only at the socket
# boundary. An earlier draft of this file re-implemented the filtering rule locally and asserted on the
# copy; it passed identically with the defect reintroduced, which makes it worthless. The unroutable
# address is handed to the REAL Test-mdiTcpPort / Test-mdiUdpPort, so the "never ran" record is the
# producer's own rather than a fixture.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
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

$script:realTcp = (Get-Item function:Test-mdiTcpPort).ScriptBlock
$script:realUdp = (Get-Item function:Test-mdiUdpPort).ScriptBlock
$script:unroutable = '::1'       # handed to the REAL probe, which cannot reach it: a genuine "never ran"
$script:refusedIp = '10.0.0.99'  # stub answers with the shipped refusal shape: a genuine measured failure

Set-Item -Path function:script:Test-mdiTcpPort -Value {
    param([string] $ComputerName, [int] $Port, [int] $TimeoutMs = 1500, [switch] $IsRetry)
    if ($ComputerName -eq $script:unroutable) { return (& $script:realTcp -ComputerName $ComputerName -Port $Port -TimeoutMs $TimeoutMs) }
    if ($ComputerName -eq $script:refusedIp) {
        return [PSCustomObject]@{ Success = $false; Detail = 'Closed - connection refused (No connection could be made because the target machine actively refused it)'; LatencyMs = 2 }
    }
    [PSCustomObject]@{ Success = $true; Detail = 'Connected'; LatencyMs = 1 }
}
Set-Item -Path function:script:Test-mdiUdpPort -Value {
    param([string] $ComputerName, [int] $Port, [int] $TimeoutMs = 1500, $Payload, $ExpectedTransactionId, $ResponseValidator)
    if ($ComputerName -eq $script:unroutable) { return (& $script:realUdp -ComputerName $ComputerName -Port $Port -TimeoutMs $TimeoutMs -Payload $Payload -ExpectedTransactionId $ExpectedTransactionId -ResponseValidator $ResponseValidator) }
    if ($ComputerName -eq $script:refusedIp) {
        return [PSCustomObject]@{ Success = $false; Detail = 'Closed - connection refused (ICMP port unreachable)'; LatencyMs = 2 }
    }
    [PSCustomObject]@{ Success = $true; Detail = 'Answered by a DNS server (1 answer record(s))'; LatencyMs = 1 }
}
Set-Item -Path function:script:Test-mdiCloudConnectivity -Value { param($Url, $TimeoutMs) [PSCustomObject]@{ Success = $true; Detail = 'Reachable'; LatencyMs = 1 } }
Set-Item -Path function:script:Test-mdiLocalTcpListener -Value { param($Port) @('listening') }
Set-Item -Path function:script:Get-mdiConfiguredDnsServer -Value { [PSCustomObject]@{ Measured = $true; Servers = @('10.0.0.53'); Detail = $null } }
Set-Item -Path function:script:Get-mdiPtrHostEntry -Value {
    param([string] $IPAddress, [int] $TimeoutMs = 3000)
    if ($IPAddress -eq $script:unroutable) { return [PSCustomObject]@{ TimedOut = $true; HostEntry = $null } }
    [PSCustomObject]@{ TimedOut = $false; HostEntry = [PSCustomObject]@{ HostName = 'resolved.contoso.com' } }
}
Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value { param($ComputerName) 'C:\Windows\Temp' }
Set-Item -Path function:script:New-mdiRemoteScriptFile -Value { param($ComputerName, $ScriptText, $Folder) $null }

$dcTargets = @([PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '10.0.0.10' })

function Invoke-Case {
    param($Name, $IP)
    $plan = New-mdiPortProbePlan -Domain 'contoso.com' -WorkspaceName 'ws' `
        -DomainController $dcTargets -NnrTarget @([PSCustomObject]@{ Name = $Name; IP = $IP }) -TimeoutMs 400
    $script:planUnderTest = $plan
    Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
        param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds)
        @((Invoke-mdiPortProbePlan -Plan $script:planUnderTest) | ConvertTo-Json -Depth 6 -Compress)
    }
    $r = Get-mdiRequiredPorts -ComputerName 'dc1.contoso.com' -Plan $plan
    [PSCustomObject]@{
        Ok     = [string] $r.isRequiredPortsOk
        Nnr    = (@($r.details.NnrFailedTargets) -join ', ')
        Failed = (@($r.details.FailedRequired) -join ', ')
    }
}

'[nnr measurement] a target nobody could probe is NOT a measured failure'
$never = Invoke-Case 'wks1.contoso.com' $script:unroutable
Assert-That 'an entirely unmeasured NNR target is not named as failed' ([string]::IsNullOrWhiteSpace($never.Nnr)) "(got '$($never.Nnr)')"
Assert-That '  ...and the check is not False' ($never.Ok -ne 'False') "(got '$($never.Ok)')"
# ...and it must not become a pass either - that is the empty-scan false green the sibling warns about.
Assert-That '  ...and not True: nothing tested is N/A' ($never.Ok -eq 'N/A') "(got '$($never.Ok)')"

''
'[nnr measurement] a target that answered and refused is still a failure'
# The narrowing must not cost a real detection - this is the whole point of the NNR check.
$shut = Invoke-Case 'wks2.contoso.com' $script:refusedIp
Assert-That 'a measured-shut NNR target is named as failed' ($shut.Nnr -match 'wks2\.contoso\.com') "(got '$($shut.Nnr)')"
Assert-That '  ...and the check is False' ($shut.Ok -eq 'False') "(got '$($shut.Ok)')"

''
'[nnr measurement] a target that resolves still passes'
$open = Invoke-Case 'wks3.contoso.com' '10.0.0.5'
Assert-That 'a resolvable NNR target is not named as failed' ([string]::IsNullOrWhiteSpace($open.Nnr)) "(got '$($open.Nnr)')"
Assert-That '  ...and the check is True' ($open.Ok -eq 'True') "(got '$($open.Ok)')"

''
'[nnr measurement] the three outcomes are genuinely distinct'
# If any two of these collapse, the check has lost the distinction it exists to make.
Assert-That 'never-ran, refused and open give three different answers' (
    (@($never.Ok, $shut.Ok, $open.Ok) | Select-Object -Unique).Count -eq 3
) "(got '$($never.Ok)' / '$($shut.Ok)' / '$($open.Ok)')"

''
'[nnr measurement] the guard is present in both halves'
# Asserted on the canonical text too, so neither half can be dropped again without a red test.
$src = Get-Content -LiteralPath $target -Raw
Assert-That 'the NNR failure list is filtered through the measured-probe predicate' (
    $src -match '\$nnrMeasuredProbes\s*=\s*@\(\$nnrProbes\s*\|\s*Where-Object\s*\{\s*Test-mdiProbeWasMeasured'
) '(the NNR failure list is unguarded again)'
Assert-That 'the not-measured verdict branch consults the NNR unmeasured count' (
    $src -match '\$mandatoryUnmeasured\.Count -gt 0 -or \$nnrUnmeasuredTargets\.Count -gt 0'
) '(the N/A branch ignores unmeasured NNR targets)'

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
