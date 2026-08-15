# A DISCOVERY PLACEHOLDER - a domain controller record with no name to connect to - was counted as a
# host the network probes could have visited, so a fully probed estate announced that it had sampled.
#
# Three sites filtered the DC inventory down to "hosts we could have probed" and all three asked only
# whether the row was UNREACHABLE:
#
#     $portCandidateHost = @(@($ReportData.DomainControllers) | Where-Object { $_ -and -not (Test-mdiServerIsUnreachable -Server $_) } | ...)   -> PortCandidateHostCount
#     NnrCandidateCount  = @(@($ReportData.DomainControllers) | Where-Object { $_ -and -not (Test-mdiServerIsUnreachable -Server $_) } | ...).Count
#     if ($sensorHosts.Count -eq 0) { $sensorHosts = @(@($ReportData.DomainControllers) | Where-Object { $_ -and -not (Test-mdiServerIsUnreachable -Server $_) }) }   # the pre-deployment fallback in New-mdiRemediationScript
#
# A placeholder is the same class of gap as an unreachable server, in a stronger form: it is not a
# machine at all. Get-mdiDomainControllerReadiness emits it for a directory record carrying neither
# dNSHostName nor Name, and keeps it "out of $DomainController, which is a list of names to connect to
# and there is no name to connect to" - so by construction it can NEVER appear in a probe plan.
#
# Measured on the shipped functions, one real reachable DC plus two unnamed records:
#
#     PortCandidateHostCount 1 -> 3 , NnrCandidateCount 1 -> 3
#     console verdict gained ' (network probes used a sample: ports 1 of 3 host(s), raise
#     -MaxLdapTargetsPerDomain; name resolution 1 of 3 host(s), raise -MaxNnrTargets)'
#
# and the generated remediation script gained a block naming both phantoms as sensor servers whose
# "NNR probes will still fail", telling the operator to re-run "once those servers resolve" - which can
# never happen, because the gap is a missing dNSHostName, not a name-resolution failure. The advice is
# inert in the other direction too: no value of -MaxLdapTargetsPerDomain can widen a probe to a host
# that has no address. Worse, it runs the wrong way round on the headline - the COMPLETE estate is
# described as sampled, which devalues the disclosure on runs where a sample was genuinely taken.
#
# The guarded siblings a few lines away (the server-count populations, the sensor populations) already
# excluded placeholders, so two surfaces of one idea disagreed. Both clauses now live in the single
# predicate Test-mdiServerIsProbeCandidate, which is what all three sites call.
#
# NOTE ON METHOD. Every placeholder row here is produced by the SHIPPED Get-mdiDomainControllerReadiness
# from a Resolve-mdiDomainController result reporting Unnamed = 2; none is hand-built. The counters come
# from the shipped Get-mdiReportStatistics, the console clause from the shipped Get-mdiVerdictQualifier,
# and the remediation text from the shipped New-mdiRemediationScript. Stubs sit only at the OS boundary.
#
# TWO ASSERTIONS GUARD AGAINST OVER-CORRECTING, and they matter as much as the rest: a placeholder must
# still be CHARGED and still be SURFACED. It keeps its High 'Discovery' finding in the generated
# script's manual-attention list, and the genuinely unreachable server keeps its own. A "fix" that
# simply dropped placeholders from the report would satisfy the counters and silently lose the finding.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
$script:warns = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:warns.Add([string] $Message) }

# ---- OS boundary stubs -------------------------------------------------------------------------
$script:unnamedCount = 0
$script:dcNames = @()
$script:unreachableHosts = @()
$script:sensorPresent = $true

Set-Item -Path function:script:Resolve-mdiDomainController -Value {
    param($Domain)
    [PSCustomObject]@{
        Servers = @($script:dcNames | ForEach-Object { [PSCustomObject]@{ Name = $_ } })
        Method  = 'LDAP'; Error = $null; Unnamed = $script:unnamedCount
    }
}
Set-Item -Path function:global:Get-ADObject -Value { param($Filter, $Server, $ErrorAction) $null }
Set-Item -Path function:global:Get-ADComputer -Value {
    param($Identity, $Server, $Properties, $ErrorAction)
    [PSCustomObject]@{ DNSHostName = [string] $Identity; IPv4Address = '10.0.0.11'; OperatingSystem = 'Windows Server 2022' }
}
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param($ComputerName, $KnownAddress)
    switch -Wildcard ([string] $ComputerName) {
        'dc1*' { @('10.0.0.11') }
        'dc2*' { @('10.0.0.12') }
        'dc3*' { @('10.0.0.13') }
        default { @() }
    }
}
Set-Item -Path function:script:Test-mdiServerReachable -Value {
    param($ComputerName)
    if ($script:unreachableHosts -contains [string] $ComputerName) { [PSCustomObject]@{ Reachable = $false; Method = 'ICMP, TCP 135, WMI' } }
    else { [PSCustomObject]@{ Reachable = $true; Method = 'ICMP' } }
}
Set-Item -Path function:script:Get-mdiServerRequirements -Value { param($ComputerName) @{ isMinHwRequirementsOk = $true; details = [ordered]@{} } }
Set-Item -Path function:script:Get-mdiPowerScheme -Value { param($ComputerName) @{ isPowerSchemeOk = $true; details = [ordered]@{} } }
Set-Item -Path function:script:Get-mdiAdvancedAuditing -Value { param($ComputerName, $ExpectedAuditing) @{ isAdvancedAuditingOk = $true; details = [ordered]@{} } }
Set-Item -Path function:script:Get-mdiNtlmAuditing -Value { param($ComputerName) @{ isNtlmAuditingOk = $true; details = [ordered]@{} } }
Set-Item -Path function:script:Get-mdiCertReadiness -Value { param($ComputerName) @{ isRootCertificatesOk = $true; details = [ordered]@{} } }
Set-Item -Path function:script:Get-mdiSensorVersion -Value { param($ComputerName) if ($script:sensorPresent) { '2.246.0' } else { 'Not installed' } }
Set-Item -Path function:script:Get-mdiCaptureComponent -Value { param($ComputerName) 'Npcap' }
Set-Item -Path function:script:Get-mdiMachineType -Value { param($ComputerName) 'VMware' }
Set-Item -Path function:script:Get-mdiOSVersion -Value { param($ComputerName) @{ isOsVerOk = $true; details = [ordered]@{} } }
Set-Item -Path function:script:Get-mdiSensorHealth -Value {
    param($ComputerName)
    if ($script:sensorPresent) { @{ isSensorHealthOk = $true; details = [ordered]@{ Installed = $true; UpdaterService = 'Running' } } }
    else { @{ isSensorHealthOk = $false; details = [ordered]@{ Installed = $false; UpdaterService = 'Not installed' } } }
}
Set-Item -Path function:script:Get-mdiTimeSync -Value { param($ComputerName, $MaxSkewMinutes) @{ isTimeSyncOk = $true; details = [ordered]@{} } }
$script:MaxClockSkewMinutes = 5

# Built from the REAL $settings.RequiredPorts table so Group/Requirement are the shipped values.
# $script:nnrBlocked selects between "everything answered" (the scope cases) and "every NNR method
# against wks1 was measured shut" (the remediation case, which is what makes the generator emit an
# NNR firewall section at all).
$script:nnrBlocked = $false
Set-Item -Path function:script:Get-mdiRequiredPorts -Value {
    param($ComputerName, $Plan)
    $results = @($settings.RequiredPorts | ForEach-Object {
            if ($script:nnrBlocked -and [string] $_.Group -eq 'NNR') {
                [PSCustomObject]@{ Id = $_.Id; Name = $_.Name; Protocol = $_.Protocol; Port = $_.Port
                    Scope = $_.Scope; Group = $_.Group; Requirement = $_.Requirement
                    Target = 'wks1.contoso.com'; TargetIP = '10.0.0.77'
                    Applicable = $true; Success = $false; Detail = 'Connection refused'
                }
            } else {
                [PSCustomObject]@{ Id = $_.Id; Name = $_.Name; Protocol = $_.Protocol; Port = $_.Port
                    Scope = $_.Scope; Group = $_.Group; Requirement = $_.Requirement
                    Target = [string] $ComputerName; TargetIP = '10.0.0.11'
                    Applicable = $true; Success = $true; Detail = 'Connected'
                }
            }
        })
    if ($script:nnrBlocked) {
        @{ isRequiredPortsOk = $false; details = [ordered]@{ Results = $results; FailedRequired = @(); NnrFailedTargets = @('wks1.contoso.com') } }
    } else {
        @{ isRequiredPortsOk = $true; details = [ordered]@{ Results = $results; FailedRequired = @(); NnrFailedTargets = @() } }
    }
}

$plan = [PSCustomObject]@{ Targets = @('dc1.contoso.com') }

function New-Estate {
    param([string[]] $Names, [int] $Unnamed = 0, [string[]] $Unreachable = @(), [bool] $Sensor = $true)
    $script:dcNames = $Names
    $script:unnamedCount = $Unnamed
    $script:unreachableHosts = $Unreachable
    $script:sensorPresent = $Sensor
    $dcs = @(Get-mdiDomainControllerReadiness -Domain 'contoso.com' -PortProbePlan $plan)
    [PSCustomObject]@{
        DomainControllers   = $dcs
        CAServers           = @()
        EntraConnectServers = @()
        DomainsInScope      = @('contoso.com')
        Domain              = 'contoso.com'
        NnrTargetComputer   = @()
        SkippedAreas        = @()
    }
}

# ================================================================================================
# The predicate itself, on rows the SHIPPED producer built.
# ================================================================================================
$rowsMixed = (New-Estate -Names @('dc1.contoso.com', 'dc2.contoso.com') -Unnamed 2 -Unreachable @('dc2.contoso.com')).DomainControllers
$realRow = @($rowsMixed | Where-Object { [string] $_.FQDN -eq 'dc1.contoso.com' })[0]
$deadRow = @($rowsMixed | Where-Object { [string] $_.FQDN -eq 'dc2.contoso.com' })[0]
$phRow = @($rowsMixed | Where-Object { Test-mdiServerIsPlaceholder -Server $_ })[0]

Assert-That 'the shipped producer really did emit placeholder rows' ($null -ne $phRow)
Assert-That 'a reachable real server IS a probe candidate' (Test-mdiServerIsProbeCandidate -Server $realRow)
Assert-That 'an unreachable server is NOT a probe candidate' (-not (Test-mdiServerIsProbeCandidate -Server $deadRow))
Assert-That 'a discovery placeholder is NOT a probe candidate' (-not (Test-mdiServerIsProbeCandidate -Server $phRow)) `
    ("IsPlaceholder={0} FQDN='{1}'" -f $phRow.IsPlaceholder, $phRow.FQDN)
Assert-That 'a $null row is NOT a probe candidate' (-not (Test-mdiServerIsProbeCandidate -Server $null))

# ================================================================================================
# The scope counters and the console verdict clause.
# A = one real DC (control). B = the SAME estate plus two unnamed records. C = the guarded sibling.
# ================================================================================================
$rA = New-Estate -Names @('dc1.contoso.com')
$sA = Get-mdiReportStatistics -ReportData $rA 3>$null
$qA = [string] (Get-mdiVerdictQualifier -ReportData $rA -Statistics $sA)

$rB = New-Estate -Names @('dc1.contoso.com') -Unnamed 2
$sB = Get-mdiReportStatistics -ReportData $rB 3>$null
$qB = [string] (Get-mdiVerdictQualifier -ReportData $rB -Statistics $sB)

$rC = New-Estate -Names @('dc1.contoso.com', 'dc2.contoso.com', 'dc3.contoso.com') -Unreachable @('dc2.contoso.com', 'dc3.contoso.com')
$sC = Get-mdiReportStatistics -ReportData $rC 3>$null
$qC = [string] (Get-mdiVerdictQualifier -ReportData $rC -Statistics $sC)

Assert-That 'control: a clean one-DC estate claims no sampling' ($qA -notmatch 'sample') ("got '{0}'" -f $qA)
Assert-That 'control: one candidate host for ports' ($sA.PortCandidateHostCount -eq 1) ("got {0}" -f $sA.PortCandidateHostCount)

Assert-That 'placeholders do not inflate PortCandidateHostCount' ($sB.PortCandidateHostCount -eq $sA.PortCandidateHostCount) `
    ("control={0} withPlaceholders={1}" -f $sA.PortCandidateHostCount, $sB.PortCandidateHostCount)
Assert-That 'placeholders do not inflate NnrCandidateCount' ($sB.NnrCandidateCount -eq $sA.NnrCandidateCount) `
    ("control={0} withPlaceholders={1}" -f $sA.NnrCandidateCount, $sB.NnrCandidateCount)
Assert-That 'placeholders invent no sampling disclosure on the console verdict' ($qB -notmatch 'sample') ("got '{0}'" -f $qB)
Assert-That 'placeholders do not invent a -MaxLdapTargetsPerDomain instruction' ($qB -notmatch 'MaxLdapTargetsPerDomain') ("got '{0}'" -f $qB)
Assert-That 'placeholders do not invent a -MaxNnrTargets instruction' ($qB -notmatch 'MaxNnrTargets') ("got '{0}'" -f $qB)
Assert-That 'the candidate count never exceeds the number of real reachable hosts' ($sB.PortCandidateHostCount -le $sB.ReachableServers) `
    ("candidates={0} reachable={1}" -f $sB.PortCandidateHostCount, $sB.ReachableServers)

# The guarded sibling must not regress: unreachable servers were ALREADY excluded here.
Assert-That 'unreachable servers stay excluded from PortCandidateHostCount' ($sC.PortCandidateHostCount -eq 1) ("got {0}" -f $sC.PortCandidateHostCount)
Assert-That 'unreachable servers stay excluded from NnrCandidateCount' ($sC.NnrCandidateCount -eq 1) ("got {0}" -f $sC.NnrCandidateCount)
Assert-That 'an estate with unreachable servers claims no sampling' ($qC -notmatch 'sample') ("got '{0}'" -f $qC)

# OVER-CORRECTION GUARD: the placeholder is still CHARGED as an unread check. Dropping placeholder
# rows from the report entirely would satisfy every counter above and lose the finding.
Assert-That 'a placeholder is still counted as an unread check, not silently dropped' ($sB.ChecksUnread -eq $sA.ChecksUnread + 2) `
    ("control={0} withPlaceholders={1} (expected control+2)" -f $sA.ChecksUnread, $sB.ChecksUnread)

# ================================================================================================
# The pre-deployment fallback in the remediation generator.
# No sensor deployed anywhere + a measured-blocked NNR target is what makes the generator emit an
# NNR firewall section and choose the domain controllers as its sensor source list.
# ================================================================================================
$script:nnrBlocked = $true
$outDir = Join-Path $env:TEMP ('mdi-probecandidate-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Get-GeneratedScript {
    param($Report, [string] $Tag)
    $p = Join-Path $outDir "remed-$Tag.ps1"
    $script:warns.Clear()
    New-mdiRemediationScript -ReportData $Report -FilePath $p 3>$null | Out-Null
    if (Test-Path $p) { [IO.File]::ReadAllText($p) } else { '' }
}

$rNo = New-Estate -Names @('dc1.contoso.com') -Sensor $false
$tNo = Get-GeneratedScript -Report $rNo -Tag 'no-placeholder'
$warnNo = @($script:warns | Where-Object { $_ -match 'Name Resolution' })

$rPh = New-Estate -Names @('dc1.contoso.com') -Unnamed 2 -Sensor $false
$tPh = Get-GeneratedScript -Report $rPh -Tag 'with-placeholder'
$warnPh = @($script:warns | Where-Object { $_ -match 'Name Resolution' })

# The section the fallback feeds, isolated so the placeholder's legitimate manual-attention finding
# (asserted below) does not mask a difference here.
function Get-SensorSourceRegion {
    param([string] $ScriptText)
    @($ScriptText -split "`r?`n" | Where-Object { $_ -match '# Sources |# NOT COVERED|# below do NOT allow|# Re-run Test-MdiReadiness' }) -join "`n"
}
$regionNo = Get-SensorSourceRegion -ScriptText $tNo
$regionPh = Get-SensorSourceRegion -ScriptText $tPh

Assert-That 'the generator really did emit an NNR sensor-source section' ($regionNo -match '# Sources ') ("got '{0}'" -f $regionNo)
Assert-That 'placeholders do not change the NNR sensor-source section' ($regionPh -eq $regionNo) `
    ("without='{0}' with='{1}'" -f $regionNo, $regionPh)
Assert-That 'no phantom sensor server is declared NOT COVERED' ($tPh -notmatch 'NOT COVERED') `
    (@($tPh -split "`r?`n" | Where-Object { $_ -match 'NOT COVERED' }) -join ' ')
Assert-That 'the generated script never claims a nameless record will fail its NNR probes' ($tPh -notmatch 'their NNR probes will still fail')
Assert-That 'the operator is not told to re-run once a nameless record "resolves"' ($tPh -notmatch 'once those servers resolve')
Assert-That 'no console warning is raised about addresses for phantom sensor servers' ($warnPh.Count -eq $warnNo.Count) `
    ("without={0} with={1}: {2}" -f $warnNo.Count, $warnPh.Count, ($warnPh -join ' | '))

# OVER-CORRECTION GUARD: the placeholder must still reach the operator, with the CORRECT cause.
Assert-That 'the placeholder is still surfaced under manual attention' ($tPh -match 'Domain controller \(not named\)') `
    ('no [High] discovery line found in the generated script')
Assert-That 'the manual-attention line states the real cause (dNSHostName), not name resolution' ($tPh -match 'Repair the dNSHostName attribute') `
    ('discovery finding lost its remedy text')

# And the unreachable server keeps its own manual-attention line - the behaviour this fix mirrors.
$rDead = New-Estate -Names @('dc1.contoso.com', 'dc2.contoso.com') -Unreachable @('dc2.contoso.com') -Sensor $false
$tDead = Get-GeneratedScript -Report $rDead -Tag 'unreachable'
Assert-That 'an unreachable server is still surfaced under manual attention' ($tDead -match 'dc2\.contoso\.com: Server is not available and could not be tested')
Assert-That 'an unreachable server is still not an emitted remediation target' (
    @($tDead -split "`r?`n" | Where-Object { $_ -match "^\s+'dc2\.contoso\.com'" }).Count -eq 0)

Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
