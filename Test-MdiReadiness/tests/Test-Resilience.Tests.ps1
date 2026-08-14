<#
    Resilience regression suite.

    Every assertion here corresponds to a bug found by running the script against the live lab, where a
    single failing server or a failed discovery either aborted the whole run or, worse, produced a
    confident report of nothing. These are the cases that do not appear in a healthy multi-DC lab and
    that a customer hits on their first run.
#>

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }

$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $errors)
if ($errors) { Write-Host "PARSE ERRORS"; exit 1 }

$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))

# The helpers read two script-scoped constant lists that live at file scope rather than inside a
# function, so dot-sourcing the function bodies alone leaves them null - and "$_.Name -notin $null" is
# true for everything, which silently turned the status flags back into visible checks. Loading them
# the same way the settings block is loaded keeps the harness honest about what the script really does.
# EVERY script-scoped constant is loaded, not a hand-maintained list. The list went stale the moment a
# new constant was added: $script:mdiPortNotTestedPattern was null in the harness, and "-notmatch $null"
# treats the pattern as an empty string, which matches everything - so a filter meant to exclude
# untested probes silently excluded ALL of them and the suite failed for a reason that had nothing to
# do with the script.
foreach ($constAst in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -like '$script:*' -and
            $null -eq $n.Parent.Parent.Parent }, $false)) {
    . ([scriptblock]::Create($constAst.Extent.Text))
}
foreach ($constant in @()) {
    $assignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -eq ('$script:{0}' -f $constant) }, $true)[0]
    if ($null -eq $assignment) { throw "Could not find `$script:$constant in the script" }
    . ([scriptblock]::Create($assignment.Extent.Text))
}

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name $Detail" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

function New-Report {
    param($Dcs, $Cas, $Ecs, [bool] $Adfs = $true, [bool] $Obj = $true, [bool] $Exch = $true)
    [PSCustomObject]@{
        Domain                 = 'contoso.com'
        DomainControllers      = $Dcs
        CAServers              = $Cas
        EntraConnectServers    = $Ecs
        DomainAdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = $Adfs }
        DomainObjectAuditing   = [PSCustomObject]@{ isObjectAuditingOk = $Obj }
        DomainExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $Exch }
    }
}
$healthy = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; PowerSettings = $true; AdvancedAuditing = $true }

Write-Host "`n[1] A run that checked nothing is never READY" -ForegroundColor Yellow
# The most damaging failure mode: ($empty -ne $true).Count is 0, which reads as "no check failed", so a
# scan that enumerated no servers scored as a clean pass.
Assert-That 'zero servers is not ready' ((Test-mdiReadinessResult -ReportData (New-Report @() @() @())) -eq $false)
Assert-That 'a healthy forest is still ready' ((Test-mdiReadinessResult -ReportData (New-Report @($healthy) @() @())) -eq $true)
Assert-That 'a failed check is not ready' ((Test-mdiReadinessResult -ReportData (New-Report @([PSCustomObject]@{ FQDN = 'd'; PowerSettings = $false }) @() @())) -eq $false)

Write-Host "`n[2] An unreachable server fails the run" -ForegroundColor Yellow
# An unreachable server carries a Comment and no boolean checks, so it contributed nothing to measure
# and used to pass silently.
$unreachable = [PSCustomObject]@{ FQDN = 'dc9.contoso.com'; Comment = 'Server is not available: ICMP, TCP 135 and WMI all failed' }
Assert-That 'unreachable alone is not ready' ((Test-mdiReadinessResult -ReportData (New-Report @($unreachable) @() @())) -eq $false)
Assert-That 'one unreachable among healthy is not ready' ((Test-mdiReadinessResult -ReportData (New-Report @($healthy, $unreachable) @() @())) -eq $false)

Write-Host "`n[3] Checks on non-domain-controller servers count" -ForegroundColor Yellow
# The property list used to be projected from DomainControllers only, so a CA-only or Entra-Connect-only
# check could never fail the run.
$caBad = [PSCustomObject]@{ FQDN = 'ca1.contoso.com'; CAAuditing = $false }
$ecBad = [PSCustomObject]@{ FQDN = 'ec1.contoso.com'; AdvancedAuditingEntraConnect = $false }
Assert-That 'a CA-only failure is caught' ((Test-mdiReadinessResult -ReportData (New-Report @($healthy) @($caBad) @())) -eq $false)
Assert-That 'an Entra Connect-only failure is caught' ((Test-mdiReadinessResult -ReportData (New-Report @($healthy) @() @($ecBad))) -eq $false)

Write-Host "`n[4] A single server is not an array" -ForegroundColor Yellow
# PowerShell exposes a one-element result as a bare PSObject. $a.DomainControllers + $a.CAServers is then
# PSObject + PSObject, which throws "does not contain a method named op_Addition". This broke four
# separate functions at once and is invisible in a multi-DC lab.
$singleDcReport = New-Report $healthy $null $null
Assert-That 'verdict handles a single server' ((Test-mdiReadinessResult -ReportData $singleDcReport) -eq $true)
$stats = $null
try { $stats = Get-mdiReportStatistics -ReportData $singleDcReport } catch {}
Assert-That 'statistics handle a single server' ($null -ne $stats -and $stats.TotalServers -eq 1) "(TotalServers=$($stats.TotalServers))"
$fixFile = Join-Path $env:TEMP ('mdi-single-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 6))
$gen = $null
try { $gen = New-mdiRemediationScript -ReportData $singleDcReport -FilePath $fixFile } catch {}
Assert-That 'the remediation generator handles a single server' ($null -ne $gen)
Remove-Item $fixFile -Force -ErrorAction SilentlyContinue

Write-Host "`n[5] The registry reader survives a hostile server" -ForegroundColor Yellow
# A remote registry read fails for ordinary reasons. It used to throw and unwind the entire run.
$regResult = 'threw'
try {
    # 192.0.2.1 is TEST-NET-1 and is guaranteed not to answer, so this exercises the connection failure path.
    $regResult = Get-mdiRegistryValueSet -ComputerName '192.0.2.1' -ExpectedRegistrySet @('SYSTEM\CurrentControlSet\Services\Foo,Start,2') -WarningAction SilentlyContinue
    if ($null -eq $regResult) { $regResult = 'null' }
} catch { $regResult = 'threw' }
Assert-That 'an unreachable registry returns rather than throwing' ($regResult -ne 'threw') "(got $regResult)"

$source = Get-Content $scriptPath -Raw
Assert-That 'OpenRemoteBaseKey is inside a try' ($source -match '(?s)try \{\s*\$hklm = \[Microsoft\.Win32\.RegistryKey\]::OpenRemoteBaseKey')
# Format-tolerant, but still requires the GUARD: the GetValue call must sit INSIDE 'if ($regKey) {'.
# The previous pattern demanded the whole thing on ONE line, so it broke the moment the block gained
# a second statement (reading the value KIND) even though the null test was untouched. A test that
# fails on layout rather than on behaviour trains people to edit the test, which is how a real guard
# eventually gets deleted unnoticed.
Assert-That 'the subkey handle is null-tested' ($source -match 'if \(\$regKey\) \{[\s\S]{0,300}?\$regKey\.GetValue\(')
Assert-That 'the base key is closed in a finally' ($source -match 'finally \{[\s\S]{0,200}\$hklm\.Close\(\)')

Write-Host "`n[6] One bad server does not end the scan" -ForegroundColor Yellow
# Each of the three server loops must isolate its per-server checks.
$loopBodies = @{
    'domain controller' = 'Could not finish testing {0}: {1}'
}
$isolationCount = ([regex]::Matches($source, "Testing stopped early: \{0\}")).Count
Assert-That 'all three server loops flag a partial failure' ($isolationCount -eq 3) "(found $isolationCount of 3)"
$warnCount = ([regex]::Matches($source, "Could not finish testing \{0\}")).Count
Assert-That 'all three server loops warn on a partial failure' ($warnCount -eq 3) "(found $warnCount of 3)"
$detailsReset = ([regex]::Matches($source, "# Declared before the branch so an unreachable server does not inherit")).Count
Assert-That 'the details object is reset per server in all three loops' ($detailsReset -eq 3) "(found $detailsReset of 3)"

Write-Host "`n[7] Discovery falls back rather than reporting an empty forest" -ForegroundColor Yellow
# Get-ADDomainController needs ADWS on TCP 9389, a separate optional service. LDAP on 389 has to work or
# the directory does not function at all, so it is the right fallback.
Assert-That 'an LDAP discovery helper exists' ($source -match 'function Get-mdiDomainControllerFromLdap')
Assert-That 'a resolver tries ADWS then LDAP' ($source -match 'function Resolve-mdiDomainController')
Assert-That 'the LDAP filter matches writable domain controllers' ($source -match 'userAccountControl:1\.2\.840\.113556\.1\.4\.803:=8192')
Assert-That 'the LDAP filter also matches read-only domain controllers' ($source -match 'userAccountControl:1\.2\.840\.113556\.1\.4\.803:=67108864')
Assert-That 'the fallback is announced' ($source -match 'falling back to LDAP')
Assert-That 'a total discovery failure is warned about' ($source -match 'No domain controller was checked')
Assert-That 'a scan that found nothing is not called a readiness result' ($source -match 'SCAN INCOMPLETE')

Write-Host "`n[8] A null identity never reaches -Identity" -ForegroundColor Yellow
# Get-ADObject returns null when nothing matches. Binding null to -Identity is a parameter binding
# failure that -ErrorAction SilentlyContinue cannot suppress and try/catch does not catch, so the server
# disappeared from the report without a word.
Assert-That 'the identity is resolved defensively' ($source -match 'if \(\$adObject\) \{ \$identity = \$adObject \}')
Assert-That 'the discovered name survives a failed lookup' ($source -match '\$fqdn = if \(\$dcComputer -and \$dcComputer\.DNSHostName\)')
Assert-That 'no splat still binds a bare Get-ADObject result to Identity' ($source -notmatch 'Identity\s*=\s*if \(\$_ -match')

Write-Host "`n[9] A check that could not be read is not a failed check" -ForegroundColor Yellow
# Access denied, a stopped service or a blocked port means the setting was not read. Reporting that as
# false sends people to fix a power scheme, a disk or an operating system version that is very likely
# already correct - and on a contained or hardened server that is every check at once.
$allNa = [PSCustomObject]@{ FQDN = 'dc-na.contoso.com'; ServerRequirements = 'N/A'; PowerSettings = 'N/A'; OSVersion = 'N/A' }
$mixed = [PSCustomObject]@{ FQDN = 'dc-mix.contoso.com'; NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = 'N/A' }
Assert-That 'nothing measured is not ready' ((Test-mdiReadinessResult -ReportData (New-Report @($allNa) @() @())) -eq $false)
# An unread check now blocks a READY verdict outright, so a server that is partly unreadable is not
# ready either. Section 12 covers that case; here the point is only that it is not silently ignored.
Assert-That 'a partially unmeasured server is not ready' ((Test-mdiReadinessResult -ReportData (New-Report @($mixed) @() @())) -eq $false)
Assert-That 'one unmeasurable server fails the run' ((Test-mdiReadinessResult -ReportData (New-Report @($healthy, $allNa) @() @())) -eq $false)

$naStats = Get-mdiReportStatistics -ReportData (New-Report @($mixed) @() @())
# Asserted as a DELTA against the same report with no unreadable check, rather than against absolute
# totals. The absolute numbers also carry the domain-level directory checks, which are nothing to do
# with what this assertion is about - it broke the moment those were folded into the score, even
# though the behaviour it tests had not changed at all. The property is that an 'N/A' check counts
# towards neither the passes nor the measured total, and that is what is measured here.
$mixedMeasured = [PSCustomObject]@{ FQDN = 'dc-mix.contoso.com'; NtlmAuditing = $true; AdvancedAuditing = $true }
$measuredStats = Get-mdiReportStatistics -ReportData (New-Report @($mixedMeasured) @() @())
Assert-That 'N/A is counted as neither a pass nor a total' (
    ($naStats.ChecksTotal -eq $measuredStats.ChecksTotal) -and ($naStats.ChecksPassed -eq $measuredStats.ChecksPassed)) `
    "(with N/A $($naStats.ChecksPassed)/$($naStats.ChecksTotal) vs without $($measuredStats.ChecksPassed)/$($measuredStats.ChecksTotal))"
Assert-That 'and it is counted as unread instead' ($naStats.ChecksUnread -eq ($measuredStats.ChecksUnread + 1)) `
    "(with N/A $($naStats.ChecksUnread) vs without $($measuredStats.ChecksUnread))"

# Every check that reads a remote server must be able to say "unknown". A boolean-only result forces a
# read failure to be reported as a configuration failure.
foreach ($fn in 'Get-mdiServerRequirements', 'Get-mdiOSVersion', 'Get-mdiPowerScheme', 'Get-mdiCertReadiness') {
    $body = ($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fn }, $true)[0]).Extent.Text
    Assert-That "$fn reports unknown rather than false" ($body -match "=\s*'N/A'")
}

# A raw HRESULT in a version or platform field reads as if that string were the value.
foreach ($fn in 'Get-mdiSensorVersion', 'Get-mdiMachineType') {
    $body = ($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fn }, $true)[0]).Extent.Text
    Assert-That "$fn does not return the exception text as a value" ($body -notmatch '\$return\s*=\s*\$_\.Exception\.Message')
}

Write-Host "`n[10] The report distinguishes a failure from a missing measurement" -ForegroundColor Yellow
# A red FAIL against a server that was never reachable, or against a check that could not be read, sends
# people to fix settings that were never observed to be wrong.
$fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -eq 'Set-MdiReadinessReport' }, $true)[0]
$fnText = $fn.Extent.Text
$blockStart = $fnText.IndexOf('$convertServerTable = {')
$blockEnd = $fnText.IndexOf("`n    }", $blockStart)
. ([scriptblock]::Create($fnText.Substring($blockStart, $blockEnd - $blockStart + 6)))

$renderServers = @(
    [PSCustomObject]@{ FQDN = 'dc-good.contoso.com'; PowerSettings = $true; AdvancedAuditing = $true; SensorVersion = '2.255.1'; CapturingComponent = 'Npcap'; MachineType = 'Hyper-V'; PartialFailure = $false; Unreachable = $false }
    [PSCustomObject]@{ FQDN = 'dc-fail.contoso.com'; PowerSettings = $false; AdvancedAuditing = $true; SensorVersion = 'N/A'; CapturingComponent = 'N/A'; MachineType = 'Azure'; PartialFailure = $false; Unreachable = $false }
    [PSCustomObject]@{ FQDN = 'dc-na.contoso.com'; PowerSettings = 'N/A'; AdvancedAuditing = 'N/A'; SensorVersion = 'N/A'; CapturingComponent = 'N/A'; MachineType = 'N/A'; PartialFailure = $false; Unreachable = $false }
    # Unreachability is signalled by the explicit flag, not by the presence of a Comment: a server that
    # WAS reached and then failed one check part way through also carries a Comment, and badging it
    # "not reachable" told the reader to disregard results that were real.
    [PSCustomObject]@{ FQDN = 'dc-down.contoso.com'; Comment = 'Server is not available: ICMP, TCP 135 and WMI all failed'; SensorVersion = 'N/A'; CapturingComponent = 'N/A'; MachineType = 'N/A'; PartialFailure = $false; Unreachable = $true }
)
$rendered = & $convertServerTable $renderServers $null 'none'
Assert-That 'a genuine failure is still red' (([regex]::Matches($rendered, 'class="red">False')).Count -eq 1)
Assert-That 'a genuine pass is still green' (([regex]::Matches($rendered, 'class="green">True')).Count -eq 3)
Assert-That 'an unread check reads Not tested, not FAIL' ($rendered -match 'muted-cell[^>]*>Not tested')
Assert-That 'no raw N/A cell survives' (([regex]::Matches($rendered, '<td>N/A</td>')).Count -eq 0)
Assert-That 'an unreachable server is marked on its row' ($rendered -match '<tr class="unreachable"')
Assert-That 'the unreachable badge names the state' ($rendered -match 'badge-warn">not reachable')
Assert-That 'the unreachable reason is carried in the tooltip' ($rendered -match 'title="Server is not available: ICMP, TCP 135 and WMI all failed"')

$reportSource = Get-Content $scriptPath -Raw
Assert-That 'an untested port is not reported as Blocked' ($reportSource -match 'muted-cell.{0,30}Not tested</td>')
Assert-That 'untested ports get their own section' ($reportSource -match 'Ports that could not be tested')
# Asserted BEHAVIOURALLY. This used to match the shape of the $failures expression in the source, so
# it broke when that filter started going through Test-mdiProbeWasMeasured - a change that only made
# it stricter (a probe whose Success carried no real result was being painted red). What matters is
# which table an unmeasured probe lands in, so that is what is checked.
$untestedPortServer = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'
    Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{
            ProbedFrom = 'dc1.contoso.com'; FailedRequired = @(); NnrFailedTargets = @()
            Results = @(
                [PSCustomObject]@{ Id = 'LdapTcp'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389
                    Scope = 'DomainController'; Group = ''; Requirement = 'Required'
                    Target = 'dc2.contoso.com'; TargetIP = '10.0.0.2'
                    Applicable = $true; Success = $null; Detail = 'Not tested - access is denied' }
                [PSCustomObject]@{ Id = 'RpcTcp'; Name = 'RPC'; Protocol = 'TCP'; Port = 135
                    Scope = 'DomainController'; Group = ''; Requirement = 'Required'
                    Target = 'dc3.contoso.com'; TargetIP = '10.0.0.3'
                    Applicable = $true; Success = $false; Detail = 'Connection refused' }
            ) } }
}
$untestedHtml = Get-mdiRequiredPortsHtml -Server @($untestedPortServer)
$attentionBlock = [regex]::Match($untestedHtml, '(?s)Ports that need attention.*?</table>').Value
$couldNotBlock = [regex]::Match($untestedHtml, '(?s)Ports that could not be tested.*?</table>').Value
Assert-That 'untested ports are excluded from the action list' ($attentionBlock -notmatch 'dc2\.contoso\.com') $attentionBlock
Assert-That 'a measured failure is still in the action list' ($attentionBlock -match 'dc3\.contoso\.com')
Assert-That 'the untested port is listed as untested instead' ($couldNotBlock -match 'dc2\.contoso\.com')
Assert-That 'a report with nothing measured is not called clean' ($reportSource -match 'returned no readable results at all')
Assert-That 'the styles define the not-tested cell' ($reportSource -match 'td\.muted-cell')
Assert-That 'the styles define the unreachable row' ($reportSource -match 'tr\.unreachable td')

Write-Host "`n[11] Sensor v3.x prerequisites are not invented when the server cannot be read" -ForegroundColor Yellow
# The report claimed five real domain controllers were "not a domain controller". Every v3 check derived
# its answer from a WMI or registry read that defaulted to a falsy value on failure, so an unreadable
# server produced a full column of confident Fails.
function New-V3Stub {
    param([int] $ProductType, [string] $Build, [bool] $Readable = $true, [bool] $WmiOk = $true)
    if ($WmiOk) {
        # Win32_Service is answered as a real service record (the Sense check reads .State/.StartMode
        # through Get-mdiServiceStateResult -> Get-WmiObject now that the plain Get-mdiServiceState
        # wrapper has been removed); every other class returns the operating-system shape.
        Set-Item -Path function:script:Get-WmiObject -Value ([scriptblock]::Create(@"
param(`$ComputerName, `$Namespace, `$Class, `$Property, `$Filter, `$Query, `$ErrorAction)
if (`$Class -eq 'Win32_Service' -and `$Filter -match "= 'Sense'") {
    return [PSCustomObject]@{ Name = 'Sense'; State = 'Running'; StartMode = 'Auto'; PathName = 'C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe' }
}
[PSCustomObject]@{ Caption = 'Windows Server test'; ProductType = $ProductType; BuildNumber = '$Build'; Version = '10.0.$Build' }
"@))
    } else {
        Set-Item -Path function:script:Get-WmiObject -Value { throw 'Access is denied. (Exception from HRESULT: 0x80070005)' }
    }
    $readableText = if ($Readable) { '$true' } else { '$false' }
    Set-Item -Path function:script:Get-mdiRemoteRegistryResult -Value ([scriptblock]::Create(
            "param(`$ComputerName,`$Key,`$Value) [PSCustomObject]@{ Readable=$readableText; Value=`$(if(`$Value -eq 'UBR'){99999}else{1}); Error='denied' }"))
    Set-Item -Path function:script:Get-mdiCaptureComponent -Value { param($ComputerName) 'N/A' }
    if ($WmiOk) {
        # Stubbed at Get-mdiServiceStateResult, which is now the only service-query seam. The
        # readability-discarding wrapper it used to stub was deleted after an access-denied reply
        # reached the v3.x checks as "the service is not installed".
        Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
            param($ComputerName, $ServiceName)
            $svc = if ($ServiceName -eq 'Sense') { [PSCustomObject]@{ State = 'Running'; StartMode = 'Auto' } } else { $null }
            [PSCustomObject]@{ Service = $svc; Readable = $true; Error = $null }
        }
    } else {
        # WMI is unreachable, so the service list cannot be READ - which is not the same as the
        # services being absent, and the checks must report N/A rather than a measured failure.
        Set-Item -Path function:script:Get-mdiServiceStateResult -Value {
            param($ComputerName, $ServiceName)
            [PSCustomObject]@{ Service = $null; Readable = $false; Error = 'Access is denied.' }
        }
    }
}

New-V3Stub -ProductType 2 -Build '20348'
$v3Healthy = Get-mdiSensorV3Readiness -ComputerName 'dc-ok.contoso.com'
Assert-That 'a healthy domain controller is ready' ($v3Healthy.isSensorV3Ready -eq $true) "(got $($v3Healthy.isSensorV3Ready))"

New-V3Stub -ProductType 2 -Build '14393'
$v3Old = Get-mdiSensorV3Readiness -ComputerName 'dc2016.contoso.com'
Assert-That 'a Windows Server 2016 DC is genuinely blocked' ($v3Old.isSensorV3Ready -eq $false) "(got $($v3Old.isSensorV3Ready))"

New-V3Stub -ProductType 3 -Build '20348'
$v3Member = Get-mdiSensorV3Readiness -ComputerName 'mem.contoso.com'
Assert-That 'a member server is genuinely blocked' ($v3Member.isSensorV3Ready -eq $false) "(got $($v3Member.isSensorV3Ready))"

New-V3Stub -ProductType 2 -Build '20348' -Readable $false -WmiOk $false
$v3Unknown = Get-mdiSensorV3Readiness -ComputerName 'dc-denied.contoso.com'
Assert-That 'an unreadable server is unknown, never blocked' ([string] $v3Unknown.isSensorV3Ready -eq 'N/A') "(got $($v3Unknown.isSensorV3Ready))"
Assert-That 'an unreadable server reports no blockers' (@($v3Unknown.details.Blockers).Count -eq 0) "(got $(@($v3Unknown.details.Blockers).Count))"
Assert-That 'an unreadable server never claims it is not a domain controller' (
    -not (@($v3Unknown.details.Checks | Where-Object { $_.Name -eq 'Server is a domain controller' })[0].Status -eq $false))
Assert-That 'every unread check is marked as not measured' (
    @($v3Unknown.details.Checks | Where-Object { $_.Requirement -eq 'Required' -and -not $_.Measured }).Count -eq 5)
Assert-That 'the unknown checks are named' (@($v3Unknown.details.UnknownChecks).Count -eq 5)
Assert-That 'the sensor state says it was not determined' ($v3Unknown.details.SensorState -match 'Not determined')

Remove-Item function:script:Get-WmiObject, function:script:Get-mdiRemoteRegistryResult,
function:script:Get-mdiCaptureComponent, function:script:Get-mdiServiceState -ErrorAction SilentlyContinue

# 'N/A' is truthy, so a bare if() rendered an unknown server as meeting every prerequisite.
#
# Asserted BEHAVIOURALLY. These two checks used to match the source text for
# "$_.SensorV3Ready -eq $true" and "[string] $_.SensorV3Ready -eq 'N/A'", and they broke when the
# comparison was replaced by ConvertTo-mdiBoolean - which is STRICTER, because it normalises $null
# and '' as well as 'N/A'. A test that fails when the code is improved is testing the wrong thing;
# what matters is that an unmeasured server is never counted as ready.
$v3Report = [PSCustomObject]@{
    DomainControllers = @(
        [PSCustomObject]@{ FQDN = 'ready.contoso.com'; Domain = 'c.com'; Unreachable = $false
            SensorV3Ready = $true; Details = [PSCustomObject]@{ SensorV3ReadyDetails = [PSCustomObject]@{ Checks = @(); SensorState = 'Running' } } }
        [PSCustomObject]@{ FQDN = 'unknown.contoso.com'; Domain = 'c.com'; Unreachable = $false
            SensorV3Ready = 'N/A'; Details = [PSCustomObject]@{ SensorV3ReadyDetails = [PSCustomObject]@{ Checks = @(); SensorState = 'Not determined' } } }
    )
    CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('c.com'); Domain = 'c.com'; Forest = 'c.com'
}
$v3Stats = Get-mdiReportStatistics -ReportData $v3Report
Assert-That 'an N/A v3 state is not counted as ready' ($v3Stats.V3Ready -eq 1) "(V3Ready=$($v3Stats.V3Ready) of 2 servers)"
Assert-That 'an N/A v3 state is not counted as evaluated' ($v3Stats.V3Evaluated -eq 1) "(V3Evaluated=$($v3Stats.V3Evaluated))"
# The same must hold for the other falsy-but-truthy shapes, which is why the literal comparison was
# replaced: $null and '' are equally "not measured".
foreach ($unknown in @($null, '', 'N/A', 'Unknown')) {
    $one = [PSCustomObject]@{
        DomainControllers = @([PSCustomObject]@{ FQDN = 'x.c.com'; Domain = 'c.com'; Unreachable = $false
                SensorV3Ready = $unknown; Details = [PSCustomObject]@{ SensorV3ReadyDetails = [PSCustomObject]@{ Checks = @(); SensorState = 'Not determined' } } })
        CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('c.com'); Domain = 'c.com'; Forest = 'c.com'
    }
    Assert-That ("a v3 state of '{0}' counts as neither ready nor evaluated" -f $(if ($null -eq $unknown) { 'null' } else { $unknown })) (
        (Get-mdiReportStatistics -ReportData $one).V3Ready -eq 0)
}
# An unmeasured check must render as "Not tested" rather than as a pass.
Assert-That 'an unmeasured v3 check renders as Not tested' ($reportSource -match 'muted-cell[^>]*>Not tested</td>')
Assert-That 'the registry reader reports readability separately from value' ($reportSource -match 'function Get-mdiRemoteRegistryResult')
Assert-That 'checks carry a Measured flag' ($reportSource -match 'Measured\s*=\s*-not \(\$Detail -like')

Write-Host "`n[12] A partially readable scan is never reported as a clean one" -ForegroundColor Yellow
# Seen live: access was denied on almost everything, yet the run printed
# "0 issue(s) found: 5/5 checks passed across 5 server(s)" because only the checks that could be
# measured were counted. A customer reads that as a clean bill of health for a scan that saw nothing.
$partial = 1..5 | ForEach-Object {
    [PSCustomObject]@{ FQDN = "dc$_.contoso.com"; NtlmAuditing = $true
        ServerRequirements = 'N/A'; PowerSettings = 'N/A'; OSVersion = 'N/A'; RootCertificates = 'N/A'; TimeSync = 'N/A'
    }
}
$partialReport = New-Report $partial @() @()
$partialStats = Get-mdiReportStatistics -ReportData $partialReport
Assert-That 'unread checks are counted' ($partialStats.ChecksUnread -eq 25) "(got $($partialStats.ChecksUnread))"
Assert-That 'a partially read scan is not ready' ((Test-mdiReadinessResult -ReportData $partialReport) -eq $false)

$fullyRead = 1..3 | ForEach-Object { [PSCustomObject]@{ FQDN = "dc$_.contoso.com"; NtlmAuditing = $true; PowerSettings = $true } }
$fullReport = New-Report $fullyRead @() @()
Assert-That 'a fully read healthy forest is still ready' ((Test-mdiReadinessResult -ReportData $fullReport) -eq $true)
Assert-That 'a fully read forest reports no unread checks' ((Get-mdiReportStatistics -ReportData $fullReport).ChecksUnread -eq 0)

$summarySource = Get-Content $scriptPath -Raw
Assert-That 'the run warns when checks could not be read' ($summarySource -match 'could not be read at all, so this is only a partial picture')
Assert-That 'the statistics expose the unread count' ($summarySource -match 'ChecksUnread\s*=')
Assert-That 'the per-server score carries the unread count' ($summarySource -match 'Unread\s*=\s*\$unread')

Write-Host ("`n================ {0} passed / {1} failed ================" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
