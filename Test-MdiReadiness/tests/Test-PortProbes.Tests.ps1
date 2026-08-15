# Test harness: loads only the function definitions from Test-MdiReadiness.ps1 and exercises the port probes
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors -join '; ')" }

# $settings is needed by New-mdiPortProbePlan / Get-mdiRequiredPortsHtml
$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))

$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))

# EVERY script-scoped constant is loaded. These live at file scope rather than inside a function, so
# dot-sourcing the function bodies alone leaves them null - and a null regex in "-notmatch" matches
# everything, which silently inverted a filter and failed a suite for a reason unrelated to the script.
foreach ($constAst in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -like '$script:*' -and
            $null -eq $n.Parent.Parent.Parent }, $false)) {
    . ([scriptblock]::Create($constAst.Extent.Text))
}
Write-Host ("Loaded {0} functions and {1} port definitions" -f $functions.Count, $settings.RequiredPorts.Count) -ForegroundColor Cyan

$pass = 0; $fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name $Detail" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

Write-Host "`n[1] Packet builders" -ForegroundColor Yellow
$nb = New-mdiNetBiosNodeStatusPacket
Assert-That 'NBSTAT packet is 50 bytes' ($nb.Length -eq 50) "(got $($nb.Length))"
Assert-That 'NBSTAT encodes wildcard name CKAAAA...' ([Text.Encoding]::ASCII.GetString($nb, 13, 32) -eq ('CK' + ('AA' * 15)))
Assert-That 'NBSTAT question type is NBSTAT (0x0021)' ($nb[46] -eq 0x00 -and $nb[47] -eq 0x21)
Assert-That 'NBSTAT question class is IN' ($nb[48] -eq 0x00 -and $nb[49] -eq 0x01)

$dns = New-mdiDnsQueryPacket -Name 'contoso.com'
Assert-That 'DNS packet has 1 question' ($dns[4] -eq 0 -and $dns[5] -eq 1)
Assert-That 'DNS packet encodes labels' ($dns[12] -eq 7 -and [Text.Encoding]::ASCII.GetString($dns, 13, 7) -eq 'contoso' -and $dns[20] -eq 3)
Assert-That 'DNS packet QTYPE=A QCLASS=IN' ($dns[-4] -eq 0 -and $dns[-3] -eq 1 -and $dns[-2] -eq 0 -and $dns[-1] -eq 1)

$cldap = New-mdiCldapPingPacket
Assert-That 'CLDAP starts with SEQUENCE' ($cldap[0] -eq 0x30)
Assert-That 'CLDAP declared length matches' ($cldap[1] -eq ($cldap.Length - 2)) "(decl=$($cldap[1]) actual=$($cldap.Length - 2))"
Assert-That 'CLDAP messageID = 1' ($cldap[2] -eq 0x02 -and $cldap[3] -eq 0x01 -and $cldap[4] -eq 0x01)
Assert-That 'CLDAP protocolOp is searchRequest (0x63)' ($cldap[5] -eq 0x63)
Assert-That 'CLDAP searchRequest length matches' ($cldap[6] -eq ($cldap.Length - 7)) "(decl=$($cldap[6]) actual=$($cldap.Length - 7))"
Assert-That 'CLDAP requests namingContexts' ([Text.Encoding]::ASCII.GetString($cldap) -match 'namingContexts')
Assert-That 'CLDAP filter is present-objectClass' ([Text.Encoding]::ASCII.GetString($cldap) -match 'objectClass')

Write-Host "`n[2] TCP probe against real endpoints" -ForegroundColor Yellow
$open = Test-mdiTcpPort -ComputerName 'www.microsoft.com' -Port 443 -TimeoutMs 5000
Assert-That 'TCP 443 to a reachable host succeeds' ($open.Success) "-> $($open.Detail)"
# A real listener proves the success path end to end, independently of how the OS treats closed ports
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$listenerPort = $listener.LocalEndpoint.Port
$live = Test-mdiTcpPort -ComputerName '127.0.0.1' -Port $listenerPort -TimeoutMs 2000
Assert-That 'TCP probe connects to a live listener' ($live.Success -and $live.Detail -eq 'Connected') "-> $($live.Detail)"
Assert-That 'Listener is discoverable' (@(Test-mdiLocalTcpListener -Port $listenerPort).Count -gt 0)
$listener.Stop()
$closed = Test-mdiTcpPort -ComputerName '127.0.0.1' -Port $listenerPort -TimeoutMs 2000
Assert-That 'TCP to a closed port fails with a diagnostic' ((-not $closed.Success) -and $closed.Detail -match 'Closed|Blocked') "-> $($closed.Detail)"
Assert-That 'Stopped listener is no longer discoverable' (@(Test-mdiLocalTcpListener -Port $listenerPort).Count -eq 0)
$sw = [Diagnostics.Stopwatch]::StartNew()
$filtered = Test-mdiTcpPort -ComputerName '198.51.100.7' -Port 135 -TimeoutMs 1500
$sw.Stop()
Assert-That 'TCP to a black-holed IP reports blocked' ((-not $filtered.Success) -and $filtered.Detail -match 'Blocked') "-> $($filtered.Detail)"
# A silent port is retried ONCE with a longer budget before it is called blocked, because a single
# short timeout is not proof of a firewall - a domain controller across a slow WAN legitimately
# exceeds 1500 ms, and asserting "filtered" on that basis produced a change request to open a port
# that was already open. The bound therefore covers the first attempt plus the retry, and the point
# of the assertion is unchanged: the probe must remain bounded and must not hang.
$retryBudget = [Math]::Max(1500 * 3, 5000)
Assert-That 'TCP probe stays bounded across the retry' ($sw.ElapsedMilliseconds -lt (1500 + $retryBudget + 2500)) "($($sw.ElapsedMilliseconds) ms)"
Assert-That 'a blocked port says it was retried' ($filtered.Detail -match 'retried') "-> $($filtered.Detail)"

Write-Host "`n[3] UDP DNS probe against a real resolver" -ForegroundColor Yellow
$udpDns = Test-mdiUdpPort -ComputerName '8.8.8.8' -Port 53 -Payload (New-mdiDnsQueryPacket -Name 'microsoft.com') -TimeoutMs 5000
Assert-That 'UDP 53 probe gets a DNS reply' ($udpDns.Success) "-> $($udpDns.Detail)"
$udpDead = Test-mdiUdpPort -ComputerName '198.51.100.7' -Port 137 -Payload (New-mdiNetBiosNodeStatusPacket) -TimeoutMs 1200
Assert-That 'UDP to a black-holed IP reports blocked' ((-not $udpDead.Success) -and $udpDead.Detail -match 'Blocked|Closed') "-> $($udpDead.Detail)"

Write-Host "`n[4] Reverse DNS / cloud connectivity" -ForegroundColor Yellow
# Retried, and tolerant of a timeout. This asserts on a live PTR lookup over the internet, so a
# single slow resolver made the whole suite fail with nothing wrong in the code - a flaky test is
# worse than no test, because it trains you to ignore a red result. What matters here is that a
# successful lookup is classified as success and a timeout is classified as NOT TESTED rather than as
# a missing PTR record; both are checked, and the run only fails if it does neither.
$ptr = $null
foreach ($attempt in 1..3) {
    $ptr = Test-mdiReverseDns -IPAddress '8.8.8.8'
    if ($ptr.Success) { break }
    Start-Sleep -Milliseconds 400
}
$ptrTimedOut = (-not $ptr.Success) -and ([string] $ptr.Detail -match $script:mdiPortNotTestedPattern)
Assert-That 'Reverse DNS resolves 8.8.8.8 (or reports it as not tested)' ($ptr.Success -or $ptrTimedOut) "-> $($ptr.Detail)"
Assert-That 'a reverse lookup is never reported as a missing PTR when it did not answer' (
    $ptr.Success -or ([string] $ptr.Detail -notmatch 'No PTR record')) "-> $($ptr.Detail)"
$noPtr = Test-mdiReverseDns -IPAddress '192.0.2.55'
Assert-That 'Reverse DNS reports a missing PTR' (-not $noPtr.Success) "-> $($noPtr.Detail)"
$cloud = Test-mdiCloudConnectivity -Url 'https://www.microsoft.com' -TimeoutMs 15000
Assert-That 'Cloud connectivity probe succeeds over HTTPS' ($cloud.Success) "-> $($cloud.Detail)"
$badCloud = Test-mdiCloudConnectivity -Url 'https://no-such-workspacesensorapi.atp.azure.com' -TimeoutMs 8000
Assert-That 'Cloud probe fails on an unresolvable URL' (-not $badCloud.Success) "-> $($badCloud.Detail)"

Write-Host "`n[5] Plan building" -ForegroundColor Yellow
$plan = New-mdiPortProbePlan -Domain 'contoso.com' `
    -DomainController @([PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '10.0.0.4' }) `
    -NnrTarget @([PSCustomObject]@{ Name = 'wks1.contoso.com'; IP = '10.0.0.9' }) `
    -WorkspaceName 'contoso-corp' -TimeoutMs 1500
Assert-That 'Plan builds the sensor API URL' ($plan.SensorApiUrl -eq 'https://contoso-corpsensorapi.atp.azure.com') "-> $($plan.SensorApiUrl)"
Assert-That 'Plan carries every documented port' (@($plan.Probes).Count -eq @($settings.RequiredPorts).Count)
Assert-That 'LDAPS is optional in single forest' ((@($plan.Probes | Where-Object Id -eq 'LdapsTcp').Requirement) -eq 'Optional')
$mfPlan = New-mdiPortProbePlan -Domain 'contoso.com' -MultiForest -WorkspaceName 'x'
Assert-That 'LDAPS becomes required with -MultiForest' ((@($mfPlan.Probes | Where-Object Id -eq 'LdapsTcp').Requirement) -eq 'Required')
Assert-That '-MultiForest does not mutate the settings table' ((@($settings.RequiredPorts | Where-Object Id -eq 'LdapsTcp').Requirement) -eq 'Optional')

Write-Host "`n[6] Remote payload generation + round-trip" -ForegroundColor Yellow
$cmd = Get-mdiPortProbeCommandLine -Plan $plan -OutputFile 'C:\Windows\Temp\mdi-test.json'
Assert-That 'Command line is a powershell.exe -EncodedCommand' ($cmd -match '^powershell\.exe .*-EncodedCommand ')
Assert-That 'Command line fits the WMI limit' ($cmd.Length -lt 30000) "($($cmd.Length) chars)"
$stub = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($cmd -split ' ')[-1]))
$inner = [regex]::Match($stub, "FromBase64String\('([^']+)'\)").Groups[1].Value
$ms = New-Object IO.MemoryStream (, [Convert]::FromBase64String($inner))
$gz = New-Object IO.Compression.GzipStream $ms, ([IO.Compression.CompressionMode]::Decompress)
$payload = (New-Object IO.StreamReader $gz).ReadToEnd()
Assert-That 'Payload round-trips through gzip+base64' ($payload.Length -gt 1000) "($($payload.Length) chars)"
Assert-That 'Payload carries Invoke-mdiPortProbePlan' ($payload -match 'function Invoke-mdiPortProbePlan')
Assert-That 'Payload carries every probe primitive' (@('Test-mdiTcpPort', 'Test-mdiUdpPort', 'New-mdiNetBiosNodeStatusPacket',
        'New-mdiDnsQueryPacket', 'New-mdiCldapPingPacket', 'Test-mdiNnrNetBios', 'Test-mdiReverseDns',
        'Test-mdiCloudConnectivity', 'Test-mdiLocalTcpListener', 'Test-mdiLocalUdpListener', 'Get-mdiConfiguredDnsServer' |
        Where-Object { $payload -notmatch ('function {0} ' -f [regex]::Escape($_)) }).Count -eq 0)
$payloadErrors = $null
[void] [System.Management.Automation.Language.Parser]::ParseInput($payload, [ref] $null, [ref] $payloadErrors)
Assert-That 'Payload is syntactically valid PowerShell' (@($payloadErrors).Count -eq 0) ("$(@($payloadErrors).Count) errors")

Write-Host "`n[7] Running a plan end-to-end (localhost)" -ForegroundColor Yellow
$livePlan = New-mdiPortProbePlan -Domain 'microsoft.com' `
    -DomainController @([PSCustomObject]@{ Name = 'localhost'; IP = '127.0.0.1' }) `
    -NnrTarget @([PSCustomObject]@{ Name = 'dns.google'; IP = '8.8.8.8' }) -TimeoutMs 1500
$results = Invoke-mdiPortProbePlan -Plan $livePlan
Assert-That 'Plan execution returns results' (@($results).Count -gt 0) "($(@($results).Count) results)"
Assert-That 'Cloud probe is N/A without -WorkspaceName' ((@($results | Where-Object Id -eq 'CloudSsl').Applicable) -eq $false)
Assert-That 'RADIUS is N/A without -TestVpnRadius' ((@($results | Where-Object Id -eq 'RadiusUdp').Applicable) -eq $false)
Assert-That 'Localhost 444 is N/A when the updater is not running' ((@($results | Where-Object Id -eq 'UpdaterSsl').Applicable) -eq $false) `
    "-> $((@($results | Where-Object Id -eq 'UpdaterSsl').Detail))"
# The reverse lookup goes to a real resolver over the real network, so a bare "Success -eq $true"
# made this suite depend on the internet answering within 1500 ms. It fails intermittently on a
# loaded machine - it did, while eight scan workers were saturating the link - and a test that goes
# red for reasons unrelated to the code trains everyone to re-run it rather than read it.
#
# What actually matters is asserted instead, and it is the stronger property: a lookup that did not
# answer must be reported as NOT MEASURED, never as a measured failure. A timeout means "whether a
# PTR record exists is unknown"; calling that a failure would send an operator to fix name
# resolution on the strength of a probe that never got an answer. Both outcomes are accepted, and
# the one thing that is forbidden - Success $false with a not-tested detail - is checked explicitly.
$reverseDns = @($results | Where-Object Id -eq 'NnrReverseDns')[0]
$reverseResolved = ($reverseDns.Success -eq $true)
$reverseUnmeasured = ([string] $reverseDns.Detail -match $script:mdiPortNotTestedPattern)
Assert-That 'Reverse DNS probe produced a usable outcome' ($reverseResolved -or $reverseUnmeasured) `
    "-> $($reverseDns.Detail)"
# The probe primitives mark "this did not run" with the detail marker and leave Success $false - the
# same encoding Invoke-mdiPortProbePlan uses deliberately for a DNS server list it could not read.
# What must never happen is the AGGREGATION treating that as a measured failure, so the assertion is
# on the shared predicate every consumer goes through rather than on the raw record.
Assert-That 'an unanswered reverse lookup is not counted as a measured result' `
    (-not ($reverseUnmeasured -and (Test-mdiProbeWasMeasured -Record $reverseDns))) `
    "-> Success=$($reverseDns.Success) Detail=$($reverseDns.Detail)"
Assert-That 'Every result carries a Detail' (@($results | Where-Object { -not $_.Detail }).Count -eq 0)
$results | Format-Table Id, Protocol, Port, Target, Applicable, Success, Detail -AutoSize | Out-String -Width 210 | Write-Host

Write-Host "`n[8] HTML rendering" -ForegroundColor Yellow
$fakeServers = @(
    [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; RequiredPorts = $false; Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{
                ProbedFrom = 'Sensor server (outbound)'; Results = $results | ForEach-Object { $_ | Add-Member ProbedFrom 'Sensor server (outbound)' -PassThru -Force }
            }
        }
    }
)
$html = Get-mdiRequiredPortsHtml -Server $fakeServers
Assert-That 'HTML contains the summary table' ($html -match '<th>Protocol</th>')
Assert-That 'HTML contains the NNR matrix' ($html -match 'Network Name Resolution \(NNR\) matrix')
Assert-That 'HTML links the NNR troubleshooting doc' ($html -match 'aka\.ms/mdi/nnr/troubleshooting')
Assert-That 'HTML escapes angle brackets' ($html -notmatch '<td[^>]*>[^<]*<workspace>')
$emptyHtml = Get-mdiRequiredPortsHtml -Server @()
Assert-That 'HTML handles no results gracefully' ($emptyHtml -match 'skipped or produced no results')

Write-Host "`n[9] Windows PowerShell binder-safety regression" -ForegroundColor Yellow
# @() on a System.Collections.Generic.List[object] throws "Argument types do not match" on some Windows
# PowerShell 5.1 builds (reproduced on 5.1.20348.4294). The script must not instantiate that type.
$scriptText = Get-Content $scriptPath -Raw
$listObjectDecls = @([regex]::Matches($scriptText, 'New-Object[^\r\n]*Generic\.List\[object\]'))
Assert-That 'No Generic.List[object] is instantiated' ($listObjectDecls.Count -eq 0) `
    "($($listObjectDecls.Count) found)"
# Generic collections that remain must only be consumed in ways proven safe on that build:
# List[byte] via .ToArray(), List[string] via -join / @()
$genericDecls = @([regex]::Matches($scriptText, 'New-Object[^\r\n]*Generic\.List\[(\w+)\]') |
        ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
Assert-That 'Remaining generic lists are only byte/string' (
    @($genericDecls | Where-Object { $_ -notin @('byte', 'string') }).Count -eq 0) "($($genericDecls -join ', '))"
$v3 = Get-mdiSensorV3Readiness -ComputerName $env:COMPUTERNAME -SensorVersion 'N/A' -ErrorAction SilentlyContinue
Assert-That 'Get-mdiSensorV3Readiness returns a result' ($null -ne $v3)
Assert-That 'Get-mdiSensorV3Readiness returns checks' (@($v3.details.Checks).Count -gt 0) "($(@($v3.details.Checks).Count) checks)"
Assert-That 'Every v3 check has a name and detail' (@($v3.details.Checks | Where-Object { -not $_.Name -or -not $_.Detail }).Count -eq 0)
Assert-That 'Blockers are rendered as strings' (@($v3.details.Blockers | Where-Object { $_ -isnot [string] }).Count -eq 0)
$v3.details.Checks | Format-Table Name, Requirement, Status -AutoSize | Out-String -Width 210 | Write-Host
$v3Html = Get-mdiSensorV3Html -Server @([PSCustomObject]@{
        FQDN = $env:COMPUTERNAME; SensorV3Ready = $v3.isSensorV3Ready
        Details = [PSCustomObject]@{ SensorV3ReadyDetails = $v3.details }
    })
Assert-That 'v3 HTML renders a prerequisite table' ($v3Html -match '<th>Type</th>')
Assert-That 'v3 HTML reports the migration verdict' ($v3Html -match 'Eligible for in-place migration')
Assert-That 'v3 HTML handles no results gracefully' ((Get-mdiSensorV3Html -Server @()) -match 'skipped or produced no results')

Write-Host "`n[10] Remediation script generation" -ForegroundColor Yellow
# The generated script must always be valid PowerShell, whatever the findings look like
$fakeReport = @{
    Domain               = 'contoso.com'
    DomainControllers    = @(
        [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; IP = '10.0.0.4'; AdvancedAuditing = $false; NtlmAuditing = $false
            PowerSettings = $false; SensorHealth = $false; TimeSync = $false; RequiredPorts = $false
            Details = [PSCustomObject]@{
                RequiredPortsDetails = [PSCustomObject]@{
                    Results = @(
                        [PSCustomObject]@{ Id = 'NnrNetBios'; Name = 'NNR - NetBIOS'; Protocol = 'UDP'; Port = 137
                            Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'; Target = 'wks1.contoso.com'
                            Applicable = $true; Success = $false; Detail = 'Blocked' }
                        [PSCustomObject]@{ Id = 'NnrRpc'; Name = 'NNR - NTLM over RPC'; Protocol = 'TCP'; Port = 135
                            Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'; Target = 'wks1.contoso.com'
                            Applicable = $true; Success = $false; Detail = 'Blocked' }
                    )
                }
                SensorV3ReadyDetails = [PSCustomObject]@{ Blockers = @('Defender for Endpoint is onboarded: not onboarded') }
            }
        }
    )
    DomainObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $false }
    DomainDeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $false
        details = [PSCustomObject]@{ Container = 'CN=Deleted Objects,DC=contoso,DC=com'; Detail = 'No read access' }
    }
}
$fixFile = Join-Path $env:TEMP ('mdi-fix-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 6))
$fix = New-mdiRemediationScript -ReportData $fakeReport -FilePath $fixFile
Assert-That 'Remediation script is written' (Test-Path $fix.Path)
Assert-That 'Remediation script has sections' ($fix.SectionCount -ge 6) "($($fix.SectionCount) sections)"
$fixErrors = $null
[void] [System.Management.Automation.Language.Parser]::ParseFile($fix.Path, [ref] $null, [ref] $fixErrors)
Assert-That 'Remediation script is valid PowerShell' (@($fixErrors).Count -eq 0) `
    "($(@($fixErrors | ForEach-Object { 'L' + $_.Extent.StartLineNumber + ': ' + $_.Message }) -join ' | '))"
$fixText = Get-Content $fix.Path -Raw
Assert-That 'Remediation supports -WhatIf' ($fixText -match 'SupportsShouldProcess')
Assert-That 'Remediation fixes advanced auditing' ($fixText -match 'auditpol\.exe /set /subcategory')
Assert-That 'Remediation fixes NTLM auditing' ($fixText -match 'AuditReceivingNTLMTraffic')
Assert-That 'Remediation fixes the power scheme' ($fixText -match '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c')
Assert-That 'Remediation creates NNR firewall rules' ($fixText -match 'New-NetFirewallRule')
Assert-That 'NNR rules are scoped to the sensor IPs' ($fixText -match '-RemoteAddress \$RemoteAddress')
Assert-That 'Remediation restarts the sensor services' ($fixText -match 'AATPSensorUpdater')
Assert-That 'Remediation resynchronises the clock' ($fixText -match 'w32tm\.exe /resync')
Assert-That 'Remediation grants Deleted Objects access' ($fixText -match 'dsacls\.exe')
Assert-That 'No stray double backtick continuation' ($fixText -notmatch '``\s*\r?\n')
# A clean report must still produce a runnable, empty script
$cleanFile = Join-Path $env:TEMP ('mdi-fix-clean-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 6))
$clean = New-mdiRemediationScript -FilePath $cleanFile -ReportData @{
    Domain = 'contoso.com'
    DomainControllers = @([PSCustomObject]@{ FQDN = 'dc1.contoso.com'; IP = '10.0.0.4'; AdvancedAuditing = $true; Details = [PSCustomObject]@{} })
}
Assert-That 'Clean report yields zero sections' ($clean.SectionCount -eq 0)
$cleanErrors = $null
[void] [System.Management.Automation.Language.Parser]::ParseFile($clean.Path, [ref] $null, [ref] $cleanErrors)
Assert-That 'Clean remediation script is valid PowerShell' (@($cleanErrors).Count -eq 0)

# A member server and a Windows Server 2016 domain controller can never run the v3.x sensor: those
# are statements of what the server is, not tasks. Raising them as remediation sends people chasing
# something they cannot change, so only the actionable blockers may reach the generated script.
$blockFile = Join-Path $env:TEMP ('mdi-fix-v3-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 6))
$newV3 = { param($fqdn, $actionable, $all)
    [PSCustomObject]@{ FQDN = $fqdn; Details = [PSCustomObject]@{ SensorV3ReadyDetails =
            [PSCustomObject]@{ Blockers = $all; ActionableBlockers = $actionable } } }
}
$blocked = New-mdiRemediationScript -FilePath $blockFile -ReportData @{
    Domain            = 'contoso.com'
    DomainControllers = @(
        (& $newV3 'dc2016.contoso.com' @() @('Windows Server 2019 or later: build 14393 - keep using the v2.x sensor')),
        (& $newV3 'dc2019.contoso.com' @('Defender for Endpoint is onboarded: the server is not onboarded') @('Defender for Endpoint is onboarded: the server is not onboarded'))
    )
    CAServers         = @((& $newV3 'ca01.contoso.com' @() @('Server is a domain controller: Not a domain controller')))
    # A member server that also fails a fixable check: it still cannot run v3.x, so fixing the
    # fixable part changes nothing and the server must not be listed at all.
    EntraConnectServers = @((& $newV3 'aadc01.contoso.com' @() @('Server is a domain controller: Not a domain controller', 'Defender for Endpoint is onboarded: the server is not onboarded')))
}
$blockedText = Get-Content $blockFile -Raw
Assert-That 'Only the actionable v3 blockers make a section' ($blocked.SectionCount -eq 1)
Assert-That 'The remediable server is listed' ($blockedText -match 'dc2019\.contoso\.com')
Assert-That 'A Windows Server 2016 DC is not listed' ($blockedText -notmatch 'dc2016\.contoso\.com')
Assert-That 'A member server is not listed' ($blockedText -notmatch 'ca01\.contoso\.com')
Assert-That 'An ineligible server is dropped even with a fixable blocker' ($blockedText -notmatch 'aadc01\.contoso\.com')

# The guidance has to be printed, not left in comments: a comment is invisible to whoever runs the
# generated script, so a warning pointing at "the link above" tells them nothing.
Assert-That 'The v3 guidance is printed, not commented' ($blockedText -match "Write-Host\s+'\s+Onboard the server")
Assert-That 'No warning refers to invisible comments' ($blockedText -notmatch 'See the (comments|link) above')

$auditFile = Join-Path $env:TEMP ('mdi-fix-audit-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 6))
[void] (New-mdiRemediationScript -FilePath $auditFile -ReportData @{
        Domain               = 'contoso.com'
        DomainControllers    = @([PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Details = [PSCustomObject]@{} })
        DomainObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $false }
    })
$auditText = Get-Content $auditFile -Raw
Assert-That 'Object auditing prints the portal path' ($auditText -match 'Write-Host.+Advanced features')
Assert-That 'Object auditing prints its own link' ($auditText -match "Write-Host\s+'.+aka\.ms/mdi/objectauditing")
$blockErrors = $null
[void] [System.Management.Automation.Language.Parser]::ParseFile($auditFile, [ref] $null, [ref] $blockErrors)
Assert-That 'The auditing remediation is valid PowerShell' (@($blockErrors).Count -eq 0)

Remove-Item $fix.Path, $clean.Path, $blockFile, $auditFile -Force -ErrorAction SilentlyContinue

Write-Host "`n[11] Baseline history and trend" -ForegroundColor Yellow
$histDir = Join-Path $env:TEMP ('mdi-hist-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 6))
$fakeStats = [PSCustomObject]@{ ChecksPassed = 10; ChecksTotal = 16; TotalServers = 2
    ServerScores = @([PSCustomObject]@{ Failed = 0 }, [PSCustomObject]@{ Failed = 2 })
    PortsOpen = 40; PortsTotal = 42; NnrResolvable = 4; NnrTargetCount = 4; V3Ready = 0; V3Evaluated = 2
}
$b1 = Get-mdiBaselineHistory -BaselinePath $histDir -Domain 'contoso.com' -Statistics $fakeStats
Assert-That 'First run records one entry' (@($b1.History).Count -eq 1) "($(@($b1.History).Count))"
$b2 = Get-mdiBaselineHistory -BaselinePath $histDir -Domain 'contoso.com' -Statistics $fakeStats
# Regression: @(... | ConvertFrom-Json) nests the whole history into a single element in Windows PowerShell
Assert-That 'Second run appends without nesting' (@($b2.History).Count -eq 2) "($(@($b2.History).Count))"
Assert-That 'History entries are scalar objects' (@($b2.History | Where-Object { @($_.ChecksTotal).Count -ne 1 }).Count -eq 0)
$b3 = Get-mdiBaselineHistory -BaselinePath $histDir -Domain 'contoso.com' -Statistics $fakeStats
Assert-That 'Third run keeps growing' (@($b3.History).Count -eq 3) "($(@($b3.History).Count))"
$trend = New-mdiTrendChart -History $b3.History
Assert-That 'Trend chart renders an SVG' ($trend -match '<svg class="trend"')
Assert-That 'Trend chart plots every run' ((([regex]::Matches($trend, 'trend-dot')).Count) -eq 3)
Assert-That 'Trend chart uses invariant decimals' ($trend -notmatch '\d,\d{2}[ ",]')
$single = New-mdiTrendChart -History @($b1.History)
Assert-That 'Single run shows a hint instead of a chart' ($single -match 'At least two runs')
Remove-Item $histDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n[12] End-of-run output contract" -ForegroundColor Yellow
# A long verbose run that ends with a bare "False" reads like a failure rather than a verdict, so the
# boolean only goes on the pipeline when it is asked for. These are AST checks: the end of the script
# cannot be reached without a live forest.
$scriptText = Get-Content $scriptPath -Raw
$paramBlock = $ast.ParamBlock
$switchNames = @($paramBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
Assert-That 'PassThru is a parameter' ($switchNames -contains 'PassThru')
Assert-That 'AsJson and FailOnIssues are still there' (($switchNames -contains 'AsJson') -and ($switchNames -contains 'FailOnIssues'))
Assert-That 'PassThru is documented' ($scriptText -match '\.PARAMETER PassThru')

# The bare $result must be guarded. Anything else puts False back on the pipeline.
Assert-That 'the result is emitted only under PassThru' ($scriptText -match '\}\s*elseif\s*\(\$PassThru\)\s*\{\s*\$result\s*\}')
Assert-That 'no unguarded else branch emits the result' ($scriptText -notmatch '\}\s*else\s*\{\s*\$result\s*\}')

# Matched on the CONSOLE WRITER rather than on Write-Host specifically. The console output moved
# behind Write-mdiConsole so that -AsJson can keep human text off stdout, and asserting on the old
# cmdlet name failed a behaviour-preserving change while still passing if the lines were deleted.
$consoleWriter = 'Write-(Host|mdiConsole)(?: -AsJson:\$AsJson)?'
# There are THREE terminal outcomes, not two: a run that completed and is ready, a run that completed
# with findings, and a scan that stopped part way and is explicitly not a readiness result.
#
# Each is asserted on its own text rather than by counting matches of a shared pattern. The count was
# wrong in both directions: adding the incomplete-scan outcome failed this test even though the new
# branch is exactly the human-readable line the test exists to require, and a count of two would have
# been satisfied just as well by the same outcome printed twice with the other one deleted.
$readyLine = @([regex]::Matches($scriptText, "$consoleWriter \('  READY "))
$issuesLine = @([regex]::Matches($scriptText, "$consoleWriter \('  \{0\} issue\(s\) found: "))
$partialLine = @([regex]::Matches($scriptText, "$consoleWriter \('  \{0\} issue\(s\) found on the part of the estate"))
Assert-That 'the ready outcome is printed for a human' ($readyLine.Count -eq 1) "(found $($readyLine.Count))"
Assert-That 'the issues-found outcome is printed for a human' ($issuesLine.Count -eq 1) "(found $($issuesLine.Count))"
Assert-That 'the incomplete-scan outcome is printed for a human' ($partialLine.Count -eq 1) "(found $($partialLine.Count))"
Assert-That 'the failing outcome is not labelled NOT READY' ($scriptText -notmatch "$consoleWriter \('  NOT READY")
Assert-That 'the report path is printed' ($scriptText -match "$consoleWriter \('  Report: \{0\}'")

Write-Host "`n================ $pass passed / $fail failed ================" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
