<#
    Assertions written to close gaps found by MUTATION TESTING.

    Eighteen realistic bugs were introduced into the script one at a time and the whole suite was run
    against each. Eleven were caught. The seven below were NOT - the tests stayed green while the
    script gave a wrong answer - so each assertion here exists because a specific real defect could
    have shipped unnoticed.

    The mutation that a test does not catch is the bug that reaches the customer, so these are written
    against BEHAVIOUR wherever the code can be called directly, and against structure only where the
    function is too coupled to WMI or to a live directory to invoke in a harness.
#>
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors -join '; ')" }

$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))
foreach ($constAst in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -like '$script:*' -and
            $null -eq $n.Parent.Parent.Parent }, $false)) {
    . ([scriptblock]::Create($constAst.Extent.Text))
}

$pass = 0; $fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name $Detail" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

function New-Report {
    param([object[]] $Servers)
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @($Servers); CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @()
        DomainAdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DomainObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
        DomainExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
        DomainDeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
    }
}

Write-Host "`n[M4] The Unreachable flag fails the run on its own" -ForegroundColor Yellow
# Removing the unreachable guard from the verdict left every other suite green, because an
# unreachable server normally carries no checks and so fails for a different reason anyway. A server
# that answered reachability, produced one passing check and was THEN flagged is the case that slips
# through: nothing else in the verdict objects to it.
$flagged = [PSCustomObject]@{
    FQDN = 'dc-flagged.contoso.com'; Domain = 'contoso.com'
    Unreachable = $true; PartialFailure = $false
    PowerSettings = $true
    Comment = 'Server is not available: ICMP, TCP 135 and WMI all failed'
}
Assert-That 'a server flagged unreachable fails the run even when a check passed' (
    (Test-mdiReadinessResult -ReportData (New-Report @($flagged))) -eq $false)
$flaggedStats = Get-mdiReportStatistics -ReportData (New-Report @($flagged))
Assert-That 'it is counted as unreachable, not as a passing server' (
    $flaggedStats.UnreachableCount -eq 1 -and $flaggedStats.ReachableServers -eq 0) `
    "(unreachable $($flaggedStats.UnreachableCount), reachable $($flaggedStats.ReachableServers))"
Assert-That 'and it produces a finding' (
    @(Get-mdiIssueList -Statistics $flaggedStats -ReportData (New-Report @($flagged))).Count -gt 0)

Write-Host "`n[M7] Address discovery returns every address, not the first" -ForegroundColor Yellow
# Reducing Get-mdiComputerAddress to "the first address" left every suite green, yet that is exactly
# the multi-homing blind spot behind the NNR health alert: the second NIC is never probed.
# A known address plus whatever the name resolves to must both survive.
$both = @(Get-mdiComputerAddress -ComputerName 'localhost' -KnownAddress '10.99.99.99')
Assert-That 'a known address is not discarded in favour of DNS' ('10.99.99.99' -in $both) `
    "(got $($both -join ', '))"
$twoKnown = @(Get-mdiComputerAddress -ComputerName 'no-such-host.invalid' -KnownAddress '10.99.99.99')
Assert-That 'an unresolvable name still yields its known address' ($twoKnown.Count -eq 1)
# The behavioural proof that nothing truncates the list: feed a name that resolves to several
# addresses through the inventory and confirm every one becomes a probe target.
$inventoryRows = @(
    [PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '10.0.0.1'; Domain = 'contoso.com'; MultiHomed = $true }
    [PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '192.168.5.1'; Domain = 'contoso.com'; MultiHomed = $true }
)
$nnr = Resolve-mdiNnrTarget -DomainControllers $inventoryRows -MaxTargets 5
Assert-That 'both addresses of one host become NNR targets' (@($nnr).Count -eq 2) "(got $(@($nnr).Count))"

Write-Host "`n[M8] The LDAP sample counts hosts, never NICs" -ForegroundColor Yellow
# The existing check for this was STATIC - it searched the source for a Group-Object call - so
# deleting the collapse was caught only by luck of the fixture. These exercise the cap itself, which
# is where the damage is: two NICs of one DC eating the budget leaves the second DC untested.
$multiInventory = @(
    [PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '10.0.0.1'; Domain = 'contoso.com' }
    [PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '192.168.1.1'; Domain = 'contoso.com' }
    [PSCustomObject]@{ Name = 'dc2.contoso.com'; IP = '10.0.0.2'; Domain = 'contoso.com' }
)
$capped1 = @(Resolve-mdiLdapTarget -DomainControllers $multiInventory -MaxPerDomain 1)
# The cap counts HOSTS, never NICs: a cap of one selects a single domain controller, and every address
# that host answers on is then probed (LDAP is now issued by IP, so both NICs must be tested). The
# invariant is that ONE distinct host was chosen - not that a single row came back, which was the old
# collapse that let DNS round-robin pick which NIC of a multi-homed DC was ever tested.
Assert-That 'a cap of one selects one host (all its NICs), not a partial DC' (
    @($capped1 | Select-Object -ExpandProperty Name -Unique).Count -eq 1 -and $capped1.Count -eq 2) "(got $($capped1.Count) rows across $(@($capped1 | Select-Object -ExpandProperty Name -Unique).Count) host(s))"
$capped2 = @(Resolve-mdiLdapTarget -DomainControllers $multiInventory -MaxPerDomain 2)
Assert-That 'a cap of two picks two distinct hosts' (
    @($capped2 | Select-Object -ExpandProperty Name -Unique).Count -eq 2) "(got $($capped2.Name -join ', '))"
# dc1 (two NICs) + dc2 (one NIC) = three probe targets across two hosts: every NIC of each selected host.
Assert-That 'every NIC of the selected hosts is probed' ($capped2.Count -eq 3) "(got $($capped2.Count) rows)"

Write-Host "`n[M12] A reverse-direction probe is never a ports verdict" -ForegroundColor Yellow
# Turning the fallback's 'N/A' back into a boolean left the suite green, and that mutation produces
# the most expensive wrong answer this tool can give: a firewall change request for a port that was
# only ever measured in the opposite direction.
$fallbackServer = [PSCustomObject]@{
    FQDN = 'dc-fallback.contoso.com'; Domain = 'contoso.com'
    RequiredPorts = 'N/A'; PowerSettings = $true
    Unreachable = $false; PartialFailure = $false
    Details = [ordered]@{
        RequiredPortsDetails = [PSCustomObject]@{
            ProbedFrom = 'This computer (inbound to the server)'
            FailedRequired = @('Not tested in the required direction (sensor outbound) - measured inbound from this computer instead: TCP/135 to dc1: Blocked')
            NnrFailedTargets = @('Not tested in the required direction - measured inbound from this computer instead: dc1 (10.0.0.1)')
            Results = @()
        }
    }
}
Assert-That "a fallback RequiredPorts is not counted as a boolean check" (
    @(Get-mdiCheckProperty -Server $fallbackServer | Where-Object { $_.Name -eq 'RequiredPorts' }).Count -eq 0)
Assert-That 'it is counted as unread instead' (
    (Get-mdiUnreadCheckCount -Server $fallbackServer) -ge 1) "(got $(Get-mdiUnreadCheckCount -Server $fallbackServer))"
Assert-That 'so the run cannot be ready' (
    (Test-mdiReadinessResult -ReportData (New-Report @($fallbackServer))) -eq $false)
# And the findings must say "not measured", not "blocked".
$fbStats = Get-mdiReportStatistics -ReportData (New-Report @($fallbackServer))
$fbIssues = @(Get-mdiIssueList -Statistics $fbStats -ReportData (New-Report @($fallbackServer)))
Assert-That 'no finding claims a port is blocked' (
    @($fbIssues | Where-Object { [string] $_.Area -eq 'Name resolution' }).Count -eq 0) `
    "($(($fbIssues | ForEach-Object { $_.Area }) -join ', '))"
Assert-That 'the reverse-direction result is reported as not measured' (
    @($fbIssues | Where-Object { [string] $_.Area -eq 'Not measured' }).Count -ge 1)
# The contract: an untested probe must never produce a firewall rule. Asserted by RUNNING the
# generator, not by grepping its source. This assertion used to read
#   $remediationText -match 'Detail -notmatch \$script:mdiPortNotTestedPattern'
# which pinned one literal spelling of the filter rather than its effect, so it broke the moment the
# clause was routed through the shared Test-mdiProbeWasMeasured predicate - a change that STRENGTHENED
# the guard, because the predicate additionally requires Success to be a real boolean and so also
# excludes a probe whose result normalised to $null. A grep cannot tell those two apart; the
# generated file can.
$nnrUntestedRecord = [PSCustomObject]@{
    Id = 'nnr-UDP-137'; Group = 'NNR'; Scope = 'NetworkDevice'; Requirement = 'AtLeastOne'
    Protocol = 'UDP'; Port = 137; Target = 'dc1.contoso.com'; TargetIP = '10.0.0.1'
    Applicable = $true; Success = $null
    Detail = 'Not tested in the required direction - measured inbound from this computer instead'
}
# The untested probe must share a target with a GENUINELY MEASURED failure. On its own the target is
# classified NnrUntested, never enters $unresolvableKey, and no filter downstream can emit it - so an
# assertion built on it alone passes whatever the guard does. Proven: the first version of this
# assertion used the untested record by itself and SURVIVED having the guard deleted outright.
# With a measured failure beside it the target becomes NnrMeasured, and the only thing standing
# between the untested probe and a New-NetFirewallRule is the guard under test.
$nnrMeasuredFailure = [PSCustomObject]@{
    Id = 'nnr-TCP-135'; Group = 'NNR'; Scope = 'NetworkDevice'; Requirement = 'AtLeastOne'
    Protocol = 'TCP'; Port = 135; Target = 'dc1.contoso.com'; TargetIP = '10.0.0.1'
    Applicable = $true; Success = $false; Detail = 'Connection refused'
}
$nnrServer = [PSCustomObject]@{
    FQDN = 'dc-nnr.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; Comment = $null
    SensorVersion = '2.240.0.0'; Addresses = @('10.0.0.10'); IP = '10.0.0.10'
    RequiredPorts = $false
    Details = [PSCustomObject]@{
        RequiredPortsDetails = [PSCustomObject]@{ Results = @($nnrMeasuredFailure, $nnrUntestedRecord) }
    }
}
$nnrOut = Join-Path ([IO.Path]::GetTempPath()) ('mdi-m12-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
try {
    $null = New-mdiRemediationScript -ReportData (New-Report @($nnrServer)) -FilePath $nnrOut
    $nnrScript = if (Test-Path $nnrOut) { [IO.File]::ReadAllText($nnrOut) } else { '' }
} finally { Remove-Item $nnrOut -Force -ErrorAction SilentlyContinue }
$nnrRules = @([regex]::Matches($nnrScript, 'MDI-NNR-[A-Za-z]+-In') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-That 'the measured NNR failure still produces its rule' (
    $nnrRules -contains 'MDI-NNR-RPC-In') "(emitted: $($nnrRules -join ', '))"
Assert-That 'the NNR remediation excludes untested probes' (
    $nnrRules -notcontains 'MDI-NNR-NetBIOS-In') "(emitted: $($nnrRules -join ', '))"

Write-Host "`n[M15] The probe plan survives serialisation" -ForegroundColor Yellow
# The plan is shipped to the sensor as JSON. At too shallow a depth its nested targets collapse to
# type-name strings, the remote probe runs with NO targets, and the empty result silently triggers
# the reverse-direction fallback - a scan that looks like it ran and measured nothing.
$plan = New-mdiPortProbePlan -Domain 'contoso.com' `
    -DomainController @([PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '10.0.0.1' }) `
    -NnrTarget @([PSCustomObject]@{ Name = 'wks1.contoso.com'; IP = '10.0.0.50' }) `
    -WorkspaceName 'contoso' -TimeoutMs 1500
$roundTrip = ($plan | ConvertTo-Json -Depth 6 -Compress) | ConvertFrom-Json
Assert-That 'the probes survive the round trip' (
    @($roundTrip.Probes).Count -eq @($plan.Probes).Count) "(got $(@($roundTrip.Probes).Count))"
Assert-That 'a probe keeps its identity' (
    -not [string]::IsNullOrWhiteSpace([string] @($roundTrip.Probes)[0].Id)) "(got '$(@($roundTrip.Probes)[0].Id)')"
Assert-That 'the NNR targets keep their address' (
    [string] @($roundTrip.NnrTargets)[0].IP -eq '10.0.0.50') "(got '$(@($roundTrip.NnrTargets)[0].IP)')"
Assert-That 'the domain controller targets keep their address' (
    [string] @($roundTrip.DomainControllers)[0].IP -eq '10.0.0.1')
Assert-That 'nothing collapsed to a type name' (
    ($plan | ConvertTo-Json -Depth 6 -Compress) -notmatch 'System\.(Object|Collections|Management)')
# The depth actually used by the shipping code, proven by decoding the plan it really ships rather
# than by matching source text. The previous form searched Get-mdiPortProbeCommandLine for a literal
# "ConvertTo-Json -Depth 6" and broke the moment that line moved to a helper, while the behaviour it
# guards was intact - a test that fails on a refactor but would pass on a real depth regression.
$shippedText = Get-mdiPortProbeScriptText -Plan $plan -OutputFile 'C:\Windows\Temp\mdi-depth.json'
$shippedB64 = [regex]::Match($shippedText, "ConvertFrom-Json \(\[text\.encoding\]::UTF8\.GetString\(\[convert\]::FromBase64String\('([A-Za-z0-9+/=]+)'\)").Groups[1].Value
$shippedPlan = [text.encoding]::UTF8.GetString([convert]::FromBase64String($shippedB64)) | ConvertFrom-Json
Assert-That 'the shipped plan is serialised deep enough' (
    ([string] @($shippedPlan.DomainControllers)[0].IP -eq '10.0.0.1') -and
    ([string] @($shippedPlan.NnrTargets)[0].IP -eq '10.0.0.50') -and
    (-not [string]::IsNullOrWhiteSpace([string] @($shippedPlan.Probes)[0].Id))
) "(dc '$(@($shippedPlan.DomainControllers)[0].IP)', nnr '$(@($shippedPlan.NnrTargets)[0].IP)')"

Write-Host "`n[M16] The trend refuses to invent a delta" -ForegroundColor Yellow
# Removing the comparability guard left the suite green while the chart drew a confident
# "up 8 points" arrow across a script upgrade that had simply added a check.
$sameEstate = @(
    [PSCustomObject]@{ Timestamp = '2026-08-01T09:00:00'; ChecksPassed = 8; ChecksTotal = 10
        CheckNames = @('PowerSettings', 'AdvancedAuditing'); ServerNames = @('dc1') }
    [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00'; ChecksPassed = 9; ChecksTotal = 10
        CheckNames = @('PowerSettings', 'AdvancedAuditing'); ServerNames = @('dc1') }
)
$sameHtml = New-mdiTrendChart -History $sameEstate
Assert-That 'an unchanged estate still gets a delta' ($sameHtml -match 'pt vs previous run') `
    "(the guard must not suppress a legitimate comparison)"

$checksChanged = @(
    [PSCustomObject]@{ Timestamp = '2026-08-01T09:00:00'; ChecksPassed = 8; ChecksTotal = 10
        CheckNames = @('PowerSettings', 'AdvancedAuditing'); ServerNames = @('dc1') }
    [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00'; ChecksPassed = 12; ChecksTotal = 15
        CheckNames = @('PowerSettings', 'AdvancedAuditing', 'NewCheck'); ServerNames = @('dc1') }
)
$changedHtml = New-mdiTrendChart -History $checksChanged
Assert-That 'a changed check set is not comparable' ($changedHtml -match 'Not comparable') "(got a delta arrow)"
Assert-That 'and it says why' ($changedHtml -match 'set of checks changed')

$serversChanged = @(
    [PSCustomObject]@{ Timestamp = '2026-08-01T09:00:00'; ChecksPassed = 8; ChecksTotal = 10
        CheckNames = @('PowerSettings'); ServerNames = @('dc1', 'dc2') }
    [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00'; ChecksPassed = 5; ChecksTotal = 5
        CheckNames = @('PowerSettings'); ServerNames = @('dc1') }
)
Assert-That 'a decommissioned server is not comparable' (
    (New-mdiTrendChart -History $serversChanged) -match 'Not comparable')
$noFingerprint = @(
    [PSCustomObject]@{ Timestamp = '2026-08-01T09:00:00'; ChecksPassed = 8; ChecksTotal = 10 }
    [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00'; ChecksPassed = 9; ChecksTotal = 10 }
)
Assert-That 'a run recorded before the fingerprint is not comparable' (
    (New-mdiTrendChart -History $noFingerprint) -match 'Not comparable')

Write-Host "`n[M17] A timed-out remote command yields nothing to parse" -ForegroundColor Yellow
# Removing the guard let a killed process's truncated JSON be parsed into a handful of probe
# results - which reads as a completed scan that found most ports closed.
$remoteText = ($functions | Where-Object { $_.Name -eq 'Invoke-mdiRemoteCommand' }).Extent.Text
Assert-That 'the timeout sets the result to null instead of reading the file' (
    $remoteText -match 'if \(\$timedOut\) \{\s*\r?\n?\s*\$return = \$null')
Assert-That 'the file read is in the else branch, not after the guard' (
    $remoteText -match '\$timedOut[\s\S]{0,200}\} else \{[\s\S]{0,200}Get-Content -Path \$remoteFile')
Assert-That 'a timed-out process is terminated, not abandoned' ($remoteText -match '\.Terminate\(\)')
Assert-That 'and the operator is told' ($remoteText -match 'did not finish within')
# The guard must not be a throw: throwing lands in this function's own catch, which then tries the
# WMI read path and parses exactly the partial file the guard exists to reject.
Assert-That 'the guard is not a throw that its own catch would swallow' (
    $remoteText -notmatch "if \(\`$timedOut\) \{ throw")

Write-Host "`n================ $pass passed / $fail failed ================" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
