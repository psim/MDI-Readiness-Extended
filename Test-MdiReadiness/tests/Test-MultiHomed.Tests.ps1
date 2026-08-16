<#
    Verifies that a multi-homed domain controller is probed on every address.

    A domain controller with two NICs is ordinary - backup, management, cluster heartbeat or a DMZ leg
    - and it was the blind spot behind the health alert this tool exists to explain. Network Name
    Resolution works on whatever source address the sensor OBSERVED in traffic, so a DC that answers
    NNR on one interface and is filtered on another fails resolution for half of what the sensor sees.

    Every address-learning path in the script previously returned exactly one address:
      - Get-ADComputer's IPv4Address property is a single value.
      - [System.Net.Dns]::GetHostAddresses(...)[0] picks an arbitrary A record, and a different one on
        each call when DNS round-robins, so two runs disagreed with each other.

    The result was a green report next to a lit portal alert, with nothing connecting the two.

    Pinned here: every address-learning path returns EVERY address of a host, so a NIC the scan never
    probed cannot sit behind a green report - the inventory emits one row per address and records that
    the host is multi-homed, NNR targets and the LDAP sample cover every NIC while their caps still
    count hosts, the NNR matrix and statistics group by address as well as by name so one machine's
    two NICs never merge, and no code path takes the first resolved address.
#>
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$loadedHash = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash
$canonicalPath = $(if ($env:MDI_CANONICAL) { $env:MDI_CANONICAL } else { $c = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1'; if (Test-Path -LiteralPath $c) { $c } else { Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1' } })
$canonicalHash = $(if (Test-Path -LiteralPath $canonicalPath) { (Get-FileHash -LiteralPath $canonicalPath -Algorithm SHA256).Hash } else { '<canonical not found>' })
"LOADED_PATH=$scriptPath"
"LOADED_SHA256=$loadedHash"
"CANONICAL_SHA256=$canonicalHash"
"HASH_MATCH=$($loadedHash -eq $canonicalHash)"
# Enforced only when the test IS running against the canonical file. Run-Suite.ps1 deliberately
# executes from an ISOLATED COPY so that the canonical can be edited mid-run without corrupting the
# result - its own header says "a result gathered from a directory that can change underneath the run
# is not evidence of anything". Comparing the copy against the LIVE canonical re-read at test time
# therefore measured a race, not the product: this file threw before a single assertion ran whenever
# another edit landed during the suite, and the run was reported as "no-assertions" rather than as a
# pass or a failure. The hashes are still printed above, so a stale copy remains visible.
# NOT fatal. Run-Suite.ps1 deliberately executes from an ISOLATED COPY so the canonical can be edited
# mid-run without corrupting the result - its own header says "a result gathered from a directory that
# can change underneath the run is not evidence of anything". Re-reading the LIVE canonical here and
# throwing on any difference measured that race instead of the product: this file aborted before a
# single assertion ran whenever another edit landed during the suite, and was reported as
# "no-assertions" rather than as a pass or a failure - a test silently not running at all. The hashes
# are printed above, so a genuinely stale copy is still visible to anyone reading the output.
if ($loadedHash -ne $canonicalHash) { Write-Host 'NOTE: running against an isolated copy that differs from the current canonical file.' -ForegroundColor DarkYellow }
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors -join '; ')" }

$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))

# EVERY script-scoped constant is loaded, not a hand-maintained list. The list went stale the moment a
# new constant was added: $script:mdiPortNotTestedPattern was null in the harness, and "-notmatch $null"
# treats the pattern as an empty string, which matches everything - so a filter meant to exclude
# untested probes silently excluded ALL of them.
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

$source = Get-Content $scriptPath -Raw

Write-Host "`n[1] Address discovery returns every address, deterministically" -ForegroundColor Yellow
# localhost resolves without touching the network, so the helper can be exercised for real.
$loopback = @(Get-mdiComputerAddress -ComputerName 'localhost')
Assert-That 'loopback is excluded as a service address' ($loopback -notcontains '127.0.0.1')

# A known address is honoured even when DNS knows nothing about the name.
$known = @(Get-mdiComputerAddress -ComputerName 'no-such-host.invalid' -KnownAddress '10.0.0.5')
Assert-That 'an unresolvable name still yields its known address' (
    $known.Count -eq 1 -and $known[0] -eq '10.0.0.5') "(got $($known -join ', '))"

$none = @(Get-mdiComputerAddress -ComputerName 'no-such-host.invalid')
Assert-That 'an unresolvable name with no known address yields nothing' ($none.Count -eq 0)

# Drive the shipped helper. Source-text assertions passed when a similarly named helper or a comment
# contained the expected token, without proving the returned address set was correct.
$ordered = @(Get-mdiComputerAddress -ComputerName '10.0.0.10' -KnownAddress @('10.0.0.10', '10.0.0.9'))
Assert-That 'addresses are sorted numerically, not as text' (
    $ordered.Count -eq 2 -and $ordered[0] -eq '10.0.0.9' -and $ordered[1] -eq '10.0.0.10') "(got $($ordered -join ', '))"
$apipa = @(Get-mdiComputerAddress -ComputerName '169.254.10.20' -KnownAddress '169.254.10.20')
Assert-That 'APIPA is rejected' ($apipa.Count -eq 0) "(got $($apipa -join ', '))"
$duplicates = @(Get-mdiComputerAddress -ComputerName '10.0.0.5' -KnownAddress @('10.0.0.5', '10.0.0.5'))
Assert-That 'duplicates are removed' ($duplicates.Count -eq 1 -and $duplicates[0] -eq '10.0.0.5') "(got $($duplicates -join ', '))"

Write-Host "`n[2] The inventory yields one probe target per address" -ForegroundColor Yellow
$inventoryText = ($functions | Where-Object { $_.Name -eq 'Get-mdiDomainControllerInventory' }).Extent.Text
Assert-That 'the inventory asks for every address' ($inventoryText -match 'Get-mdiComputerAddress')
Assert-That 'it emits one row per address'         ($inventoryText -match 'foreach \(\$address in \$addresses\)')
Assert-That 'it records that a host is multi-homed' ($inventoryText -match 'MultiHomed')

Write-Host "`n[3] NNR probes every address; LDAP samples hosts but probes every NIC of each" -ForegroundColor Yellow
# NNR resolves an OBSERVED ADDRESS, so every address is a distinct resolution target. LDAP is now also
# issued BY IP (never by name, which let DNS round-robin choose the tested NIC), so once the per-domain
# HOST sample is chosen every NIC of the selected hosts is probed. The cap counting hosts still stops
# one multi-homed DC from eating the whole budget and leaving a second DC untested.
$nnrText = ($functions | Where-Object { $_.Name -eq 'Resolve-mdiNnrTarget' }).Extent.Text
Assert-That 'NNR targets come from every address' ($nnrText -match 'Get-mdiComputerAddress')
Assert-That 'the NNR cap counts hosts, not addresses' ($nnrText -match "Group-Object -Property Name")

$ldapText = ($functions | Where-Object { $_.Name -eq 'Resolve-mdiLdapTarget' }).Extent.Text
Assert-That 'the LDAP sample groups by host to count the cap' ($ldapText -match "Group-Object -Property Name")

# Proven by running it: two addresses of one DC plus one address of another, capped at 2 hosts. The
# result keeps every unique (Name, IP) pair of the selected hosts.
$inventory = @(
    [PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '10.0.0.1'; Domain = 'contoso.com'; MultiHomed = $true }
    [PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '192.168.5.1'; Domain = 'contoso.com'; MultiHomed = $true }
    [PSCustomObject]@{ Name = 'dc2.contoso.com'; IP = '10.0.0.2'; Domain = 'contoso.com'; MultiHomed = $false }
)
$ldapTargets = Resolve-mdiLdapTarget -DomainControllers $inventory -MaxPerDomain 2
Assert-That 'LDAP picks two distinct hosts, not two NICs of one' (
    @($ldapTargets | Select-Object -ExpandProperty Name -Unique).Count -eq 2) "(got $(@($ldapTargets).Name -join ', '))"
# LDAP is now issued by IP, so every NIC of each selected host is a probe target: a DC that answers
# LDAP on one interface and is filtered on another must be tested on BOTH. dc1 (two NICs) + dc2 (one)
# = three targets across two hosts. Collapsing to one row per host let round-robin pick the tested NIC.
Assert-That 'every NIC of the selected hosts becomes an LDAP target' (@($ldapTargets).Count -eq 3) "(got $(@($ldapTargets).Count))"

# The cap still applies per domain, counting HOSTS: a cap of one selects a single DC and probes all of
# its addresses (here dc1's two NICs).
$capped = Resolve-mdiLdapTarget -DomainControllers $inventory -MaxPerDomain 1
Assert-That 'the per-domain cap counts hosts (one host, all its NICs)' (
    @($capped | Select-Object -ExpandProperty Name -Unique).Count -eq 1 -and @($capped).Count -eq 2) "(got $(@($capped).Count) rows across $(@($capped | Select-Object -ExpandProperty Name -Unique).Count) host(s))"

Write-Host "`n[4] The report keeps the two addresses apart" -ForegroundColor Yellow
# Grouping the NNR matrix by name alone merged a multi-homed host's rows back together, so a host with
# one working NIC and one blocked NIC read as fully resolvable - re-hiding the exact failure.
Assert-That 'the NNR matrix groups by address as well as name' (
    $source -match 'Group-Object -Property Target, TargetIP')
# Asserted by BEHAVIOUR rather than by matching the source text. The statistics now build their
# grouping key explicitly - Group-Object collapses every null or empty key into one shared group, so a
# record with a missing Target could be covered by an unrelated success - and a test that matched the
# old literal string failed on a change that kept the very behaviour it was written to protect. What
# matters is the outcome: a multi-homed host with one working NIC and one blocked NIC must NOT read
# as fully resolvable.
$multiHomed = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; OSVersion = $true
    RequiredPorts = $true
    Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{
            FailedRequired = @(); NnrFailedTargets = @()
            Results = @(
                [PSCustomObject]@{ Group = 'NNR'; Protocol = 'UDP'; Port = 137; Target = 'host.contoso.com'
                    TargetIP = '10.0.0.1'; Requirement = 'AtLeastOne'; Success = $true; Detail = 'Resolved'; Applicable = $true }
                [PSCustomObject]@{ Group = 'NNR'; Protocol = 'UDP'; Port = 137; Target = 'host.contoso.com'
                    TargetIP = '10.0.0.2'; Requirement = 'AtLeastOne'; Success = $false; Detail = 'Blocked'; Applicable = $true }
            ) } } }
$mhStats = Get-mdiReportStatistics -ReportData ([PSCustomObject]@{ DomainControllers = @($multiHomed)
        CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com') })
Assert-That 'the NNR statistics keep a multi-homed host''s addresses apart' (
    $mhStats.NnrTargetCount -eq 2 -and $mhStats.NnrResolvable -eq 1) `
    "(resolvable=$($mhStats.NnrResolvable) of $($mhStats.NnrTargetCount))"
Assert-That 'no NNR grouping is left keyed on the name alone' (
    $source -notmatch 'Group-Object -Property Target\s*\|')

Write-Host "`n[5] Remediation scopes firewall rules to every sensor address" -ForegroundColor Yellow
# The generated rules allow inbound access BY SOURCE ADDRESS. A multi-homed sensor probes from
# whichever interface routes to the target, so a rule naming only its primary address never matches
# and the port stays shut against the traffic that matters - while the operator believes it is fixed.
$remediationText = ($functions | Where-Object { $_.Name -eq 'New-mdiRemediationScript' }).Extent.Text
Assert-That 'the source list uses every address of each sensor' (
    $remediationText -match '\$_\.Addresses')

Write-Host "`n[6] Capacity sampling does not double-count a NIC team" -ForegroundColor Yellow
# An LBFO team exposes the Multiplexor Driver interface AND its physical members, and every packet
# traverses both. Summing all of them multiplied the packet rate by the number of members, which
# pushes the sizing into a larger band and can invent an "insufficient capacity" finding.
$sampleAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$script:mdiTrafficSampleScript' }, $true)[0].Extent.Text
Assert-That 'teamed adapters are detected' ($sampleAssignment -match 'Multiplexor')
Assert-That 'the team is counted instead of its members' ($sampleAssignment -match '\$adapters = \$teamed')

Write-Host "`n[7] Descriptive address fields never count as unread checks" -ForegroundColor Yellow
# Addresses is a descriptive field. Left out of the informational list it would be counted as a check
# that could not be read, and a perfectly healthy forest could never be reported as ready.
Assert-That 'Addresses is informational' ('Addresses' -in $script:mdiInformationalProperty)
Assert-That 'Domain is informational'    ('Domain' -in $script:mdiInformationalProperty)

$server = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1', '192.168.5.1')
    Domain = 'contoso.com'; NtlmAuditing = $true
    PartialFailure = $false; Unreachable = $false
}
Assert-That 'a multi-homed server reports no unread checks' (
    (Get-mdiUnreadCheckCount -Server $server) -eq 0) "(got $(Get-mdiUnreadCheckCount -Server $server))"
Assert-That 'a multi-homed server exposes exactly its real checks' (
    @(Get-mdiCheckProperty -Server $server).Count -eq 1) "(got $(@(Get-mdiCheckProperty -Server $server).Count))"

Write-Host "`n[8] No single-address shortcut is left anywhere" -ForegroundColor Yellow
# The original defect, in the exact shape it took. If this reappears the blind spot is back.
$firstAddress = [regex]::Matches($source, 'GetHostAddresses\([^)]*\)[^)]*\)\[0\]')
Assert-That 'no code takes the first resolved address' (
    $firstAddress.Count -eq 0) "(found $($firstAddress.Count))"

Write-Host "`n================ $pass passed / $fail failed ================" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
