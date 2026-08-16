<#
    One machine must be one machine on every surface, and its addresses must survive to all of them.

    A domain controller reached by both its short name and its FQDN, or holding more than one NIC, was
    not held to a single identity end to end. Aliases survived discovery as separate rows, so one
    machine was counted twice; addresses were dropped or retyped between discovery, the per-address
    inventory, the NNR and LDAP plans, the probe records, the score, the issue list, the generated
    remediation, the HTML tabs and the JSON, so a machine present on one surface went missing on
    another. An estate of seven real machines could be reported as eight, and a DC with no address at
    all could disappear from coverage rather than be charged as not measured.

    Pinned here, across every surface: aliases merge to the canonical FQDN and no short alias survives;
    IPv6 is canonical and mapped forms are folded; both NICs of a multi-homed DC reach the inventory,
    the plans and the probe records; different machines sharing an address stay separate; only the
    failing NIC produces failures; the addressless DC stays in the population, is charged as not
    measured, is named in the issue list with its reason, and renders an explicit Not determined cell;
    the remediation names the failing host and exact address without substituting the healthy NIC; and
    the HTML and JSON both show seven canonical machines, not an eighth alias row.
#>

$ErrorActionPreference = 'Stop'
$canonical = $(if ($env:MDI_CANONICAL) { $env:MDI_CANONICAL } else { $c = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1'; if (Test-Path -LiteralPath $c) { $c } else { Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1' } })
$loaded = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $loaded)) { $loaded = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$loadedHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($loaded))).Replace('-','')
$canonicalHash = $(if (Test-Path -LiteralPath $canonical) { [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($canonical))).Replace('-','') } else { '<canonical not found>' })
"LOADED_PATH=$loaded"
"LOADED_SHA256=$loadedHash"
"CANONICAL_SHA256=$canonicalHash"
"HASH_MATCH=$($loadedHash -eq $canonicalHash)"
if ($loadedHash -ne $canonicalHash) { 'NOTE=loaded copy differs from the canonical file (expected inside an isolated suite copy)' }
$text = [IO.File]::ReadAllText($loaded) -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
if ($text -notmatch '(?m)^function ConvertTo-mdiBoolean') { throw "The file loaded from $loaded is not the Test-MdiReadiness product script." }
$main = $text.IndexOf('#region Main'); if ($main -gt 0) { $text = $text.Substring(0, $main) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That([string] $Name, [bool] $Condition, [string] $Detail = '') {
    if ($Condition) { $script:pass++; "  PASS  $Name" }
    else { $script:fail++; "  FAIL  $Name $Detail" }
}
function Type-Of($Value) { if ($null -eq $Value) { '<null>' } else { $Value.GetType().FullName } }

$script:directoryRows = @(
    [PSCustomObject]@{ HostName = 'dc1.example.test'; Name = 'DC1'; IPv4Address = '10.0.0.11'; IPv6Address = $null }
    [PSCustomObject]@{ HostName = 'dc2.example.test'; Name = 'DC2'; IPv4Address = $null; IPv6Address = '2001:0db8:0:0:0:0:0:22' }
    [PSCustomObject]@{ HostName = 'dc3.example.test'; Name = 'DC3'; IPv4Address = $null; IPv6Address = '::ffff:10.0.0.33' }
    [PSCustomObject]@{ HostName = 'dc4.example.test'; Name = 'DC4'; IPv4Address = $null; IPv6Address = $null }
    [PSCustomObject]@{ HostName = 'dc5.example.test'; Name = 'DC5'; IPv4Address = '10.0.0.55'; IPv6Address = $null }
    [PSCustomObject]@{ HostName = 'dc6.example.test'; Name = 'DC6'; IPv4Address = '10.0.0.55'; IPv6Address = $null }
    [PSCustomObject]@{ HostName = 'DC7'; Name = 'DC7'; IPv4Address = '10.0.0.77'; IPv6Address = $null }
    [PSCustomObject]@{ HostName = 'dc7.example.test'; Name = 'DC7'; IPv4Address = '10.0.0.77'; IPv6Address = $null }
)
$script:addressMap = @{
    'dc1.example.test' = @('10.0.0.12', '10.0.0.11')
    'dc2.example.test' = @('2001:0db8:0:0:0:0:0:22')
    'dc3.example.test' = @('::ffff:10.0.0.33')
    'dc4.example.test' = @()
    'dc5.example.test' = @('10.0.0.55')
    'dc6.example.test' = @('10.0.0.55')
    'dc7.example.test' = @('10.0.0.77')
}
Set-Item -Path function:script:Get-ADDomainController -Value {
    param($Server, $Filter, $ErrorAction)
    $script:directoryRows
}
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param([string] $ComputerName, [string[]] $KnownAddress = $null)
    $values = @($script:addressMap[$ComputerName])
    if (-not $script:addressMap.ContainsKey($ComputerName)) { $values = @($KnownAddress) }
    @(@(foreach ($value in $values) {
        $canonicalAddress = ConvertTo-mdiCanonicalIPAddress -Value $value
        if ($null -ne $canonicalAddress -and (Test-mdiUsableComputerAddress -Value $canonicalAddress)) { $canonicalAddress }
    }) | Select-Object -Unique | Sort-Object -Property @{ Expression = { Get-mdiIPAddressSortKey -Value $_ } })
}

'[discovery -> inventory] one canonical host identity owns one canonical address set'
$resolved = Resolve-mdiDomainController -Domain 'example.test'
$discovery = @($resolved.Servers)
$inventory = @(Get-mdiDomainControllerInventory -Domain @('example.test'))
"RAW_DISCOVERY_COUNT=$($discovery.Count) TYPE=$(Type-Of $resolved.Servers)"
foreach ($row in $discovery) { "RAW_DISCOVERY NAME=[$($row.Name)] NAME_TYPE=$(Type-Of $row.Name) IP=[$($row.IP)] IP_TYPE=$(Type-Of $row.IP) ADDRESSES=[$(@($row.Addresses) -join ',')] ADDRESSES_TYPE=$(Type-Of $row.Addresses)" }
foreach ($row in $inventory) { "RAW_INVENTORY NAME=[$($row.Name)] NAME_TYPE=$(Type-Of $row.Name) IP=[$($row.IP)] IP_TYPE=$(Type-Of $row.IP) ADDRESSES=[$(@($row.Addresses) -join ',')] ADDRESSES_TYPE=$(Type-Of $row.Addresses)" }
Assert-That 'short and FQDN aliases merge during shipped discovery' ($discovery.Count -eq 7) "count=$($discovery.Count)"
Assert-That 'the retained alias spelling is the canonical FQDN' (@($discovery | Where-Object { $_.Name -eq 'dc7.example.test' }).Count -eq 1)
Assert-That 'no short alias survives discovery' (@($discovery | Where-Object { $_.Name -eq 'DC7' }).Count -eq 0)
$dc1Discovery = @($discovery | Where-Object { $_.Name -eq 'dc1.example.test' })[0]
Assert-That 'both addresses of a multi-homed DC stay on discovery' ((@($dc1Discovery.Addresses) -join ',') -eq '10.0.0.11,10.0.0.12') "addresses=$(@($dc1Discovery.Addresses) -join ',')"
Assert-That 'the discovery address collection has one stable array type' ($dc1Discovery.Addresses -is [object[]]) "type=$(Type-Of $dc1Discovery.Addresses)"
Assert-That 'expanded IPv6 is canonical at the discovery boundary' (@($discovery | Where-Object Name -eq 'dc2.example.test')[0].IP -eq '2001:db8::22')
Assert-That 'mapped IPv6 is folded at the discovery boundary' (@($discovery | Where-Object Name -eq 'dc3.example.test')[0].IP -eq '10.0.0.33')
Assert-That 'the per-address inventory preserves every machine and NIC' ($inventory.Count -eq 8) "count=$($inventory.Count)"
Assert-That 'every inventory Addresses field has the same array type' (@($inventory | Where-Object { $_.Addresses -isnot [object[]] }).Count -eq 0) "types=$(@($inventory | ForEach-Object { Type-Of $_.Addresses } | Select-Object -Unique) -join ',')"

'[target plans -> probe records] names and addresses do not fork'
$nnrTargets = @(Resolve-mdiNnrTarget -DomainControllers $inventory -MaxTargets 0)
$ldapTargets = @(Resolve-mdiLdapTarget -DomainControllers $inventory -MaxPerDomain 0)
Assert-That 'the alias is one NNR endpoint, not two' (@($nnrTargets | Where-Object { $_.IP -eq '10.0.0.77' }).Count -eq 1)
Assert-That 'the alias is one LDAP endpoint, not two' (@($ldapTargets | Where-Object { $_.IP -eq '10.0.0.77' }).Count -eq 1)
Assert-That 'different machines sharing an address remain separate' (@($nnrTargets | Where-Object { $_.IP -eq '10.0.0.55' } | Select-Object -ExpandProperty Name -Unique).Count -eq 2)
Assert-That 'both multi-homed endpoints reach the NNR plan' ((@($nnrTargets | Where-Object Name -eq 'dc1.example.test').IP -join ',') -eq '10.0.0.11,10.0.0.12')
$plan = New-mdiPortProbePlan -Domain 'example.test' -DomainController $ldapTargets -NnrTarget $nnrTargets -TimeoutMs 20
$plan.Probes = @($plan.Probes | Where-Object { $_.Id -in @('NnrRpc', 'LdapTcp') })
Set-Item -Path function:script:Get-mdiConfiguredDnsServer -Value { [PSCustomObject]@{ Servers = @(); Measured = $true; Detail = $null } }
Set-Item -Path function:script:Test-mdiTcpPort -Value {
    param([string] $ComputerName, [int] $Port, [int] $TimeoutMs, [switch] $IsRetry)
    $ok = $ComputerName -ne '10.0.0.12'
    [PSCustomObject]@{ Success = $ok; LatencyMs = 1; Detail = $(if ($ok) { 'Connected' } else { 'Closed - connection refused' }) }
}
$records = Invoke-mdiPortProbePlan -Plan $plan
foreach ($record in $records) { "RAW_RECORD TARGET=[$($record.Target)] TARGET_TYPE=$(Type-Of $record.Target) TARGETIP=[$($record.TargetIP)] TARGETIP_TYPE=$(Type-Of $record.TargetIP) APPLICABLE=[$($record.Applicable)] APPLICABLE_TYPE=$(Type-Of $record.Applicable) SUCCESS=[$($record.Success)] SUCCESS_TYPE=$(Type-Of $record.Success)" }
Assert-That 'the probe records retain the one canonical alias spelling' (@($records | Where-Object Target -eq 'dc7.example.test').Count -eq 2)
Assert-That 'no short alias reaches a probe record' (@($records | Where-Object Target -eq 'DC7').Count -eq 0)
Assert-That 'only the second NIC produces the measured failures' (@($records | Where-Object { $_.Success -eq $false -and $_.TargetIP -eq '10.0.0.12' }).Count -eq 2)

function New-ServerRow([string] $Name, $IP, [object[]] $Addresses, [object[]] $Results = @()) {
    $details = [PSCustomObject]@{}
    $row = [PSCustomObject][ordered]@{
        FQDN = $Name; IP = $IP; Addresses = @($Addresses); Domain = 'example.test'
        Unreachable = $false; PartialFailure = $false; NtlmAuditing = $true; SensorVersion = '2.250'; Details = $details
    }
    if (@($Results).Count -gt 0) {
        Add-Member -InputObject $row -MemberType NoteProperty -Name RequiredPorts -Value $false
        Add-Member -InputObject $details -MemberType NoteProperty -Name RequiredPortsDetails -Value ([PSCustomObject]@{
            ProbedFrom = 'Sensor server (outbound)'; FailedRequired = @(); NnrFailedTargets = @(); Results = @($Results)
        })
    }
    $row
}
$serverRows = @(foreach ($group in @($inventory | Where-Object Name | Group-Object Name)) {
        $addresses = @($group.Group | ForEach-Object { @($_.Addresses) + @($_.IP) } | Where-Object { $_ } | Select-Object -Unique | Sort-Object -Property @{ Expression = { Get-mdiIPAddressSortKey $_ } })
        New-ServerRow -Name $group.Name -IP $(if ($addresses.Count) { $addresses[0] } else { $null }) -Addresses $addresses -Results $(if ($group.Name -eq 'dc1.example.test') { $records } else { @() })
    })
$addressless = @(Get-mdiAddresslessDomainController -Inventory $inventory)
$domainRow = [PSCustomObject]@{
    Domain = 'example.test'
    AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A'; Measured = $true }; AdfsAuditingMeasured = $true
    ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true; Measured = $true }; ObjectAuditingMeasured = $true
    ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A'; Measured = $true }; ExchangeAuditingMeasured = $true
    DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; Measured = $true; details = [PSCustomObject]@{ Detail = 'Configured' } }; DeletedObjectsMeasured = $true
}
$report = [PSCustomObject][ordered]@{
    ScriptVersion = $settings.ScriptVersion; Domain = 'example.test'; Forest = 'example.test'
    ForestDiscovery = [PSCustomObject]@{ Name = 'example.test'; Domains = @('example.test'); Method = 'Stub'; Complete = $true; Error = $null }
    DomainsInScope = @('example.test'); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); AddresslessDomainControllers = $addressless
    NnrTargetComputer = @(); MaxNnrTargets = 0; DomainControllers = $serverRows; CAServers = @(); EntraConnectServers = @()
    DomainAuditing = @($domainRow); DomainAdfsAuditing = $domainRow.AdfsAuditing; DomainObjectAuditing = $domainRow.ObjectAuditing
    DomainExchangeAuditing = $domainRow.ExchangeAuditing; DomainDeletedObjects = $domainRow.DeletedObjects
    DomainSchemaVersion = [PSCustomObject]@{ schemaVersion = 88; details = 'Windows Server 2019' }; SkippedAreas = @()
}

'[issues and coverage] an addressless named DC is explicit unmeasured population'
$stats = Get-mdiReportStatistics -ReportData $report
$issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report)
"RAW_STATS TOTAL_SERVERS=$($stats.TotalServers) NNR_CANDIDATES=$($stats.NnrCandidateCount) NNR_DISTINCT=$($stats.NnrDistinctTargetCount) PORT_CANDIDATES=$($stats.PortCandidateHostCount) PORT_DISTINCT=$($stats.PortDistinctTargetCount) CHECKS_UNREAD=$($stats.ChecksUnread)"
foreach ($issue in $issues) { "RAW_ISSUE SERVER=[$($issue.Server)] AREA=[$($issue.Area)] ISSUE=[$($issue.Issue)]" }
Assert-That 'the addressless helper returns the named DC once' ($addressless.Count -eq 1 -and $addressless[0] -eq 'dc4.example.test') "value=$($addressless -join ',')"
Assert-That 'the coverage population includes all seven real machines' ($stats.PortCandidateHostCount -eq 7 -and $stats.NnrCandidateCount -eq 7) "port=$($stats.PortCandidateHostCount) nnr=$($stats.NnrCandidateCount)"
Assert-That 'the coverage surface shows only six machines entered a plan' ($stats.PortDistinctTargetCount -eq 6 -and $stats.NnrDistinctTargetCount -eq 6) "port=$($stats.PortDistinctTargetCount) nnr=$($stats.NnrDistinctTargetCount)"
Assert-That 'the score charges the missing endpoint as not measured' (@($stats.ServerScores | Where-Object FQDN -eq 'Domain controller address not determined - dc4.example.test').Count -eq 1)
Assert-That 'the issue list names the addressless DC and why it was omitted' (@($issues | Where-Object { $_.Server -eq 'dc4.example.test' -and $_.Area -eq 'Not measured' -and $_.Issue -match 'LDAP and Network Name Resolution' }).Count -eq 1)
Assert-That 'the issue list names the exact failed NIC' (@($issues | Where-Object { $_.Issue -match 'dc1\.example\.test \(10\.0\.0\.12\)' }).Count -ge 2)

'[HTML, JSON and remediation] every output carries the same endpoint facts'
$outDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi-crosssurface-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
if (Test-Path -LiteralPath $outDir) { Remove-Item -LiteralPath $outDir -Recurse -Force }
[void] [IO.Directory]::CreateDirectory($outDir)
try {
    $remediationPath = Join-Path $outDir 'Fix-MdiReadiness-example.test.ps1'
    $remediation = New-mdiRemediationScript -ReportData $report -FilePath $remediationPath
    $remediationText = [IO.File]::ReadAllText($remediationPath)
    Assert-That 'the generated remediation names the failing host and exact address' ($remediationText.Contains('dc1.example.test (10.0.0.12)'))
    Assert-That 'the generated remediation does not substitute the healthy NIC' (-not $remediationText.Contains('dc1.example.test (10.0.0.11)'))

    $script:SkipCA = $true; $script:SkipEntraConnect = $true; $script:SkipNetworkPorts = $false; $script:SkipSensorV3Readiness = $true
    $htmlPath = Set-MdiReadinessReport -Domain 'example.test' -Path $outDir -ReportData $report -Remediation $remediation -SkipTrend
    $html = [IO.File]::ReadAllText($htmlPath)
    $dcTab = [regex]::Match($html, '(?s)<section class="panel" id="tab-dcs">(.*?)<section class="panel" id="tab-ports">').Groups[1].Value
    Assert-That 'the DC table exposes the first NIC' ($dcTab.Contains('10.0.0.11'))
    Assert-That 'the DC table exposes the second NIC' ($dcTab.Contains('10.0.0.12'))
    Assert-That 'the DC table exposes canonical IPv6' ($dcTab.Contains('2001:db8::22'))
    Assert-That 'the addressless DC has an explicit Not determined cell' ($dcTab -match 'dc4\.example\.test[\s\S]*?Not determined')
    Assert-That 'the HTML tab count is seven canonical machines' ($html -match 'Domain controllers <span class="count">7</span>')

    $jsonPath = Join-Path $outDir 'mdi-example.test.json'
    $jsonText = [IO.File]::ReadAllText($jsonPath)
    $json = $jsonText | ConvertFrom-Json
    "RAW_JSON_TYPE=$(Type-Of $jsonText) DC_COUNT=$(@($json.DomainControllers).Count)"
    foreach ($row in @($json.DomainControllers)) { "RAW_JSON NAME=[$($row.FQDN)] IP=[$($row.IP)] IP_TYPE=$(Type-Of $row.IP) ADDRESSES=[$(@($row.Addresses) -join ',')] ADDRESSES_TYPE=$(Type-Of $row.Addresses)" }
    Assert-That 'JSON contains seven machines, not an eighth alias row' (@($json.DomainControllers).Count -eq 7)
    Assert-That 'JSON retains only the canonical alias spelling' (@($json.DomainControllers | Where-Object FQDN -eq 'dc7.example.test').Count -eq 1 -and @($json.DomainControllers | Where-Object FQDN -eq 'DC7').Count -eq 0)
    $jsonDc1 = @($json.DomainControllers | Where-Object FQDN -eq 'dc1.example.test')[0]
    Assert-That 'JSON retains both multi-homed addresses' ((@($jsonDc1.Addresses) -join ',') -eq '10.0.0.11,10.0.0.12')
    $jsonDc4 = @($json.DomainControllers | Where-Object FQDN -eq 'dc4.example.test')[0]
    Assert-That 'JSON uses a real null and an empty address array for the addressless DC' ($null -eq $jsonDc4.IP -and @($jsonDc4.Addresses).Count -eq 0)
} finally {
    Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue
}

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail) { exit 1 }