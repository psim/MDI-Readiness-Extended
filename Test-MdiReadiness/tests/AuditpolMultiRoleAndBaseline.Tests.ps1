# The last of the wave 5/6 findings.
#
#  c-6  A TRUNCATED auditpol backup was compared as though it were complete, so the subcategories the
#       export never reached looked like subcategories that are not audited - a measured failure, whose
#       remediation rewrites audit policy on a domain controller that was probably already correct.
#       Measured on a real host: auditpol /backup exports EVERY subcategory (64 rows, 38 of them set to
#       0), so a short file is truncation and never a clean policy.
#  h-4  The HTML tables iterated an UNMERGED server list while the KPI above them used a merged one, so
#       a host holding the DC, CA and Entra Connect roles showed its single blocked port three times.
#  v-6  V3Evaluated excluded only the exact string 'N/A', so $null, '' or an unrecognised word counted
#       as evaluated-and-not-ready: the denominator grew while the numerator did not.
#  v-9  Baseline history shape - DISPROVEN, and pinned here so it stays correct.

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

'[auditpol] a truncated backup is not a measured failure'
$expectedAudit = $settings.AdvancedAuditPolicyDCs
$auditRows = @($expectedAudit | ConvertFrom-Csv)
$auditHeader = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
function Set-AuditBackup {
    param([int] $Take = 999, [switch] $WrongValue, [switch] $Realistic)
    $count = [Math]::Min($Take, $auditRows.Count)
    $lines = @($auditRows | Select-Object -First $count | ForEach-Object {
            $value = if ($WrongValue -and $_.'Subcategory GUID' -eq $auditRows[0].'Subcategory GUID') { '0' } else { $_.'Setting Value' }
            'DC1,System,{0},{1},Success and Failure,,{2}' -f $_.Subcategory, $_.'Subcategory GUID', $value
        })
    # A real backup also carries dozens of subcategories MDI never asks about.
    if ($Realistic) { $lines += 1..40 | ForEach-Object { 'DC1,System,Other {0},{{0cce9{0:D3}-69ae-11d9-bed3-505054503030}},No Auditing,,0' -f $_ } }
    $script:auditText = @($auditHeader) + $lines
    function global:Invoke-mdiRemoteCommand { param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds) $script:auditText }
}
Set-AuditBackup -Realistic
Assert-That 'a complete backup that is correct still passes' (
    (Get-mdiAdvancedAuditing -ComputerName 'dc1' -ExpectedAuditing $expectedAudit 3>$null).isAdvancedAuditingOk -eq $true)
Set-AuditBackup -Realistic -WrongValue
Assert-That 'a complete backup with a wrong value still FAILS' (
    (Get-mdiAdvancedAuditing -ComputerName 'dc1' -ExpectedAuditing $expectedAudit 3>$null).isAdvancedAuditingOk -eq $false)
foreach ($take in @(1, [Math]::Max(1, $auditRows.Count - 1))) {
    Set-AuditBackup -Take $take -Realistic
    $r = Get-mdiAdvancedAuditing -ComputerName 'dc1' -ExpectedAuditing $expectedAudit 3>$null
    Assert-That "a backup carrying $take of $($auditRows.Count) subcategories is not measured" (
        [string] $r.isAdvancedAuditingOk -eq 'N/A') "(got '$($r.isAdvancedAuditingOk)')"
    # Asserted on MEANING, not on one word: the operator must be told the policy was NOT read and
    # why, rather than being shown a policy failure. Pinning the literal 'truncated' broke when the
    # message was widened to name the second cause (an unparseable export) without changing behaviour.
    Assert-That '  ...and says the policy could not be read' (
        [string] $r.details -match 'Not tested' -and
        [string] $r.details -match 'cut off|could not be parsed|partial')
}
function global:Invoke-mdiRemoteCommand { param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds) @() }
Assert-That 'no output at all is still not measured' (
    [string] (Get-mdiAdvancedAuditing -ComputerName 'dc1' -ExpectedAuditing $expectedAudit 3>$null).isAdvancedAuditingOk -eq 'N/A')
Remove-Item Function:\global:Invoke-mdiRemoteCommand -ErrorAction SilentlyContinue

'[multi-role] one host in three roles is one row everywhere'
$portRecord = [PSCustomObject]@{ Id = 'Ldap'; Name = 'LDAP'; Group = 'LDAP'; Protocol = 'TCP'; Port = 389
    Target = 'dc2.contoso.com'; TargetIP = '10.0.0.2'; Requirement = 'Required'
    Success = $false; Detail = 'Connection refused'; Applicable = $true
}
function New-RoleServer {
    [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false
        OSVersion = $true; TimeSync = $false; SensorHealth = $false
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @($portRecord) }
            TimeSyncDetails = [PSCustomObject]@{ Detail = 'Clock is 12 minutes behind' }
            SensorHealthDetails = [PSCustomObject]@{ Installed = $true; Issues = @('The AATPSensor service is Stopped (start mode: Auto)') }
        }
    }
}
$multiRole = [PSCustomObject]@{
    DomainControllers = @((New-RoleServer)); CAServers = @((New-RoleServer)); EntraConnectServers = @((New-RoleServer))
    DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'
}
$merged = @(Merge-mdiServerByFqdn -Server @(@($multiRole.DomainControllers) + @($multiRole.CAServers) + @($multiRole.EntraConnectServers) | Where-Object { $_ }))
Assert-That 'the three role rows merge into one host' ($merged.Count -eq 1) "(got $($merged.Count))"
# Asserted as "merging changes nothing", not as a raw occurrence count. The intent of this test is
# that a host holding three roles is ONE row, not three - so the honest check is that the merged
# output is identical to the single-role output. Pinning the literal count to 1 instead accidentally
# encoded a separate defect: this record carries a probe Id that is not in the shipped port list, and
# the matrix used to iterate the shipped ids only, so the row was silently DROPPED and the detail
# appeared once purely because one of its two surfaces was missing. Fixing that drop made the count 2
# and failed a test whose actual subject - the merge - was working perfectly.
$singleRole = @(New-RoleServer)
Assert-That 'merging three roles renders exactly what one role renders' (
    (Get-mdiRequiredPortsHtml -Server $merged) -eq (Get-mdiRequiredPortsHtml -Server $singleRole))
Assert-That '  ...and the blocked port is present at all' (
    ([regex]::Matches((Get-mdiRequiredPortsHtml -Server $merged), 'Connection refused')).Count -ge 1)
Assert-That 'the clock finding renders once' (
    ([regex]::Matches((Get-mdiTimeSyncHtml -Server $merged), '12 minutes behind')).Count -eq 1)
Assert-That 'the sensor table has one row' (
    ([regex]::Matches((Get-mdiSensorHealthHtml -Server $merged), '<tr><td class="mono">')).Count -eq 1)
Assert-That 'the merge preserves the sensor issues for the remediation generator' (
    @($merged[0].Details.SensorHealthDetails.Issues).Count -eq 1)
# The shipped builder must use the merged list, or the tables and the KPI disagree again.
Assert-That 'the report builder merges before building its tables' (
    (Get-Command Set-MdiReadinessReport).Definition -match 'allServers = @\(Merge-mdiServerByFqdn')
$multiStats = Get-mdiReportStatistics -ReportData $multiRole
Assert-That 'the KPI counts one server' (@($multiStats.Servers).Count -eq 1)
Assert-That 'and one port record' ($multiStats.PortsTotal -eq 1) "(got $($multiStats.PortsTotal))"
# Two genuinely different servers must still be two rows.
Assert-That 'two distinct hosts stay two rows' (
    @(Merge-mdiServerByFqdn -Server @(
            [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; OSVersion = $true; Details = [PSCustomObject]@{} }
            [PSCustomObject]@{ FQDN = 'dc2.contoso.com'; Unreachable = $false; OSVersion = $true; Details = [PSCustomObject]@{} }
        )).Count -eq 2)

'[sensor v3] only a real measurement counts as evaluated'
foreach ($case in @(
        @{ V = $true; Evaluated = 1; Ready = 1; N = '[bool] true' }
        @{ V = $false; Evaluated = 1; Ready = 0; N = '[bool] false' }
        @{ V = 'True'; Evaluated = 1; Ready = 1; N = "string 'True'" }
        @{ V = 'False'; Evaluated = 1; Ready = 0; N = "string 'False'" }
        @{ V = 'N/A'; Evaluated = 0; Ready = 0; N = "'N/A'" }
        @{ V = $null; Evaluated = 0; Ready = 0; N = 'null' }
        @{ V = ''; Evaluated = 0; Ready = 0; N = 'empty string' }
        @{ V = 'Unknown'; Evaluated = 0; Ready = 0; N = "'Unknown'" }
    )) {
    $s = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false
        OSVersion = $true; SensorV3Ready = $case.V
        Details = [PSCustomObject]@{ SensorV3ReadyDetails = [PSCustomObject]@{ MigrationEligible = $true; Blockers = @(); ActionableBlockers = @(); UnknownChecks = @() } }
    }
    $st = Get-mdiReportStatistics -ReportData ([PSCustomObject]@{ DomainControllers = @($s); CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com') })
    Assert-That "SensorV3Ready $($case.N): evaluated=$($case.Evaluated) ready=$($case.Ready)" (
        $st.V3Evaluated -eq $case.Evaluated -and $st.V3Ready -eq $case.Ready) "(got evaluated=$($st.V3Evaluated) ready=$($st.V3Ready))"
}

'[baseline] the history survives one entry, many entries and corruption'
$blDir = Join-Path $env:TEMP ('bl-{0}' -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $blDir | Out-Null
try {
    $blStats = Get-mdiReportStatistics -ReportData ([PSCustomObject]@{
            DomainControllers = @([PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false; OSVersion = $true; Details = [PSCustomObject]@{} })
            CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com')
        })
    $first = Get-mdiBaselineHistory -BaselinePath $blDir -Domain 'contoso.com' -Statistics $blStats 3>$null
    Assert-That 'the first run writes one entry' (@($first.History).Count -eq 1)
    $reread = (Get-Content -LiteralPath $first.Path -Raw) | ConvertFrom-Json
    Assert-That 'a one-entry file re-reads as one entry, not as its properties' (@($reread).Count -eq 1) "(got $(@($reread).Count))"
    Assert-That '  ...and that entry is an object' (@($reread)[0].Timestamp -is [string])
    Start-Sleep -Milliseconds 1100
    $second = Get-mdiBaselineHistory -BaselinePath $blDir -Domain 'contoso.com' -Statistics $blStats 3>$null
    Assert-That 'the second run appends rather than replacing' (@($second.History).Count -eq 2) "(got $(@($second.History).Count))"
    foreach ($corrupt in @('', 'null', '{', '[{"Timestamp":', 'not json', '[]')) {
        Set-Content -LiteralPath $first.Path -Value $corrupt -Encoding UTF8
        $recovered = Get-mdiBaselineHistory -BaselinePath $blDir -Domain 'contoso.com' -Statistics $blStats 3>$null
        Assert-That ("a history containing '{0}' does not fail the scan" -f $(if ($corrupt -eq '') { '(empty)' } else { $corrupt })) (
            @($recovered.History).Count -ge 1)
    }
} finally {
    Remove-Item $blDir -Recurse -Force -ErrorAction SilentlyContinue
}

'[baseline lock] a permission failure is not reported as contention'
# Only CONTENTION is worth retrying. An UnauthorizedAccessException means the folder is not writable
# and waiting cannot change that - but every run stalled the full 15 seconds and reported "another
# run is writing the baseline history", sending the operator to hunt a concurrent scan that does not
# exist while the real cause, an ACL on the folder they passed with -BaselinePath, went unmentioned.
$script:baselineWarnings = @()
function global:Write-mdiWarning { param($Message) $script:baselineWarnings += $Message }
$baselineStats = [PSCustomObject]@{ ChecksPassed = 1; ChecksTotal = 1; ChecksUnread = 0; ServerScores = @()
    PortsOpen = 0; PortsTotal = 0; NnrResolvable = 0; NnrTargetCount = 0 }

$denyDir = Join-Path $env:TEMP ('mdi-deny-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $denyDir -Force | Out-Null
$denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $env:USERNAME, 'Write', 'ContainerInherit,ObjectInherit', 'None', 'Deny')
$denyAcl = Get-Acl $denyDir
$denyAcl.AddAccessRule($denyRule)
Set-Acl -Path $denyDir -AclObject $denyAcl
try {
    $script:baselineWarnings = @()
    $denyWatch = [Diagnostics.Stopwatch]::StartNew()
    $null = Get-mdiBaselineHistory -BaselinePath $denyDir -Domain 'example.invalid' -Statistics $baselineStats
    $denyWatch.Stop()
    $denyMessage = ($script:baselineWarnings | Out-String)
    Assert-That 'an unwritable baseline folder fails fast' ($denyWatch.Elapsed.TotalSeconds -lt 5) "($([int]$denyWatch.Elapsed.TotalSeconds)s)"
    Assert-That '  ...and names permissions as the cause' ($denyMessage -match 'not writable by this account')
    Assert-That '  ...not a phantom concurrent run' ($denyMessage -notmatch 'another run is writing')
} finally {
    $restoreAcl = Get-Acl $denyDir
    [void] $restoreAcl.RemoveAccessRule($denyRule)
    Set-Acl -Path $denyDir -AclObject $restoreAcl
    Remove-Item $denyDir -Recurse -Force -ErrorAction SilentlyContinue
}

'[baseline lock] genuine contention is still retried'
$busyDir = Join-Path $env:TEMP ('mdi-busy-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $busyDir -Force | Out-Null
$busyLock = [System.IO.File]::Open((Join-Path $busyDir 'mdi-baseline-example.invalid.json.lock'),
    'OpenOrCreate', 'ReadWrite', 'None')
try {
    $script:baselineWarnings = @()
    $busyWatch = [Diagnostics.Stopwatch]::StartNew()
    $null = Get-mdiBaselineHistory -BaselinePath $busyDir -Domain 'example.invalid' -Statistics $baselineStats
    $busyWatch.Stop()
    $busyMessage = ($script:baselineWarnings | Out-String)
    Assert-That 'a genuinely held lock IS waited for' ($busyWatch.Elapsed.TotalSeconds -ge 10) "($([int]$busyWatch.Elapsed.TotalSeconds)s)"
    Assert-That '  ...and is reported as another run' ($busyMessage -match 'another run is writing')
} finally {
    $busyLock.Close(); $busyLock.Dispose()
    Remove-Item $busyDir -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item Function:\global:Write-mdiWarning -ErrorAction SilentlyContinue

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
