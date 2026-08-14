<#
    A backup containing ONLY per-user audit policy must not be read as the machine's system policy.

    'auditpol /backup' exports per-user audit policy alongside the system policy, and a per-user row
    carries the SAME Subcategory GUID as the system row for that subcategory. Get-mdiAdvancedAuditing
    already knows this: it recognises a per-user target by its locale-neutral SHAPE ('DOMAIN\user',
    'user@domain', or a raw 'S-1-...' SID) and prefers the system rows.

    But that filter only engaged when the export carried MORE THAN ONE distinct Policy Target. With a
    single per-user target there is exactly one, the multi-target guard never fired, and the fallback
    - "if the user-shaped filter would remove everything, keep the rows rather than filter to nothing"
    - handed alice's rows to the comparison as though they were the machine's policy. An export whose
    only content was 'CONTOSO\alice' configured across all eight required subcategories therefore
    reported the domain controller as correctly audited while its actual system policy was never in
    the file at all.

    That is a false green on a detection-coverage control, and nothing else in the report contradicts
    it: per-user policy applies only to the named principal, so MDI's own coverage of the machine is
    entirely unknown.

    The fallback still has a real job - an export whose system target is spelled unusually must stay
    readable - and this test pins that it keeps doing it. A system target is a single translated word
    carrying none of the user-principal markers, so it lands in the non-per-user set and is still
    read; only an export in which EVERY row is user-shaped is unreadable.

    Unread, not failed. Reporting $false here would write eight `auditpol.exe /set` calls into the
    remediation script against a domain controller whose real policy nobody has seen - the same
    reasoning the function already applies to a truncated or unparseable backup.
#>

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

# The expectation table the shipped script itself uses, so the test cannot drift from the product.
$dcPolicy = $settings.AdvancedAuditPolicyDCs
$required = @(@($dcPolicy | ConvertFrom-Csv) | ForEach-Object {
        [PSCustomObject]@{ Guid = [string] $_.'Subcategory GUID'; Value = [string] $_.'Setting Value' }
    })

# A 7-column 'auditpol /backup' export, exactly as the parser expects to receive it. Filler rows are
# included because a real backup lists every subcategory the machine has, and the completeness guard
# keys off that.
function New-Backup {
    param([string] $PolicyTarget = 'System', [string] $Machine = 'DC1', [hashtable] $SettingByGuid = @{})
    $lines = New-Object System.Collections.ArrayList
    [void] $lines.Add('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    $n = 0
    foreach ($r in $required) {
        $n++
        $value = if ($SettingByGuid.ContainsKey($r.Guid)) { $SettingByGuid[$r.Guid] } else { $r.Value }
        [void] $lines.Add(('{0},{1},Required subcategory {2},{3},Success and Failure,,{4}' -f $Machine, $PolicyTarget, $n, $r.Guid, $value))
    }
    for ($i = 0; $i -lt 56; $i++) {
        $g = '{{0cce9{0:x3}-69ae-11d9-bed3-505054503030}}' -f (0x300 + $i)
        [void] $lines.Add(('{0},{1},Filler subcategory {2},{3},No Auditing,,0' -f $Machine, $PolicyTarget, $i, $g))
    }
    , $lines.ToArray()
}

# Only the two transport helpers are stubbed. Every other line of Get-mdiAdvancedAuditing is the
# shipped code, which is the point: the defect lives in its parsing, not in how it fetches the file.
Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value { param([string] $ComputerName) 'C:\Windows\Temp' }
Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
    param([string] $ComputerName, [string] $CommandLine, [string] $LocalFile, [int] $TimeoutSeconds = 30)
    $script:auditOutput
}

function Invoke-Check {
    param([string[]] $Backup)
    $script:auditOutput = $Backup
    Get-mdiAdvancedAuditing -ComputerName 'dc1.contoso.com' -ExpectedAuditing $dcPolicy
}

'[advanced auditing] a backup carrying only per-user policy is UNREAD, not a pass'
foreach ($principal in @('CONTOSO\alice', 'alice@contoso.com', 'S-1-5-21-1111111111-2222222222-3333333333-1104')) {
    $r = Invoke-Check (New-Backup -PolicyTarget $principal)
    Assert-That ("only per-user rows for '{0}' is not reported as configured" -f $principal) `
        ([string] $r.isAdvancedAuditingOk -ne 'True') "(got '$($r.isAdvancedAuditingOk)')"
    Assert-That ("  ...and is reported as NOT MEASURED rather than as a failure" ) `
        ([string] $r.isAdvancedAuditingOk -eq 'N/A') "(got '$($r.isAdvancedAuditingOk)')"
    Assert-That ("  ...and says why, naming the per-user policy") `
        ([string] $r.details -match 'per-user' -and [string] $r.details -match 'Not tested') "(detail '$([string] $r.details)')"
}

'[advanced auditing] the system policy is still read when it is present'
$control = Invoke-Check (New-Backup -PolicyTarget 'System')
Assert-That 'a correct system policy still passes' ([string] $control.isAdvancedAuditingOk -eq 'True') `
    "(got '$($control.isAdvancedAuditingOk)')"

# The fallback the fix must not break: a system target spelled unusually carries no user-principal
# marker, so it is still the system policy and must still be read.
foreach ($odd in @('Systeme', 'Sistema', 'Systemrichtlinie')) {
    $r = Invoke-Check (New-Backup -PolicyTarget $odd)
    Assert-That ("an unusual system target '{0}' is still read" -f $odd) `
        ([string] $r.isAdvancedAuditingOk -eq 'True') "(got '$($r.isAdvancedAuditingOk)')"
}

'[advanced auditing] a real system policy alongside per-user policy is still preferred'
# The blind-DC case: system policy is 0 everywhere, alice's per-user policy is correct. The system
# rows must win, so the check must FAIL rather than pass on the strength of alice's rows.
$blind = @{}
foreach ($r in $required) { $blind[$r.Guid] = '0' }
$mixed = New-Object System.Collections.ArrayList
foreach ($line in (New-Backup -PolicyTarget 'System' -SettingByGuid $blind)) { [void] $mixed.Add($line) }
foreach ($line in ((New-Backup -PolicyTarget 'CONTOSO\alice') | Select-Object -Skip 1)) { [void] $mixed.Add($line) }
$r = Invoke-Check ($mixed.ToArray())
Assert-That 'a blind system policy is a measured FAILURE, not a pass borrowed from per-user rows' `
    ([string] $r.isAdvancedAuditingOk -eq 'False') "(got '$($r.isAdvancedAuditingOk)')"

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
