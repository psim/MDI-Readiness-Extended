<#
    An audit policy setting that was never read must not be reported as a setting that is WRONG.

    Get-mdiAdvancedAuditing compares an `auditpol /backup` CSV against the settings MDI requires, using
    an exact string match on 'Subcategory GUID' and 'Setting Value'. auditpol emits a COLUMN-ALIGNED
    CSV, so its fields can carry padding, and an exact match is defeated by padding in two ways:

      * a padded Subcategory GUID failed the row filter, so the row was never collected and the
        completeness guard reported the export as truncated - "carried 8 subcategories but only 0 of
        the 8 MDI requires" - for a backup that was complete and correct;
      * a padded, EMPTY or non-numeric Setting Value passed the filter and then failed the comparison,
        which is far worse: it becomes a MEASURED audit-policy failure, and the generated remediation
        script writes eight `auditpol.exe /set` calls against a production domain controller whose
        current policy was never actually read.

    That last outcome is the most expensive wrong answer this check can give, which is why an
    unreadable Setting Value is now unmeasured ('N/A') - the same treatment the function already gives
    a backup it could not read at all.

    These tests assert the returned tri-state and detail for crafted auditpol output. They never
    inspect the script's source text, and they never run auditpol.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

$header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
$expected = @($settings.AdvancedAuditPolicyDCs | ConvertFrom-Csv)

# A complete, correct backup built from the requirement table itself, so the control cannot drift when
# the required subcategories change.
function New-Backup {
    param([scriptblock] $Mutate = $null)
    $rows = @($expected | ForEach-Object {
            [PSCustomObject]@{
                Guid  = [string] $_.'Subcategory GUID'
                Value = [string] $_.'Setting Value'
            }
        })
    if ($Mutate) { $rows = @(& $Mutate $rows) }
    @($header) + @($rows | ForEach-Object {
            'DC1,System,Some Subcategory,{0},Success and Failure,,{1}' -f $_.Guid, $_.Value
        })
}

# The remote call is what returns the backup text, so that is the single thing stubbed.
$script:backup = $null
Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
    param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds)
    , $script:backup
}
Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value { param($ComputerName) 'C:\Windows\Temp' }
function Get-Audit {
    param($Lines)
    $script:backup = @($Lines)
    Get-mdiAdvancedAuditing -ComputerName 'dc1.contoso.com' -ExpectedAuditing $settings.AdvancedAuditPolicyDCs
}

Write-Host 'The controls: a correct backup passes, a genuinely wrong one fails' -ForegroundColor Cyan
$ok = Get-Audit (New-Backup)
Assert-That 'a complete correct backup is a measured PASS' ($ok.isAdvancedAuditingOk -eq $true) "got '$($ok.isAdvancedAuditingOk)'"

$noAudit = Get-Audit (New-Backup { param($r) $r[0].Value = '0'; $r })
Assert-That 'a subcategory set to no auditing is a measured FAILURE' ($noAudit.isAdvancedAuditingOk -eq $false) "got '$($noAudit.isAdvancedAuditingOk)'"
$successOnly = Get-Audit (New-Backup { param($r) $r[0].Value = '1'; $r })
Assert-That 'Success-only where Success+Failure is required still FAILS' ($successOnly.isAdvancedAuditingOk -eq $false) "got '$($successOnly.isAdvancedAuditingOk)'"

Write-Host 'A Setting Value that was never read is unmeasured, never a failure' -ForegroundColor Cyan
$cases = @(
    @{ Name = 'one Setting Value empty'; M = { param($r) $r[0].Value = ''; $r } }
    @{ Name = 'one Setting Value whitespace'; M = { param($r) $r[0].Value = '   '; $r } }
    @{ Name = 'one Setting Value non-numeric'; M = { param($r) $r[0].Value = 'n/a'; $r } }
    @{ Name = 'every Setting Value empty'; M = { param($r) foreach ($x in $r) { $x.Value = '' }; $r } }
)
foreach ($c in $cases) {
    $r = Get-Audit (New-Backup $c.M)
    Assert-That "$($c.Name): the check is the tri-state 'N/A'" ([string] $r.isAdvancedAuditingOk -eq 'N/A') "got '$($r.isAdvancedAuditingOk)'"
    Assert-That "  ...and is never a measured failure" ($r.isAdvancedAuditingOk -ne $false) "got '$($r.isAdvancedAuditingOk)'"
    Assert-That "  ...and the detail marks it as not tested" ([string] $r.details -like 'Not tested*') "got '$($r.details)'"
}

# A 6-column export carries no Setting Value column at all.
$sixCol = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting') +
@($expected | ForEach-Object { 'DC1,System,Some Subcategory,{0},Success and Failure,' -f [string] $_.'Subcategory GUID' })
$six = Get-Audit $sixCol
Assert-That 'a 6-column export with no Setting Value column is unmeasured' ([string] $six.isAdvancedAuditingOk -eq 'N/A') "got '$($six.isAdvancedAuditingOk)'"
Assert-That '  ...and is never a measured failure' ($six.isAdvancedAuditingOk -ne $false) "got '$($six.isAdvancedAuditingOk)'"

Write-Host 'A column-aligned export that pads its fields is still read correctly' -ForegroundColor Cyan
$padValue = Get-Audit (New-Backup { param($r) foreach ($x in $r) { $x.Value = $x.Value + '  ' }; $r })
Assert-That 'padded Setting Values still PASS' ($padValue.isAdvancedAuditingOk -eq $true) "got '$($padValue.isAdvancedAuditingOk)' / $($padValue.details)"

$padGuid = Get-Audit (New-Backup { param($r) foreach ($x in $r) { $x.Guid = $x.Guid + ' ' }; $r })
Assert-That 'padded Subcategory GUIDs still PASS' ($padGuid.isAdvancedAuditingOk -eq $true) "got '$($padGuid.isAdvancedAuditingOk)' / $($padGuid.details)"
Assert-That '  ...and are not reported as a truncated export' ([string] $padGuid.details -notlike '*cut off*') "got '$($padGuid.details)'"

# Padding must not become a way to HIDE a real failure.
$padWrong = Get-Audit (New-Backup { param($r) $r[0].Value = ' 0 '; $r })
Assert-That 'a padded WRONG value is still a measured failure' ($padWrong.isAdvancedAuditingOk -eq $false) "got '$($padWrong.isAdvancedAuditingOk)'"

Write-Host 'A GUID is matched case-insensitively' -ForegroundColor Cyan
$lower = Get-Audit (New-Backup { param($r) foreach ($x in $r) { $x.Guid = $x.Guid.ToLowerInvariant() }; $r })
Assert-That 'lower-case GUIDs still PASS' ($lower.isAdvancedAuditingOk -eq $true) "got '$($lower.isAdvancedAuditingOk)' / $($lower.details)"

Write-Host 'A genuinely truncated export is still reported as unmeasured' -ForegroundColor Cyan
# The completeness guard must survive: dropping a required subcategory is not the same as padding one.
$truncated = Get-Audit (New-Backup { param($r) @($r | Select-Object -Skip 1) })
Assert-That 'a backup missing a required subcategory is unmeasured' ([string] $truncated.isAdvancedAuditingOk -eq 'N/A') "got '$($truncated.isAdvancedAuditingOk)'"
Assert-That '  ...and is never a measured failure' ($truncated.isAdvancedAuditingOk -ne $false) "got '$($truncated.isAdvancedAuditingOk)'"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
