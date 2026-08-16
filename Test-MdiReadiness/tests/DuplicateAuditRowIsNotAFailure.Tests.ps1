<#
    A required subcategory listed TWICE must not turn a correct audit policy into a measured failure.

    Get-mdiAdvancedAuditing compares the required subcategories against the machine's auditpol
    /backup export with Compare-Object, which counts MULTIPLICITY: eight expected rows against nine
    actual rows differ even when every distinct row matches.

    The per-user filter above the comparison already documents this hazard - "a perfectly configured
    domain controller reported NOT configured the moment any per-user row existed, because the
    comparison counts multiplicity" - but that filter only engages when the export carries MORE THAN
    ONE distinct Policy Target. A duplicate under a single target never reaches it.

    Measured on the shipped function before the fix: an export whose eight required subcategories
    were all correct, with one of them repeated carrying the SAME correct value, returned $false and
    the only difference Compare-Object reported was

        => {0CCE9211-69AE-11D9-BED3-505054503030} = 3

    a row that matches what was expected. $false is the verdict that writes `auditpol.exe /set` for
    every required subcategory into the remediation script, so this rewrites the audit policy of a
    domain controller that was already correct - the same outcome the function's other guards exist
    to prevent.

    Duplicates that DISAGREE are a different fact and must not be collapsed: a subcategory recorded
    twice with two different values has no readable setting, so it is unmeasured ('N/A'), never a
    measured pass and never a measured failure.
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
Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value { param($ComputerName) 'C:\Windows\Temp' }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$expectedCsv = $settings.AdvancedAuditPolicyDCs
$expectedRows = @($expectedCsv | ConvertFrom-Csv)

$script:fakeOutput = @()
Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
    param($ComputerName, $CommandLine, $LocalFile)
    return $script:fakeOutput
}

$header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
function New-Row {
    param($Guid, $Value, $PolicyTarget = 'System')
    'DC1,{0},Some Subcategory,{1},Success and Failure,,{2}' -f $PolicyTarget, $Guid, $Value
}
function New-Export {
    param([string[]] $Rows)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add($header)
    foreach ($r in $Rows) { $l.Add($r) }
    return $l.ToArray()
}
function Get-Verdict {
    param([string[]] $Export)
    $script:fakeOutput = $Export
    (Get-mdiAdvancedAuditing -ComputerName 'DC1' -ExpectedAuditing $expectedCsv)
}

$correct = @($expectedRows | ForEach-Object { New-Row $_.'Subcategory GUID' $_.'Setting Value' })
$firstGuid = [string] $expectedRows[0].'Subcategory GUID'
$firstValue = [string] $expectedRows[0].'Setting Value'

Write-Host "`n[1] Baseline: a clean, correct export is a measured pass" -ForegroundColor Yellow
$r = Get-Verdict (New-Export $correct)
Assert-That 'a correct export reads True' ($r.isAdvancedAuditingOk -eq $true) "(got '$($r.isAdvancedAuditingOk)')"

Write-Host "`n[2] A required subcategory repeated with the SAME correct value is still correct" -ForegroundColor Yellow
$dup = @($correct) + @(New-Row $firstGuid $firstValue)
$r = Get-Verdict (New-Export $dup)
Assert-That 'a duplicated correct row is not a measured failure' ($r.isAdvancedAuditingOk -isnot [bool] -or $r.isAdvancedAuditingOk -ne $false) "(got '$($r.isAdvancedAuditingOk)')"
Assert-That '  ...and it reads True, not merely unmeasured' ($r.isAdvancedAuditingOk -eq $true) "(got '$($r.isAdvancedAuditingOk)')"

Write-Host "`n[3] Repeated three times, and more than one subcategory repeated" -ForegroundColor Yellow
$dup3 = @($correct) + @(New-Row $firstGuid $firstValue) + @(New-Row $firstGuid $firstValue) +
    @(New-Row ([string] $expectedRows[1].'Subcategory GUID') ([string] $expectedRows[1].'Setting Value'))
$r = Get-Verdict (New-Export $dup3)
Assert-That 'several duplicated correct rows still read True' ($r.isAdvancedAuditingOk -eq $true) "(got '$($r.isAdvancedAuditingOk)')"

Write-Host "`n[4] Duplicates that DISAGREE are unmeasured, not a measured verdict" -ForegroundColor Yellow
$conflict = @($correct) + @(New-Row $firstGuid '0')
$r = Get-Verdict (New-Export $conflict)
Assert-That 'a contradictory duplicate is not a measured pass' ($r.isAdvancedAuditingOk -ne $true) "(got '$($r.isAdvancedAuditingOk)')"
Assert-That '  ...and not a measured failure either' (-not ($r.isAdvancedAuditingOk -is [bool] -and $r.isAdvancedAuditingOk -eq $false)) "(got '$($r.isAdvancedAuditingOk)')"
Assert-That '  ...it is N/A' ([string] $r.isAdvancedAuditingOk -eq 'N/A') "(got '$($r.isAdvancedAuditingOk)')"
Assert-That '  ...and says why, naming the subcategory' (([string] $r.details) -match [regex]::Escape($firstGuid)) "(details: '$($r.details)')"

Write-Host "`n[5] The fix must not silence a genuinely wrong policy" -ForegroundColor Yellow
# Every required subcategory present exactly once, but one carries the wrong value.
$wrong = @($expectedRows | ForEach-Object {
        $v = if ([string] $_.'Subcategory GUID' -eq $firstGuid) { '0' } else { $_.'Setting Value' }
        New-Row $_.'Subcategory GUID' $v
    })
$r = Get-Verdict (New-Export $wrong)
Assert-That 'a genuinely misconfigured subcategory still reads False' ($r.isAdvancedAuditingOk -is [bool] -and $r.isAdvancedAuditingOk -eq $false) "(got '$($r.isAdvancedAuditingOk)')"

# And a wrong value that is ALSO duplicated must stay a failure - de-duplication must not turn a
# real misconfiguration into a pass.
$wrongDup = @($wrong) + @(New-Row $firstGuid '0')
$r = Get-Verdict (New-Export $wrongDup)
Assert-That 'a duplicated WRONG row still reads False' ($r.isAdvancedAuditingOk -is [bool] -and $r.isAdvancedAuditingOk -eq $false) "(got '$($r.isAdvancedAuditingOk)')"

Write-Host "`n[6] A missing subcategory is still unmeasured, not a failure" -ForegroundColor Yellow
$missing = @($correct | Select-Object -Skip 1)
$r = Get-Verdict (New-Export $missing)
Assert-That 'an incomplete export is N/A' ([string] $r.isAdvancedAuditingOk -eq 'N/A') "(got '$($r.isAdvancedAuditingOk)')"

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
