$ErrorActionPreference = 'Stop'
$script:p = 0; $script:f = 0
function Check {
    param($Name, $Expected, $Actual)
    if ("$Expected" -eq "$Actual") { $script:p++; '  PASS {0,-56} => {1}' -f $Name, $Actual }
    else { $script:f++; '  FAIL {0,-56} => got [{1}] want [{2}]' -f $Name, $Actual, $Expected }
}

$scriptPath = (Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1')
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
'target LastWriteTime: {0}' -f (Get-Item $scriptPath).LastWriteTime
$raw = Get-Content $scriptPath -Raw
$t = $raw -replace '(?m)^#Requires.*$', ''
$t = $t -replace '\[CmdletBinding\([^)]*\)\]', ''
$i = $t.IndexOf('#region Main'); if ($i -gt 0) { $t = $t.Substring(0, $i) }
Invoke-Expression $t

# The comparison under test is lifted VERBATIM out of the current file rather than retyped, so this
# probe cannot pass against a matcher that no longer exists. If the extraction fails, the test fails.
$matcherPattern = '(?s)\$isAuditingOk = @\(\$expectedAuditing \| Where-Object \{.*?\}\)\.Count -eq @\(\$expectedAuditing\)\.Count'
$m = [regex]::Match($raw, $matcherPattern)
if (-not $m.Success) { throw 'Could not extract the object auditing matcher from the script' }
$matcherText = $m.Value
'extracted matcher, {0} chars; compares AceFlagsValue: {1}' -f $matcherText.Length, ($matcherText -match 'AceFlagsValue')
$matcher = [scriptblock]::Create($matcherText + "`n" + '$isAuditingOk')

$expectedAuditing = $settings.ObjectAuditing | ConvertFrom-Csv |
    Select-Object SecurityIdentifier, AccessMask, AuditFlagsValue, AceFlagsValue, InheritedObjectAceType

function Test-ObjectAuditing {
    param([int] $AceFlags)
    $appliedAuditing = @($expectedAuditing | ForEach-Object {
            [PSCustomObject]@{ SecurityIdentifier = $_.SecurityIdentifier; AccessMask = [int] $_.AccessMask
                AuditFlagsValue = [int] $_.AuditFlagsValue; AceFlagsValue = $AceFlags
                InheritedObjectAceType = $_.InheritedObjectAceType }
        })
    & $matcher
}

Write-Host ''
Write-Host '=== Object auditing must require ContainerInherit on the domain root ===' -ForegroundColor Cyan
Check 'a non-inheriting ACE (flags 64) is NOT accepted' $false (Test-ObjectAuditing -AceFlags 64)
Check 'ObjectInherit only (65) is NOT accepted' $false (Test-ObjectAuditing -AceFlags 65)
Check 'no flags at all (0) is NOT accepted' $false (Test-ObjectAuditing -AceFlags 0)
Check 'ContainerInherit + Success (66) is accepted' $true (Test-ObjectAuditing -AceFlags 66)
Check 'an INHERITED ACE (66+16=82) is still accepted' $true (Test-ObjectAuditing -AceFlags 82)
Check 'a superset (195) is accepted' $true (Test-ObjectAuditing -AceFlags 195)

Write-Host ''
Write-Host '=== Audit flags remain a subset test (no regression) ===' -ForegroundColor Cyan
$appliedAuditing = @($expectedAuditing | ForEach-Object {
        [PSCustomObject]@{ SecurityIdentifier = $_.SecurityIdentifier; AccessMask = [int] $_.AccessMask
            AuditFlagsValue = 3; AceFlagsValue = 66; InheritedObjectAceType = $_.InheritedObjectAceType }
    })
Check 'Success+Failure (3) still satisfies an expected Success (1)' $true (& $matcher)
$appliedAuditing = @($expectedAuditing | ForEach-Object {
        [PSCustomObject]@{ SecurityIdentifier = $_.SecurityIdentifier; AccessMask = [int] $_.AccessMask
            AuditFlagsValue = 2; AceFlagsValue = 66; InheritedObjectAceType = $_.InheritedObjectAceType }
    })
Check 'Failure only (2) still fails' $false (& $matcher)

Write-Host ''
Write-Host '=== CA AuditFilter: extracted verbatim from the file ===' -ForegroundColor Cyan
$caPattern = '(?s)isCaAuditingOk = @\(\$details \| Where-Object \{.*?\}\)\.Count -eq 0'
$mc = [regex]::Match($raw, $caPattern)
if (-not $mc.Success) { throw 'Could not extract the CA auditing matcher' }
$caMatcher = [scriptblock]::Create(('$r = ' + $mc.Value.Substring('isCaAuditingOk = '.Length) + "`n" + '$r'))
foreach ($case in @(
        @{ V = 127; Want = $true; N = 'exactly the required bits (127)' }
        @{ V = 255; Want = $true; N = 'a superset (255) is not a misconfiguration' }
        @{ V = 63; Want = $false; N = 'a missing bit (63) still fails' }
        @{ V = 1270; Want = $false; N = 'a coincidental digit string (1270) still fails' }
        @{ V = 0; Want = $false; N = 'auditing disabled (0) still fails' }
    )) {
    $details = @([PSCustomObject]@{ regKey = 'x'; value = $case.V; expectedValue = '127' })
    Check $case.N $case.Want (& $caMatcher)
}
# A non-numeric expectation must keep the anchored string comparison.
$details = @([PSCustomObject]@{ regKey = 'x'; value = 'Enabled'; expectedValue = 'Enabled' })
Check 'a non-numeric expectation still matches as text' $true (& $caMatcher)
$details = @([PSCustomObject]@{ regKey = 'x'; value = 'Disabled'; expectedValue = 'Enabled' })
Check 'a non-numeric mismatch still fails' $false (& $caMatcher)

Write-Host ''
Write-Host '=== Deleted Objects: the union is computed per trustee ===' -ForegroundColor Cyan
# Behavioural, not textual. These two used to assert that particular inline source strings existed,
# so they failed the moment both DACL readers were refactored onto one shared evaluator even though
# the behaviour they describe - the per-trustee union - was preserved exactly. A test that breaks on
# a refactor it should be indifferent to is a test that will be "fixed" by weakening it.
$unionSid = 'S-1-5-21-1-2-3-1001'
function New-UnionAce($mask, $allow = $true) {
    [PSCustomObject]@{ Trustee = $unionSid; IsAllow = $allow; IsDeny = (-not $allow); Mask = $mask
        InheritOnly = $false; PropertySetScoped = $false }
}
Check 'rights granted by two separate ACEs are unioned' $true (
    @(Get-mdiEffectiveDaclTrustee -Ace @((New-UnionAce 0x4), (New-UnionAce 0x10)) -RequiredMask (0x4 -bor 0x10)).Count -eq 1)
Check 'one ACE carrying both rights is still a grant' $true (
    @(Get-mdiEffectiveDaclTrustee -Ace @(New-UnionAce (0x4 -bor 0x10)) -RequiredMask (0x4 -bor 0x10)).Count -eq 1)
Check 'half the rights is not a grant' $true (
    @(Get-mdiEffectiveDaclTrustee -Ace @(New-UnionAce 0x4) -RequiredMask (0x4 -bor 0x10)).Count -eq 0)
Check 'rights are NOT unioned across different trustees' $true (
    @(Get-mdiEffectiveDaclTrustee -Ace @((New-UnionAce 0x4), ([PSCustomObject]@{ Trustee = 'S-1-5-32-544'; IsAllow = $true; IsDeny = $false; Mask = 0x10; InheritOnly = $false; PropertySetScoped = $false })) -RequiredMask (0x4 -bor 0x10)).Count -eq 0)
$readMask = 0x4 -bor 0x10
function Test-Union {
    param([int[]] $Masks)
    $byTrustee = New-Object -TypeName 'System.Collections.Generic.Dictionary[string,int]'
    $sid = 'S-1-5-21-1-2-3-1001'
    foreach ($mask in $Masks) {
        $cur = 0
        if ($byTrustee.ContainsKey($sid)) { $cur = $byTrustee[$sid] }
        $byTrustee[$sid] = $cur -bor $mask
    }
    ($byTrustee[$sid] -band $readMask) -eq $readMask
}
Check 'one ACE carrying both rights is accepted' $true (Test-Union @(0x14))
Check 'two ACEs, one right each, are accepted' $true (Test-Union @(0x4, 0x10))
Check 'only ListChildren is still rejected' $false (Test-Union @(0x4))
Check 'only ReadProperty is still rejected' $false (Test-Union @(0x10))
Check 'unrelated rights are still rejected' $false (Test-Union @(0x20, 0x40))

Write-Host ''
"TOTAL PASS=$script:p FAIL=$script:f"
if ($script:f -gt 0) { exit 1 }
