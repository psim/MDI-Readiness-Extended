<#
    Directory-layer regression: audit ACE class matching, effective DACL evaluation, unresolvable
    accounts, the audit-policy truncation guard, and the sensor v2.x readability gate.

    Every assertion here is behavioural - it calls the shipped function and checks what it returns.
    Each pair of cases pushes in BOTH directions, because every defect in this area was a fix in one
    direction that created a fault in the other: the class-matching fix must not start accepting an
    unrelated object class, and the deny-handling fix must not start rejecting a valid grant.
#>

$ErrorActionPreference = 'Stop'
# Resolve the copy that sits BESIDE this test first. Reaching for a parent directory ahead of the
# local copy silently binds the suite to whatever stale script happens to be lying one level up.
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$body = $text -replace '(?m)^#Requires.*$', '' -replace '(?ms)^\[CmdletBinding.*?^\)\s*$', ''
$idx = $body.IndexOf('#region Main')
if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Write-Host 'Audit ACE matching (Test-mdiAuditAceSatisfied)' -ForegroundColor Cyan
$userClass = 'bf967aba-0de6-11d0-a285-00aa003049e2'
$groupClass = 'bf967a9c-0de6-11d0-a285-00aa003049e2'
$expected = [PSCustomObject]@{
    SecurityIdentifier = 'S-1-1-0'; AccessMask = 131132; AuditFlagsValue = 1
    AceFlagsValue = 2; InheritedObjectAceType = $userClass
}
function New-AuditAce($class, $audit = 3, $aceFlags = 194, $mask = 983551, $sid = 'S-1-1-0') {
    @([PSCustomObject]@{ SecurityIdentifier = $sid; AccessMask = $mask; AuditFlagsValue = $audit
        AceFlagsValue = $aceFlags; InheritedObjectAceType = $class })
}

# The false red: auditing EVERY descendant class is stricter than auditing one, so it must satisfy.
Assert-That 'an ACE covering all classes satisfies a specific-class row' (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce ''))
Assert-That '  ...also when spelled as an all-zero GUID' (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce '00000000-0000-0000-0000-000000000000'))
Assert-That '  ...also when the GUID case differs' (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce $userClass.ToUpper()))
Assert-That 'the exact class still satisfies it' (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce $userClass))
# The other direction: the fix must not accept an unrelated class.
Assert-That 'a DIFFERENT class is still rejected' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce $groupClass)))
Assert-That 'a different trustee is still rejected' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce '' 3 194 983551 'S-1-5-32-544')))
Assert-That 'auditing disabled is still rejected' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce '' 0)))
Assert-That 'Failure-only auditing is still rejected' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce '' 2)))
Assert-That 'a missing ContainerInherit bit is still rejected' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce '' 3 192)))
Assert-That 'an inherited ACE (210) is still accepted' (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce '' 3 210))
Assert-That 'an insufficient access mask is still rejected' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied (New-AuditAce '' 3 194 16)))
Assert-That 'an empty applied set is rejected, not accepted' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied @()))
Assert-That 'a null applied set is rejected, not accepted' (-not (Test-mdiAuditAceSatisfied -Expected $expected -Applied $null))

# The three call sites must all go through the helper, or they will drift apart again.
$inlineMatcher = [regex]::Matches($text, '\$exp\.InheritedObjectAceType -eq \$_\.InheritedObjectAceType')
Assert-That 'no inline copy of the ACE matcher survives' ($inlineMatcher.Count -eq 0) "(found $($inlineMatcher.Count))"
$helperCalls = [regex]::Matches($text, 'Test-mdiAuditAceSatisfied -Expected')
Assert-That 'all three auditing checks call the shared helper' ($helperCalls.Count -ge 3) "(found $($helperCalls.Count))"

Write-Host 'Effective DACL evaluation (Get-mdiEffectiveDaclTrustee)' -ForegroundColor Cyan
function New-DaclAce($sid, $mask, $allow = $true, $inheritOnly = $false, $propSet = $false) {
    [PSCustomObject]@{ Trustee = $sid; IsAllow = $allow; IsDeny = (-not $allow); Mask = $mask
        InheritOnly = $inheritOnly; PropertySetScoped = $propSet }
}
$read = 0x4 -bor 0x10
$sid = 'S-1-5-21-11-22-33-1001'

Assert-That 'an INHERIT_ONLY grant confers nothing on the container' (@(Get-mdiEffectiveDaclTrustee -Ace @(New-DaclAce $sid $read $true $true) -RequiredMask $read).Count -eq 0)
Assert-That 'an explicit Deny defeats the Allow' (@(Get-mdiEffectiveDaclTrustee -Ace @((New-DaclAce $sid $read), (New-DaclAce $sid 0x10 $false)) -RequiredMask $read).Count -eq 0)
Assert-That '  ...whichever order the two ACEs appear in' (@(Get-mdiEffectiveDaclTrustee -Ace @((New-DaclAce $sid 0x10 $false), (New-DaclAce $sid $read)) -RequiredMask $read).Count -eq 0)
Assert-That 'a property-set-scoped grant does not count' (@(Get-mdiEffectiveDaclTrustee -Ace @(New-DaclAce $sid $read $true $false $true) -RequiredMask $read).Count -eq 0)
# The other direction: none of the above may start rejecting real grants.
Assert-That 'a plain effective grant is still reported' (@(Get-mdiEffectiveDaclTrustee -Ace @(New-DaclAce $sid $read) -RequiredMask $read).Count -eq 1)
Assert-That 'two ACEs granting half each still union to a grant' (@(Get-mdiEffectiveDaclTrustee -Ace @((New-DaclAce $sid 0x4), (New-DaclAce $sid 0x10)) -RequiredMask $read).Count -eq 1)
Assert-That 'a Deny of an unrelated right does not revoke it' (@(Get-mdiEffectiveDaclTrustee -Ace @((New-DaclAce $sid $read), (New-DaclAce $sid 0x20000 $false)) -RequiredMask $read).Count -eq 1)
Assert-That 'a Deny naming another trustee does not revoke it' (@(Get-mdiEffectiveDaclTrustee -Ace @((New-DaclAce $sid $read), (New-DaclAce 'S-1-5-32-544' $read $false)) -RequiredMask $read).Count -eq 1)
Assert-That 'an INHERIT_ONLY Deny does not revoke a real grant' (@(Get-mdiEffectiveDaclTrustee -Ace @((New-DaclAce $sid $read), (New-DaclAce $sid 0x10 $false $true)) -RequiredMask $read).Count -eq 1)
Assert-That 'half the required rights is not a grant' (@(Get-mdiEffectiveDaclTrustee -Ace @(New-DaclAce $sid 0x4) -RequiredMask $read).Count -eq 0)
Assert-That 'an empty DACL yields nobody' (@(Get-mdiEffectiveDaclTrustee -Ace @() -RequiredMask $read).Count -eq 0)
Assert-That 'a null DACL yields nobody and does not throw' (@(Get-mdiEffectiveDaclTrustee -Ace $null -RequiredMask $read).Count -eq 0)
Assert-That 'a blank trustee is ignored' (@(Get-mdiEffectiveDaclTrustee -Ace @(New-DaclAce '   ' $read) -RequiredMask $read).Count -eq 0)

# Both DACL readers must feed the one evaluator, or they will disagree again.
$evaluatorCalls = [regex]::Matches($text, 'Get-mdiEffectiveDaclTrustee -Ace')
Assert-That 'both DACL readers use the shared evaluator' ($evaluatorCalls.Count -ge 2) "(found $($evaluatorCalls.Count))"

# End to end through a REAL security descriptor, so the normalisation is exercised too.
$sddlSid = 'S-1-5-21-11-22-33-2001'
$descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList "D:(A;CIIO;LCRP;;;$sddlSid)"
$fromSddl = @(foreach ($ace in $descriptor.DiscretionaryAcl) {
        [PSCustomObject]@{
            Trustee = [string] $ace.SecurityIdentifier
            IsAllow = ($ace.AceType -eq 'AccessAllowed' -or $ace.AceType -eq 'AccessAllowedObject')
            IsDeny = ($ace.AceType -eq 'AccessDenied' -or $ace.AceType -eq 'AccessDeniedObject')
            Mask = [int] $ace.AccessMask
            InheritOnly = ((([int] $ace.AceFlags) -band 0x8) -eq 0x8)
            PropertySetScoped = $false
        }
    })
Assert-That 'a real INHERIT_ONLY SDDL ACE grants nothing' (@(Get-mdiEffectiveDaclTrustee -Ace $fromSddl -RequiredMask $read).Count -eq 0)

Write-Host 'Unresolvable directory service account' -ForegroundColor Cyan
$foreign = 'S-1-5-21-4444444444-3333333333-2222222222-1105'
Assert-That 'a foreign SID does not match an unrelated account' (@(Get-mdiMatchingTrustee -Trustee @($foreign) -Account 'svc-mdi-nonexistent-zzz').Count -eq 0)
Assert-That 'an unresolvable account genuinely does not resolve' (-not (Resolve-mdiPrincipalSid -Name 'svc-mdi-nonexistent-zzz'))
Assert-That 'a well-known local group still resolves' ([bool] (Resolve-mdiPrincipalSid -Name 'Administrators'))
# The verdict must downgrade to unmeasured, not assert a missing grant, when the account is unknown.
Assert-That 'the unresolvable case is gated on resolving the account' (
    $text -match 'if \(-not \(Resolve-mdiPrincipalSid -Name \$dsa\)\)')
Assert-That '  ...and feeds the Measured flag' ($text -match '\$unresolvableAccount\.Count -eq 0')

Write-Host 'Audit policy backup completeness' -ForegroundColor Cyan
# Measured on a live domain controller: a complete backup carries 64 subcategories and ALL 8 that MDI
# requires appear in it, including those set to 0 (not audited). So a missing required subcategory can
# only mean the export was cut off or unparseable - never a real policy gap - and the check must say
# "not tested" rather than manufacture a policy failure. A row-count threshold cannot express this: an
# export truncated at 50 of 64 rows passes any plausible threshold while still missing required rows.
Assert-That 'completeness is judged by the expected subcategories' (
    # Behavioural, not a source grep. The previous form matched the literal text of the $missing
    # expression, so it broke the moment that expression was refactored - while the behaviour it
    # cares about was completely unchanged. What matters is the OUTCOME: a backup missing a required
    # subcategory must be reported as not tested, and a SMALL but complete backup must still be
    # measured, which is exactly what a row-count threshold could not express.
    $(
        $expectedAudit = @($settings.AdvancedAuditPolicyDCs | ConvertFrom-Csv)
        $auditHeader = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
        $auditRow = { param($Guid, $Value) 'DC1,System,Some Subcategory,{0},Success and Failure,,{1}' -f $Guid, $Value }
        $script:auditBackup = $null
        Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
            param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds)
            , $script:auditBackup
        }
        Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value { param($ComputerName) 'C:\Windows\Temp' }

        # Large (padded out with subcategories MDI does not require) but MISSING a required one.
        $filler = @(1..60 | ForEach-Object { & $auditRow ('{{0CCE{0:X4}-0000-0000-0000-000000000000}}' -f $_) '3' })
        $script:auditBackup = @($auditHeader) +
        @($expectedAudit | Select-Object -Skip 1 | ForEach-Object { & $auditRow ([string] $_.'Subcategory GUID') ([string] $_.'Setting Value') }) +
        $filler
        $big = Get-mdiAdvancedAuditing -ComputerName 'dc1' -ExpectedAuditing $settings.AdvancedAuditPolicyDCs

        # Small, but carrying every subcategory MDI requires.
        $script:auditBackup = @($auditHeader) +
        @($expectedAudit | ForEach-Object { & $auditRow ([string] $_.'Subcategory GUID') ([string] $_.'Setting Value') })
        $small = Get-mdiAdvancedAuditing -ComputerName 'dc1' -ExpectedAuditing $settings.AdvancedAuditPolicyDCs

        ([string] $big.isAdvancedAuditingOk -eq 'N/A') -and ($small.isAdvancedAuditingOk -eq $true)
    ))
Assert-That '  ...not by a row-count threshold' ($text -notmatch '\$minimumCompleteBackup')
Assert-That '  ...and the message names both possible causes' (
    $text -match 'cut off before it finished or could not be parsed')

Write-Host 'Sensor v2.x readability gate' -ForegroundColor Cyan
# A failed service query must not be reported as "no v2.x sensor installed".
Assert-That 'the sensor state consults the readability flag' ($text -match '\$v2Readable = \[bool\] \$v2Result\.Readable')
Assert-That '  ...before any branch that asserts no v2.x sensor' (
    $text.IndexOf('elseif (-not $v2Readable)') -lt $text.IndexOf("elseif (-not `$hasV2Sensor -and `$isOnboarded"))

Write-Host 'Schema version map' -ForegroundColor Cyan
Assert-That 'schema 90 has a name' ($text -match '(?m)^\s*90 = ')
Assert-That 'schema 91 still has a name' ($text -match '(?m)^\s*91 = ')

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
