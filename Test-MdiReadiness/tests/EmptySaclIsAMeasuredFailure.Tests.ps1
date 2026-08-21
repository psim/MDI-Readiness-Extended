<#
    AN EMPTY SACL IS AN ANSWER, AND IT WAS REPORTED AS "NEVER READ".

    Get-mdiDsSacl guarded the case where the directory returns a security descriptor whose SystemAcl
    is $null - the shape Active Directory produces when the caller does not hold SeSecurityPrivilege
    and the SACL is silently stripped - and correctly reported that as not measured. It did NOT
    guard the adjacent shape: a SACL that is PRESENT and contains ZERO ACEs. That is what a
    container whose auditing has never been configured, or has been cleared, actually looks like,
    and finding exactly that is what this tool exists for.

    With zero applied ACEs $appliedAuditing is @(), so

        DifferenceObject = $appliedAuditing | Select-Object -Property $properties

    yields nothing and binds $null. Compare-Object REFUSES a null -DifferenceObject, and the
    resulting terminating error landed in the catch - whose own comment states "Reaching this catch
    means the SACL was never READ, so it can never be evidence that auditing is misconfigured". It
    had been read. Its content was the answer.

    Measured on the shipped function with a descriptor whose SACL is present and empty, binary
    round-tripped so it is the shape the directory delivers, for all three shipped expectation
    tables (ObjectAuditing, ExchangeAuditing, ADFSAuditing):

        isAuditingOk = 'N/A'   Measured = $false
        details      = "Cannot bind argument to parameter 'DifferenceObject' because it is null."

    So a domain with no MDI auditing at all was indistinguishable from one the tool was not allowed
    to read: it blocked readiness as "unread" rather than naming the gap, and showed the operator a
    PowerShell parameter-binding error as the reason. Adding one single unrelated ACE to the very
    same descriptor made it report correctly as misconfigured, so the blindness was at EXACTLY zero.

    Anyone tempted by the one-line fix should note that wrapping the projection as
    @($applied | Select-Object -Property $properties) does NOT work: Compare-Object refuses an empty
    array for the same reason it refuses $null. The guard has to be explicit.

    These assertions drive the REAL Get-mdiDsSacl end to end, faking only the DirectorySearcher, so
    the descriptor parsing, the SACL projection and the verdict arithmetic are all the product's own.
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

function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$pass = 0; $fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name $Detail" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

Write-Host "`nAn empty SACL is a measured failure, not an unread check" -ForegroundColor Cyan

# Only the DirectorySearcher is faked. The bytes handed back are produced by RawSecurityDescriptor
# and round-tripped through GetBinaryForm, so the product parses the same octets the directory sends.
$script:fakeDescriptorBytes = $null
function New-Object {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$TypeName, [Parameter(Position = 1)][object[]]$ArgumentList,
        [object]$Property, [string]$ComObject, [switch]$Strict)
    if ($TypeName -like '*DirectorySearcher*') {
        $s = [PSCustomObject]@{ CacheResults = $false; SearchScope = $null; ReferralChasing = $null
            SecurityMasks = $null; PropertiesToLoad = (Microsoft.PowerShell.Utility\New-Object System.Collections.ArrayList) }
        Add-Member -InputObject $s.PropertiesToLoad -MemberType ScriptMethod -Name AddRange -Value { param($x) } -Force
        Add-Member -InputObject $s -MemberType ScriptMethod -Name FindOne -Value {
            $props = @{}
            if ($null -ne $script:fakeDescriptorBytes) { $props['ntsecuritydescriptor'] = @(, $script:fakeDescriptorBytes) }
            [PSCustomObject]@{ Properties = $props }
        }
        Add-Member -InputObject $s -MemberType ScriptMethod -Name Dispose -Value { }
        return $s
    }
    return Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}

function Set-Descriptor {
    param([string] $Sddl)
    $sd = Microsoft.PowerShell.Utility\New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    $bytes = Microsoft.PowerShell.Utility\New-Object byte[] $sd.BinaryLength
    $sd.GetBinaryForm($bytes, 0)
    $script:fakeDescriptorBytes = $bytes
}

# The Exchange table is one row - S-1-1-0, AccessMask 32, AuditFlagsValue 3, AceFlagsValue 194 - so a
# correctly configured container can be expressed as a single SDDL audit ACE and the three states
# (correct / wrong / absent) can be compared on one axis.
$exchangeExpected = @($settings.ExchangeAuditing | ConvertFrom-Csv)
$objectExpected = @($settings.ObjectAuditing | ConvertFrom-Csv |
        Select-Object SecurityIdentifier, AccessMask, AuditFlagsValue, AceFlagsValue, InheritedObjectAceType)

$sddlNoSacl = 'O:BAG:BAD:(A;;FA;;;WD)'
$sddlEmptySacl = 'O:BAG:BAD:(A;;FA;;;WD)S:'
$sddlCorrect = 'O:BAG:BAD:(A;;FA;;;WD)S:(AU;CISAFA;0x20;;;WD)'
$sddlWrong = 'O:BAG:BAD:(A;;FA;;;WD)S:(AU;CISAFA;0x1;;;WD)'

# THE DEFECT. A SACL that exists and is empty must be a MEASURED FAILURE.
Set-Descriptor $sddlEmptySacl
$empty = Get-mdiDsSacl -LdapPath 'LDAP://contoso.invalid/CN=Test' -ExpectedAuditing $exchangeExpected
Assert-That 'an empty SACL is recorded as MEASURED - it was read' (
    $empty.Measured -eq $true) "(got Measured=$($empty.Measured))"
Assert-That 'an empty SACL fails the check rather than reporting N/A' (
    $empty.isAuditingOk -is [bool] -and $empty.isAuditingOk -eq $false) "(got '$($empty.isAuditingOk)')"
Assert-That 'the reason given is the absence of audit entries, not a binding error' (
    ([string] $empty.details) -notlike '*DifferenceObject*') "(got '$([string] $empty.details)')"
Assert-That 'the reason names the path that was read' (
    ([string] $empty.details) -like '*CN=Test*') "(got '$([string] $empty.details)')"

# The same shape against the six-row Object table, so the guard is not specific to a one-row
# expectation - the empty side is what is empty, whatever the expected side holds.
Set-Descriptor $sddlEmptySacl
$emptyObj = Get-mdiDsSacl -LdapPath 'LDAP://contoso.invalid/DC=x' -ExpectedAuditing $objectExpected
Assert-That 'the same holds for the six-row object-auditing expectation' (
    $emptyObj.Measured -eq $true -and $emptyObj.isAuditingOk -eq $false) `
    "(got '$($emptyObj.isAuditingOk)', Measured=$($emptyObj.Measured))"

# CONTROL. A STRIPPED SACL is a different fact and must keep reporting as not measured, or this fix
# would have traded one wrong answer for another - telling an administrator their auditing is broken
# when the tool was merely not allowed to look at it.
Set-Descriptor $sddlNoSacl
$stripped = Get-mdiDsSacl -LdapPath 'LDAP://contoso.invalid/CN=Test' -ExpectedAuditing $exchangeExpected
Assert-That 'CONTROL: a stripped SACL (null SystemAcl) is still NOT measured' (
    $stripped.Measured -eq $false -and [string] $stripped.isAuditingOk -eq 'N/A') `
    "(got '$($stripped.isAuditingOk)', Measured=$($stripped.Measured))"

# CONTROL. A populated but WRONG SACL was always reported correctly, and still must be - this is the
# neighbouring state that proves the check measures something and that the guard did not swallow it.
Set-Descriptor $sddlWrong
$wrong = Get-mdiDsSacl -LdapPath 'LDAP://contoso.invalid/CN=Test' -ExpectedAuditing $exchangeExpected
Assert-That 'CONTROL: a populated but incorrect SACL is a measured failure' (
    $wrong.Measured -eq $true -and $wrong.isAuditingOk -eq $false) `
    "(got '$($wrong.isAuditingOk)', Measured=$($wrong.Measured))"

# CONTROL. The correctly configured container must still pass, or the guard would have made every
# domain fail.
Set-Descriptor $sddlCorrect
$ok = Get-mdiDsSacl -LdapPath 'LDAP://contoso.invalid/CN=Test' -ExpectedAuditing $exchangeExpected
Assert-That 'CONTROL: a correctly configured SACL still passes' (
    $ok.Measured -eq $true -and $ok.isAuditingOk -eq $true) `
    "(got '$($ok.isAuditingOk)', Measured=$($ok.Measured))"

# The three states must be TELLABLE APART. Before the fix, absent and unreadable were the same
# answer, which is the whole defect.
Assert-That 'absent, unreadable and misconfigured are three distinguishable answers' (
    ([string] $empty.isAuditingOk) -ne ([string] $stripped.isAuditingOk) -and
    $empty.Measured -ne $stripped.Measured -and
    ([string] $empty.details) -ne ([string] $stripped.details)) `
    "(empty='$($empty.isAuditingOk)'/$($empty.Measured), stripped='$($stripped.isAuditingOk)'/$($stripped.Measured))"

Remove-Item Function:\New-Object

Write-Host ''
Write-Host "pass=$pass  fail=$fail" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
