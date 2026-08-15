<#
    LIST OBJECT WAS CREDITED AS LIST CONTENTS, AND ONLY BY ONE OF THE TWO READERS.

    Get-mdiDeletedObjectsPermission decides whether the Directory Service Account can read the
    Deleted Objects container. MDI's documented grant is LCRP - List Contents (0x4) plus Read
    Property (0x10), which is what "dsacls /G <DSA>:LCRP" leaves behind.

    The directory-module fallback reader treated ListObject (0x80) as satisfying the List Contents
    requirement:

        if (($rightsValue -band 0x4) -eq 0x4 -or ($rightsValue -band 0x80) -eq 0x80) { $mask = $mask -bor 0x4 }

    ListObject is not a substitute for List Contents. It is the List Object mode right, which does
    nothing unless the third character of the forest's dSHeuristics enables that mode - a setting
    this script never reads - and even then LO is not equivalent to LC.

    Two things made this worse than a wrong bit:

      * It is a FALSE GREEN on a security claim. Measured against Windows itself, an ACE granting
        ListObject + ReadProperty gives AccessCheck = FALSE. The check nonetheless reported
        "The Directory Service Account has read access to the Deleted Objects container", with a
        passing verdict and zero issues, so nobody was told to grant the right that is actually
        missing.
      * The RAW reader, for the same ACE, correctly returned False. So the same container was
        reported as granting read or not granting it purely according to which reader happened to
        succeed first - and the permissive one was the fallback. The comment directly above this
        code describes that exact cross-reader disagreement being found and fixed once already; a
        single extra bit reintroduced it.

    These assertions drive the shipped producer with real ActiveDirectorySecurity /
    ActiveDirectoryAccessRule objects, because ActiveDirectoryRights is a [Flags] enum and a fake
    that hands back a string would hide every bitmask question this file exists to pin.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

# The account whose access is being asked about. A real SID, translated the way the shipped reader
# translates one, so the trustee match is the genuine one rather than a string that happens to agree.
$currentSid = [string] ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

$script:aclUnderTest = $null
$script:readerCalls = 0

Set-Item -Path function:script:Get-ADRootDSE -Value {
    param($Server, $ErrorAction)
    [PSCustomObject]@{ defaultNamingContext = 'DC=contoso,DC=com' }
}
Set-Item -Path function:script:Get-ADObject -Value {
    param($Identity, $Server, [switch] $IncludeDeletedObjects, $Properties, $ErrorAction, $Filter)
    $script:readerCalls++
    [PSCustomObject]@{ nTSecurityDescriptor = $script:aclUnderTest }
}
# The RAW reader is deliberately made unavailable so this exercises the directory-module FALLBACK -
# the reader that carried the defect. The raw path already returns the right answer for these ACEs,
# so without this the test would measure the wrong half of the disagreement.
Set-Item -Path function:script:New-Object -Value {
    param([string] $TypeName, [object[]] $ArgumentList)
    if ($TypeName -eq 'System.DirectoryServices.DirectoryEntry' -or
        $TypeName -eq 'System.DirectoryServices.DirectorySearcher') {
        throw 'the raw reader is deliberately unavailable in this test'
    }
    if ($PSBoundParameters.ContainsKey('ArgumentList')) {
        Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
    } else {
        Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName
    }
}

function New-AclWith {
    param([string] $Rights)
    $sec = Microsoft.PowerShell.Utility\New-Object System.DirectoryServices.ActiveDirectorySecurity
    $rule = Microsoft.PowerShell.Utility\New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        (Microsoft.PowerShell.Utility\New-Object System.Security.Principal.SecurityIdentifier($currentSid)),
        ([System.DirectoryServices.ActiveDirectoryRights] $Rights),
        [System.Security.AccessControl.AccessControlType]::Allow)
    $sec.AddAccessRule($rule)
    $sec
}

function Invoke-Permission {
    param([string] $Rights)
    $script:aclUnderTest = New-AclWith -Rights $Rights
    $before = $script:readerCalls
    $r = Get-mdiDeletedObjectsPermission -Domain 'contoso.com' -DirectoryServiceAccount @($currentSid) 3>$null
    if ($script:readerCalls -le $before) { throw 'the ACL reader stub was never called - the probe measured nothing' }
    $r
}

# The rights value must really be the flags enum, or a bitmask test on it proves nothing.
$probeRights = [System.DirectoryServices.ActiveDirectoryRights] 'ReadProperty, ListObject'
if ($probeRights.GetType().FullName -ne 'System.DirectoryServices.ActiveDirectoryRights') {
    throw 'the rights value is not the real flags enum'
}
if ([int] $probeRights -ne (0x10 -bor 0x80)) { throw "unexpected mask: $([int] $probeRights)" }
# And the control must genuinely pass, or every failure below is the harness rather than the code.
if ((Invoke-Permission -Rights 'ListChildren, ReadProperty').isDeletedObjectsPermissionOk -ne $true) {
    throw 'the LCRP control did not pass - the harness is not reaching the reader correctly'
}
Write-Host 'ListObject must not be credited as List Contents' -ForegroundColor Cyan
$lorp = Invoke-Permission -Rights 'ReadProperty, ListObject'
Assert-That 'LORP is not reported as read access' ($lorp.isDeletedObjectsPermissionOk -ne $true) (
    "ok=$($lorp.isDeletedObjectsPermissionOk)")
Assert-That 'and it is still a MEASURED answer, not an unknown' (
    [string] $lorp.isDeletedObjectsPermissionOk -ne 'N/A') "ok=$($lorp.isDeletedObjectsPermissionOk)"
Assert-That 'the detail does not claim the account has read access' (
    [string] $lorp.details.Detail -notlike '*has read access*') "detail=$($lorp.details.Detail)"

Write-Host ''
Write-Host 'CONTROLS - every grant that genuinely contains List Contents must still pass' -ForegroundColor Cyan
foreach ($case in @(
        @{ N = 'LCRP, the documented grant'; R = 'ListChildren, ReadProperty' },
        @{ N = 'GenericExecute + ReadProperty (what dsacls actually leaves)'; R = 'ReadProperty, GenericExecute' },
        @{ N = 'GenericRead'; R = 'GenericRead' },
        @{ N = 'GenericAll'; R = 'GenericAll' })) {
    $r = Invoke-Permission -Rights $case.R
    Assert-That "CONTROL: $($case.N) is read access" ($r.isDeletedObjectsPermissionOk -eq $true) (
        "ok=$($r.isDeletedObjectsPermissionOk) detail=$($r.details.Detail)")
}

# The bits, stated directly: these are the masks the controls above rely on.
Assert-That 'GenericRead contains both required bits' (
    ([int] [System.DirectoryServices.ActiveDirectoryRights] 'GenericRead' -band 0x14) -eq 0x14)
Assert-That 'GenericAll contains both required bits' (
    ([int] [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll' -band 0x14) -eq 0x14)
Assert-That 'GenericExecute contains List Contents' (
    ([int] [System.DirectoryServices.ActiveDirectoryRights] 'GenericExecute' -band 0x4) -eq 0x4)
Assert-That 'ListObject contains NEITHER required bit' (
    ([int] [System.DirectoryServices.ActiveDirectoryRights] 'ListObject' -band 0x14) -eq 0)

Write-Host ''
Write-Host 'A grant missing only Read Property must still fail' -ForegroundColor Cyan
$lcOnly = Invoke-Permission -Rights 'ListChildren'
Assert-That 'List Contents alone is not enough' ($lcOnly.isDeletedObjectsPermissionOk -ne $true) (
    "ok=$($lcOnly.isDeletedObjectsPermissionOk)")
$rpOnly = Invoke-Permission -Rights 'ReadProperty'
Assert-That 'Read Property alone is not enough' ($rpOnly.isDeletedObjectsPermissionOk -ne $true) (
    "ok=$($rpOnly.isDeletedObjectsPermissionOk)")

Write-Host ''
Write-Host 'The NAME-matching fallback branch must agree with the bitmask branch' -ForegroundColor Cyan
# The reader falls back to matching rights NAMES when the value cannot be parsed as the enum - the
# path taken for the shims and doubles that also feed it. That branch carried its own copy of the
# ListObject substitution, so fixing only the bitmask branch would leave the defect live wherever a
# rights value arrives unparseable. Reached with an ACE whose rights text contains a name the enum
# does not know, which is what makes the cast fail.
function New-FakeAce {
    param([string] $RightsText)
    [PSCustomObject]@{
        IdentityReference    = $currentSid
        ActiveDirectoryRights = $RightsText
        AccessControlType    = 'Allow'
        PropagationFlags     = 'None'
        InheritanceFlags     = 'None'
        ObjectType           = '00000000-0000-0000-0000-000000000000'
        InheritedObjectType  = '00000000-0000-0000-0000-000000000000'
        IsInherited          = $false
    }
}
function Invoke-PermissionWithText {
    param([string] $RightsText)
    # Confirm the value really does defeat the enum cast, or this exercises the bitmask branch by
    # accident and proves nothing about the fallback.
    $parses = $true
    try { [void] [int] ([System.DirectoryServices.ActiveDirectoryRights] $RightsText) } catch { $parses = $false }
    if ($parses) { throw "'$RightsText' parses as the enum, so it does not reach the name branch" }
    $script:aclUnderTest = [PSCustomObject]@{ Access = @(New-FakeAce -RightsText $RightsText) }
    $before = $script:readerCalls
    $r = Get-mdiDeletedObjectsPermission -Domain 'contoso.com' -DirectoryServiceAccount @($currentSid) 3>$null
    if ($script:readerCalls -le $before) { throw 'the ACL reader stub was never called' }
    $r
}

$textLorp = Invoke-PermissionWithText -RightsText 'ListObject, ReadProperty, NotARealRight'
Assert-That 'name branch: LORP is not read access either' (
    $textLorp.isDeletedObjectsPermissionOk -ne $true) "ok=$($textLorp.isDeletedObjectsPermissionOk)"

$textLcrp = Invoke-PermissionWithText -RightsText 'ListChildren, ReadProperty, NotARealRight'
Assert-That 'CONTROL name branch: LCRP is still read access' (
    $textLcrp.isDeletedObjectsPermissionOk -eq $true) "ok=$($textLcrp.isDeletedObjectsPermissionOk)"

$textGeneric = Invoke-PermissionWithText -RightsText 'GenericAll, NotARealRight'
Assert-That 'CONTROL name branch: GenericAll is still read access' (
    $textGeneric.isDeletedObjectsPermissionOk -eq $true) "ok=$($textGeneric.isDeletedObjectsPermissionOk)"

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
