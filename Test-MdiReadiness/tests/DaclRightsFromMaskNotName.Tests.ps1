<#
    A Directory Service Account that genuinely held the required access was reported as holding none
    of it, and the operator was told to re-grant permissions that were already in place.

    The Deleted Objects DACL reader decided which rights an ACE carried by matching the RENDERED enum
    name of ActiveDirectoryRights:

        $rights = [string] $ace.ActiveDirectoryRights
        if ($rights -match 'ListChildren|ListObject|GenericRead|GenericAll') { $mask = $mask -bor 0x4 }

    ActiveDirectoryRights is a [Flags] enum whose COMPOSITE names subsume the individual bits, so
    ToString() hides rights that are present. GenericExecute is ReadControl|ListChildren (0x20004), so
    an ACE granting List Contents + Read Property + Read Control - 0x20014, exactly what
    "dsacls /G <DSA>:LCRP" leaves behind, because READ_CONTROL rides along on any real ACE - renders as

        "ReadProperty, GenericExecute"

    which contains no substring 'ListChildren'. The 0x4 bit was never set, the trustee failed the
    required mask, and the check reported "the container security descriptor was read and no trustee
    holds both List Contents and Read Property", advising dsacls /G "<DSA>":LCRP against a production
    system container - to grant access the account already had.

    The assertions are BEHAVIOURAL. They build ACE records the way the reader builds them, from real
    ActiveDirectoryRights values, and run them through the real Get-mdiEffectiveDaclTrustee. Each
    case is checked against ground truth taken from the BITS, which is what the directory enforces.
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

$LIST_CHILDREN = 0x4
$READ_PROPERTY = 0x10
$LIST_OBJECT = 0x80
$READ_CONTROL = 0x20000
$REQUIRED = $LIST_CHILDREN -bor $READ_PROPERTY

Write-Host 'The premise: composite enum names really do hide the individual bits' -ForegroundColor Cyan
# If this stops being true the rest of the file proves nothing, so it is asserted rather than assumed.
# It is also the precise fact the original name-matching overlooked.
$renderedLcRpRc = [string] ([System.DirectoryServices.ActiveDirectoryRights] ($LIST_CHILDREN -bor $READ_PROPERTY -bor $READ_CONTROL))
Assert-That 'LC|RP|RC does not render the word ListChildren' ($renderedLcRpRc -notmatch 'ListChildren') "rendered '$renderedLcRpRc'"
Assert-That '  ...it renders GenericExecute instead' ($renderedLcRpRc -match 'GenericExecute') "rendered '$renderedLcRpRc'"
Assert-That '  ...and GenericExecute really is ReadControl|ListChildren' (
    [int][System.DirectoryServices.ActiveDirectoryRights]::GenericExecute -eq ($READ_CONTROL -bor $LIST_CHILDREN))

<#
    Rebuilds an ACE record the way the Deleted Objects reader does, straight from a rights value, and
    asks the real evaluator whether the trustee qualifies.
#>
function Test-Grant {
    param([int] $RightsValue, [bool] $InheritOnly = $false, [bool] $PropertySetScoped = $false, [bool] $Deny = $false)
    $mask = 0
    if (($RightsValue -band $LIST_CHILDREN) -eq $LIST_CHILDREN -or ($RightsValue -band $LIST_OBJECT) -eq $LIST_OBJECT) { $mask = $mask -bor 0x4 }
    if (($RightsValue -band $READ_PROPERTY) -eq $READ_PROPERTY) { $mask = $mask -bor 0x10 }
    $ace = @([PSCustomObject]@{
            Trustee           = 'CONTOSO\svc-mdi'
            IsAllow           = (-not $Deny)
            IsDeny            = $Deny
            Mask              = $mask
            InheritOnly       = $InheritOnly
            PropertySetScoped = $PropertySetScoped
        })
    @(Get-mdiEffectiveDaclTrustee -Ace $ace -RequiredMask $REQUIRED).Count -gt 0
}

Write-Host 'Rights are judged from the bits, not from how the enum prints' -ForegroundColor Cyan
$adr = [System.DirectoryServices.ActiveDirectoryRights]
$cases = [ordered]@{
    'LC|RP                      ' = $LIST_CHILDREN -bor $READ_PROPERTY
    'LC|RP|RC  (real dsacls LCRP)' = $LIST_CHILDREN -bor $READ_PROPERTY -bor $READ_CONTROL
    'LO|RP|RC  (list-object form)' = $LIST_OBJECT -bor $READ_PROPERTY -bor $READ_CONTROL
    'GenericRead                 ' = [int] $adr::GenericRead
    'GenericAll                  ' = [int] $adr::GenericAll
    'LC|RC only (no read prop)   ' = $LIST_CHILDREN -bor $READ_CONTROL
    'RP|RC only (no list)        ' = $READ_PROPERTY -bor $READ_CONTROL
    'RC only                     ' = $READ_CONTROL
    'WriteProperty|RC            ' = ([int] $adr::WriteProperty) -bor $READ_CONTROL
}
foreach ($label in $cases.Keys) {
    $value = $cases[$label]
    # Ground truth from the bits - what the directory itself enforces.
    $expected = ((($value -band $LIST_CHILDREN) -eq $LIST_CHILDREN) -or (($value -band $LIST_OBJECT) -eq $LIST_OBJECT)) -and
                (($value -band $READ_PROPERTY) -eq $READ_PROPERTY)
    $actual = Test-Grant -RightsValue $value
    $rendered = [string] ([System.DirectoryServices.ActiveDirectoryRights] $value)
    Assert-That ("{0} granted={1}" -f $label.Trim(), $expected) ($actual -eq $expected) "got $actual (renders as '$rendered')"
}

Write-Host 'The composite-name cases specifically' -ForegroundColor Cyan
# These are the ones the name matching got wrong; called out separately so a regression is unambiguous.
Assert-That 'a DSA granted LCRP by dsacls qualifies' (Test-Grant -RightsValue ($LIST_CHILDREN -bor $READ_PROPERTY -bor $READ_CONTROL)) 'the account holds both rights and was rejected'
Assert-That 'GenericExecute alone does NOT qualify' (-not (Test-Grant -RightsValue ([int] $adr::GenericExecute))) 'it carries no ReadProperty'
Assert-That 'GenericExecute|ReadProperty qualifies' (Test-Grant -RightsValue (([int] $adr::GenericExecute) -bor $READ_PROPERTY))

Write-Host 'Rights that are absent are still absent' -ForegroundColor Cyan
# The fix must not become permissive - a false green here hides a genuinely broken delegation.
Assert-That 'no rights at all does not qualify' (-not (Test-Grant -RightsValue 0))
Assert-That 'Delete|WriteDacl does not qualify' (-not (Test-Grant -RightsValue (([int] $adr::Delete) -bor ([int] $adr::WriteDacl))))
Assert-That 'CreateChild|DeleteChild does not qualify' (-not (Test-Grant -RightsValue (([int] $adr::CreateChild) -bor ([int] $adr::DeleteChild))))

Write-Host 'The other ACE qualifiers still hold' -ForegroundColor Cyan
# An InheritOnly ACE does not apply to the object itself, and a property-set-scoped ACE is not a
# grant on the whole object - both must keep disqualifying even now the mask is read correctly.
$full = $LIST_CHILDREN -bor $READ_PROPERTY -bor $READ_CONTROL
Assert-That 'an InheritOnly ACE does not qualify' (-not (Test-Grant -RightsValue $full -InheritOnly $true))
Assert-That 'a property-set-scoped ACE does not qualify' (-not (Test-Grant -RightsValue $full -PropertySetScoped $true))
Assert-That 'a DENY of the same rights does not qualify' (-not (Test-Grant -RightsValue $full -Deny $true))

Write-Host 'Deny still overrides an allow of the same rights' -ForegroundColor Cyan
# Evaluated through the real function with both ACEs present, which is the ordering that matters.
$mixed = @(
    [PSCustomObject]@{ Trustee = 'CONTOSO\svc-mdi'; IsAllow = $true; IsDeny = $false; Mask = $REQUIRED; InheritOnly = $false; PropertySetScoped = $false }
    [PSCustomObject]@{ Trustee = 'CONTOSO\svc-mdi'; IsAllow = $false; IsDeny = $true; Mask = $LIST_CHILDREN; InheritOnly = $false; PropertySetScoped = $false }
)
Assert-That 'an allow undone by a deny does not qualify' (
    @(Get-mdiEffectiveDaclTrustee -Ace $mixed -RequiredMask $REQUIRED).Count -eq 0) 'the deny was ignored'

Write-Host 'Two partial allows still union to a grant' -ForegroundColor Cyan
# Real DACLs split rights across ACEs; the union must survive the change to bitwise reading.
$split = @(
    [PSCustomObject]@{ Trustee = 'CONTOSO\svc-mdi'; IsAllow = $true; IsDeny = $false; Mask = $LIST_CHILDREN; InheritOnly = $false; PropertySetScoped = $false }
    [PSCustomObject]@{ Trustee = 'CONTOSO\svc-mdi'; IsAllow = $true; IsDeny = $false; Mask = $READ_PROPERTY; InheritOnly = $false; PropertySetScoped = $false }
)
Assert-That 'List Contents and Read Property in separate ACEs qualify' (
    @(Get-mdiEffectiveDaclTrustee -Ace $split -RequiredMask $REQUIRED).Count -eq 1) 'the union failed'

Write-Host 'End to end through the real reader, not a copy of it' -ForegroundColor Cyan
<#
    Everything above builds the ACE record the way the reader builds it. That would keep passing if the
    reader itself went back to matching enum NAMES, so the decisive check drives the whole of
    Get-mdiDeletedObjectsPermission with the directory stubbed:

      - Get-ADRootDSE supplies a naming context.
      - The DirectorySearcher path is left to fail on its own (there is no domain here), which is what
        sends the function into the Get-ADObject fallback - the path that carried the defect.
      - Get-ADObject returns a descriptor whose .Access holds real ActiveDirectoryRights values.

    Stubbing is at SCRIPT scope because that is the only scope the function's internal calls resolve
    against; `function global:Get-ADObject` would not override them.
#>
Set-Item -Path function:script:Get-ADRootDSE -Value {
    param($Server, $ErrorAction)
    [PSCustomObject]@{ defaultNamingContext = 'DC=contoso,DC=com' }
}

function Test-ContainerVerdict {
    param([int] $RightsValue, [string] $Trustee = 'CONTOSO\svc-mdi')
    Set-Item -Path function:script:Get-ADObject -Value {
        param(
            $Identity,
            $Server,
            [switch] $IncludeDeletedObjects,
            $Properties,
            $ErrorAction
        )
        [PSCustomObject]@{
            nTSecurityDescriptor = [PSCustomObject]@{
                Access = @([PSCustomObject]@{
                        IdentityReference     = $script:stubTrustee
                        ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights] $script:stubRights
                        AccessControlType     = 'Allow'
                        PropagationFlags      = 'None'
                        ObjectType            = [Guid]::Empty
                    })
            }
        }
    }
    $script:stubRights = $RightsValue
    $script:stubTrustee = $Trustee
    Get-mdiDeletedObjectsPermission -Domain 'contoso.com' -DirectoryServiceAccount @($Trustee)
}

# The exact grant "dsacls /G <DSA>:LCRP" leaves on the container.
$dsaclsGrant = $LIST_CHILDREN -bor $READ_PROPERTY -bor $READ_CONTROL
$verdict = Test-ContainerVerdict -RightsValue $dsaclsGrant
Assert-That 'the container descriptor was read' ($verdict.Measured -eq $true) "Measured=$($verdict.Measured)"
Assert-That 'a DSA granted LCRP is reported as having access' ($verdict.isDeletedObjectsPermissionOk -eq $true) "got '$($verdict.isDeletedObjectsPermissionOk)'"
Assert-That '  ...and no dsacls re-grant is advised' (
    [string] $verdict.details.Detail -notmatch 'dsacls') "detail said: $($verdict.details.Detail)"

# The genuinely broken case must still fail, or the fix would be a false green.
$noReadProp = Test-ContainerVerdict -RightsValue ($LIST_CHILDREN -bor $READ_CONTROL)
Assert-That 'a DSA missing Read Property is still reported as failing' ($noReadProp.isDeletedObjectsPermissionOk -eq $false) "got '$($noReadProp.isDeletedObjectsPermissionOk)'"
Assert-That '  ...and IS advised to run dsacls' (
    [string] $noReadProp.details.Detail -match 'dsacls') "detail said: $($noReadProp.details.Detail)"

$generic = Test-ContainerVerdict -RightsValue ([int] $adr::GenericAll)
Assert-That 'a DSA with GenericAll is reported as having access' ($generic.isDeletedObjectsPermissionOk -eq $true) "got '$($generic.isDeletedObjectsPermissionOk)'"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
