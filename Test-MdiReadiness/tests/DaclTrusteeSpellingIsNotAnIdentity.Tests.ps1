<#
    Two spellings of one trustee are one trustee, so a DENY must still subtract from its ALLOW.

    THE DEFECT THIS PINS. Get-mdiEffectiveDaclTrustee is the single shared evaluator for the Deleted
    Objects DACL - "one evaluator, fed by both DACL readers", written because two inline
    interpretations of the same DACL had drifted apart. It computes effective rights as
    ALLOW AND NOT DENY, and rule 2 of its own header states why:

        "Deny. Windows evaluates a DACL as allow-minus-deny; an explicit Deny ReadProperty on the
         account revokes the right however many Allow entries also name it. Deny ACEs were simply
         discarded, so a deliberately revoked account still reported as holding read access."

    It accumulated into:

        $allow = New-Object 'System.Collections.Generic.Dictionary[string,int]'
        $deny  = New-Object 'System.Collections.Generic.Dictionary[string,int]'

    A .NET Dictionary[string,int] built without a comparer uses EqualityComparer<string>.Default,
    which is ORDINAL and CASE-SENSITIVE. Windows resolves a trustee by SID and is case-insensitive
    about the name it is written with.

    That only bites if the keys can be NAMES, and for one of the two callers they are. The readers
    disagree about what a Trustee is:

        raw descriptor path (-ResolveSid) : Trustee = [string] $ace.SecurityIdentifier   a SID
        directory-module fallback         : Trustee = [string] $ace.IdentityReference    FABCORP\MDI-Readers

    Measured on the shipped function, fed exactly the record shape the fallback reader builds:

        Allow FABCORP\MDI-Readers LC+RP, Deny fabcorp\mdi-readers RP
            -> granted FABCORP\MDI-Readers      the deny was DROPPED        FALSE GREEN
        Allow FABCORP\svc-mdi LC,  Allow fabcorp\svc-mdi RP
            -> granted nothing                  the union was SPLIT         FALSE RED

    The same DACL written in one consistent case behaved correctly, which is why nothing caught it.

    WHY BOTH DIRECTIONS ARE DESTRUCTIVE. The dropped deny is the exact outcome rule 2 exists to
    prevent: an account whose read access was deliberately revoked is reported as still holding it.
    The split union is the false red this file elsewhere warns "is acted on against production
    directories" - the run reports "no trustee holds both List Contents and Read Property" and the
    generated remediation fires dsacls /G "<DSA>":LCRP at a system container to re-grant a delegation
    that is already in place. The function's own header records that granting LCRP in one operation
    and RP in another "is what happens when a delegation is amended, or when two different tools each
    add an entry" - so the split-grant shape is ordinary, not contrived.

    WHY THE NAMES ARE ONE IDENTITY, MEASURED RATHER THAN ASSUMED:

        NTAccount('BUILTIN\Administrators').Equals(NTAccount('builtin\administrators'))  -> True
        both .Translate(SecurityIdentifier)                                              -> S-1-5-32-544
        NTAccount.Value                                       PRESERVES the spelling it was built from

    So .NET's own identity type calls them the same principal, they resolve to one SID, and
    IdentityReference is NOT canonicalised on the way out - the string can differ while the principal
    does not. A dictionary keyed on that string is keyed on a spelling, not on an identity.

    THE FIX. Build both dictionaries with [StringComparer]::OrdinalIgnoreCase. That is already this
    codebase's convention for name-like keys - it is used at six sibling sites (the domain scope set,
    the examined/dcDomains/seen sets in Get-mdiUnexaminedDomain, the unread-name set in the issue
    list, and the remediation dedup set). These two were the deviation.

    Pinned here:

    1. A DENY spelled in different case still subtracts from its ALLOW.
    2. Two ALLOW aces for one principal in different case still union.
    3. Same-case allow/deny still behaves - the rule the fix must not disturb.
    4. The SID-keyed caller is unaffected.
    5. The fix must NOT over-merge: two genuinely different principals that differ by more than case
       stay separate, and a deny against one of them does not touch the other.
    6. InheritOnly, PropertySetScoped and the RequiredMask test still apply across case.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiEffectiveDaclTrustee') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

# LIST_CONTENTS and READ_PROPERTY: what "read" means on the Deleted Objects container, and what the
# production callers pass as RequiredMask.
$LC = 0x4; $RP = 0x10; $READ = $LC -bor $RP

# Exactly the record shape the directory-module reader builds at its call site: Trustee taken from
# IdentityReference, IsAllow/IsDeny from AccessControlType, a numeric Mask, and the two scope flags.
function New-Ace {
    param($Trustee, $Allow = $false, $Deny = $false, $Mask = 0, $InheritOnly = $false, $PropSet = $false)
    [PSCustomObject]@{
        Trustee = $Trustee; IsAllow = $Allow; IsDeny = $Deny; Mask = $Mask
        InheritOnly = $InheritOnly; PropertySetScoped = $PropSet
    }
}
function Granted {
    param($Aces, $Mask = $READ)
    # Returned WITHOUT the comma operator, exactly as the product's own resolvers do, and therefore
    # WRAPPED at every call site below. A one-element result unrolls to a bare string on assignment,
    # and $g[0] on a string is its first CHARACTER - which silently turned an identity assertion into
    # a comparison against 'S'. The product file documents this same trap on Resolve-mdiNnrTarget.
    @(Get-mdiEffectiveDaclTrustee -Ace $Aces -RequiredMask $Mask)
}

'--- 1. a DENY in different case still subtracts (was: dropped, FALSE GREEN) ---'
$g = Granted @(
    (New-Ace -Trustee 'FABCORP\MDI-Readers' -Allow $true -Mask $READ)
    (New-Ace -Trustee 'fabcorp\mdi-readers' -Deny  $true -Mask $RP)
)
Assert-That 'a case-different deny revokes the right' ($g.Count -eq 0) "granted: $($g -join ', ')"

# The deny written in UPPER against a lower allow, so the fix cannot be a one-directional lowercase.
$g = Granted @(
    (New-Ace -Trustee 'fabcorp\mdi-readers' -Allow $true -Mask $READ)
    (New-Ace -Trustee 'FABCORP\MDI-READERS' -Deny  $true -Mask $LC)
)
Assert-That 'the direction of the case difference does not matter' ($g.Count -eq 0) "granted: $($g -join ', ')"

'--- 2. two ALLOW aces in different case still union (was: split, FALSE RED) ---'
# The function header records this shape as ordinary: "granting LCRP in one operation and RP in
# another - which is what happens when a delegation is amended, or when two different tools each add
# an entry - produces two ACEs that jointly grant read access".
$g = Granted @(
    (New-Ace -Trustee 'FABCORP\svc-mdi' -Allow $true -Mask $LC)
    (New-Ace -Trustee 'fabcorp\svc-mdi' -Allow $true -Mask $RP)
)
Assert-That 'a split grant across case still unions to read' ($g.Count -eq 1) "granted: $($g -join ', ')"

'--- 3. the same-case rules the fix must not disturb ---'
$g = Granted @(
    (New-Ace -Trustee 'FABCORP\MDI-Readers' -Allow $true -Mask $READ)
    (New-Ace -Trustee 'FABCORP\MDI-Readers' -Deny  $true -Mask $RP)
)
Assert-That 'same-case deny still subtracts' ($g.Count -eq 0) "granted: $($g -join ', ')"
$g = Granted @( (New-Ace -Trustee 'FABCORP\MDI-Readers' -Allow $true -Mask $READ) )
Assert-That 'a plain allow of both rights still grants' ($g.Count -eq 1) "granted: $($g -join ', ')"
$g = Granted @( (New-Ace -Trustee 'FABCORP\MDI-Readers' -Allow $true -Mask $LC) )
Assert-That 'a partial grant still does not qualify' ($g.Count -eq 0) "granted: $($g -join ', ')"

'--- 4. the SID-keyed caller is unaffected ---'
$sid = 'S-1-5-21-9999999999-8888888888-7777777777-1105'
$g = Granted @(
    (New-Ace -Trustee $sid -Allow $true -Mask $LC)
    (New-Ace -Trustee $sid -Allow $true -Mask $RP)
)
Assert-That 'SID accumulation still unions' (@($g).Count -eq 1 -and @($g)[0] -eq $sid) "granted: $($g -join ', ')"

'--- 5. the fix must not OVER-merge: different principals stay different ---'
# Case-insensitivity is not fuzziness. Two accounts whose names differ by more than case are two
# principals, and merging them would be a far worse defect than the one being fixed - it is the
# "FABRIKAM\svc-mdi satisfied by CONTOSO\svc-mdi" false green Get-mdiMatchingTrustee exists to avoid.
$g = Granted @(
    (New-Ace -Trustee 'FABCORP\svc-mdi' -Allow $true -Mask $READ)
    (New-Ace -Trustee 'MDILAB\svc-mdi'  -Deny  $true -Mask $RP)
)
Assert-That 'a deny against another domain does not revoke this one' (@($g).Count -eq 1 -and @($g)[0] -eq 'FABCORP\svc-mdi') "granted: $($g -join ', ')"
$g = Granted @(
    (New-Ace -Trustee 'FABCORP\svc-mdi'     -Allow $true -Mask $LC)
    (New-Ace -Trustee 'FABCORP\svc-mdi-old' -Allow $true -Mask $RP)
)
Assert-That 'two similarly named accounts do not pool their rights' ($g.Count -eq 0) "granted: $($g -join ', ')"
$g = Granted @(
    (New-Ace -Trustee 'FABCORP\svc-mdi' -Allow $true -Mask $READ)
    (New-Ace -Trustee 'MDILAB\svc-mdi'  -Allow $true -Mask $READ)
)
Assert-That 'two distinct principals both qualify separately' ($g.Count -eq 2) "granted: $($g -join ', ')"

'--- 6. the scope rules still apply across case ---'
# An INHERIT_ONLY allow confers nothing on the object it sits on, so it must not become the thing a
# case-different deny is subtracted from - nor rescue a trustee that has no effective grant.
$g = Granted @( (New-Ace -Trustee 'FABCORP\MDI-Readers' -Allow $true -Mask $READ -InheritOnly $true) )
Assert-That 'an inherit-only allow still confers nothing' ($g.Count -eq 0) "granted: $($g -join ', ')"
$g = Granted @( (New-Ace -Trustee 'FABCORP\MDI-Readers' -Allow $true -Mask $READ -PropSet $true) )
Assert-That 'a property-set scoped allow still confers nothing' ($g.Count -eq 0) "granted: $($g -join ', ')"
# A case-different DENY that is itself inherit-only applies to children, not here, so it must NOT
# revoke - the case fix must not accidentally promote a scoped deny into an effective one.
$g = Granted @(
    (New-Ace -Trustee 'FABCORP\MDI-Readers' -Allow $true -Mask $READ)
    (New-Ace -Trustee 'fabcorp\mdi-readers' -Deny  $true -Mask $RP -InheritOnly $true)
)
Assert-That 'an inherit-only deny does not revoke, whatever its case' ($g.Count -eq 1) "granted: $($g -join ', ')"

''
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
