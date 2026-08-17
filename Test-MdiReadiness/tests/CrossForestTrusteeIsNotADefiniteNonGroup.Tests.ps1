<#
    A trustee this host cannot classify must not be reported as a definite non-group.

    THE DEFECT THIS PINS. Get-mdiPrincipalKind decides whether an ACL trustee on the Deleted Objects
    container is a Group, a NonGroup, or Unknown. Its own header states the rule the answer exists to
    honour:

        "'Unknown' is not 'NonGroup': a type lookup fails when the trustee is an orphaned SID, a
         foreign security principal, or in a trust this host cannot query, and in none of those cases
         is 'not proven to be a group' the same as 'proven to be a user'."

    The code did not implement that rule. It read:

        if (@($principal.objectClass) -contains 'group') { return 'Group' }
        return 'NonGroup'

    so EVERY path that was not positively a group returned the definite answer NonGroup. The header
    had assumed a foreign security principal would make the lookup FAIL and reach the catch block. It
    does not fail. When a trustee lives in another forest across a trust, the local directory holds a
    real local object for it - a foreignSecurityPrincipal stub carrying the foreign SID - so
    Get-ADObject FINDS it, and its objectClass is @('top','foreignSecurityPrincipal'), which does not
    contain 'group'. A cross-forest GROUP was therefore answered 'NonGroup' with full confidence.

    WHY THAT IS DESTRUCTIVE. Get-mdiDeletedObjectsAccess routes Group to 'N/A' and Unknown to 'N/A' -
    both unverified, both harmless. Only NonGroup is a definite non-match, and a definite non-match on
    every trustee produces "The Directory Service Account does not have read access", a High finding,
    and a generated dsacls /takeownership + re-grant fired at a production system container to repair
    a delegation that is perfectly intact. That is the exact false red the function's header says it
    exists to prevent - it was simply reachable through a door the header had not noticed was open.

    WHY IT SURVIVED, AND WHY THE LAB REACHES IT NOW. v1.1.5 shipped against a single forest, where a
    trustee on a local container is a local user or a local group and the two-answer logic is right.
    The bidirectional cross-forest trust to fabrikam.local added on 17 August is the first topology in
    which a foreignSecurityPrincipal can appear on that DACL at all. The same stub also exists in
    EVERY domain for well-known SIDs - S-1-5-11 Authenticated Users is a foreignSecurityPrincipal
    object and is a group - so the wrong answer was reachable before, just never with a delegation
    shape anyone had reason to grant.

    THE SECOND HALF, SAME ROOT. The lookup succeeding is not the same as the class being readable.
    objectClass comes back $null when a server did not return the requested property, and an element
    that is not a string is not a class name. Measured on the shipped function, every one of these
    produced a definite answer from a value nobody read:

        objectClass $null   -> NonGroup      objectClass ''   -> NonGroup
        objectClass @()     -> NonGroup      objectClass 42   -> NonGroup
        objectClass $true   -> GROUP

    The last is the same coercion trap in the opposite direction: -contains converts its right operand
    to the left element's type, and the non-empty string 'group' converts to $true, so @($true)
    -contains 'group' is TRUE. An unreadable objectClass could be reported as a definite Group.

    THE FIX. Classify only from class names actually read, as strings. Nothing readable -> Unknown.
    'group' -> Group. 'foreignSecurityPrincipal' -> Unknown, because the object's real class lives in
    a directory this host cannot query. Any other class that WAS read stays NonGroup, exactly as
    shipped - restricting that to a whitelist of recognised principal classes was tried and is wrong,
    because groupPolicyContainer is a definite non-group this suite already pins elsewhere and a
    whitelist turned that measured answer into 'not measured'.

    Pinned here:

    1. A cross-forest group's foreignSecurityPrincipal stub is Unknown, never NonGroup.
    2. So is the well-known S-1-5-11 stub that every domain carries.
    3. A real same-forest group is still Group and a real same-forest user is still NonGroup - the
       fix must not buy safety by refusing to answer.
    4. A BUILTIN alias is still decided from its SID prefix, without a directory.
    5. Every unreadable objectClass shape - $null, '', @(), a non-string, a bool - is Unknown, in
       NEITHER definite direction.
    6. The branches that were already Unknown stay Unknown.
    7. Unknown and Group both keep the Deleted Objects verdict off the destructive branch.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiPrincipalKind') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

# Neither forest is reachable from a test run, and the branch under test is the one AFTER the SID is
# known, so the translation is stubbed explicitly rather than relied upon - the test must pin the
# behaviour on a domain-joined machine too.
$script:sidmap = @{
    'FABCORP\MDI-Readers'              = 'S-1-5-21-9999999999-8888888888-7777777777-1105'
    'NT AUTHORITY\Authenticated Users' = 'S-1-5-11'
    'MDILAB\MDI-Readers'               = 'S-1-5-21-1111111111-2222222222-3333333333-1104'
    'MDILAB\svc-mdi'                   = 'S-1-5-21-1111111111-2222222222-3333333333-1201'
    'MDILAB\dc01$'                     = 'S-1-5-21-1111111111-2222222222-3333333333-1005'
    'BUILTIN\Administrators'           = 'S-1-5-32-544'
}
Set-Item -Path function:script:Resolve-mdiPrincipalSid -Value {
    param($Name)
    $k = [string] $Name
    if ($script:sidmap.ContainsKey($k)) { return $script:sidmap[$k] }
    $null
}

# What the LOCAL directory returns for each SID. A cross-forest principal is present only as a
# foreignSecurityPrincipal stub; a same-forest principal is present as itself.
$script:adobjects = @{
    'S-1-5-21-9999999999-8888888888-7777777777-1105' = @('top', 'foreignSecurityPrincipal')
    'S-1-5-11'                                       = @('top', 'foreignSecurityPrincipal')
    'S-1-5-21-1111111111-2222222222-3333333333-1104' = @('top', 'group')
    'S-1-5-21-1111111111-2222222222-3333333333-1201' = @('top', 'person', 'organizationalPerson', 'user')
    'S-1-5-21-1111111111-2222222222-3333333333-1005' = @('top', 'person', 'organizationalPerson', 'user', 'computer')
}
Set-Item -Path function:script:Get-ADObject -Value {
    param($Server, $Filter, $Properties, $ErrorAction)
    $f = [string] $Filter
    foreach ($sid in $script:adobjects.Keys) {
        if ($f -match [regex]::Escape($sid)) { return [PSCustomObject]@{ objectClass = $script:adobjects[$sid] } }
    }
    $null
}

'--- 1. a cross-forest group is Unknown, not a definite NonGroup ---'
$kind = Get-mdiPrincipalKind -Name 'FABCORP\MDI-Readers' -Domain 'mdilab.local'
Assert-That 'a foreignSecurityPrincipal stub is not NonGroup' ($kind -ne 'NonGroup') "got $kind"
Assert-That 'and it is reported Unknown' ($kind -eq 'Unknown') "got $kind"

'--- 2. the well-known stub every domain carries ---'
$kind = Get-mdiPrincipalKind -Name 'NT AUTHORITY\Authenticated Users' -Domain 'mdilab.local'
Assert-That 'S-1-5-11 is not a definite non-group' ($kind -ne 'NonGroup') "got $kind"
Assert-That 'S-1-5-11 is Unknown' ($kind -eq 'Unknown') "got $kind"

'--- 3. the fix must not buy safety by refusing to answer ---'
Assert-That 'a real same-forest group is still Group' ((Get-mdiPrincipalKind -Name 'MDILAB\MDI-Readers' -Domain 'mdilab.local') -eq 'Group')
Assert-That 'a real same-forest user is still NonGroup' ((Get-mdiPrincipalKind -Name 'MDILAB\svc-mdi' -Domain 'mdilab.local') -eq 'NonGroup')
Assert-That 'a computer account is still NonGroup' ((Get-mdiPrincipalKind -Name 'MDILAB\dc01$' -Domain 'mdilab.local') -eq 'NonGroup')

'--- 4. a BUILTIN alias is decided from its SID, with no directory at all ---'
Set-Item -Path function:script:Get-ADObject -Value { param($Server, $Filter, $Properties, $ErrorAction) throw 'must not be consulted for a BUILTIN alias' }
Assert-That 'BUILTIN\Administrators is Group without a lookup' ((Get-mdiPrincipalKind -Name 'BUILTIN\Administrators' -Domain 'mdilab.local') -eq 'Group')

'--- 5. an unreadable objectClass is a definite answer in NEITHER direction ---'
$unreadable = @(
    @{ Label = '$null'; Make = { [PSCustomObject]@{ objectClass = $null } } }
    @{ Label = "''"; Make = { [PSCustomObject]@{ objectClass = '' } } }
    @{ Label = 'whitespace'; Make = { [PSCustomObject]@{ objectClass = '   ' } } }
    @{ Label = '@()'; Make = { [PSCustomObject]@{ objectClass = @() } } }
    @{ Label = '$true'; Make = { [PSCustomObject]@{ objectClass = $true } } }
    @{ Label = '$false'; Make = { [PSCustomObject]@{ objectClass = $false } } }
    @{ Label = 'an integer'; Make = { [PSCustomObject]@{ objectClass = 42 } } }
    @{ Label = 'property absent'; Make = { [PSCustomObject]@{ distinguishedName = 'CN=x' } } }
    @{ Label = '@($null)'; Make = { [PSCustomObject]@{ objectClass = @($null) } } }
    @{ Label = '@(1,2)'; Make = { [PSCustomObject]@{ objectClass = @(1, 2) } } }
)
foreach ($case in $unreadable) {
    $obj = & $case.Make
    Set-Item -Path function:script:Get-ADObject -Value ([scriptblock]::Create('param($Server,$Filter,$Properties,$ErrorAction); $script:probeObject').GetNewClosure())
    $script:probeObject = $obj
    $kind = Get-mdiPrincipalKind -Name 'MDILAB\MDI-Readers' -Domain 'mdilab.local'
    Assert-That ("objectClass {0} is not a definite Group" -f $case.Label) ($kind -ne 'Group') "got $kind"
    Assert-That ("objectClass {0} is not a definite NonGroup" -f $case.Label) ($kind -ne 'NonGroup') "got $kind"
    Assert-That ("objectClass {0} is Unknown" -f $case.Label) ($kind -eq 'Unknown') "got $kind"
}

'--- 6. the branches that were already Unknown stay Unknown ---'
Set-Item -Path function:script:Get-ADObject -Value { param($Server, $Filter, $Properties, $ErrorAction) throw 'directory unreachable' }
Assert-That 'a lookup that throws is Unknown' ((Get-mdiPrincipalKind -Name 'MDILAB\MDI-Readers' -Domain 'mdilab.local') -eq 'Unknown')
Set-Item -Path function:script:Get-ADObject -Value { param($Server, $Filter, $Properties, $ErrorAction) $null }
Assert-That 'a lookup that finds nothing is Unknown' ((Get-mdiPrincipalKind -Name 'MDILAB\MDI-Readers' -Domain 'mdilab.local') -eq 'Unknown')
Assert-That 'an unresolvable SID is Unknown' ((Get-mdiPrincipalKind -Name 'NOSUCH\nobody' -Domain 'mdilab.local') -eq 'Unknown')
foreach ($d in @('', $null, '   ')) {
    Assert-That ("an unreadable -Domain [{0}] is Unknown" -f $d) ((Get-mdiPrincipalKind -Name 'MDILAB\MDI-Readers' -Domain $d) -eq 'Unknown')
}
Assert-That 'an empty -Name is Unknown' ((Get-mdiPrincipalKind -Name '' -Domain 'mdilab.local') -eq 'Unknown')
Assert-That 'a null -Name is Unknown' ((Get-mdiPrincipalKind -Name $null -Domain 'mdilab.local') -eq 'Unknown')

'--- 7. only NonGroup reaches the destructive branch, so the two safe answers must stay safe ---'
# Get-mdiDeletedObjectsAccess sends Group and Unknown to the unverified 'N/A' verdict and only a
# definite NonGroup to the "does not have read access" finding. Pinned as a property of the kinds
# themselves so the routing cannot be inverted without this failing.
Set-Item -Path function:script:Get-ADObject -Value {
    param($Server, $Filter, $Properties, $ErrorAction)
    $f = [string] $Filter
    foreach ($sid in $script:adobjects.Keys) {
        if ($f -match [regex]::Escape($sid)) { return [PSCustomObject]@{ objectClass = $script:adobjects[$sid] } }
    }
    $null
}
$crossForest = @('FABCORP\MDI-Readers', 'NT AUTHORITY\Authenticated Users')
$destructive = @($crossForest | Where-Object { (Get-mdiPrincipalKind -Name $_ -Domain 'mdilab.local') -eq 'NonGroup' })
Assert-That 'no cross-forest trustee lands on the destructive branch' ($destructive.Count -eq 0) "these did: $($destructive -join ', ')"

''
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
