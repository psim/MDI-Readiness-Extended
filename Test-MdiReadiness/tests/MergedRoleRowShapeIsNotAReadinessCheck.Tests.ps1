<#
    A role row written as a DICTIONARY must not have the dictionary's own .NET members MATERIALISED
    onto the merged host as real readiness checks, and a dictionary row's unmeasured checks must
    still be counted as unread.

    THE DEFECT THIS PINS. Two functions walked a server row with $Row.PSObject.Properties, which over
    an IDictionary enumerates the DICTIONARY'S OWN .NET MEMBERS - Count, Keys, Values, SyncRoot,
    IsReadOnly, IsFixedSize, IsSynchronized - and never its entries.

    1. Merge-mdiServerByFqdn, the merge loop:

           foreach ($prop in $srv.PSObject.Properties) {
               ...
               if ($null -eq $existing) {
                   Add-Member -InputObject $target -MemberType NoteProperty -Name $name -Value $prop.Value -Force

       Three of those members are real booleans, and the loop's own $isCheck test admits "a real
       [bool] on either side" from ANY property name by design, so all three were Add-Member'd onto
       the surviving row as genuine readiness checks - while every real entry of that role was never
       looked at. Measured on the shipped functions, ONE physical host holding TWO roles (a domain
       controller that also carries the certification authority role, which is exactly what this
       merge exists for), with the CA role row written the two ways a report can carry it:

           CA row PSCustomObject   isAdvancedAuditingOk=True  isPowerSchemeOk=False
           CA row Hashtable        isAdvancedAuditingOk=True  IsFixedSize=False  IsReadOnly=False
                                                              IsSynchronized=False

       So the genuine FAILURE isPowerSchemeOk=False was DELETED from the merged host - a false green -
       and three checks that cannot exist took its place - a false red. ChecksTotal went 3 to 5.
       Measured end to end through the real New-mdiRemediationScript on the same estate, the script
       an operator executes against production domain controllers gained three invented findings:

           Write-Host '    [High] dcfab01.fabrikam.local: Is Read Only check failed'
           Write-Host '    [High] dcfab01.fabrikam.local: Is Fixed Size check failed'
           Write-Host '    [High] dcfab01.fabrikam.local: Is Synchronized check failed'

       and its manual-attention count went 2 to 4.

    2. Get-mdiUnreadCheckName, which names the checks that could not be measured:

           @($Server.PSObject.Properties | Where-Object { ... ([string] $_.Value -eq 'N/A') ... })

       A dictionary row has no 'N/A' ENTRY to find, so the unread list came back empty. This one
       fails purely in the FALSE GREEN direction. Measured on the shipped function, one server
       written both ways:

           PSCustomObject row   2 unread   isDeletedObjectsPermissionOk, isObjectAuditingOk
           Hashtable row        0 unread

       Get-mdiUnreadCheckCount reads that list, so the score charged the server nothing for two
       checks nobody had read.

    WHY THE SIBLING FIX DID NOT CATCH IT. Get-mdiCheckProperty already normalises through
    ConvertTo-mdiRecordObject (see DictionaryServerRowKeepsItsChecks.Tests.ps1). That cannot help
    here: the merge path MATERIALISES the plumbing as real NoteProperties on an object-shaped row, so
    by the time any reader sees it there is nothing dictionary-shaped left to normalise. The merged
    row is a perfectly ordinary PSCustomObject that genuinely carries IsReadOnly = $false.

    WHY THE SHAPE ARRIVES AT ALL. A live scan writes PSCustomObject rows and ConvertFrom-Json in
    Windows PowerShell 5.1 produces objects, so it never appears on the ordinary path. It arrives
    from another tool's JSON, an -AsJson round trip, a hand-edited report or an older version - which
    is why ConvertTo-mdiRecordObject exists in this script at all. A cross-forest estate is where
    that stops being hypothetical: -MultiForest reaches a second forest whose report is the one most
    likely to be handed between tools.

    THE FIX. Merge-mdiServerByFqdn normalises each row through ConvertTo-mdiRecordObject at the top
    of the loop, which also repairs the first-role branch - $srv.PSObject.Copy() on a Hashtable
    returns another Hashtable, so a host whose FIRST discovered role was dictionary-shaped left the
    merge target dictionary-shaped too. Get-mdiUnreadCheckName normalises for the same reason.

    Pinned here:

    1. A dictionary role row merged into an object one yields exactly the checks the all-object
       estate yields.
    2. The merged row carries NO plumbing property - IsReadOnly, IsFixedSize, IsSynchronized, Count,
       Keys, Values, SyncRoot - as a real member, which is the materialisation itself.
    3. The dictionary role's genuine FAILURE survives the merge, so the false-green half cannot
       return.
    4. Every merge ORDERING agrees: object+object, object+dict, dict+object, dict+dict.
    5. Every IDictionary shape is covered, not just Hashtable - a [PSCustomObject] cast only
       special-cases Hashtable and OrderedDictionary, and the report's shape is not this script's
       choice.
    6. The generated remediation script contains no "Is Read Only / Is Fixed Size / Is Synchronized
       check failed" line - the surface an operator actually executes.
    7. A dictionary row's 'N/A' checks are still counted as unread, by name and by count.
    8. Ordinary all-object estates are unchanged, so the normalisation cost nothing.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Merge-mdiServerByFqdn') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

# The dictionary's own members. IsReadOnly, IsFixedSize and IsSynchronized are the three booleans that
# were admitted as readiness checks; the rest must not be materialised onto the merged row either.
$plumbing = @('IsReadOnly', 'IsFixedSize', 'IsSynchronized', 'Count', 'Keys', 'Values', 'SyncRoot')

# A cross-forest domain controller that also holds the certification authority role - one physical
# host discovered under two roles, which is the case Merge-mdiServerByFqdn exists for.
$dcFields = [ordered]@{
    FQDN                 = 'dcfab01.fabrikam.local'
    Domain               = 'fabrikam.local'
    OperatingSystem      = 'Windows Server 2022'
    Unreachable          = $false
    isAdvancedAuditingOk = $true
    isNtlmAuditingOk     = $true
}
$caFields = [ordered]@{
    FQDN                 = 'dcfab01.fabrikam.local'
    Domain               = 'fabrikam.local'
    isAdvancedAuditingOk = $true
    isPowerSchemeOk      = $false
}

function New-Row {
    param([hashtable] $Fields, [string] $Shape)
    switch ($Shape) {
        'Object' { $o = [ordered]@{}; foreach ($k in $Fields.Keys) { $o[$k] = $Fields[$k] }; return [PSCustomObject] $o }
        'Hashtable' { $h = @{}; foreach ($k in $Fields.Keys) { $h[$k] = $Fields[$k] }; return $h }
        'Ordered' { $o = [ordered]@{}; foreach ($k in $Fields.Keys) { $o[$k] = $Fields[$k] }; return $o }
        'Generic' {
            $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'
            foreach ($k in $Fields.Keys) { $d[[string] $k] = $Fields[$k] }
            return $d
        }
    }
    throw "unknown shape $Shape"
}

function Get-MergedCheckText {
    param([string] $DcShape, [string] $CaShape)
    $rows = @((New-Row -Fields $dcFields -Shape $DcShape), (New-Row -Fields $caFields -Shape $CaShape))
    $merged = @(Merge-mdiServerByFqdn -Server $rows)
    if ($merged.Count -ne 1) { return "MERGEDROWS=$($merged.Count)" }
    @(Get-mdiCheckProperty -Server $merged[0] | Sort-Object Name |
            ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '  '
}

function Get-MergedRow {
    param([string] $DcShape, [string] $CaShape)
    $rows = @((New-Row -Fields $dcFields -Shape $DcShape), (New-Row -Fields $caFields -Shape $CaShape))
    @(Merge-mdiServerByFqdn -Server $rows)[0]
}

''
'--- 1/3/4/5  the merged host, every shape and every ordering ---'
$control = Get-MergedCheckText -DcShape 'Object' -CaShape 'Object'
Assert-That 'the all-object control merges both roles onto one host with every check' `
($control -eq 'isAdvancedAuditingOk=True  isNtlmAuditingOk=True  isPowerSchemeOk=False') "got [$control]"

foreach ($ordering in @(
        @{ Name = 'object DC + Hashtable CA'; Dc = 'Object'; Ca = 'Hashtable' }
        @{ Name = 'object DC + OrderedDictionary CA'; Dc = 'Object'; Ca = 'Ordered' }
        @{ Name = 'object DC + Generic.Dictionary CA'; Dc = 'Object'; Ca = 'Generic' }
        @{ Name = 'Hashtable DC + object CA'; Dc = 'Hashtable'; Ca = 'Object' }
        @{ Name = 'Hashtable DC + Hashtable CA'; Dc = 'Hashtable'; Ca = 'Hashtable' }
        @{ Name = 'Generic.Dictionary DC + Hashtable CA'; Dc = 'Generic'; Ca = 'Hashtable' }
    )) {
    $got = Get-MergedCheckText -DcShape $ordering.Dc -CaShape $ordering.Ca
    Assert-That "$($ordering.Name) yields the same checks as the all-object estate" `
    ($got -eq $control) "got [$got] want [$control]"

    $row = Get-MergedRow -DcShape $ordering.Dc -CaShape $ordering.Ca
    # 2. The materialisation itself: a plumbing name present as a REAL member of the merged row.
    $leaked = @(@($row.PSObject.Properties) | ForEach-Object { [string] $_.Name } | Where-Object { $_ -in $plumbing })
    Assert-That "$($ordering.Name) materialises no dictionary member onto the merged row" `
    ($leaked.Count -eq 0) "materialised [$($leaked -join ', ')]"

    # 3. The false-green half, stated on its own: the dictionary role's genuine failure survives.
    $failing = @(Get-mdiCheckProperty -Server $row | Where-Object { $_.Value -eq $false } |
            ForEach-Object { [string] $_.Name })
    Assert-That "$($ordering.Name) keeps the genuine failure isPowerSchemeOk" `
    ($failing -contains 'isPowerSchemeOk') "failing checks were [$($failing -join ', ')]"
}

''
'--- 6  the generated remediation script, which is what an operator executes ---'
function Get-GeneratedScript {
    param([string] $CaShape)
    $data = [PSCustomObject]@{
        Domains             = @('fabrikam.local')
        DomainControllers   = @((New-Row -Fields $dcFields -Shape 'Object'))
        CAServers           = @((New-Row -Fields $caFields -Shape $CaShape))
        EntraConnectServers = @()
    }
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ('mdi-mergeshape-{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
    $lines = @()
    try {
        [void] (New-mdiRemediationScript -ReportData $data -FilePath $path)
        if (Test-Path -LiteralPath $path) { $lines = @(Get-Content -LiteralPath $path) }
    } finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    $lines
}

$objectScript = Get-GeneratedScript -CaShape 'Object'
Assert-That 'the control estate generates a remediation script at all' ($objectScript.Count -gt 0)

foreach ($shape in @('Hashtable', 'Ordered', 'Generic')) {
    $lines = Get-GeneratedScript -CaShape $shape
    $invented = @($lines | Where-Object {
            $_ -match 'Is Read Only check failed|Is Fixed Size check failed|Is Synchronized check failed'
        })
    Assert-That "a $shape role row invents no finding in the generated remediation script" `
    ($invented.Count -eq 0) "invented [$($invented -join ' | ')]"

    # 8. Not merely "no invented lines" - the same script as the all-object estate. The Generated
    # timestamp line is masked because it changes between two calls a second apart, which would make
    # this compare the clock rather than the row shape.
    $mask = { param($L) @($L) -replace '^\s*Generated\s*:.*$', 'Generated : <masked>' -join "`n" }
    Assert-That "a $shape role row generates the same script as the all-object estate" `
    ((& $mask $lines) -eq (& $mask $objectScript)) `
    "line counts $($lines.Count) vs $($objectScript.Count)"
}

''
'--- 7  a dictionary row''s unmeasured checks are still counted as unread ---'
# 'N/A' is what the product stores for a check that was reached but could not be read.
$unreadFields = [ordered]@{
    FQDN                         = 'memfab01.fabrikam.local'
    Domain                       = 'fabrikam.local'
    isAdvancedAuditingOk         = $true
    isDeletedObjectsPermissionOk = 'N/A'
    isObjectAuditingOk           = 'N/A'
}
$wantUnread = @(Get-mdiUnreadCheckName -Server (New-Row -Fields $unreadFields -Shape 'Object') | Sort-Object)
Assert-That 'the object control reports both unread checks' `
((@($wantUnread) -join ',') -eq 'isDeletedObjectsPermissionOk,isObjectAuditingOk') "got [$($wantUnread -join ', ')]"

foreach ($shape in @('Hashtable', 'Ordered', 'Generic')) {
    $row = New-Row -Fields $unreadFields -Shape $shape
    $names = @(Get-mdiUnreadCheckName -Server $row | Sort-Object)
    Assert-That "a $shape row names the same unread checks as the object row" `
    ((@($names) -join ',') -eq (@($wantUnread) -join ',')) "got [$($names -join ', ')] want [$($wantUnread -join ', ')]"

    $count = Get-mdiUnreadCheckCount -Server $row
    Assert-That "a $shape row is charged $($wantUnread.Count) unread check(s) by the score" `
    ($count -eq $wantUnread.Count) "got $count"

    # The unread walk must not start counting the dictionary's own members either - the mirror of the
    # merge defect, in the direction that would invent a gap rather than hide one.
    $leaked = @($names | Where-Object { $_ -in $plumbing })
    Assert-That "a $shape row counts no dictionary member as unread" ($leaked.Count -eq 0) "leaked [$($leaked -join ', ')]"
}

''
'--- 8  ordinary object rows are unchanged ---'
$plainRows = @(
    [PSCustomObject]@{ FQDN = 'dc01.mdilab.local'; Domain = 'mdilab.local'; isPowerSchemeOk = $true }
    [PSCustomObject]@{ FQDN = 'dc02.emea.mdilab.local'; Domain = 'emea.mdilab.local'; isPowerSchemeOk = $false }
)
$plainMerged = @(Merge-mdiServerByFqdn -Server $plainRows)
Assert-That 'two distinct hosts still merge to two rows' ($plainMerged.Count -eq 2) "got $($plainMerged.Count)"
Assert-That 'a row with no FQDN is still passed through rather than dropped' `
(@(Merge-mdiServerByFqdn -Server @([PSCustomObject]@{ Domain = 'fabrikam.local' })).Count -eq 1)
# An empty estate, not a null ELEMENT: the parameter is [object[]] without [AllowNull()], so the
# binder rejects a null element before the function's own $null guard is ever reached. Every caller
# builds the array with a Where-Object { $_ } filter, so that is the shape worth pinning.
Assert-That 'an empty estate still merges to nothing rather than throwing' `
(@(Merge-mdiServerByFqdn -Server @()).Count -eq 0)
# A dictionary row with no FQDN must also pass through, and must arrive normalised rather than as a
# raw dictionary whose .NET members every later reader would walk.
$noFqdn = @(Merge-mdiServerByFqdn -Server @(@{ Domain = 'fabrikam.local'; isPowerSchemeOk = $false }))
Assert-That 'a dictionary row with no FQDN is passed through' ($noFqdn.Count -eq 1) "got $($noFqdn.Count)"
Assert-That 'a passed-through dictionary row still reports its own check, not the dictionary members' `
((@(Get-mdiCheckProperty -Server $noFqdn[0] | ForEach-Object { [string] $_.Name }) -join ',') -eq 'isPowerSchemeOk') `
"got [$(@(Get-mdiCheckProperty -Server $noFqdn[0] | ForEach-Object { [string] $_.Name }) -join ', ')]"

''
"RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
