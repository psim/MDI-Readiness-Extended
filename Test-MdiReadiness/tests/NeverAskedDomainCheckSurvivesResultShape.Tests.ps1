<#
    A domain check result written as a DICTIONARY must not turn a question NOBODY ASKED into a
    measurement gap.

    THE DEFECT THIS PINS. Test-mdiDomainCheckNotAsserted exists to separate "asked of nothing" from
    "asked and not answered". Its own header states what happens when the two are confused: "the
    verdict returned NOT READY on a healthy forest, the issue list raised a High 'returned no usable
    result', and the score card counted an unread check."

    It answered the question through a presence test, and so did its sibling, the Measured fallback
    in Get-mdiDomainCheckDefinition:

        Test-mdiDomainCheckNotAsserted     if ($null -eq $Result.PSObject.Properties['NotAsserted']) { return $false }
        Get-mdiDomainCheckDefinition       if ($null -ne $Result -and $null -ne $Result.PSObject.Properties['Measured']) { ... }

    PSObject.Properties over an IDictionary enumerates the DICTIONARY'S OWN .NET MEMBERS - Count,
    Keys, Values, SyncRoot, IsReadOnly, IsFixedSize, IsSynchronized - and never its entries. Both
    presence tests therefore answer $null on a dictionary-shaped result, and NotAsserted falls back
    to its absent-means-false default.

    The live case is the DEFAULT invocation. -DirectoryServiceAccount is optional; without it the
    Deleted Objects permission check reads the DACL in full, reports who holds access, and returns
    'N/A' with NotAsserted = $true because there was no account to assert against. That is the most
    ordinary run this tool has.

    Measured on the shipped functions, one HEALTHY cross-forest domain whose every other check passes,
    with NotAsserted = $true and nothing differing but the result's shape:

        result shape          verdict     unread   findings on Deleted Objects
        PSCustomObject        READY       0        0
        Hashtable             NOT READY   1        1
        OrderedDictionary     NOT READY   1        1
        Generic.Dictionary    NOT READY   1        1

    The isolated mechanism, on the same records:

        PSCustomObject       NotAsserted? True    direct .NotAsserted = True
        Hashtable            NotAsserted? False   direct .NotAsserted = True
        OrderedDictionary    NotAsserted? False   direct .NotAsserted = True
        Generic.Dictionary   NotAsserted? False   direct .NotAsserted = True

    - the direct read works on every shape; only the PRESENCE test, which is the guard, does not.

    This fails in the FALSE RED direction, which is the safer half - but it is a REGRESSION, on one
    row shape, of a defect this file already carries a named fix for, and a false NOT READY on a
    healthy forest is what sends an operator to change a directory ACL that is fine. The string form
    'True', which the object column accepts, was refused on a dictionary for the same reason.

    THE FIX. Both readers normalise through ConvertTo-mdiRecordObject before testing for presence,
    which is the normaliser this script already applies to the port records, the server rows and the
    forest discovery record for the identical reason.

    Pinned here:

    1. NotAsserted = $true is honoured on every IDictionary shape, by the verdict.
    2. The score charges no unread check for it, on every shape.
    3. The findings table raises no Deleted Objects finding for it, on every shape.
    4. The string form 'True' is honoured on every shape, as it already was on an object.
    5. An UNREADABLE NotAsserted - $null, '', 'Unknown', 0, 1, 'no' - is still NOT honoured, on every
       shape: a value nobody could read must not silence a check. This is the direction that would
       become a false green, so it is pinned hardest.
    6. ABSENCE of NotAsserted still means false, so every report written before the property existed
       behaves exactly as it did.
    7. The Measured fallback reads a dictionary-shaped result's own Measured entry.
    8. Object-shaped results are unchanged.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Test-mdiDomainCheckNotAsserted') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

$shapes = @('PSCustomObject', 'Hashtable', 'OrderedDictionary', 'Generic.Dictionary')

function New-Result {
    param([string] $Shape, [object] $NotAsserted, [switch] $UseGiven, [switch] $OmitNotAsserted)
    $f = [ordered]@{ isDeletedObjectsPermissionOk = 'N/A' }
    if (-not $OmitNotAsserted) { $f['NotAsserted'] = $(if ($UseGiven) { $NotAsserted } else { $true }) }
    $f['Measured'] = $true
    $f['Trustees'] = @('FABCORP\Domain Admins')
    switch ($Shape) {
        'PSCustomObject' { return [PSCustomObject] $f }
        'Hashtable' { $h = @{}; foreach ($k in $f.Keys) { $h[$k] = $f[$k] }; return $h }
        'OrderedDictionary' { return $f }
        'Generic.Dictionary' {
            $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'
            foreach ($k in $f.Keys) { $d[[string] $k] = $f[$k] }
            return $d
        }
    }
    throw "unknown shape $Shape"
}

# A HEALTHY cross-forest domain. Every server check and every other domain check passes, so the only
# thing that can move the verdict is the Deleted Objects result.
function New-Estate {
    param($DeletedObjects)
    [PSCustomObject]@{
        Domain              = 'fabrikam.local'
        Domains             = @('fabrikam.local')
        DomainsInScope      = @('fabrikam.local')
        DomainAuditing      = @(
            [PSCustomObject]@{
                Domain           = 'fabrikam.local'
                ObjectAuditing   = [PSCustomObject]@{ isObjectAuditingOk = $true; Measured = $true }
                ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true; Measured = $true }
                AdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = $true; Measured = $true }
                DeletedObjects   = $DeletedObjects
            }
        )
        DomainControllers   = @(
            [PSCustomObject]@{ FQDN = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; isAdvancedAuditingOk = $true; isPowerSchemeOk = $true }
        )
        CAServers           = @()
        EntraConnectServers = @()
    }
}

function Measure-Estate {
    param($Result)
    $data = New-Estate -DeletedObjects $Result
    $stats = Get-mdiReportStatistics -ReportData $data
    $list = @(Get-mdiIssueList -Statistics $stats -ReportData $data)
    $del = @($list | Where-Object {
            (@($_.PSObject.Properties | ForEach-Object { [string] $_.Value }) -join ' ') -match 'Deleted Objects'
        })
    [PSCustomObject]@{
        Ready       = [bool] (Test-mdiReadinessResult -ReportData $data)
        Unread      = [int] $stats.ChecksUnread
        DelFindings = $del.Count
    }
}

''
'--- 1/2/3  NotAsserted = $true, the DEFAULT run with no -DirectoryServiceAccount ---'
foreach ($shape in $shapes) {
    $m = Measure-Estate (New-Result -Shape $shape)
    Assert-That "$shape : a question nobody asked leaves the verdict READY" ($m.Ready) 'false NOT READY on a healthy forest'
    Assert-That "$shape : a question nobody asked is charged no unread check" ($m.Unread -eq 0) "got $($m.Unread)"
    Assert-That "$shape : a question nobody asked raises no Deleted Objects finding" ($m.DelFindings -eq 0) "got $($m.DelFindings)"
}

''
'--- 4  the string form a JSON round trip produces ---'
foreach ($shape in $shapes) {
    $m = Measure-Estate (New-Result -Shape $shape -NotAsserted 'True' -UseGiven)
    Assert-That "$shape : NotAsserted = 'True' is honoured" ($m.Ready) 'the string form was refused'
    Assert-That "$shape : NotAsserted = 'True' is charged no unread check" ($m.Unread -eq 0) "got $($m.Unread)"
}

''
'--- 5  a NotAsserted nobody could read must NOT silence the check ---'
foreach ($shape in $shapes) {
    foreach ($v in @(
            @{ L = '$null'; V = $null }, @{ L = "''"; V = '' }, @{ L = "'Unknown'"; V = 'Unknown' },
            @{ L = '0'; V = 0 }, @{ L = '1'; V = 1 }, @{ L = "'no'"; V = 'no' }
        )) {
        $m = Measure-Estate (New-Result -Shape $shape -NotAsserted $v.V -UseGiven)
        Assert-That "$shape : NotAsserted = $($v.L) does not silence the check" (-not $m.Ready) 'an unreadable value silenced a check'
        Assert-That "$shape : NotAsserted = $($v.L) is still charged one unread" ($m.Unread -eq 1) "got $($m.Unread)"
    }
}

''
'--- 6  absence still means false ---'
foreach ($shape in $shapes) {
    $m = Measure-Estate (New-Result -Shape $shape -OmitNotAsserted)
    Assert-That "$shape : a result with no NotAsserted property is still a gap" (-not $m.Ready)
    Assert-That "$shape : a result with no NotAsserted property is charged one unread" ($m.Unread -eq 1) "got $($m.Unread)"
}

''
'--- 7  the Measured fallback reads a dictionary result''s own entry ---'
foreach ($shape in $shapes) {
    $r = New-Result -Shape $shape -NotAsserted $null -UseGiven
    $domain = [PSCustomObject]@{ Domain = 'fabrikam.local'; DeletedObjects = $r }
    $def = @(Get-mdiDomainCheckDefinition -Domain $domain |
            Where-Object { $_.Name -eq 'Deleted Objects container permission' })
    Assert-That "$shape : the Measured fallback resolves from the result object" `
    (@($def).Count -eq 1 -and $def[0].Measured -eq $true) "got [$(@($def)[0].Measured)]"
}

''
'--- the predicate itself, in isolation ---'
foreach ($shape in $shapes) {
    Assert-That "$shape : Test-mdiDomainCheckNotAsserted reads the entry" `
    ([bool] (Test-mdiDomainCheckNotAsserted -Result (New-Result -Shape $shape)))
}
Assert-That 'the predicate tolerates a null result' `
(-not (Test-mdiDomainCheckNotAsserted -Result $null))

''
"RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
