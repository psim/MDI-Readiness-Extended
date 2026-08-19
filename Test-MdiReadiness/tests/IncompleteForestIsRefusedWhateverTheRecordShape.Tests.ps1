<#
    A report whose ForestDiscovery record is DICTIONARY-SHAPED must still be refused when that record
    says the forest was not fully enumerated.

    THE DEFECT THIS PINS. Three surfaces decide, independently, whether forest discovery finished -
    the score, the findings table and the verdict - and all three asked the question the same way:

        Get-mdiReportStatistics   $null -ne $ReportData.ForestDiscovery.PSObject.Properties['Complete']
        Get-mdiIssueList          the same test, whose own comment says the conditions "mirror
                                  Test-mdiReadinessResult exactly so the two cannot diverge"
        Test-mdiReadinessResult   the same test, and it decides the VERDICT

    PSObject.Properties over an IDictionary enumerates the DICTIONARY'S OWN .NET MEMBERS - Count,
    Keys, Values, SyncRoot, IsReadOnly, IsFixedSize, IsSynchronized - and never its entries. On a
    dictionary-shaped ForestDiscovery the presence test therefore answers $null, all three guards are
    skipped, and the verdict keeps its DEFAULT, which is COMPLETE. A run that could not enumerate the
    forest - and says so in its own Error field - was certified as having enumerated it.

    Measured on the shipped functions, one healthy two-domain cross-forest estate whose every check
    passes, with Complete = $false and nothing differing but the record's shape:

        ForestDiscovery shape   verdict     unread   findings naming the forest
        PSCustomObject          NOT READY   1        1
        Hashtable               READY       0        0
        OrderedDictionary       READY       0        0
        Generic.Dictionary      READY       0        0

    All three surfaces went silent together, so there was no disagreement anywhere to notice: the
    console said READY, the score card said 4/4 with nothing unread, and the issues table was empty.
    The isolated mechanism, on the same records:

        PSCustomObject       PSObject.Properties['Complete'] present = True    .Complete = False
        Hashtable            PSObject.Properties['Complete'] present = False   .Complete = False
        OrderedDictionary    present = False   .Complete = False
        Generic.Dictionary   present = False   .Complete = False

    - the direct read works on every shape; only the PRESENCE test, which is the guard, does not.

    Every unreadable Complete behaved the same way. The object column correctly refuses $null, '',
    'Unknown', 0, 1 and 'no' - "a value that was never read is not a measurement" - and every one of
    them returned READY with no finding once the record was dictionary-shaped.

    This is the exact false green Get-mdiForestDomain names in its own words: "A -Forest run that
    quietly examined one domain out of five and then reported READY is a false green over four
    domains nobody looked at."

    WHY THE SHAPE ARRIVES. A live run builds ForestDiscovery as a PSCustomObject, and ConvertFrom-Json
    in Windows PowerShell 5.1 produces objects, so it never appears on the ordinary path. It arrives
    from another tool's JSON, an -AsJson round trip, a hand-edited report or an older version - which
    is why ConvertTo-mdiRecordObject exists in this script at all. A CROSS-FOREST estate is where that
    stops being hypothetical: -MultiForest is what reaches a second forest, and a multi-forest report
    is the one most likely to be handed between tools.

    THE FIX. One shared predicate, Test-mdiForestEnumerationIncomplete, which normalises the record
    through ConvertTo-mdiRecordObject before testing it, and all three surfaces call it. The issue
    list also reads Error and Domains from the normalised record, or the finding it now raises would
    name no scope and give no reason.

    Pinned here:

    1. Complete = $false is refused on every IDictionary shape, by the VERDICT.
    2. The score charges the same one unread check on every shape.
    3. The findings table raises a finding naming the forest on every shape.
    4. Every UNREADABLE Complete - $null, '', 'Unknown', 0, 1, 'no' - is refused on every shape,
       exactly as it already was on an object.
    5. Complete = $true is still accepted on every shape, so the fix cannot have turned the guard
       into an unconditional refusal.
    6. ABSENCE of Complete is still not incompleteness, so a report written before the property
       existed is not charged a gap it cannot have.
    7. A ReportData with no ForestDiscovery at all is unaffected.
    8. The finding raised on a dictionary-shaped record still carries the record's own Error text,
       rather than the "did not report whether it completed" fallback.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Test-mdiReadinessResult') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

# A HEALTHY cross-forest estate. Every check on both servers passes, so the only thing that can make
# this run anything other than READY is the incomplete forest enumeration itself. Anything else
# failing would mask the guard rather than test it.
function New-Estate {
    param($ForestDiscovery, [switch] $NoDiscovery)
    $o = [ordered]@{
        Domain              = 'mdilab.local'
        Domains             = @('mdilab.local', 'fabrikam.local')
        DomainsInScope      = @('mdilab.local', 'fabrikam.local')
        DomainControllers   = @(
            [PSCustomObject]@{ FQDN = 'dc01.mdilab.local'; Domain = 'mdilab.local'; isAdvancedAuditingOk = $true; isPowerSchemeOk = $true }
            [PSCustomObject]@{ FQDN = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; isAdvancedAuditingOk = $true; isPowerSchemeOk = $true }
        )
        CAServers           = @()
        EntraConnectServers = @()
    }
    if (-not $NoDiscovery) { $o['ForestDiscovery'] = $ForestDiscovery }
    [PSCustomObject] $o
}

$discoveryError = 'the query succeeded but returned no domains'

function New-Discovery {
    param([string] $Shape, [object] $CompleteValue, [switch] $UseGiven, [switch] $OmitComplete)
    $f = [ordered]@{
        Name    = 'mdilab.local'
        Domains = @('mdilab.local')
        Method  = 'None'
    }
    if (-not $OmitComplete) { $f['Complete'] = $(if ($UseGiven) { $CompleteValue } else { $false }) }
    $f['Error'] = $discoveryError
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

function Measure-Estate {
    param($Data)
    $stats = Get-mdiReportStatistics -ReportData $Data
    $list = @(Get-mdiIssueList -Statistics $stats -ReportData $Data)
    $forest = @($list | Where-Object {
            (@($_.PSObject.Properties | ForEach-Object { [string] $_.Value }) -join ' ') -match 'forest'
        })
    [PSCustomObject]@{
        Ready        = [bool] (Test-mdiReadinessResult -ReportData $Data)
        Unread       = [int] $stats.ChecksUnread
        ForestIssues = $forest.Count
        ForestText   = (@($forest | ForEach-Object { @($_.PSObject.Properties | ForEach-Object { [string] $_.Value }) -join ' ' }) -join ' | ')
    }
}

$shapes = @('PSCustomObject', 'Hashtable', 'OrderedDictionary', 'Generic.Dictionary')

''
'--- 1/2/3/8  Complete = $false, an enumeration the walker says did not finish ---'
foreach ($shape in $shapes) {
    $m = Measure-Estate (New-Estate -ForestDiscovery (New-Discovery -Shape $shape))
    Assert-That "$shape : the verdict refuses an incomplete forest enumeration" (-not $m.Ready)
    Assert-That "$shape : the score charges one unread check for the unmeasured scope" ($m.Unread -eq 1) "got $($m.Unread)"
    Assert-That "$shape : the findings table raises a finding naming the forest" ($m.ForestIssues -ge 1) "got $($m.ForestIssues)"
    Assert-That "$shape : the finding carries the record's own reason" `
    ($m.ForestText -like "*$discoveryError*") "got [$($m.ForestText)]"
}

''
'--- 4  a Complete that was never read is not a statement that discovery finished ---'
foreach ($shape in $shapes) {
    foreach ($v in @(
            @{ L = '$null'; V = $null }, @{ L = "''"; V = '' }, @{ L = "'Unknown'"; V = 'Unknown' },
            @{ L = '0'; V = 0 }, @{ L = '1'; V = 1 }, @{ L = "'no'"; V = 'no' }
        )) {
        $m = Measure-Estate (New-Estate -ForestDiscovery (New-Discovery -Shape $shape -CompleteValue $v.V -UseGiven))
        Assert-That "$shape : Complete = $($v.L) is refused" (-not $m.Ready)
        Assert-That "$shape : Complete = $($v.L) is charged one unread" ($m.Unread -eq 1) "got $($m.Unread)"
    }
}

''
'--- 5  a real completion is still accepted, on every shape ---'
foreach ($shape in $shapes) {
    $m = Measure-Estate (New-Estate -ForestDiscovery (New-Discovery -Shape $shape -CompleteValue $true -UseGiven))
    Assert-That "$shape : Complete = `$true is still READY" ($m.Ready) 'the guard became unconditional'
    Assert-That "$shape : Complete = `$true charges no unread" ($m.Unread -eq 0) "got $($m.Unread)"
    Assert-That "$shape : Complete = `$true raises no forest finding" ($m.ForestIssues -eq 0) "got $($m.ForestIssues)"
    # The string 'True' is what a JSON round trip through some producers yields.
    $s = Measure-Estate (New-Estate -ForestDiscovery (New-Discovery -Shape $shape -CompleteValue 'True' -UseGiven))
    Assert-That "$shape : Complete = 'True' is still READY" ($s.Ready)
}

''
'--- 6/7  absence is not incompleteness ---'
foreach ($shape in $shapes) {
    $m = Measure-Estate (New-Estate -ForestDiscovery (New-Discovery -Shape $shape -OmitComplete))
    Assert-That "$shape : a record with no Complete property is not charged a gap" ($m.Ready) 'absence was treated as incomplete'
    Assert-That "$shape : a record with no Complete property charges no unread" ($m.Unread -eq 0) "got $($m.Unread)"
}
$noDiscovery = Measure-Estate (New-Estate -NoDiscovery)
Assert-That 'a report with no ForestDiscovery at all is unaffected' ($noDiscovery.Ready)
Assert-That 'a report with no ForestDiscovery at all charges no unread' ($noDiscovery.Unread -eq 0) "got $($noDiscovery.Unread)"

''
'--- the shared predicate itself, which is what the three surfaces now agree through ---'
foreach ($shape in $shapes) {
    $data = New-Estate -ForestDiscovery (New-Discovery -Shape $shape)
    Assert-That "$shape : Test-mdiForestEnumerationIncomplete answers true" `
    ([bool] (Test-mdiForestEnumerationIncomplete -ReportData $data))
}
Assert-That 'the predicate tolerates a null report' `
(-not (Test-mdiForestEnumerationIncomplete -ReportData $null))

''
"RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
