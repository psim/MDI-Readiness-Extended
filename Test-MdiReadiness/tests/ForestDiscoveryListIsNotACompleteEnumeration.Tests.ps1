# [w124] A ForestDiscovery record that is NOT A SINGLE RECORD - a LIST of records, one per forest,
# or a value that is not a record at all - must not be certified as a COMPLETE forest enumeration.
#
# Test-mdiForestEnumerationIncomplete is THE definition of "did forest discovery finish", and all
# three surfaces that could refuse a run are gated on it:
#
#     Get-mdiReportStatistics   charges the domain-level unread check
#     Get-mdiIssueList          raises the Discovery finding (it calls the predicate at 16475
#                               BEFORE it reads anything out of the record)
#     Test-mdiReadinessResult   decides the VERDICT
#
# so when the predicate goes silent, all three go silent together. Its sibling test
# IncompleteForestIsRefusedWhateverTheRecordShape pins the DICTIONARY shapes. This one pins the
# shapes that are not a single record at all, which that test does not reach.
#
# THE DEFECT. The predicate decided with two early returns, both answering $false, and $false means
# COMPLETE:
#
#     $discovery = Get-mdiForestDiscoveryRecord -ReportData $ReportData
#     if ($null -eq $discovery) { return $false }
#     if ($null -eq $discovery.PSObject.Properties['Complete']) { return $false }
#
# The second was written for ABSENCE - "a report written before the property existed carries no
# Complete at all, and charging it would invent a gap on every historical baseline" - and it also
# caught every value that has no properties BECAUSE IT IS NOT A RECORD.
#
# MEASURED on the shipped function, one healthy two-domain cross-forest estate whose every check
# passes, the discovery record carrying Complete = $false and its own Error naming the failure, with
# nothing differing but the SHAPE of ForestDiscovery:
#
#     ForestDiscovery shape                incomplete?   verdict     forest findings
#     PSCustomObject                       True          NOT READY   1            (control)
#     LIST of 1 record                     True          NOT READY   1
#     LIST of 2 records, one incomplete    FALSE         READY       0            <<<
#     bare string 'failed'                 FALSE         READY       0            <<<
#     bare string ''                       FALSE         READY       0            <<<
#     bare int 0                           FALSE         READY       0            <<<
#     bare $false                          FALSE         READY       0            <<<
#     empty array                          FALSE         READY       0            <<<
#
# The ONE-element list is caught and the TWO-element list is not, and that asymmetry is the whole
# tell: PowerShell unwraps a one-element collection on the way into ConvertTo-mdiRecordObject, so it
# arrives as the record it contains, while a two-element collection stays an Object[], carries no
# 'Complete' property, and takes the ABSENCE return. The guard therefore worked for exactly the
# estate that does not need it and went silent on the one that does.
#
# WHY THE MULTI-FOREST ESTATE IS WHERE THIS ARRIVES, and it arrives by the record's own design: Main
# builds ONE ForestDiscovery record (21222-21226) even under -MultiForest, because -MultiForest only
# promotes LDAPS 636 and LDAPS-GC 3269 and does not widen the scope. So a caller assembling a report
# that really covers a cross-forest estate - or another tool merging two runs, or a hand-edited or
# -AsJson round-tripped report - writes one record PER FOREST, which is a list. The predicate's own
# header names that arrival vector: a cross-forest report "is the one most likely to be
# round-tripped through -AsJson, handed between tools or hand-edited, which is the arrival vector
# ConvertTo-mdiRecordObject exists for". A run that could not enumerate fabrikam.local, and says so
# in that record's own Error field, was certified as having enumerated it.
#
# WHAT MUST NOT CHANGE, and is asserted here as strictly as the defect itself:
#   - ABSENCE stays COMPLETE. A report written before the property existed must not gain an invented
#     gap, and neither must a null-valued field.
#   - A record carrying no Complete stays COMPLETE, for the same reason.
#   - A healthy single record with Complete = $true stays READY with no finding.
# Those three are the controls. Without them a fix that simply charged everything would pass.
#
# Run under Windows PowerShell 5.1.

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

$discoveryError = 'the cross-forest read was denied, so fabrikam.local was never enumerated'

# A HEALTHY cross-forest estate. Every check on both servers passes, so the only thing that can make
# this run anything other than READY is the forest enumeration itself.
function New-Estate {
    param([object] $ForestDiscovery, [switch] $NoDiscovery)
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

function New-Record {
    param([string] $Name, [object] $Complete, [switch] $OmitComplete)
    $f = [ordered]@{ Name = $Name; Domains = @($Name); Method = 'None' }
    if (-not $OmitComplete) { $f['Complete'] = $Complete }
    $f['Error'] = $discoveryError
    [PSCustomObject] $f
}

# All three surfaces read through ONE call, exactly as the sibling test does, so a fix that repairs
# the predicate but leaves a surface behind cannot pass.
function Measure-Surfaces {
    param($Data)
    $stats = Get-mdiReportStatistics -ReportData $Data
    $list = @(Get-mdiIssueList -Statistics $stats -ReportData $Data)
    $forest = @($list | Where-Object {
            (@($_.PSObject.Properties | ForEach-Object { [string] $_.Value }) -join ' ') -match 'forest'
        })
    [PSCustomObject]@{
        Incomplete   = [bool] (Test-mdiForestEnumerationIncomplete -ReportData $Data)
        Ready        = [bool] (Test-mdiReadinessResult -ReportData $Data)
        Unread       = [int] $stats.ChecksUnread
        ForestIssues = $forest.Count
    }
}

''
'--- CONTROLS: what must NOT change ---'

$m = Measure-Surfaces (New-Estate -NoDiscovery)
Assert-That 'ABSENT ForestDiscovery is still a COMPLETE enumeration' (-not $m.Incomplete) ("got Incomplete=$($m.Incomplete)")
Assert-That 'ABSENT ForestDiscovery still raises no forest finding' ($m.ForestIssues -eq 0) ("got $($m.ForestIssues)")

$m = Measure-Surfaces (New-Estate -ForestDiscovery $null)
Assert-That 'NULL ForestDiscovery is still a COMPLETE enumeration' (-not $m.Incomplete) ("got Incomplete=$($m.Incomplete)")

$m = Measure-Surfaces (New-Estate -ForestDiscovery (New-Record -Name 'mdilab.local' -OmitComplete))
Assert-That 'a record carrying NO Complete is still complete (historical baseline)' (-not $m.Incomplete) ("got Incomplete=$($m.Incomplete)")

$m = Measure-Surfaces (New-Estate -ForestDiscovery (New-Record -Name 'mdilab.local' -Complete $true))
Assert-That 'a healthy record Complete=$true is still complete' (-not $m.Incomplete) ("got Incomplete=$($m.Incomplete)")
Assert-That 'a healthy record Complete=$true is still READY' ($m.Ready) ("got Ready=$($m.Ready)")
Assert-That 'a healthy record Complete=$true still raises no forest finding' ($m.ForestIssues -eq 0) ("got $($m.ForestIssues)")

$m = Measure-Surfaces (New-Estate -ForestDiscovery (New-Record -Name 'mdilab.local' -Complete $false))
Assert-That 'the CONTROL: a single incomplete record is charged' ($m.Incomplete) ("got Incomplete=$($m.Incomplete)")
Assert-That 'the CONTROL: a single incomplete record is NOT READY' (-not $m.Ready) ("got Ready=$($m.Ready)")
Assert-That 'the CONTROL: a single incomplete record raises a forest finding' ($m.ForestIssues -ge 1) ("got $($m.ForestIssues)")

''
'--- THE DEFECT: a ForestDiscovery that is not a single record ---'

# One record per forest, which is what a real cross-forest report carries: mdilab.local enumerated,
# fabrikam.local NOT. The list of ONE is asserted beside it because it was the shape that already
# worked, and the asymmetry between them is what the defect was.
$oneEntry = @((New-Record -Name 'fabrikam.local' -Complete $false))
$m = Measure-Surfaces (New-Estate -ForestDiscovery $oneEntry)
Assert-That 'a LIST of 1 incomplete record is charged' ($m.Incomplete) ("got Incomplete=$($m.Incomplete)")

$twoEntries = @((New-Record -Name 'mdilab.local' -Complete $true), (New-Record -Name 'fabrikam.local' -Complete $false))
$m = Measure-Surfaces (New-Estate -ForestDiscovery $twoEntries)
Assert-That 'a LIST of 2 records with one incomplete is CHARGED' ($m.Incomplete) ("got Incomplete=$($m.Incomplete)")
Assert-That 'a LIST of 2 records with one incomplete is NOT READY' (-not $m.Ready) ("got Ready=$($m.Ready)")
Assert-That 'a LIST of 2 records with one incomplete raises a forest finding' ($m.ForestIssues -ge 1) ("got $($m.ForestIssues)")
Assert-That 'a LIST of 2 records with one incomplete charges an unread check' ($m.Unread -ge 1) ("got Unread=$($m.Unread)")

# and the same list where BOTH forests really did enumerate must stay ready, or the fix would simply
# be charging every collection.
$bothGood = @((New-Record -Name 'mdilab.local' -Complete $true), (New-Record -Name 'fabrikam.local' -Complete $true))
$m = Measure-Surfaces (New-Estate -ForestDiscovery $bothGood)
Assert-That 'a LIST of 2 COMPLETE records is still complete' (-not $m.Incomplete) ("got Incomplete=$($m.Incomplete)")
Assert-That 'a LIST of 2 COMPLETE records is still READY' ($m.Ready) ("got Ready=$($m.Ready)")

# A present but EMPTY collection: the field exists and nothing in it said the enumeration finished.
$m = Measure-Surfaces (New-Estate -ForestDiscovery @())
Assert-That 'an EMPTY ForestDiscovery collection is charged' ($m.Incomplete) ("got Incomplete=$($m.Incomplete)")

''
'--- NOT PINNED HERE: a ForestDiscovery that is not a record at all ---'
#
# AN EARLIER DRAFT OF THIS TEST ASSERTED THAT A BARE SCALAR - 'failed', '', 0, 1, $false, $true,
# 'Unknown' - IS AN INCOMPLETE ENUMERATION. THAT ASSERTION IS REMOVED, AND DELIBERATELY.
#
# ForestDiscoveryIsReadWhateverTheReportShape.Tests.ps1 pins the OPPOSITE, on all three report
# shapes, and states its reason: "ABSENCE IS NOT INCOMPLETENESS. A report written before the
# property existed carries no Complete at all, and charging it would invent a gap on every
# historical baseline." Measured on frozen copies with the product script as the only variable:
#
#     HEAD                          PASS=101 FAIL=0
#     the draft that charged bares  PASS=77  FAIL=24   (8 unreadable values x 3 report shapes)
#
# Both cannot be green. Which answer is right for an unreadable ForestDiscovery is a real question -
# it is the same family as every defect in this project - but it is a JUDGEMENT CALL FOR PIETRO, not
# a defect, and it is not the defect this file exists for. This file pins the collection defect: a
# report carrying ONE RECORD PER FOREST, which is what a cross-forest estate produces, was certified
# complete when an entry said it had not finished. That fix stands on its own and changes nothing
# about the bare-scalar answer.
#
# Recorded for Pietro in MDI-Work\hunt-state.md, 21 Aug 06:46 cycle.

''
"RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
