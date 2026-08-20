# [w111] A Policy Target nobody could read must not be ELECTED as the machine's system audit
# policy, and must not discard the readable target that carried the real one.
#
# Get-mdiAdvancedAuditing parses 'auditpol /backup' output. When the export carries more than one
# distinct Policy Target it picks ONE of them and throws the rest away:
#
#     $candidates = if ($notPerUser.Count -gt 0) { $notPerUser } else { $withGuid }
#     $byTarget   = @($candidates | Group-Object -Property 'Policy Target' |
#                     Sort-Object -Property @{ Expression = { ...distinct GUID count... } ; Descending = $true }, ...)
#     if (@($withGuid | Group-Object -Property 'Policy Target').Count -gt 1 -and $byTarget.Count -gt 0) {
#         $systemTarget = $byTarget[0].Name
#         $rows = @($allRows | Where-Object { [string] $_.'Policy Target' -eq [string] $systemTarget })
#     }
#
# Nothing upstream required that target to be READABLE. $withGuid filters on 'Subcategory GUID' and
# says nothing about the target at all; $notPerUser keeps every row whose target -notmatch '\|@|^S-1-',
# and an EMPTY target, a WHITESPACE target and an ABSENT one (a row with fewer fields than the
# seven-column header, which yields $null) all fail to match those markers. So a target that was
# never written survived every filter, became a candidate, and was ranked by the sort on nothing
# but how many distinct subcategories it happened to carry. The larger block wins - readable or not.
#
# Whichever target wins, the next line REPLACES $rows with only its rows, and every later
# measurement reads that subset alone: the completeness check, the unreadable-setting scan, the
# duplicate collapse and the final Compare-Object. The function's own comment states the stakes -
# a wrong verdict here "writes auditpol.exe /set against a production domain controller whose
# current policy is unknown ... the single most expensive wrong answer this check can give".
#
# MEASURED on the shipped function, using the SHIPPED AdvancedAuditPolicyDCs expectation. An export
# in which a readable 'System' target audits all eight required subcategories CORRECTLY (value 3),
# plus a second block carrying the same subcategories WRONGLY (value 0) and two extra ones so that
# it holds more distinct GUIDs:
#
#   second block's target                  isAdvancedAuditingOk   elected
#   -----------------------------------    --------------------   -----------------------------
#   (block absent - control)               True                   n/a, one target only
#   '' empty                               False                  "reading the system policy ()"
#   '   ' whitespace                       False                  "reading the system policy ()"
#   a tab                                  False                  "reading the system policy ()"
#
# A row TRUNCATED so that 'Policy Target' comes back $null is asserted below for completeness but
# does NOT by itself reproduce the defect: truncation also costs the row its 'Subcategory GUID', so
# $withGuid discards it before the election is ever reached. It is pinned because it is the shape an
# operator would expect to be dangerous, not because it was measured as dangerous.
#
# The control proves the shapes and parameter names are right: the SAME export minus the second
# block reads as a correct policy. So the only thing that changed the verdict was a Policy Target
# that was never read - the family every defect in this project has belonged to, a value nobody
# measured coming back looking like a measurement, here deciding which rows ARE the system policy.
#
# A multi-target export is exactly where this arises rather than a synthetic curiosity: the function
# itself records that 'Policy Target' is LOCALIZED text and deliberately never compares on it, and a
# cross-forest, trimmed or non-English export can leave it unwritten while the GUID column - the one
# thing the comparison does trust - is perfectly readable.
#
# THE FIX: only a NAMED target may be elected. The restriction is never allowed to filter everything
# away - if NO target is readable there is no better-read target to prefer, the election does not
# engage, and the rows are left exactly as they were, which is the same treatment the function
# already gives an export carrying no Policy Target column at all.
#
# What this file pins:
#   * the control still reads a correct single-target policy as correct (the shapes are right);
#   * an empty, whitespace or absent Policy Target is NEVER the elected system policy;
#   * the readable target that carried the true policy is elected instead, and its verdict matches
#     the control exactly;
#   * a readable competing target is still elected normally, so the fix did not disable the
#     multi-target branch it is narrowing;
#   * an export in which NO target is readable is left readable rather than filtered to nothing.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:said = New-Object System.Collections.Generic.List[string]
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) [void] $script:said.Add([string] $Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
Set-Item -Path function:script:Get-mdiRemoteTempFolder -Value { param($ComputerName) 'C:\Windows\Temp' }

$script:pass = 0; $script:fail = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name" }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" }
}

# The expectation is read from the SHIPPED settings, so this file cannot pass by comparing an
# export against a requirement the product does not actually hold.
$expectedCsv = @($settings.AdvancedAuditPolicyDCs -split "`r?`n" | Where-Object { $_ -ne '' })
$requiredGuids = @(@($expectedCsv | ConvertFrom-Csv).'Subcategory GUID')
Assert-True 'the shipped settings still define an advanced audit policy expectation' ($requiredGuids.Count -ge 2) `
    "count=$($requiredGuids.Count)"

$script:fakeExport = @()
Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
    param($ComputerName, $CommandLine, $LocalFile)
    $script:fakeExport
}

# auditpol /backup writes SEVEN columns and the function re-applies these names by position.
$HEADER = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'

function New-Export {
    <#  A readable 'System' target carrying the CORRECT policy for every required subcategory, plus
        an optional second block carrying the SAME subcategories wrongly and two extra ones, so the
        second block holds more distinct GUIDs and would win the election on count alone.
        -Truncate drops the trailing fields of the second block's rows so 'Policy Target' comes back
        $null - the shape an export produces when the column was never written at all. #>
    param([string] $SecondTarget, [switch] $OnlySystem, [switch] $Truncate, [switch] $NoReadableTarget)
    $lines = New-Object System.Collections.Generic.List[string]
    [void] $lines.Add($HEADER)
    if (-not $NoReadableTarget) {
        foreach ($g in $requiredGuids) {
            [void] $lines.Add(('dcfab01,System,Some Subcategory,{0},Success and Failure,No Auditing,3' -f $g))
        }
    }
    if (-not $OnlySystem) {
        foreach ($g in $requiredGuids) {
            if ($Truncate) { [void] $lines.Add(('dcfab01' -f $g)) }
            else { [void] $lines.Add(('dcfab01,{0},Some Subcategory,{1},No Auditing,No Auditing,0' -f $SecondTarget, $g)) }
        }
        [void] $lines.Add(('dcfab01,{0},Extra One,{{0CCE9999-69AE-11D9-BED3-505054503030}},No Auditing,No Auditing,0' -f $SecondTarget))
        [void] $lines.Add(('dcfab01,{0},Extra Two,{{0CCE9998-69AE-11D9-BED3-505054503030}},No Auditing,No Auditing,0' -f $SecondTarget))
    }
    @($lines)
}

function Measure-Export {
    param([string[]] $Export)
    $script:fakeExport = $Export
    $script:said.Clear()
    $r = Get-mdiAdvancedAuditing -ComputerName 'dcfab01.fabrikam.local' -ExpectedAuditing $expectedCsv
    $elected = @($script:said | Where-Object { $_ -match 'more than one policy target' })
    [PSCustomObject]@{
        Ok       = [string] $r.isAdvancedAuditingOk
        Elected  = $(if ($elected.Count -gt 0) { [string] $elected[0] } else { '' })
        Engaged  = ($elected.Count -gt 0)
    }
}

Write-Host ''
Write-Host 'CONTROL - a single readable target carrying the correct policy'
$control = Measure-Export (New-Export -OnlySystem)
Assert-True 'a correct single-target export still reads as correctly audited' ($control.Ok -eq 'True') `
    "ok=[$($control.Ok)]"
Assert-True 'and the multi-target election does not engage on a single target' (-not $control.Engaged)

Write-Host ''
Write-Host 'AN UNREAD POLICY TARGET MUST NOT BE ELECTED'
# Each of these is a target that was never READ, competing against a readable one that carries the
# true policy. Before the fix each of them won the election and inverted the verdict.
$unread = [ordered]@{
    "empty string"        = (New-Export -SecondTarget '')
    "whitespace"          = (New-Export -SecondTarget '   ')
    "a tab"               = (New-Export -SecondTarget "`t")
    "absent column value" = (New-Export -SecondTarget '' -Truncate)
}
foreach ($label in $unread.Keys) {
    $m = Measure-Export $unread[$label]
    Assert-True "$label is never elected as the system policy" `
        ($m.Elected -notmatch 'system policy \(\s*\)') "said=[$($m.Elected)]"
    Assert-True "$label leaves the verdict matching the control" ($m.Ok -eq $control.Ok) `
        "ok=[$($m.Ok)] control=[$($control.Ok)]"
}

Write-Host ''
Write-Host 'A READABLE COMPETING TARGET IS STILL ELECTED NORMALLY'
# The fix narrows the election, it does not disable it: a genuinely readable second target still
# competes on subcategory count exactly as before.
$readable = Measure-Export (New-Export -SecondTarget 'Systemrichtlinie')
Assert-True 'a readable competing target still engages the multi-target election' ($readable.Engaged)
Assert-True 'and the readable target is the one named' ($readable.Elected -match 'Systemrichtlinie') `
    "said=[$($readable.Elected)]"

Write-Host ''
Write-Host 'AN EXPORT WITH NO READABLE TARGET AT ALL IS NOT FILTERED TO NOTHING'
# There is no better-read target to prefer, so the rows must be left as they were rather than
# reduced to an empty set - the same treatment an export with no Policy Target column receives.
$none = Measure-Export (New-Export -SecondTarget '' -NoReadableTarget)
Assert-True 'no readable target leaves a verdict rather than an empty measurement' `
    ($none.Ok -in @('True', 'False')) "ok=[$($none.Ok)]"
Assert-True 'and nothing unreadable was announced as the system policy' `
    ($none.Elected -notmatch 'system policy \(\s*\)') "said=[$($none.Elected)]"

Write-Host ''
Write-Host ("RESULT  pass=$script:pass  fail=$script:fail")
if ($script:fail -gt 0) { exit 1 }
exit 0
