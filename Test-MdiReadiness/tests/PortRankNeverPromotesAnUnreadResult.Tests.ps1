<#
    The port-merge ranking must never treat an UNREAD result as evidence.

    Get-mdiPortRecordRank decides which of two roles' copies of the same probe survives a merge, and
    Get-mdiEffectivePortCheckValue turns the merged result into the value every consumer reads - the
    per-server score, the per-check pass rates and the issue list. Between them they decide whether a
    server's ports are reported as in order.

    Neither had a test naming it. That is worth closing even though both were measured CORRECT when
    this was written, because of WHERE the correctness lives.

    The ranking looks as though it depends on a coercion:

        if ($Record.Success -eq $false) { return 3 }   # measured failure, the strongest evidence
        if ($Record.Success -eq $true)  { return 2 }   # measured success

    PowerShell's -eq coerces the left operand when the right is a boolean, so these read as "is
    Success falsy / truthy" rather than "is Success the boolean". That looked like the risk. It is
    not: measured, '' -eq $false is False and 'N/A' -eq $false is False, so no unreadable form
    satisfies either line. Hoisting the Success test above the guards above it changes nothing, and a
    mutation that does exactly that leaves this file fully green - which is worth recording, because
    the obvious-looking danger here is a red herring.

    What actually protects the answer is the FINAL fallthrough. An unread record satisfies none of
    the branches and falls past all of them to a bare `1`. Every unreadable form - $null, '', 'N/A',
    whitespace, a record with no Success property at all - reaches the answer that way. Changing that
    one character to a 2 promotes every one of them to "measured success", and the merge would then
    report a required port as measured open on a value nobody read. Mutation-tested: that single
    change turns ten assertions here red.

    The string forms are pinned deliberately too: a report read back from -AsJson carries Success as
    the strings 'True' and 'False', so those MUST keep ranking as real measurements.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-Rec {
    param($Success, $Applicable = $true, $Detail = 'Connected', $Id = 'NnrRpc')
    [PSCustomObject]@{ Id = $Id; Name = 'NNR RPC'; Group = 'NNR'; Protocol = 'TCP'; Port = 135
        Target = 'dc1.contoso.com'; TargetIP = '10.0.0.1'; Requirement = 'Required'
        Success = $Success; Applicable = $Applicable; Detail = $Detail }
}
function New-Blob {
    param($Records) [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @($Records) }
}

Write-Host "`n[1] A real measurement ranks as evidence" -ForegroundColor Yellow
$blocked = Get-mdiPortRecordRank -Record (New-Rec $false)
$open = Get-mdiPortRecordRank -Record (New-Rec $true)
Assert-That 'a measured failure carries the strongest evidence' ($blocked -eq 3) "(got $blocked)"
Assert-That 'a measured success ranks below it' ($open -eq 2) "(got $open)"
Assert-That '  ...so a blocked port survives a merge against an open one' ($blocked -gt $open)

Write-Host "`n[2] Nothing UNREAD is ever ranked as a measurement" -ForegroundColor Yellow
# This is the assertion that matters. Rank 3 wins the merge and reports a required port as shut;
# rank 2 reports it as open. Either, from a value nobody read, is a verdict the estate never earned.
foreach ($case in @(
        @{ n = 'never read (null)'; v = $null },
        @{ n = 'empty string'; v = '' },
        @{ n = 'the string N/A'; v = 'N/A' },
        @{ n = 'whitespace'; v = '   ' }
    )) {
    $r = Get-mdiPortRecordRank -Record (New-Rec $case.v)
    Assert-That "$($case.n) is not evidence" ($r -lt 2) "(got rank $r - 2 and 3 are measurements)"
    Assert-That "  ...and is reported as never measured" ($r -eq 1) "(got rank $r)"
}
$noProp = [PSCustomObject]@{ Id = 'NnrRpc'; Applicable = $true; Detail = 'Connected' }
$r = Get-mdiPortRecordRank -Record $noProp
Assert-That 'a record with no Success property at all is never measured' ($r -eq 1) "(got rank $r)"
Assert-That 'a missing record ranks below everything' ((Get-mdiPortRecordRank -Record $null) -lt 0)

Write-Host "`n[3] A JSON round-trip keeps its measurements" -ForegroundColor Yellow
# ConvertTo-Json/ConvertFrom-Json carries Success as the strings 'True'/'False'. If these stopped
# ranking as measurements, every check re-read from a saved report would silently become unmeasured.
Assert-That "the string 'False' is still a measured failure" ((Get-mdiPortRecordRank -Record (New-Rec 'False')) -eq 3)
Assert-That "the string 'True' is still a measured success" ((Get-mdiPortRecordRank -Record (New-Rec 'True')) -eq 2)

Write-Host "`n[4] Not-applicable carries no evidence, and is not confused with unread" -ForegroundColor Yellow
$na = Get-mdiPortRecordRank -Record (New-Rec $false -Applicable $false)
Assert-That 'an inapplicable probe ranks lowest of the real records' ($na -eq 0) "(got $na)"
Assert-That '  ...below "never measured", which at least applies' ($na -lt 1)

Write-Host "`n[5] The merge is decided by evidence, not by discovery order" -ForegroundColor Yellow
$realOpen = New-Blob @((New-Rec $true))
$unread = New-Blob @((New-Rec ''))
foreach ($pair in @(
        @{ n = 'real first, unread second'; a = $realOpen; b = $unread },
        @{ n = 'unread first, real second'; a = $unread; b = $realOpen }
    )) {
    $merged = Merge-mdiRequiredPortsDetails -First $pair.a -Second $pair.b
    $w = @($merged.Results | Where-Object { $_.Id -eq 'NnrRpc' })[0]
    Assert-That "$($pair.n): the measurement survives" ("$($w.Success)" -eq 'True') "(surviving Success = '$($w.Success)')"
}
$realBlocked = New-Blob @((New-Rec -Success $false -Detail 'Blocked - no response'))
$merged = Merge-mdiRequiredPortsDetails -First $realOpen -Second $realBlocked
$w = @($merged.Results | Where-Object { $_.Id -eq 'NnrRpc' })[0]
Assert-That 'a blocked measurement beats an open one' ("$($w.Success)" -eq 'False') "(got '$($w.Success)')"

Write-Host "`n[6] Get-mdiEffectivePortCheckValue reports unread as unread" -ForegroundColor Yellow
# The tri-state has to reach the consumers intact: $false for measured-blocked, 'N/A' for never
# measured, $null when the measurement adds nothing. Collapsing 'N/A' to $false would invent a
# failure; collapsing it to $true would be a false green.
function New-Server {
    param($Records)
    [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false
        Addresses = @('10.0.0.1'); IP = '10.0.0.1'
        Details = [ordered]@{ RequiredPortsDetails = (New-Blob $Records) } }
}
$vBlocked = Get-mdiEffectivePortCheckValue -Server (New-Server @((New-Rec -Success $false -Detail 'Blocked')))
Assert-That 'a measured blocked port yields $false' ($vBlocked -eq $false) "(got '$vBlocked')"
$vUnread = Get-mdiEffectivePortCheckValue -Server (New-Server @((New-Rec $null)))
Assert-That 'an unmeasured probe yields N/A, not a failure' ("$vUnread" -eq 'N/A') "(got '$vUnread')"
Assert-That '  ...and N/A is not the boolean false' (-not ($vUnread -is [bool])) "(type $($vUnread.GetType().Name))"
$vOpen = Get-mdiEffectivePortCheckValue -Server (New-Server @((New-Rec $true)))
Assert-That 'an all-open estate adds nothing to override' ($null -eq $vOpen -or $vOpen -eq $true) "(got '$vOpen')"

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
