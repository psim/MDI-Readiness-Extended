<#
    A coverage figure that could not be READ must not be reported as a coverage of ZERO.

    The trend comparison refuses to compare two runs whose coverage differs, and names the reason.
    That reason is copied into a status report, so it has to say what actually happened.

    Get-mdiCoverageCount returns 0 for a null, empty or non-numeric stored value. It has to: the
    alternative is throwing on a corrupt history entry, which took the whole chart down once already.
    But that substitution is invisible downstream, and it has two consequences that combine badly:

      * an unreadable previous denominator compares UNEQUAL to a real current one, so the
        "different number of checks was covered" branch is reached, and
      * both figures are then rendered through Get-mdiWholeNumberText, which prints the substituted
        0 as '0'.

    Measured on the shipped functions before the fix: a baseline whose ChecksTotal is $null, '' or
    the string 'corrupt' produced

        a different number of checks was covered (0 then 8)

    byte-for-byte identical to the line a run that genuinely covered nothing produces.

    The two facts ask the reader to do opposite things. A real 0 says the previous run examined
    nothing and the estate has since been scanned - the trend is fine, the history is just young. An
    unreadable 0 says the baseline file is damaged and should be replaced. Reporting the second as
    the first sends the reader to the estate to explain a change that never happened, and leaves the
    corrupt file in place to do it again next run.
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

# Built to the shape the real comparison reads, so the test cannot pass against a fix that only
# works for a hand-rolled record. The field names matter: the comparison reads CheckNames and
# ServerNames, and a record missing them is declared incomparable on the fingerprint check before
# the coverage branch is ever reached - which is exactly how the first draft of this test passed
# its "does not claim a measured 0" assertions without exercising the fix at all.
function New-Run {
    param($Total, $Passed = 3, $Unread = 0, $Version = '1.1.3', $Stamp = '2026-08-15T10:00:00')
    [PSCustomObject]@{
        ChecksTotal   = $Total
        ChecksPassed  = $Passed
        ChecksUnread  = $Unread
        ScriptVersion = $Version
        Domain        = 'contoso.com'
        Forest        = 'contoso.com'
        ServerNames   = @('dc1.contoso.com')
        CheckNames    = @('RequiredPorts', 'SensorHealth')
        Instant       = $Stamp
    }
}

Write-Host "`n[1] The premise: an unreadable count is substituted with 0 and reaches this branch" -ForegroundColor Yellow
foreach ($bad in @($null, '', 'corrupt')) {
    $shown = if ($null -eq $bad) { '<null>' } elseif ($bad -eq '') { '<empty>' } else { $bad }
    Assert-That "Get-mdiCoverageCount('$shown') substitutes 0" ((Get-mdiCoverageCount -Value $bad) -eq 0)
    Assert-That "  ...so it compares unequal to a real 8, reaching the caption" `
        ((Get-mdiCoverageCount -Value $bad) -ne (Get-mdiCoverageCount -Value 8))
}
Assert-That 'Get-mdiMeasuredInteger can still tell the two apart' `
    (($null -eq (Get-mdiMeasuredInteger $null)) -and ((Get-mdiMeasuredInteger 0) -eq 0))

Write-Host "`n[2] An unreadable previous count is NOT reported as a coverage of zero" -ForegroundColor Yellow
foreach ($bad in @($null, '', 'corrupt')) {
    $shown = if ($null -eq $bad) { '<null>' } elseif ($bad -eq '') { '<empty>' } else { $bad }
    $r = Test-mdiTrendPointsComparable -Previous (New-Run $bad) -Current (New-Run 8)
    Assert-That "previous='$shown' is not comparable" (-not $r.IsComparable)
    Assert-That "  ...and the reason does not claim a measured 0" ($r.Reason -notmatch '\(0 then') "(reason: '$($r.Reason)')"
    Assert-That "  ...and it says the count could not be read" ($r.Reason -match 'could not be read') "(reason: '$($r.Reason)')"
}

Write-Host "`n[3] An unreadable CURRENT count is caught the same way" -ForegroundColor Yellow
$r = Test-mdiTrendPointsComparable -Previous (New-Run 8) -Current (New-Run 'corrupt')
Assert-That 'not comparable' (-not $r.IsComparable)
Assert-That '  ...and the reason does not claim a measured 0' ($r.Reason -notmatch 'then 0\)') "(reason: '$($r.Reason)')"
Assert-That '  ...and it says the count could not be read' ($r.Reason -match 'could not be read') "(reason: '$($r.Reason)')"

Write-Host "`n[4] A run that GENUINELY covered nothing still says so" -ForegroundColor Yellow
# The fix must not silence the real case: 0 is a legitimate measurement and reads differently.
$r = Test-mdiTrendPointsComparable -Previous (New-Run 0 0 0) -Current (New-Run 8)
Assert-That 'a real zero is still not comparable' (-not $r.IsComparable)
Assert-That '  ...and its reason is NOT the unreadable wording' ($r.Reason -notmatch 'could not be read') "(reason: '$($r.Reason)')"

Write-Host "`n[5] Two readable but different counts keep the original wording" -ForegroundColor Yellow
$r = Test-mdiTrendPointsComparable -Previous (New-Run 6) -Current (New-Run 8)
Assert-That 'not comparable' (-not $r.IsComparable)
Assert-That '  ...and both figures are named' ($r.Reason -match '\(6 then 8\)') "(reason: '$($r.Reason)')"

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }

