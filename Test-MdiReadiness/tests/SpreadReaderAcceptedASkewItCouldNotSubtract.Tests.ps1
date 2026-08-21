# THE SPREAD READER ACCEPTED A SKEW THE SPREAD ARITHMETIC COULD NOT SUBTRACT
#
# Get-mdiClockSpread answers the one rule the time synchronization card exists to state: the sensor
# servers must be within five minutes OF EACH OTHER. It is the ONLY estate-wide check in the script -
# every other check is per server - so it runs while the report is being ASSEMBLED, and it has four
# callers: Get-mdiReportStatistics, Get-mdiOverviewHtml, Get-mdiTimeSyncHtml and
# Test-mdiReadinessResult.
#
# It read every server's skew with [long]::TryParse, deliberately, so that a value which is not a
# number cannot be silently turned into 0. Having accepted the value as a readable [long], it then
# computed the spread as:
#
#     $spread = [long] ($highest.SkewSeconds - $lowest.SkewSeconds)
#
# Two Int64 values can be subtracted to a result OUTSIDE the Int64 range. PowerShell widens such a
# subtraction to [double], and the [long] cast of that double throws. So one function accepted a
# value at one line and could not do arithmetic on it four lines later.
#
# Measured on the shipped function, the extended lab's estate - three AD sites, with dcfab01 reached
# across the fabrikam.local cross-forest trust carrying a skew of [int64]::MaxValue:
#
#     the reader ([long]::TryParse) accepts it   ->  True
#     Get-mdiClockSpread                         ->  THREW "Cannot convert value
#                                                    9.22337203685478E+18 to type System.Int64 -
#                                                    arithmetic operation resulted in an overflow"
#     Get-mdiTimeSyncHtml                        ->  THREW (the same exception, escaping)
#
# The second line is the damage: the throw escapes into the report builder, so the cost is the WHOLE
# report rather than one cell. That is precisely what Get-mdiTimeSyncHtml's own comment about this
# same field says must not happen - re-narrowing a skew "would throw while BUILDING the report -
# losing the whole HTML file rather than one cell".
#
# SCOPE, stated no more strongly than it was measured: a LIVE single run cannot reach this.
# Get-mdiTimeSync builds SkewSeconds from a DateTime difference, and the DateTime range caps a live
# skew at 315537897600 seconds - twelve orders of magnitude below the Int64 limit. It is reachable by
# a report READ BACK, merged or edited outside one run: the field survives the JSON round trip by
# design and is re-parsed here with TryParse for exactly that reason. That is the same scope under
# which the -Maximum/-Minimum tolerance defect in this very function was accepted and fixed.
#
# WHAT THIS TEST PINS:
#   1. An extreme but LEGAL skew does not throw, on the function or on the report card built from it.
#   2. It is reported as a measured FAILURE, not as 'N/A'. Returning 'N/A' would be the wrong fix:
#      both clocks WERE read and they disagree by more than any tolerance permits, and
#      Get-mdiReportStatistics charges the estate row only on a definite $false - so answering 'N/A'
#      would delete the worst clock disagreement the tool can find.
#   3. The ORDINARY case is unchanged: a stock estate still reports the same [long] spread, the same
#      verdict, and the same type. Without this a "fix" that widened everything to decimal, or that
#      refused every large value, would pass while changing every report that already worked.
#   4. Unreadable skews are still dropped rather than counted, so the fix did not loosen the reader.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-ClockRow {
    param($Fqdn, $Skew, $Sync = $true, $MaxSkew = 5)
    [PSCustomObject]@{
        FQDN     = $Fqdn
        TimeSync = $Sync
        Details  = [PSCustomObject]@{
            TimeSyncDetails = [PSCustomObject]@{
                SkewSeconds    = $Skew
                MaxSkewMinutes = $MaxSkew
                RemoteUtc      = '2026-08-21 14:00:00'
                Detail         = 'Clock read'
            }
        }
    }
}

# The extended lab: three AD sites, and dcfab01 reached across the fabrikam.local cross-forest trust.
function New-CrossForestEstate {
    param($OutlierSkew)
    @(
        (New-ClockRow 'dc1.mdilab.local'       (-240))
        (New-ClockRow 'dc2.mdilab.local'       (-238))
        (New-ClockRow 'dc3.emea.mdilab.local'  (-236))
        (New-ClockRow 'dcbr01.mdilab.local'    (-235))
        (New-ClockRow 'dcfab01.fabrikam.local' $OutlierSkew)
    )
}

''
'[the defect] a legal but extreme skew must not throw out of the estate-wide check'
foreach ($extreme in @(
        @{ Name = 'Int64 max'; Value = [int64]::MaxValue }
        @{ Name = 'Int64 min'; Value = [int64]::MinValue }
    )) {
    $estate = New-CrossForestEstate -OutlierSkew $extreme.Value
    $threw = $null
    $result = $null
    try { $result = Get-mdiClockSpread -Server $estate } catch { $threw = $_.Exception.Message }
    Assert-That "$($extreme.Name) skew does not throw Get-mdiClockSpread" ($null -eq $threw) "threw: $threw"

    # It is a measured FAILURE, never 'N/A'. Both clocks were read.
    Assert-That "$($extreme.Name) skew is reported as a measured failure, not 'N/A'" `
    ($null -ne $result -and $result.IsWithin -eq $false) "IsWithin=$(if ($result) { $result.IsWithin } else { '<threw>' })"

    # All five clocks were read, so none may be dropped to make the arithmetic work.
    Assert-That "$($extreme.Name) skew still counts all five clocks as measured" `
    ($null -ne $result -and $result.Measured -eq 5) "Measured=$(if ($result) { $result.Measured } else { '<threw>' })"

    # A spread must still be stated. Dropping it to $null would read as "not measured".
    Assert-That "$($extreme.Name) skew still yields a spread value" `
    ($null -ne $result -and $null -ne $result.SpreadSeconds) 'SpreadSeconds was null'
}

''
'[the blast radius] the report card built from it must not be destroyed either'
foreach ($extreme in @(
        @{ Name = 'Int64 max'; Value = [int64]::MaxValue }
        @{ Name = 'Int64 min'; Value = [int64]::MinValue }
    )) {
    $estate = New-CrossForestEstate -OutlierSkew $extreme.Value
    $threw = $null
    $html = $null
    try { $html = Get-mdiTimeSyncHtml -Server $estate } catch { $threw = $_.Exception.Message }
    Assert-That "$($extreme.Name) skew does not throw Get-mdiTimeSyncHtml" ($null -eq $threw) "threw: $threw"
    Assert-That "$($extreme.Name) skew still renders the spread sentence" `
    ($null -ne $html -and $html -match 'MDI requires between sensor servers') 'the summary sentence was absent'
    # The card must say the estate FAILS, not pass it.
    Assert-That "$($extreme.Name) skew renders the FAILING spread sentence" `
    ($null -ne $html -and $html -match 'which is MORE than') 'the failing wording was absent'
}

''
'[unchanged] the ordinary estate must be untouched, in value, verdict AND type'
# Every spread a real run can produce fits in [long]; the fix must not change what those reports say.
$stock = New-CrossForestEstate -OutlierSkew 240
$s = Get-mdiClockSpread -Server $stock
Assert-That 'a stock cross-forest estate still spans 480 seconds' ($s.SpreadSeconds -eq 480) "got $($s.SpreadSeconds)"
Assert-That 'a stock cross-forest estate still FAILS the 5-minute rule' ($s.IsWithin -eq $false) "got $($s.IsWithin)"
Assert-That 'a stock spread is still emitted as [long], not widened' ($s.SpreadSeconds -is [long]) "got $($s.SpreadSeconds.GetType().Name)"
Assert-That 'a stock estate still names the furthest behind' ($s.Earliest -eq 'dc1.mdilab.local') "got $($s.Earliest)"
Assert-That 'a stock estate still names the furthest ahead' ($s.Latest -eq 'dcfab01.fabrikam.local') "got $($s.Latest)"

$tight = @(
    (New-ClockRow 'dc1.mdilab.local' (-2))
    (New-ClockRow 'dc2.mdilab.local' 3)
)
$t = Get-mdiClockSpread -Server $tight
Assert-That 'a tight estate still passes' ($t.IsWithin -eq $true -and $t.SpreadSeconds -eq 5) "spread=$($t.SpreadSeconds) within=$($t.IsWithin)"
Assert-That 'a tight spread is still emitted as [long]' ($t.SpreadSeconds -is [long]) "got $($t.SpreadSeconds.GetType().Name)"

''
'[unchanged] the reader must not have been loosened by the fix'
# If the fix had widened the READER as well as the arithmetic, an unreadable skew would start
# counting as a measurement - the exact failure this whole function is built to refuse.
foreach ($bad in @(
        @{ Name = 'null'; Value = $null }
        @{ Name = 'empty string'; Value = '' }
        @{ Name = 'non-numeric text'; Value = 'abc' }
        @{ Name = 'boolean'; Value = $true }
        @{ Name = 'hashtable'; Value = @{} }
        @{ Name = 'decimal'; Value = 1.5 }
        @{ Name = 'two-element array'; Value = @(240, 300) }
    )) {
    $estate = New-CrossForestEstate -OutlierSkew $bad.Value
    $r = Get-mdiClockSpread -Server $estate
    Assert-That "an unreadable skew ($($bad.Name)) is still dropped, not counted" ($r.Measured -eq 4) "Measured=$($r.Measured)"
    Assert-That "an unreadable skew ($($bad.Name)) does not drag the spread to a measurement" ($r.SpreadSeconds -eq 5) "spread=$($r.SpreadSeconds)"
}

''
"pass=$script:pass  fail=$script:fail"
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
