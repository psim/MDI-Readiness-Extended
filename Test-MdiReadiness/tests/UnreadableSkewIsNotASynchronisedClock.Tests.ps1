<#
    A SKEW THAT WAS NEVER READ IS NOT A PERFECTLY SYNCHRONISED CLOCK, AND MUST NOT COST THE TABLE.

    Get-mdiTimeSyncHtml rendered the skew cell with a BARE $null guard followed by a HARD cast:

        $skew = if ($null -ne $sync.SkewSeconds) { [string] ([long] $sync.SkewSeconds) + ' s' } else { 'n/a' }

    Every shape that is not $null passed that guard and reached [long]. Measured on the shipped
    function, one otherwise complete server, SkewSeconds replaced one shape at a time:

        $null        'n/a'                    correct
        0            '0 s'                    correct
        42           '42 s'                   correct
        5000000000   '5000000000 s'           correct - the Int64 headroom works as designed
        '180'        '180 s'                  correct
        ''           '0 s'   <- A PERFECTLY SYNCHRONISED CLOCK, FOR A SERVER NOBODY TIMED
        $true        '1 s'   <- the same illusion, from a flag
        '   '        THREW  Cannot convert value "   " to type "System.Int64"
        'n/a'        THREW  Cannot convert value "n/a" to type "System.Int64"
        'unknown'    THREW  Cannot convert value "unknown" to type "System.Int64"
        @{}          THREW  Cannot convert the "System.Collections.Hashtable" value ... to "System.Int64"
        1e30 as text THREW  Value was either too large or too small for an Int64

    and with three good clocks beside one unreadable fourth, every throwing shape destroyed the
    ENTIRE time synchronization table - three servers whose clocks were read perfectly well lost
    their rows because a fourth carried a field nobody could read.

    '0 s' is the more dangerous of the two failures. The skew cell carries the same colour class as
    the verdict cell beside it, so an unread clock rendered as the tightest possible synchronisation
    on a row that can be painted green.

    WHAT MAKES THIS CLEAR-CUT: the comment directly above the line shows the author guarding this
    exact class of failure in ONE direction only -

        # [long] for the same reason Get-mdiTimeSync produces one: a skew of more than 68 years does
        # not fit in an Int32, and re-narrowing it here would throw while BUILDING the report - losing
        # the whole HTML file rather than one cell.

    The overflow direction was deliberate; the non-numeric direction was not considered. And the
    remedy was already in the file twice: the sync VERDICT on the line immediately above is
    normalised through ConvertTo-mdiBoolean, whose own comment says '' and 'Unknown' and 'N/A' are
    not measurements - and ConvertTo-mdiMeasuredNumber, the numeric twin, already answers every
    failing shape above with $null while still parsing 42, '180' and 5000000000.

    ClockBeyondIntRange.Tests.ps1 pins the OVERFLOW direction in the producer, Get-mdiTimeSync. It
    does not reach the renderer, which is why this survived.

    These assertions drive the REAL renderer and read the cells back out of the emitted HTML.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

function New-SyncServer {
    param([string] $Fqdn, [object] $Skew, [object] $TimeSync = $true)
    [PSCustomObject]@{
        FQDN     = $Fqdn
        TimeSync = $TimeSync
        Details  = [PSCustomObject]@{
            TimeSyncDetails = [PSCustomObject]@{
                SkewSeconds = $Skew
                RemoteUtc   = '2026-08-19T07:00:00Z'
                Detail      = 'Compared with the local clock'
            }
        }
    }
}

# Three clocks that were read perfectly well. Their rows must survive whatever the fourth carries.
function Get-GoodEstate {
    # Deliberately no clock at 0 s or 1 s: those are the two values the defect INVENTED out of an
    # unreadable field ('' rendered 0 s, $true rendered 1 s), so a good row carrying either would
    # mask the very assertion that detects them.
    @(
        (New-SyncServer -Fqdn 'dc1.mdilab.local' -Skew 7)
        (New-SyncServer -Fqdn 'dc3.emea.mdilab.local' -Skew 4)
        (New-SyncServer -Fqdn 'dc5.mdilab.local' -Skew 2)
    )
}
function Get-SkewCells {
    param([string] $Html)
    @([regex]::Matches($Html, '<td class="[\w-]+">([^<]*?\s*s|n/a)</td>') | ForEach-Object { $_.Groups[1].Value.Trim() })
}
function Get-RowCount {
    param([string] $Html)
    @([regex]::Matches($Html, '<tr><td class="mono">')).Count
}

Write-Host 'Time sync skew: an unreadable reading is neither a measurement nor a crash' -ForegroundColor Cyan

$unreadable = @(
    @{ L = 'empty string'; V = '' }
    @{ L = 'whitespace'; V = '   ' }
    @{ L = 'the word "n/a"'; V = 'n/a' }
    @{ L = 'the word "unknown"'; V = 'unknown' }
    @{ L = 'the word "N/A"'; V = 'N/A' }
    @{ L = 'boolean $true'; V = $true }
    @{ L = 'boolean $false'; V = $false }
    @{ L = 'hashtable'; V = @{} }
    @{ L = 'multi-element array'; V = @(1, 2) }
    @{ L = 'beyond Int64'; V = '1000000000000000000000000000000' }
    # A decimal is not a shape Get-mdiTimeSync emits - it produces a [long] - and Get-mdiClockSpread
    # already refuses it, because it parses with [long]::TryParse. It is listed as unreadable HERE so
    # that the renderer and the spread cannot disagree about which skews were readable, which is the
    # class of two-surfaces-one-fact contradiction this codebase spends most of its guards on.
    @{ L = 'decimal string "12.7"'; V = '12.7' }
    @{ L = 'double 12.7'; V = [double] 12.7 }
)

# ---------------------------------------------------------------------------------------------------
# THE CRASH. One unreadable clock must not cost the three that were read.
# ---------------------------------------------------------------------------------------------------
foreach ($case in $unreadable) {
    $estate = @(Get-GoodEstate) + @(New-SyncServer -Fqdn 'dcfab01.fabrikam.local' -Skew $case.V)
    $html = $null
    $threw = ''
    try { $html = (Get-mdiTimeSyncHtml -Server $estate) -join "`n" } catch { $threw = $_.Exception.Message }

    Assert-That ("renders at all with SkewSeconds = {0}" -f $case.L) ($threw -eq '') $threw
    if ($threw -ne '') { continue }

    Assert-That ("keeps all four rows with SkewSeconds = {0}" -f $case.L) `
    ((Get-RowCount -Html $html) -eq 4) ("rows={0}" -f (Get-RowCount -Html $html))

    $cells = Get-SkewCells -Html $html
    # The specific false measurement: '' printed '0 s' and $true printed '1 s'.
    Assert-That ("invents no zero skew for SkewSeconds = {0}" -f $case.L) `
    (@($cells | Where-Object { $_ -eq '0 s' }).Count -eq 0) ("cells=[{0}]" -f ($cells -join ','))
    Assert-That ("invents no one-second skew for SkewSeconds = {0}" -f $case.L) `
    (@($cells | Where-Object { $_ -eq '1 s' }).Count -eq 0) ("cells=[{0}]" -f ($cells -join ','))
    Assert-That ("says the skew is not available for SkewSeconds = {0}" -f $case.L) `
    ($cells -contains 'n/a') ("cells=[{0}]" -f ($cells -join ','))
    # The three readable clocks must still read exactly as they did.
    foreach ($good in '7 s', '4 s', '2 s') {
        Assert-That ("keeps the readable {0} row with SkewSeconds = {1}" -f $good, $case.L) `
        ($cells -contains $good) ("cells=[{0}]" -f ($cells -join ','))
    }
}

# ---------------------------------------------------------------------------------------------------
# READABLE SHAPES ARE STILL READ. A fix that answered every non-[long] with 'n/a' would throw away a
# numeric string, which a JSON round trip legitimately produces, and the Int64 headroom the comment
# above the line was written to preserve.
# ---------------------------------------------------------------------------------------------------
$readable = @(
    @{ L = 'zero'; V = 0; Expect = '0 s' }
    @{ L = 'int 42'; V = 42; Expect = '42 s' }
    @{ L = 'negative -42'; V = -42; Expect = '-42 s' }
    @{ L = 'numeric string "180"'; V = '180'; Expect = '180 s' }
    # The PARSED value must be rendered, not the raw text. These three parse to a number whose
    # spelling differs from the field, so printing the field back would show ' 42  s', '+42 s' or
    # '0042 s'. The skew column is a measurement, and a measurement is normalised on the way out.
    @{ L = 'whitespace-padded " 42 "'; V = ' 42 '; Expect = '42 s' }
    @{ L = 'explicitly signed "+42"'; V = '+42'; Expect = '42 s' }
    @{ L = 'zero-padded "0042"'; V = '0042'; Expect = '42 s' }
    # A ONE-ELEMENT array is not an unread value: [string] @(42) is "42", the reading is recoverable,
    # and Get-mdiClockSpread parses it identically - so both surfaces agree and it is READ, not
    # refused. @(1,2) flattens to "1 2", which parses as nothing and is listed as unreadable above.
    @{ L = 'one-element array'; V = @(42); Expect = '42 s' }
    @{ L = 'beyond Int32 (5e9)'; V = [long] 5000000000; Expect = '5000000000 s' }
    @{ L = 'negative beyond Int32'; V = [long] -5000000000; Expect = '-5000000000 s' }
)
foreach ($case in $readable) {
    $html = (Get-mdiTimeSyncHtml -Server @(New-SyncServer -Fqdn 'dcfab01.fabrikam.local' -Skew $case.V)) -join "`n"
    $cells = Get-SkewCells -Html $html
    Assert-That ("reads SkewSeconds = {0} as {1}" -f $case.L, $case.Expect) `
    ($cells -contains $case.Expect) ("cells=[{0}]" -f ($cells -join ','))
    Assert-That ("does not call SkewSeconds = {0} unavailable" -f $case.L) `
    (-not ($cells -contains 'n/a')) ("cells=[{0}]" -f ($cells -join ','))
}

# A 68-year skew must still render its digits - the case ClockBeyondIntRange exists for, checked here
# at the RENDERER so the two halves of that defect cannot drift apart.
$sixtyEight = (New-TimeSpan -Start ([datetime]'1958-01-01') -End ([datetime]'2026-08-19')).TotalSeconds
$bigHtml = (Get-mdiTimeSyncHtml -Server @(New-SyncServer -Fqdn 'dc-deadbattery.mdilab.local' -Skew ([long] $sixtyEight))) -join "`n"
Assert-That 'a 68-year skew renders its digits rather than n/a' `
((Get-SkewCells -Html $bigHtml) -notcontains 'n/a') ("cells=[{0}]" -f ((Get-SkewCells -Html $bigHtml) -join ','))

# ---------------------------------------------------------------------------------------------------
# $null STILL MEANS "not measured", and it is the ordinary way to say so.
# ---------------------------------------------------------------------------------------------------
$nullHtml = (Get-mdiTimeSyncHtml -Server (@(Get-GoodEstate) +
        @(New-SyncServer -Fqdn 'dcfab01.fabrikam.local' -Skew $null))) -join "`n"
Assert-That 'a $null skew still renders n/a' ((Get-SkewCells -Html $nullHtml) -contains 'n/a')
Assert-That 'a $null skew keeps every row' ((Get-RowCount -Html $nullHtml) -eq 4)

# ---------------------------------------------------------------------------------------------------
# THE RULE IS STATED ONCE. Get-mdiClockSpread already parses this same field with [long]::TryParse,
# with its own comment saying a skew that came back as a string or as anything that is not a number
# must not be silently turned into 0. The renderer reading it a different way is the two-surfaces-
# one-fact contradiction this codebase guards against, so the two are pinned to agree here.
# ---------------------------------------------------------------------------------------------------
function Test-SpreadReadsIt {
    param([object] $Skew)
    # Two servers, because a spread needs two measured clocks; the second is a known-good reference.
    $spread = Get-mdiClockSpread -Server @(
        (New-SyncServer -Fqdn 'a.mdilab.local' -Skew $Skew)
        (New-SyncServer -Fqdn 'b.mdilab.local' -Skew 0)
    )
    # When the skew was readable there are two clocks and a spread; when it was not, only one.
    $null -ne $spread.SpreadSeconds
}
function Test-RendererReadsIt {
    param([object] $Skew)
    # Wrapped: on the unfixed product the renderer THROWS for several of these shapes, and a test that
    # aborts says less than one that reports. A throw is "did not read it" for the purposes of the
    # agreement question, and the separate crash assertions above are what pin the throw itself.
    try {
        $html = (Get-mdiTimeSyncHtml -Server @(New-SyncServer -Fqdn 'a.mdilab.local' -Skew $Skew)) -join "`n"
    }
    catch { return $false }
    -not ((Get-SkewCells -Html $html) -contains 'n/a')
}

foreach ($case in $unreadable) {
    Assert-That ("the spread also refuses {0}" -f $case.L) (-not (Test-SpreadReadsIt -Skew $case.V))
    Assert-That ("renderer and spread agree on {0}" -f $case.L) `
    ((Test-RendererReadsIt -Skew $case.V) -eq (Test-SpreadReadsIt -Skew $case.V))
}
foreach ($case in $readable) {
    Assert-That ("renderer and spread agree on {0}" -f $case.L) `
    ((Test-RendererReadsIt -Skew $case.V) -eq (Test-SpreadReadsIt -Skew $case.V)) `
    ("renderer={0} spread={1}" -f (Test-RendererReadsIt -Skew $case.V), (Test-SpreadReadsIt -Skew $case.V))
}
Assert-That 'the spread refuses $null' (-not (Test-SpreadReadsIt -Skew $null))

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) `
    -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $(if ($script:fail) { 1 } else { 0 })
