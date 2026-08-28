<#
    [w223b] 'Unknown' is the service control manager's own word for "I could not determine this", and
    it was the one member of that family painted RED.

    Get-mdiServiceStateClass and Get-mdiServiceStateText are a deliberate pair - "paired so the words
    and the colour cannot disagree" - and both route a blank value and 'N/A' to the not-measured
    answer: 'muted-cell' and 'Not tested'. The SCM's literal 'Unknown' fell past both guards, so the
    cell was painted with the same class as a genuinely Stopped service and the word 'Unknown' was
    printed beside it.

    That is the exact contradiction this pair was written to remove, restated one token later. The
    class comment already says why the family matters: 'N/A' "is this codebase's universal 'not
    measured' token", and the adjacent start-mode column "returns grey for a blank value, so on ONE
    ROW, describing ONE service, the start mode cell called an unread value grey while the state cell
    beside it called the same unread value red."

    MEASURED before the fix, on the shipped functions:

        state            class        text            reading
        'Running'        green        Running         correct
        'Stopped'        red          Stopped         correct - a measured failure
        ''               muted-cell   Not tested      correct
        'N/A'            muted-cell   Not tested      correct
        'Unknown'        RED          Unknown         <<< a measured failure asserted about a
                                                          value the SCM said it could not determine

    REACHABILITY, stated plainly rather than dressed up. Today's producer does not emit it: with
    Installed = 'N/A' the row already reads 'Not tested' and no red appears. It arrives from a
    details object whose Installed reads true while the token is 'Unknown' - a report round-tripped
    through JSON, written by an older version, or produced by another tool. This file treats all
    three as real arrivals elsewhere, and the fix is one clause beside the existing 'N/A' test.

    Run under Windows PowerShell 5.1.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path -LiteralPath $target)) {
    $parent = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
    if (Test-Path -LiteralPath $parent) { $target = $parent }
}
if (-not (Test-Path -LiteralPath $target)) {
    $staged = Join-Path (Split-Path (Split-Path $here -Parent) -Parent) 'MDI-Repo\Test-MdiReadiness\Test-MdiReadiness.ps1'
    if (Test-Path -LiteralPath $staged) { $target = $staged }
}
if (-not (Test-Path -LiteralPath $target)) { Write-Host 'FAIL  the product script could not be located'; exit 1 }

$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

"`n[1] THE DEFECT - the SCM's 'Unknown' is not a measured failure"
foreach ($spelling in @('Unknown', 'unknown', 'UNKNOWN', '  Unknown  ')) {
    $class = Get-mdiServiceStateClass -State $spelling
    $words = Get-mdiServiceStateText -State $spelling
    Assert-That "'$spelling' is not painted as a failure" ($class -eq 'muted-cell') "(class='$class')"
    Assert-That "  ...and reads 'Not tested', not the token" ($words -eq 'Not tested') "(text='$words')"
}

"`n[2] THE PAIR MUST NOT DISAGREE - the whole reason these two functions exist"
foreach ($state in @('Running', 'Stopped', 'Not installed', '', '   ', 'N/A', 'Unknown', $null)) {
    $class = Get-mdiServiceStateClass -State $state
    $words = Get-mdiServiceStateText -State $state
    $label = if ($null -eq $state) { '<null>' } elseif ($state -eq '') { "''" } else { $state }
    # 'Not tested' words and a red class would be the contradiction; so would a measured word on a
    # muted cell.
    $agree = if ($words -eq 'Not tested') { $class -eq 'muted-cell' } else { $class -ne 'muted-cell' }
    Assert-That "the words and the colour agree for: $label" $agree "(class='$class' text='$words')"
}

"`n[3] CONTROLS - a state that WAS read keeps its meaning"
Assert-That "'Running' is still green" ((Get-mdiServiceStateClass -State 'Running') -eq 'green')
Assert-That "'Stopped' is still red - a measured failure must stay a failure" `
((Get-mdiServiceStateClass -State 'Stopped') -eq 'red')
Assert-That "  ...and still says so" ((Get-mdiServiceStateText -State 'Stopped') -eq 'Stopped')
Assert-That "'Not installed' is still grey - no service is not the same as unread" `
((Get-mdiServiceStateClass -State 'Not installed') -eq 'grey')
Assert-That "a blank state is still muted" ((Get-mdiServiceStateClass -State '') -eq 'muted-cell')
Assert-That "'N/A' is still muted" ((Get-mdiServiceStateClass -State 'N/A') -eq 'muted-cell')

"`n[4] A STATE THAT IS NOT A STRING is still refused, and never rendered"
foreach ($odd in @(@{}, @(1, 2), 12345, $true, [PSCustomObject]@{ X = 1 })) {
    $class = Get-mdiServiceStateClass -State $odd
    $words = Get-mdiServiceStateText -State $odd
    Assert-That ("a {0} state is muted, not red" -f $odd.GetType().Name) ($class -eq 'muted-cell') "(class='$class')"
    Assert-That ("  ...and prints no rendering of it" -f '') `
    (([string] $words) -notmatch 'System\.|@\{|True|12345') "(text='$words')"
}

"`n[5] 'Unknown' MUST NOT become a catch-all - a state merely unrecognised is still a failure"
# The fix must add ONE token to the not-measured family, not turn every unrecognised string muted.
# A service reporting a real state this code does not enumerate is still a state that WAS read.
foreach ($real in @('Paused', 'StartPending', 'StopPending', 'Degraded')) {
    Assert-That "'$real' is still treated as a read state, not as unread" `
    ((Get-mdiServiceStateClass -State $real) -eq 'red') "(class='$(Get-mdiServiceStateClass -State $real)')"
}

""
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
