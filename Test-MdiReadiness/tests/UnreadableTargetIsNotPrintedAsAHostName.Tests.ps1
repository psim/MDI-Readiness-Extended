<#
    AN UNREADABLE PROBE TARGET MUST NOT BE PRINTED TO THE OPERATOR AS THE NAME OF THE HOST THAT
    FAILED.

    Get-mdiTargetLabel, Get-mdiNnrIssueText and Get-mdiUnmeasuredProbeText produce the sentences an
    engineer actually works from - the findings table in the HTML report, the "[High] <server>: ..."
    lines in the generated remediation script, and the ports card. All three typed -Target and
    -TargetIP as [string], so the value was RENDERED AT PARAMETER BIND TIME, before any guard in
    those functions could see it. A cast is a test of the rendering, not of the value: a hashtable
    binds as 'System.Collections.Hashtable' and a two-element list as its elements joined by a
    space. Neither is whitespace, so both passed every emptiness guard and were returned as the
    identity of a machine.

    Measured end to end on the shipped functions, one sensor with one readable blocked target
    (dc9.mdilab.local) and one unreadable one, the SAME run produced both of these:

        warning   "N blocked Network Name Resolution result(s) carry no readable target, so no
                   inbound firewall rule could be generated for them."
        finding   "[High] mem03.mdilab.local: Name resolution could not be tested for
                   System.Collections.Hashtable System.Collections.Hashtable
                   System.Collections.Hashtable (10.10.1.50 10.10.1.50 10.10.1.50)"

    - the run naming a host called System.Collections.Hashtable on the same page as a warning
    saying those targets have no readable name. With a list-shaped Target it is worse: the three
    NNR methods FUSE into one name belonging to no machine,
    'dca.mdilab.local dcb.mdilab.local dca.mdilab.local dcb...', so an engineer is sent to a host
    that does not exist while the two that really failed are never named.

    Fixed at the three functions rather than at the eleven call sites, for the reason
    ConvertTo-mdiText already states in this file: one choke point cannot drift, whereas a cast
    that must be remembered at every call site is a rule - and this one had been remembered at
    exactly ONE of them (Get-mdiRequiredPorts, the only site that wrapped its Target in
    ConvertTo-mdiReadableDomainName). An unreadable value now reduces to the empty string, which
    the existing guards already handle: the label falls through to the ADDRESS, which is true and
    is the only identifying thing about such a record that anybody read.

    WHAT THIS TEST PINS
      1. readable targets are labelled exactly as before - no behaviour change on the normal path;
      2. no unreadable shape ever reaches a FINDING SENTENCE as a rendered type name or as fused
         list elements;
      3. such a target is named by its address instead, so the row still identifies something real;
      4. a target with neither a readable name nor a readable address says "an unnamed target"
         rather than inventing one;
      5. Get-mdiNnrIssueText and Get-mdiUnmeasuredProbeText agree with Get-mdiTargetLabel, because
         the remediation generator marks a finding COVERED by matching its text - if the two
         wordings are fixed inconsistently the coverage matching silently breaks.

    NOTE ON SCOPE, learned by getting it wrong: assertions here are made against the FINDING
    SENTENCES these functions return, never against the whole generated remediation script. That
    script legitimately contains 'New-Object System.Collections.ArrayList' and
    "New-Object 'System.Object[]'" in its own PowerShell source - measured, three such lines in a
    run where every target is perfectly readable - so a test that greps the whole file for
    'System.Collections' is red for a reason that has nothing to do with this defect.
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

# Every shape a probe record's Target can arrive in that nobody actually read. These reach the
# report through an -AsJson round trip, a merged cross-forest report, another tool, or a
# hand-edited baseline - the arrival vector this file names everywhere.
$unreadable = [ordered]@{
    'null'       = $null
    'empty'      = ''
    'blank'      = '   '
    'hashtable'  = @{ dnsHostName = 'dcfab01.fabrikam.local' }
    'pscustom'   = [PSCustomObject]@{ dnsHostName = 'dcfab01.fabrikam.local' }
    'twoElement' = @('dca.mdilab.local', 'dcb.mdilab.local')
    'nestedList' = @(@('dca.mdilab.local', 'dcb.mdilab.local'))
    'bool'       = $true
}
# A rendering that must never appear in a sentence shown to an operator.
function Test-LooksRendered {
    param([string] $Sentence)
    ($Sentence -match 'System\.Collections') -or
    ($Sentence -match 'System\.Object\[') -or
    ($Sentence -match '@\{') -or
    ($Sentence -match 'dca\.mdilab\.local dcb\.mdilab\.local')
}

Write-Host 'An unreadable probe target is never printed as the name of the host that failed'

# ---- 1. the normal path is unchanged -------------------------------------------------------
Assert-That 'a readable name and address still label as "name (address)"' `
    ((Get-mdiTargetLabel -Target 'dcfab01.fabrikam.local' -TargetIP '10.10.1.50') -eq 'dcfab01.fabrikam.local (10.10.1.50)')
Assert-That 'a readable name with no address still labels as the bare name' `
    ((Get-mdiTargetLabel -Target 'dcfab01.fabrikam.local' -TargetIP '') -eq 'dcfab01.fabrikam.local')
Assert-That 'a target recorded only as an address still labels as that address' `
    ((Get-mdiTargetLabel -Target '' -TargetIP '10.10.1.50') -eq '10.10.1.50')
Assert-That 'the NNR wording is unchanged for a readable target' `
    ((Get-mdiNnrIssueText -Target 'dcfab01.fabrikam.local' -TargetIP '10.10.1.50') -eq 'No NNR method could resolve dcfab01.fabrikam.local (10.10.1.50)')
Assert-That 'the untested wording is unchanged for a readable target' `
    ((Get-mdiUnmeasuredProbeText -Prefix 'Name resolution could not be tested for' -Target 'dcfab01.fabrikam.local' -TargetIP '10.10.1.50' -Detail 'Connection refused') `
            -eq 'Name resolution could not be tested for dcfab01.fabrikam.local (10.10.1.50): Connection refused')

# ---- 2/3. no unreadable shape is ever rendered into a sentence --------------------------------
foreach ($name in $unreadable.Keys) {
    $shape = $unreadable[$name]

    $label = [string] (Get-mdiTargetLabel -Target $shape -TargetIP '10.10.1.50')
    Assert-That "$name : Get-mdiTargetLabel does not render it" (-not (Test-LooksRendered $label)) "got '$label'"
    Assert-That "$name : Get-mdiTargetLabel falls back to the address" ($label -eq '10.10.1.50') "got '$label'"

    $nnr = [string] (Get-mdiNnrIssueText -Target $shape -TargetIP '10.10.1.50')
    Assert-That "$name : Get-mdiNnrIssueText does not render it" (-not (Test-LooksRendered $nnr)) "got '$nnr'"
    Assert-That "$name : Get-mdiNnrIssueText still names the address" ($nnr -match '10\.10\.1\.50') "got '$nnr'"

    $unm = [string] (Get-mdiUnmeasuredProbeText -Prefix 'Name resolution could not be tested for' -Target $shape -TargetIP '10.10.1.50' -Detail 'Connection refused')
    Assert-That "$name : Get-mdiUnmeasuredProbeText does not render it" (-not (Test-LooksRendered $unm)) "got '$unm'"
}

# ---- 4. neither half readable: say so, do not invent a name ----------------------------------
foreach ($name in $unreadable.Keys) {
    $shape = $unreadable[$name]
    $label = [string] (Get-mdiTargetLabel -Target $shape -TargetIP $shape)
    Assert-That "$name : an unreadable name AND address label as nothing at all" ($label -eq '') "got '$label'"

    $nnr = [string] (Get-mdiNnrIssueText -Target $shape -TargetIP $shape)
    Assert-That "$name : the NNR row says 'an unnamed target' rather than a rendering" `
        ($nnr -eq 'No NNR method could resolve an unnamed target') "got '$nnr'"

    $unm = [string] (Get-mdiUnmeasuredProbeText -Prefix 'Name resolution could not be tested for' -Target $shape -TargetIP $shape -Detail 'Connection refused')
    Assert-That "$name : the untested row says 'an unnamed target' rather than a rendering" `
        ($unm -eq 'Name resolution could not be tested for an unnamed target: Connection refused') "got '$unm'"
}

# ---- 5. an unreadable REASON is not appended as though it were the cause ----------------------
$withBadDetail = [string] (Get-mdiUnmeasuredProbeText -Prefix 'Name resolution could not be tested for' `
        -Target 'dc9.mdilab.local' -TargetIP '10.30.0.10' -Detail @{ code = 5 })
Assert-That 'an unreadable Detail is not appended as the reason' `
    (-not (Test-LooksRendered $withBadDetail)) "got '$withBadDetail'"

# ---- 6. the two wordings stay in step, or the generator loses its coverage matching -----------
# Get-mdiNnrIssueText deliberately words the NAMELESS case differently - "an unnamed target at
# <address>" rather than pasting the address in where a host name belongs - so it is only the
# shared-label composition when there IS a readable name. Both forms are asserted, because the
# remediation generator marks a finding covered by matching this exact text.
Assert-That 'a readable target composes the NNR sentence from the shared label' `
    ((Get-mdiNnrIssueText -Target 'dc9.mdilab.local' -TargetIP '10.30.0.10') `
            -eq ('No NNR method could resolve ' + (Get-mdiTargetLabel -Target 'dc9.mdilab.local' -TargetIP '10.30.0.10')))
foreach ($name in $unreadable.Keys) {
    $shape = $unreadable[$name]
    $fromNnr = [string] (Get-mdiNnrIssueText -Target $shape -TargetIP '10.10.1.50')
    Assert-That "$name : an unreadable name is worded as an unnamed target AT the address" `
        ($fromNnr -eq 'No NNR method could resolve an unnamed target at 10.10.1.50') "got '$fromNnr'"
    Assert-That "$name : the address in that sentence is the one that was read" `
        ($fromNnr -notmatch 'dcfab01|dca\.mdilab') "got '$fromNnr'"
}

Write-Host ''
Write-Host ("PASS={0} FAIL={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
