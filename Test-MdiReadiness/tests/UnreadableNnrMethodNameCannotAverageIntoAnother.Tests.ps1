# [w105] An NNR method whose NAME could not be read must not be averaged into one that resolved.
#
# The "Name resolution success rate by method" chart - the chart the report itself tells the operator
# to open when troubleshooting the "Low success rate of active name resolution" health alert - was the
# last NNR grouping still written as a bare "Group-Object -Property Name". The bare spelling groups on
# the VALUE, so two records whose Name merely RENDERS the same collapsed into a single bar and their
# measurements were averaged together. Measured on the shipped functions with one method answering 2 of
# 2 probes and a second method answering 0 of 2:
#
#   two names that render alike     ONE bar  '{System.Collections.DictionaryEntry}'  2/4 (50%)
#   a readable name beside one      ONE bar  '{System.Collections.DictionaryEntry}'  2/2 (100%) - green
#   a null or empty name            ONE bar  '' (no label at all)                    2/4 (50%)
#   two readable one-element arrays ONE bar  '{NNR - NetBIOS}'                       2/4 (50%)
#
# so the method that resolved NOTHING was never drawn as failing. It was not drawn at all: its zero was
# folded into a healthy method and the chart published a success rate that no method actually achieved,
# on the one page an operator opens precisely because name resolution is already suspect. The third
# line is the worst of them - a solid green 100% bar labelled with a .NET type name.
#
# The fourth line is what proves this is not only a bad-data problem. Those two names WERE read. They
# arrived wrapped in a single-element collection, which is exactly what ConvertFrom-Json produces for a
# single-valued JSON array, and they merged just the same. Name is not normalised on the way in -
# Get-mdiPortResultRecord normalises Success, Applicable, Server, Target and TargetIP and carries every
# other property through untouched - so whatever the sensor result held for Name arrives at the chart
# as it was.
#
# The fix groups on a rendered STRING key. A name that was actually read keys as itself, including when
# it arrives inside a single-element collection, which is unwrapped repeatedly rather than once because
# a nested array is still a collection after one unwrap. Anything that cannot be read as a name keys to
# a STATED MARKER and its records are counted as UNREAD rather than as measurements, so New-mdiBarChart
# tones the bar neutral and it asserts nothing. That is the same contract the id axis of the required
# ports table already uses with '(unidentified probe)'. Unreadable names sharing one neutral bucket is
# intended; what must never happen again is an unreadable name carrying a success rate.
#
# What this file pins:
#   * two methods that only RENDER alike no longer publish a combined success rate;
#   * an unreadable method name is STATED, never blank, and never toned as a success;
#   * a readable method standing beside an unreadable one keeps its own bar and its own numbers;
#   * names that WERE read but arrived inside a single-element collection keep their separate bars;
#   * a wholly readable estate is completely unaffected.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
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

function New-NnrResult {
    param([string] $Id, [object] $Name, [string] $Target, [bool] $Success)
    [PSCustomObject]@{
        Id          = $Id
        Name        = $Name
        Protocol    = 'TCP'
        Port        = 135
        Scope       = 'NetworkDevice'
        Group       = 'NNR'
        Requirement = 'AtLeastOne'
        Target      = $Target
        TargetIP    = '10.10.1.50'
        Applicable  = $true
        Success     = $Success
        LatencyMs   = 11
        Detail      = 'probe complete'
    }
}

# Method A answers both of its probes, method B answers neither. B must stay visible and stay at zero:
# that is the whole point - a method that resolves nothing has to be legible as a failure.
function New-NnrPair {
    param([object] $NameA, [object] $NameB)
    @(
        (New-NnrResult -Id 'NnrRpc' -Name $NameA -Target 'dcfab01.fabrikam.local' -Success $true)
        (New-NnrResult -Id 'NnrRpc' -Name $NameA -Target 'memfab01.fabrikam.local' -Success $true)
        (New-NnrResult -Id 'NnrNetBios' -Name $NameB -Target 'dcfab01.fabrikam.local' -Success $false)
        (New-NnrResult -Id 'NnrNetBios' -Name $NameB -Target 'memfab01.fabrikam.local' -Success $false)
    )
}

# The real report path, not a hand-built statistics object: Get-mdiReportStatistics decides which
# records are primary NNR and Get-mdiOverviewHtml draws the chart, so both filters are exercised.
function Get-NnrChart {
    param([object[]] $Results)
    $dc = [PSCustomObject]@{
        FQDN            = 'dc1.mdilab.local'
        Domain          = 'mdilab.local'
        Unreachable     = $false
        PartialFailure  = $false
        Details         = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = $Results } }
    }
    $report = [PSCustomObject]@{
        DomainsInScope      = @('mdilab.local')
        DomainControllers   = @($dc)
        CAServers           = @()
        EntraConnectServers = @()
        DomainAuditing      = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    $html = Get-mdiOverviewHtml -Statistics $stats -ReportData $report

    $marker = '<h3>Name resolution success rate by method</h3>'
    $at = $html.IndexOf($marker)
    $section = if ($at -lt 0) { '' } else {
        $end = $html.IndexOf('</section>', $at)
        if ($end -lt 0) { $end = $html.Length }
        $html.Substring($at, $end - $at)
    }
    # Captured up to and including the VALUE span. A non-greedy match stopping at the first
    # "</div></div>" ends inside bar-track and cuts the caption off entirely, which would make every
    # assertion below read an empty string and pass against a broken script.
    $rows = @([regex]::Matches($section, '<div class="bar-row">.*?<div class="bar-value">.*?</div></div>') | ForEach-Object { $_.Value })

    $bars = @(foreach ($row in $rows) {
            $label = ''
            $lm = [regex]::Match($row, '<div class="bar-label"[^>]*>(.*?)</div>')
            if ($lm.Success) { $label = ($lm.Groups[1].Value -replace '<[^>]+>', '') }
            # A bar can hold TWO bar-fill divs: the primary tone and a hard-coded 'na' unread segment.
            # The FIRST one inside the track is the tone; a looser match reports every partial bar 'na'.
            $tone = ''
            $tm = [regex]::Match($row, '<div class="bar-track"><div class="bar-fill ([a-z]+)"')
            if ($tm.Success) { $tone = $tm.Groups[1].Value }
            $caption = ''
            $cm = [regex]::Match($row, '<div class="bar-value">(.*?)</div>')
            if ($cm.Success) { $caption = (($cm.Groups[1].Value -replace '<[^>]+>', ' ') -replace '\s+', ' ').Trim() }
            [PSCustomObject]@{ Label = $label; Tone = $tone; Caption = $caption }
        })
    [PSCustomObject]@{ Html = $html; Section = $section; Bars = $bars }
}

function Show-Bars { param($Chart) (@($Chart.Bars | ForEach-Object { '{0}[{1}]{2}' -f $_.Label, $_.Tone, $_.Caption }) -join ' | ') }

$statedMarker = '(unidentified method)'

# ---------------------------------------------------------------------------------------------
'[w105] control: two readable methods are drawn separately and honestly'
$readable = Get-NnrChart -Results (New-NnrPair -NameA 'NNR - NTLM over RPC' -NameB 'NNR - NetBIOS')

Assert-That 'the readable control draws one bar per method' (@($readable.Bars).Count -eq 2) `
    "($(Show-Bars $readable))"
Assert-That 'the method that answered reads 2/2 (100%)' `
    (@($readable.Bars | Where-Object { $_.Caption -match '2/2 \(100%\)' }).Count -eq 1) "($(Show-Bars $readable))"
Assert-That 'the method that never answered is visible and reads 0/2 (0%)' `
    (@($readable.Bars | Where-Object { $_.Caption -match '0/2 \(0%\)' }).Count -eq 1) "($(Show-Bars $readable))"
Assert-That 'and no combined 50% rate is published' `
    (@($readable.Bars | Where-Object { $_.Caption -match '50%' }).Count -eq 0) "($(Show-Bars $readable))"

# ---------------------------------------------------------------------------------------------
'[w105] two method names that only RENDER alike do not publish a success rate'
# Two DISTINCT dictionaries. They are different objects with different contents; only their rendering
# is identical, which is precisely what the bare property grouping compared.
$aliasA = @{ method = 'rpc' }
$aliasB = @{ method = 'nbt' }
Assert-That 'the fixture really holds two distinct unreadable names' `
    (-not [object]::ReferenceEquals($aliasA, $aliasB)) '(the fixture accidentally reused one object)'

$aliased = Get-NnrChart -Results (New-NnrPair -NameA $aliasA -NameB $aliasB)

# The defect, stated exactly: a bar reading 2 of 4 at 50% is the average of a method that resolved
# everything and one that resolved nothing.
Assert-That 'no bar averages the two methods into 2/4 (50%)' `
    (@($aliased.Bars | Where-Object { $_.Caption -match '2/4 \(50%\)' }).Count -eq 0) "($(Show-Bars $aliased))"
Assert-That 'an unreadable method name is stated rather than rendered as a type name' `
    (@($aliased.Bars | Where-Object { $_.Label -eq $statedMarker }).Count -ge 1) "($(Show-Bars $aliased))"
Assert-That 'no bar is labelled with a .NET type name' `
    (@($aliased.Bars | Where-Object { $_.Label -match 'System\.|DictionaryEntry|Object\[\]' }).Count -eq 0) `
    "($(Show-Bars $aliased))"
Assert-That 'the unreadable bar is toned neutral, not as a measurement' `
    (@($aliased.Bars | Where-Object { $_.Label -eq $statedMarker -and $_.Tone -eq 'na' }).Count -ge 1) `
    "($(Show-Bars $aliased))"
Assert-That 'and it asserts a zero numerator, never a success rate' `
    (@($aliased.Bars | Where-Object { $_.Label -eq $statedMarker -and $_.Caption -match '0/\d+ \(0%\)' }).Count -ge 1) `
    "($(Show-Bars $aliased))"
Assert-That 'and it discloses that the records were not read' `
    (@($aliased.Bars | Where-Object { $_.Label -eq $statedMarker -and $_.Caption -match 'not read' }).Count -ge 1) `
    "($(Show-Bars $aliased))"

# ---------------------------------------------------------------------------------------------
'[w105] a readable method beside an unreadable one keeps its own bar'
# The worst rendering of the defect: the merged bar was toned OK and read 100%, so an unreadable
# method name produced a solid green bar.
$mixed = Get-NnrChart -Results (New-NnrPair -NameA 'NNR - NTLM over RPC' -NameB @{ method = 'nbt' })

Assert-That 'the readable method still has a bar of its own' `
    (@($mixed.Bars | Where-Object { $_.Label -eq 'NTLM over RPC' }).Count -eq 1) "($(Show-Bars $mixed))"
Assert-That 'carrying its own numbers, 2/2 (100%)' `
    (@($mixed.Bars | Where-Object { $_.Label -eq 'NTLM over RPC' -and $_.Caption -match '2/2 \(100%\)' }).Count -eq 1) `
    "($(Show-Bars $mixed))"
Assert-That 'the unreadable method is never toned as a success' `
    (@($mixed.Bars | Where-Object { $_.Label -eq $statedMarker -and $_.Tone -eq 'ok' }).Count -eq 0) `
    "($(Show-Bars $mixed))"
Assert-That 'and no bar labelled with a type name claims 100%' `
    (@($mixed.Bars | Where-Object { $_.Label -match 'System\.|DictionaryEntry' -and $_.Caption -match '100%' }).Count -eq 0) `
    "($(Show-Bars $mixed))"

# ---------------------------------------------------------------------------------------------
'[w105] a null or empty method name is stated, never blank'
foreach ($blank in @($null, '', '   ')) {
    $desc = if ($null -eq $blank) { 'null' } elseif ($blank -eq '') { 'empty' } else { 'whitespace' }
    $blankChart = Get-NnrChart -Results (New-NnrPair -NameA $blank -NameB $blank)
    Assert-That "a $desc method name produces no unlabelled bar" `
        (@($blankChart.Bars | Where-Object { [string]::IsNullOrWhiteSpace($_.Label) }).Count -eq 0) `
        "($(Show-Bars $blankChart))"
    Assert-That "a $desc method name is stated instead" `
        (@($blankChart.Bars | Where-Object { $_.Label -eq $statedMarker }).Count -ge 1) `
        "($(Show-Bars $blankChart))"
    Assert-That "a $desc method name publishes no 50% rate" `
        (@($blankChart.Bars | Where-Object { $_.Caption -match '50%' }).Count -eq 0) `
        "($(Show-Bars $blankChart))"
}

# ---------------------------------------------------------------------------------------------
'[w105] names that WERE read keep their bars even when wrapped in a collection'
# ConvertFrom-Json returns a one-element array for a single-valued JSON array. These names are
# perfectly readable; only their container differs, and they must not be treated as unreadable.
$wrappedA = @('NNR - NTLM over RPC')
$wrappedB = @('NNR - NetBIOS')
Assert-That 'the fixture really wraps the names in collections' `
    (($wrappedA -is [System.Collections.ICollection]) -and (@($wrappedA).Count -eq 1) -and (@($wrappedA)[0] -is [string])) `
    "(fixture shape is $($wrappedA.GetType().FullName))"

$wrapped = Get-NnrChart -Results (New-NnrPair -NameA $wrappedA -NameB $wrappedB)

Assert-That 'a wrapped readable name still draws its own bar per method' (@($wrapped.Bars).Count -eq 2) `
    "($(Show-Bars $wrapped))"
Assert-That 'and both names are read, not marked unidentified' `
    (@($wrapped.Bars | Where-Object { $_.Label -eq $statedMarker }).Count -eq 0) "($(Show-Bars $wrapped))"
Assert-That 'the wrapped method that answered reads 2/2 (100%)' `
    (@($wrapped.Bars | Where-Object { $_.Caption -match '2/2 \(100%\)' }).Count -eq 1) "($(Show-Bars $wrapped))"
Assert-That 'the wrapped method that never answered stays visible at 0/2 (0%)' `
    (@($wrapped.Bars | Where-Object { $_.Caption -match '0/2 \(0%\)' }).Count -eq 1) "($(Show-Bars $wrapped))"

# A name nested one level deeper is still a collection after a single unwrap. One unwrap was measured
# to leave an Object[], which fell through to the marker and lost a name that had been read.
$nestedA = @(, @('NNR - NTLM over RPC'))
$nestedB = @(, @('NNR - NetBIOS'))
$nested = Get-NnrChart -Results (New-NnrPair -NameA $nestedA -NameB $nestedB)
Assert-That 'a nested single-element collection is unwrapped to the name inside it' `
    (@($nested.Bars | Where-Object { $_.Label -eq $statedMarker }).Count -eq 0) "($(Show-Bars $nested))"
Assert-That 'and the nested pair still draws two bars' (@($nested.Bars).Count -eq 2) "($(Show-Bars $nested))"

# ---------------------------------------------------------------------------------------------
'[w105] control: an unreadable name must not spin or throw'
# A hashtable is a collection whose single "element" is the hashtable itself, so an unbounded unwrap
# would never terminate. The chart must simply render.
$htChart = Get-NnrChart -Results (New-NnrPair -NameA @{ a = 1 } -NameB @{ b = 2 })
Assert-That 'a dictionary name renders the chart rather than hanging or throwing' `
    (@($htChart.Bars).Count -ge 1) "($(Show-Bars $htChart))"

''
"UnreadableNnrMethodNameCannotAverageIntoAnother: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
