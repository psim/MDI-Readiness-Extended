# The console verdict restated a bounded network sample as full readiness.
#
#  w47-F2  The port and NNR probes are drawn from a SAMPLE by design: -MaxLdapTargetsPerDomain
#          defaults to 2 and -MaxNnrTargets to 5, so an ordinary run against a fifty controller
#          forest gathers its network evidence from two hosts for ports and five for name
#          resolution. The report cards already said so - "(2 of 50 host(s) in scope were probed
#          - raise -MaxLdapTargetsPerDomain to widen it)" - but the console line printed
#
#              READY  104/104 checks passed across 50 server(s).
#
#          with no qualification at all. "across 50 server(s)" is true of the directory checks and
#          false of the network ones, and the console line is the surface a scheduled job logs and
#          mails out, so the sample qualification was being dropped at exactly the boundary where
#          it is read by someone who will never open the HTML.
#
#          Get-mdiVerdictQualifier only ever looked at SkippedAreas. The counts it needed -
#          PortCandidateHostCount / PortDistinctTargetCount / NnrCandidateCount /
#          NnrDistinctTargetCount - were already computed and already on the statistics object the
#          console line holds; they were simply never asked for.
#
# These tests are BEHAVIOURAL: they call Get-mdiVerdictQualifier with statistics shaped like a
# sampled run and assert on the returned sentence, so they fail if the disclosure is removed
# regardless of how the function is written.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
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

function New-SampleStats {
    param(
        [int] $PortScope = 50, [int] $PortProbed = 2,
        [int] $NnrScope = 50, [int] $NnrProbed = 5
    )
    [PSCustomObject]@{
        PortCandidateHostCount  = $PortScope
        PortDistinctTargetCount = $PortProbed
        NnrCandidateCount       = $NnrScope
        NnrDistinctTargetCount  = $NnrProbed
    }
}

$noSkips = [PSCustomObject]@{ SkippedAreas = @() }

'[console sample] a sampled run says so'
# The exact shape of the w47 evidence: 50 reachable domain controllers, 2 LDAP hosts probed for
# ports, 5 NNR targets probed. Both bounds are in force, so both must be named.
$sampled = Get-mdiVerdictQualifier -ReportData $noSkips -Statistics (New-SampleStats)
Assert-That 'a sampled run produces a qualifier at all' (-not [string]::IsNullOrWhiteSpace($sampled)) "(got '$sampled')"
Assert-That '  ...naming the ports sample as probed-of-scope' ($sampled -match '2 of 50') "(got '$sampled')"
Assert-That '  ...naming the name resolution sample' ($sampled -match '5 of 50') "(got '$sampled')"
Assert-That '  ...saying it was a sample, not a total' ($sampled -match '(?i)sample') "(got '$sampled')"
# Without the remedy the reader knows the number is partial but not what to do about it.
Assert-That '  ...naming the option that widens the port sample' ($sampled -match '-MaxLdapTargetsPerDomain') "(got '$sampled')"
Assert-That '  ...naming the option that widens the NNR sample' ($sampled -match '-MaxNnrTargets') "(got '$sampled')"

'[console sample] each bound is disclosed independently'
# Ports sampled, name resolution complete: only the ports clause may appear. A qualifier that
# always names both would be describing a bound that was not in force.
$portsOnly = Get-mdiVerdictQualifier -ReportData $noSkips -Statistics (New-SampleStats -NnrScope 5 -NnrProbed 5)
Assert-That 'ports-only sampling names ports' ($portsOnly -match '2 of 50') "(got '$portsOnly')"
Assert-That '  ...and does not name -MaxNnrTargets' ($portsOnly -notmatch '-MaxNnrTargets') "(got '$portsOnly')"

$nnrOnly = Get-mdiVerdictQualifier -ReportData $noSkips -Statistics (New-SampleStats -PortScope 2 -PortProbed 2)
Assert-That 'NNR-only sampling names name resolution' ($nnrOnly -match '5 of 50') "(got '$nnrOnly')"
Assert-That '  ...and does not name -MaxLdapTargetsPerDomain' ($nnrOnly -notmatch '-MaxLdapTargetsPerDomain') "(got '$nnrOnly')"

'[console sample] a full scan reads exactly as before'
# The whole point of the gate: adding a clause to every run would make the common case noisier
# without adding a fact. Scope equal to probed is a complete scan.
$full = Get-mdiVerdictQualifier -ReportData $noSkips -Statistics (New-SampleStats -PortScope 4 -PortProbed 4 -NnrScope 4 -NnrProbed 4)
Assert-That 'a complete scan adds no qualifier' ([string]::IsNullOrEmpty($full)) "(got '$full')"

# Scope BELOW probed cannot happen from a correct estate count, but a malformed report must not
# invent a sample claim out of it.
$inverted = Get-mdiVerdictQualifier -ReportData $noSkips -Statistics (New-SampleStats -PortScope 1 -PortProbed 9 -NnrScope 1 -NnrProbed 9)
Assert-That 'scope below probed makes no sample claim' ([string]::IsNullOrEmpty($inverted)) "(got '$inverted')"

'[console sample] nothing probed is not a sample'
# Probed zero means the network was never measured. That is the "Not evaluated" statement the
# cards already make; calling it a sample would assert a measurement that does not exist. This is
# the same gate the HTML cards use, so the two surfaces cannot disagree about the same scan.
$nothing = Get-mdiVerdictQualifier -ReportData $noSkips -Statistics (New-SampleStats -PortProbed 0 -NnrProbed 0)
Assert-That 'zero probed hosts produce no sample claim' ([string]::IsNullOrEmpty($nothing)) "(got '$nothing')"

'[console sample] skips and samples coexist'
# A run can both skip an area and sample within the areas it kept. Losing either clause loses a
# different fact, so the qualifier has to carry both.
$skipped = [PSCustomObject]@{ SkippedAreas = @('Certification authority servers') }
$both = Get-mdiVerdictQualifier -ReportData $skipped -Statistics (New-SampleStats)
Assert-That 'the skip clause survives' ($both -match 'Certification authority servers') "(got '$both')"
Assert-That '  ...alongside the sample clause' ($both -match '2 of 50' -and $both -match '5 of 50') "(got '$both')"

'[console sample] the old contract is unchanged'
# Every existing caller passes only the report. Those calls must behave exactly as they did, or
# the fix would have changed surfaces it was not aimed at.
Assert-That 'no statistics means skip-only behaviour' (
    (Get-mdiVerdictQualifier -ReportData $skipped) -match 'not examined: Certification authority servers')
Assert-That 'no statistics and no skips is empty' ([string]::IsNullOrEmpty((Get-mdiVerdictQualifier -ReportData $noSkips)))
Assert-That 'a null report with statistics still discloses the sample' (
    (Get-mdiVerdictQualifier -ReportData $null -Statistics (New-SampleStats)) -match '2 of 50')
Assert-That 'null statistics is handled' ([string]::IsNullOrEmpty((Get-mdiVerdictQualifier -ReportData $noSkips -Statistics $null)))
Assert-That 'both null is handled' ([string]::IsNullOrEmpty((Get-mdiVerdictQualifier -ReportData $null -Statistics $null)))

'[console sample] missing counters are not read as a sample'
# A report written before these counters existed has none of them. Absent properties cast to 0,
# and 0 > 0 is false, so a legacy report must stay silent rather than claim "0 of 0".
$legacy = Get-mdiVerdictQualifier -ReportData $noSkips -Statistics ([PSCustomObject]@{ TotalServers = 3 })
Assert-That 'statistics without the counters produce no claim' ([string]::IsNullOrEmpty($legacy)) "(got '$legacy')"

'[console sample] the READY line actually passes the statistics'
# Behavioural end-to-end: run the real console format string with the real qualifier and assert
# the emitted line carries the disclosure. Asserting only on the function would pass even if the
# call site never handed it the statistics - which is precisely the defect.
$mainText = (Get-Content -LiteralPath $target -Raw)
$mainText = $mainText.Substring($mainText.IndexOf('#region Main'))
$readyLine = '  READY  {0}/{1} checks passed across {2} server(s).{3}' -f 104, 104, 50,
    (Get-mdiVerdictQualifier -ReportData $noSkips -Statistics (New-SampleStats))
Assert-That 'the rendered READY line names the sample' ($readyLine -match '2 of 50') "(got '$readyLine')"
Assert-That '  ...and still reports the checks' ($readyLine -match 'READY  104/104') "(got '$readyLine')"
Assert-That 'the READY call site hands over the statistics' (
    $mainText -match 'Get-mdiVerdictQualifier -ReportData \$report -Statistics \$stats')

"  $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
