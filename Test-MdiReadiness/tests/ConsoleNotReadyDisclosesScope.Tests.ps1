# The console NOT-READY verdict dropped the scope qualifier that every other surface states.
#
#  w72-F1  Get-mdiVerdictQualifier exists so a run that examined a FRACTION of the estate cannot
#          present itself as a verdict over all of it. The HTML headline applies it to both
#          verdicts, and the script says why in its own words at the call site:
#
#              "The scope qualifier is appended to BOTH verdicts, not only to READY. It was added
#               to stop an unqualified 'All prerequisites met' being produced by a run that examined
#               a fraction of them, which is the more dangerous case - but 'Action required' needs
#               it too. An operator reading that verdict is about to work through the findings
#               believing the list is complete, when a skipped area could be hiding more."
#
#          The CONSOLE applied it to READY only. Rendering Main's own two expressions against one
#          run that skipped three areas and sampled both network bounds produced:
#
#              READY  58/69 checks passed across 7 server(s). (not examined: Certification
#              authority servers, Entra Connect servers, Network ports) (network probes used a
#              sample: ports 2 of 50 host(s), raise -MaxLdapTargetsPerDomain; ...)
#
#              12 issue(s) found: 58/69 checks passed across 7 server(s).
#
#          Same run, same statistics, two console lines - and the one an operator acts on was the
#          silent one. That is the campaign's standing failure class: two surfaces of one fact
#          disagreeing, with the qualification dropped at exactly the boundary where a scheduled
#          job logs it and mails it out. '-Forest -SkipCA -SkipEntraConnect' is the ordinary
#          invocation, so the silent line was the one the lab produced all night.
#
# These tests are BEHAVIOURAL. They lift Main's two Write-mdiConsole verdict expressions out of the
# parsed script and EXECUTE them against controlled statistics, then assert on the RENDERED TEXT.
# A rewrite that keeps the disclosure passes whatever shape it takes; removing the disclosure fails
# however the line is spelled.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# Main's own variable names, so its expressions evaluate exactly as written there.
$report = [PSCustomObject]@{
    SkippedAreas = @('Certification authority servers', 'Entra Connect servers', 'Network ports')
}
$stats = [PSCustomObject]@{
    ChecksPassed = 58; ChecksTotal = 58; ChecksUnread = 11; TotalServers = 7
    PortCandidateHostCount = 50; PortDistinctTargetCount = 2
    NnrCandidateCount = 50; NnrDistinctTargetCount = 5
}
$issueCount = 12
$AsJson = $false

function Get-ConsoleVerdictLine {
    <#
        Main's console verdict lines, rendered. The expressions are taken from the PARSED script so a
        decoy string in a comment cannot satisfy the test, and they are EXECUTED so the assertion is
        about what an operator reads rather than about how the line is written.
    #>
    param([Parameter(Mandatory = $true)] [string] $ScriptText)

    $mainRegion = $ScriptText.Substring($ScriptText.IndexOf('#region Main'))
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($mainRegion, [ref] $null, [ref] $null)
    $calls = @($ast.FindAll({
                param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                $n.GetCommandName() -eq 'Write-mdiConsole' -and $n.Extent.Text -match 'checks passed'
            }, $true))
    foreach ($c in $calls) {
        $expr = @($c.CommandElements |
                Where-Object { $_ -is [System.Management.Automation.Language.ParenExpressionAst] })[0]
        if ($null -ne $expr) { Invoke-Expression $expr.Extent.Text }
    }
}

'[w72] the qualifier has something to disclose for this run'
$qualifier = Get-mdiVerdictQualifier -ReportData $report -Statistics $stats
Assert-That 'the run is qualified at all' (-not [string]::IsNullOrWhiteSpace($qualifier)) "(got '$qualifier')"
Assert-That '  ...and names the skipped areas' ($qualifier -match 'not examined: Certification authority servers')

'[w72] both console verdict lines disclose the scope of the run'
$rendered = @(Get-ConsoleVerdictLine -ScriptText $full)
foreach ($line in $rendered) { "    $($line.Trim())" }
Assert-That 'Main still emits two console verdict lines' ($rendered.Count -ge 2) "(rendered $($rendered.Count))"

$readyLine = @($rendered | Where-Object { $_ -match 'READY' })[0]
$issueLine = @($rendered | Where-Object { $_ -match 'issue\(s\) found' })[0]
Assert-That 'the READY line was rendered' ($null -ne $readyLine)
Assert-That 'the NOT-READY line was rendered' ($null -ne $issueLine)

Assert-That 'the READY line names the areas that were not examined' (
    $readyLine -match 'not examined: Certification authority servers') "($readyLine)"
# The defect. An operator reading "12 issue(s) found" is about to work the findings believing the
# list is complete; three areas were never looked at and the line said nothing.
Assert-That 'the NOT-READY line names them too' (
    $issueLine -match 'not examined: Certification authority servers') "($issueLine)"
Assert-That 'the NOT-READY line discloses the network sample' (
    $issueLine -match 'raise -MaxLdapTargetsPerDomain') "($issueLine)"

'[w72] the two console verdicts agree with each other'
# Neither line may qualify the run in a way the other does not: same report, same statistics, so
# whatever scope sentence one states the other must state as well.
$readyTail = [regex]::Match($readyLine, '(?<tail> \(not examined.*)$').Groups['tail'].Value
$issueTail = [regex]::Match($issueLine, '(?<tail> \(not examined.*)$').Groups['tail'].Value
Assert-That 'both console verdicts carry the same qualifier' ($readyTail -eq $issueTail) `
    "(READY tail '$readyTail' vs NOT-READY tail '$issueTail')"

'[w72] a full scan still reads exactly as before'
# The disclosure must be silent when there is nothing to disclose, or every ordinary run grows a
# meaningless empty clause.
$report = [PSCustomObject]@{ SkippedAreas = @() }
$stats = [PSCustomObject]@{
    ChecksPassed = 69; ChecksTotal = 69; ChecksUnread = 0; TotalServers = 7
    PortCandidateHostCount = 7; PortDistinctTargetCount = 7
    NnrCandidateCount = 7; NnrDistinctTargetCount = 7
}
$fullRendered = @(Get-ConsoleVerdictLine -ScriptText $full)
foreach ($line in $fullRendered) { "    $($line.Trim())" }
$fullIssueLine = @($fullRendered | Where-Object { $_ -match 'issue\(s\) found' })[0]
Assert-That 'a full scan adds no clause to the NOT-READY line' (
    $fullIssueLine -notmatch 'not examined' -and $fullIssueLine -notmatch 'used a sample') "($fullIssueLine)"
Assert-That '  ...and the line still ends at the server count' (
    $fullIssueLine -match 'across 7 server\(s\)\.\s*$') "($fullIssueLine)"

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
