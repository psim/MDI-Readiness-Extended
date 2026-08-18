<#
    A scan that stopped part way must not be reported to a human as a measurement.

    Main exits 255 on PartialScanCount -gt 0 with the warning "the scan did not complete ... Re-run
    it rather than reading the result", because checks that never ran are ABSENT, not passed. The
    console summary branched on TotalServers -eq 0 ONLY, so the same run also printed the ordinary
    measured headline and pointed the reader at the findings. Measured on the shipped script, one
    process printed both of these seconds apart:

        1 issue(s) found: 6/7 checks passed across 1 server(s).
        Open the report and start with the Issues found table on the Overview tab.
      WARNING: ... exiting with code 255 (scan incomplete). Re-run it rather than reading the result.

    "Open the report" and "rather than reading the result" are opposite instructions about the same
    run, and the console is the surface a human reads while the exit code is the one their pipeline
    reads. The reassuring half went to the human.

    Asserted on the REAL console text of the REAL Main block, lifted verbatim from the canonical
    file and executed in a REAL powershell.exe process, so both the printed lines and the exit code
    are genuine. A test that recomputed the branch would keep passing while the defect returned.

    The controls carry equal weight. Suppressing the measured headline unconditionally would also
    "fix" this and would destroy the ordinary output of every real scan, so a COMPLETE run that
    found issues must still print "N issue(s) found: X/Y checks passed across ..." and still send
    the reader to the Issues found table, and a clean run must still print READY and exit 0.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = (Resolve-Path -LiteralPath $target).ProviderPath

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$childText = @'
param([Parameter(Mandatory)][ValidateSet('Partial','Clean','Issues','Empty')] [string] $Case,
      [Parameter(Mandatory)][string] $Target)
$ErrorActionPreference = 'Stop'
$raw = [IO.File]::ReadAllText($Target)
$pre = $raw
$i = $pre.IndexOf('#region Main'); if ($i -lt 0) { throw 'no #region Main' }
$pre = $pre.Substring(0, $i)
$pre = $pre -replace '(?m)^\s*#Requires.*$', ''
$pre = $pre -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
Invoke-Expression $pre
# The canonical param() block sits BEFORE #region Main, so the Invoke-Expression above re-declared
# and reset these switches. They must be bound after it or the exit contract cannot be measured.
$AsJson = $false; $PassThru = $false; $FailOnIssues = $false; $OpenHtmlReport = $false

$lines = [IO.File]::ReadAllLines($Target)
$startIdx = -1; $endIdx = -1
# Anchored on $result, which is where the verdict/exit block begins. Starting earlier (at the $stats
# assignment) swept the ARTEFACT-WRITING section into the slice as well, and the child then died on
# $Path being null - a slice this test never meant to execute. The statistics the slice needs are
# supplied by the child instead, immediately below.
for ($n = 0; $n -lt $lines.Count; $n++) {
    if ($startIdx -lt 0 -and $lines[$n] -match '^\s*\$issueCount = @\(Get-mdiIssueList -Statistics \$stats -ReportData \$report\)\.Count\s*$') { $startIdx = $n }
    if ($startIdx -ge 0 -and $lines[$n] -match '^\s*exit \$exitCode\s*$') { $endIdx = $n + 1; break }
}
if ($startIdx -lt 0 -or $endIdx -lt 0) { throw "Main anchors not found (start=$startIdx end=$endIdx)" }
$slice = ($lines[$startIdx..$endIdx] -join "`r`n")

$domainAuditing = [PSCustomObject]@{
    Domain = 'contoso.com'
    ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
    ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
    DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
    ObjectAuditingMeasured = $true; ExchangeAuditingMeasured = $true
    AdfsAuditingMeasured = $true; DeletedObjectsMeasured = $true
}
function New-Dc {
    param([string] $Name, [bool] $Partial, [bool] $AllPass = $true)
    $o = [PSCustomObject]@{
        FQDN = $Name; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $Partial
        Comment = $(if ($Partial) { 'Testing stopped early: The RPC server is unavailable' } else { '' })
        Details = [PSCustomObject]@{}
    }
    Add-Member -InputObject $o -MemberType NoteProperty -Name 'AdvancedAuditing' -Value $AllPass
    Add-Member -InputObject $o -MemberType NoteProperty -Name 'NtlmAuditing' -Value $true
    # A server whose scan stopped part way simply has no property for the checks that never ran.
    if (-not $Partial) {
        Add-Member -InputObject $o -MemberType NoteProperty -Name 'PowerSettings' -Value $true
        Add-Member -InputObject $o -MemberType NoteProperty -Name 'RequiredPorts' -Value $true
        Add-Member -InputObject $o -MemberType NoteProperty -Name 'TimeSync' -Value $true
        Add-Member -InputObject $o -MemberType NoteProperty -Name 'SensorHealth' -Value $true
    }
    $o
}
switch ($Case) {
    'Partial' { $dcs = @((New-Dc -Name 'dc1.contoso.com' -Partial $true)) }
    'Clean'   { $dcs = @((New-Dc -Name 'dc1.contoso.com' -Partial $false)) }
    'Issues'  { $dcs = @((New-Dc -Name 'dc1.contoso.com' -Partial $false -AllPass $false)) }
    'Empty'   { $dcs = @() }
}
$report = [PSCustomObject]@{
    Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers = @($dcs); CAServers = @(); EntraConnectServers = @()
    DomainAuditing = @($domainAuditing)
    ForestDiscovery = $null
    DomainSchemaVersion = [PSCustomObject]@{ details = 'x'; schemaVersion = 1 }
    LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
}
$htmlReportFile = 'C:\Temp\report.html'
$remediation = $null
# Named $stats, not $s: the slice below is Main's own verdict block and reads $stats. Main computes it
# a few lines above the slice's start anchor, so the child has to supply it - and when it did not, the
# whole file died with "Cannot bind argument to parameter 'Statistics' because it is null" and
# reported zero assertions, which reads as a quiet test rather than a dead one.
$stats = Get-mdiReportStatistics -ReportData $report
$result = Test-mdiReadinessResult -ReportData $report
Write-Output ('STATS TotalServers={0} PartialScanCount={1}' -f $stats.TotalServers, $stats.PartialScanCount)
Invoke-Expression $slice
'@

$childPath = Join-Path ([IO.Path]::GetTempPath()) ('mdi-partialconsole-{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
[IO.File]::WriteAllText($childPath, $childText)

$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
function Invoke-Case {
    param([string] $Case)
    # stderr is dropped so the assertions read the CONSOLE only. The exit warnings also contain the
    # words "scan incomplete", and a console assertion that matched those would pass on a run whose
    # console said nothing at all.
    $out = & $ps -NoProfile -ExecutionPolicy Bypass -File $childPath -Case $Case -Target $target 2>$null
    [PSCustomObject]@{ Text = ($out -join "`n"); Exit = $LASTEXITCODE }
}

try {
    $partial = Invoke-Case 'Partial'
    $clean = Invoke-Case 'Clean'
    $issues = Invoke-Case 'Issues'
    $empty = Invoke-Case 'Empty'

    '[part-way scan] the console must not present a scan that gave up as a measurement'
    Assert-That 'the fixture really did stop part way' ($partial.Text -match 'PartialScanCount=[1-9]') "(stats='$($partial.Text -split "`n" | Select-Object -First 1)')"
    Assert-That 'the console declares the scan incomplete' ($partial.Text -cmatch 'SCAN INCOMPLETE') "(text='$($partial.Text)')"
    Assert-That 'the console says it is not a readiness result' ($partial.Text -match 'not a readiness result') "(text='$($partial.Text)')"
    Assert-That 'the console does not print a measured checks-passed headline' ($partial.Text -notmatch 'checks passed across') "(text='$($partial.Text)')"
    Assert-That 'the console does not send the reader into the findings as if the list were complete' ($partial.Text -notmatch 'Open the report and start with') "(text='$($partial.Text)')"
    Assert-That 'the console still reports the issues that were found' ($partial.Text -match '\d+ issue\(s\) found') "(text='$($partial.Text)')"
    Assert-That 'the console says the issue list is incomplete' ($partial.Text -match 'incomplete') "(text='$($partial.Text)')"
    Assert-That 'the process still exits 255' ($partial.Exit -eq 255) "(exit=$($partial.Exit))"

    '[complete scan with issues] the ordinary measured output must survive'
    Assert-That 'the control scan did NOT stop part way' ($issues.Text -match 'PartialScanCount=0') "(stats='$($issues.Text -split "`n" | Select-Object -First 1)')"
    Assert-That 'it still prints the measured issue headline' ($issues.Text -match '\d+ issue\(s\) found: \d+/\d+ checks passed across \d+ server\(s\)') "(text='$($issues.Text)')"
    Assert-That 'it still sends the reader to the Issues found table' ($issues.Text -match 'Open the report and start with') "(text='$($issues.Text)')"
    Assert-That 'it is NOT declared incomplete' ($issues.Text -cnotmatch 'SCAN INCOMPLETE') "(text='$($issues.Text)')"
    Assert-That 'it does not exit with the scan-incomplete sentinel' ($issues.Exit -ne 255) "(exit=$($issues.Exit))"

    '[clean scan] a genuinely complete, healthy run must still read READY'
    Assert-That 'it prints the READY verdict' ($clean.Text -cmatch 'READY\s+\d+/\d+ checks passed') "(text='$($clean.Text)')"
    Assert-That 'it is NOT declared incomplete' ($clean.Text -cnotmatch 'SCAN INCOMPLETE') "(text='$($clean.Text)')"
    Assert-That 'it exits 0' ($clean.Exit -eq 0) "(exit=$($clean.Exit))"

    '[empty scan] the case that already worked must keep working'
    Assert-That 'it is declared incomplete' ($empty.Text -cmatch 'SCAN INCOMPLETE') "(text='$($empty.Text)')"
    Assert-That 'it names the empty-estate cause' ($empty.Text -match 'No server could be enumerated') "(text='$($empty.Text)')"
    Assert-That 'it exits 255' ($empty.Exit -eq 255) "(exit=$($empty.Exit))"

    '[cross-surface] every run that exits 255 must say so on the console'
    foreach ($c in @(@{N = 'partial'; R = $partial }, @{N = 'empty'; R = $empty }, @{N = 'clean'; R = $clean }, @{N = 'issues'; R = $issues })) {
        $saysIncomplete = [bool] ($c.R.Text -cmatch 'SCAN INCOMPLETE')
        $exits255 = ($c.R.Exit -eq 255)
        Assert-That ("the console and the exit code agree for the $($c.N) run") ($saysIncomplete -eq $exits255) "(console=$saysIncomplete exit=$($c.R.Exit))"
    }
} finally {
    Remove-Item -LiteralPath $childPath -Force -ErrorAction SilentlyContinue
}

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
