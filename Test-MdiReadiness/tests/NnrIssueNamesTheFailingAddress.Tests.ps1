<#
    THE ISSUE ROW CLAIMED A HOST COULD NOT BE RESOLVED WHEN ONE OF ITS TWO ADDRESSES RESOLVED FINE.

    A multi-homed host is discovered once per address and probed per address, so one NIC can answer
    every Network Name Resolution method while another answers none. The issue text named only the
    host:

        PRODUCER_NNR_FAILED_TARGETS=dual.contoso.com (10.0.0.11)
        STATISTICS_NNR=1/2
        ISSUE=No NNR method could resolve dual.contoso.com

    The producer had already derived the failing ADDRESS, and the statistics said one of two targets
    resolved - so the row an operator works from made a claim the same run contradicted two lines
    above it, and gave them no way to find the broken NIC. On a domain controller with a management
    NIC and a production NIC that is the difference between a five-minute fix and an afternoon.

    The address is appended only when it adds something: a single-homed target, or one discovered by
    address alone, keeps the shorter sentence.

    SECOND HALF, easy to miss: the remediation generator marks a finding as covered by matching its
    TEXT. Changing the wording without changing that call would have left a covered-marker matching
    nothing, so the finding would have reappeared under "needs manual attention" for a firewall rule
    the script had just written. The function's own doc comment records that this drift has happened
    before. Both ends are asserted here.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

Write-Host 'The failing ADDRESS is named when the target has more than one' -ForegroundColor Cyan
$qualified = Get-mdiNnrIssueText -Target 'dual.contoso.com' -TargetIP '10.0.0.11'
Assert-That 'the host is named' ($qualified -match 'dual\.contoso\.com') "text=$qualified"
Assert-That 'and so is the address that failed' ($qualified -match '10\.0\.0\.11') "text=$qualified"

Write-Host ''
Write-Host 'CONTROLS - the address is only added when it adds something' -ForegroundColor Cyan
Assert-That 'CONTROL: no address given keeps the short sentence' (
    (Get-mdiNnrIssueText -Target 'single.contoso.com') -eq 'No NNR method could resolve single.contoso.com')
Assert-That 'CONTROL: an empty address keeps the short sentence' (
    (Get-mdiNnrIssueText -Target 'single.contoso.com' -TargetIP '') -eq 'No NNR method could resolve single.contoso.com')
# A target discovered by address alone carries the same value in both fields; "10.0.0.5 (10.0.0.5)"
# is noise, not information.
Assert-That 'CONTROL: an address equal to the name is not repeated' (
    (Get-mdiNnrIssueText -Target '10.0.0.5' -TargetIP '10.0.0.5') -eq 'No NNR method could resolve 10.0.0.5')
# The malformed-input guard this function already carries must survive: an unnamed target must not
# throw, because that once cost the entire HTML report.
Assert-That 'CONTROL: an empty target still yields a sentence rather than throwing' (
    (Get-mdiNnrIssueText -Target '') -eq 'No NNR method could resolve an unnamed target')
Assert-That 'CONTROL: a null target still yields a sentence' (
    (Get-mdiNnrIssueText -Target $null) -eq 'No NNR method could resolve an unnamed target')
Assert-That 'CONTROL: an unnamed target WITH an address names the address' (
    (Get-mdiNnrIssueText -Target '' -TargetIP '10.0.0.11') -match '10\.0\.0\.11')

Write-Host ''
Write-Host 'The issue list uses it, so the row an operator reads carries the address' -ForegroundColor Cyan
function New-NnrRecord {
    param([string] $TargetIP, [bool] $Success, [int] $Port, [string] $Name)
    [PSCustomObject]@{
        Id = "Nnr$Name"; Name = "NNR - $Name"; Protocol = 'UDP'; Port = $Port
        Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'
        Target = 'dual.contoso.com'; TargetIP = $TargetIP
        Applicable = $true; Success = $Success
        Detail = $(if ($Success) { 'Connected' } else { 'Closed - connection refused' })
    }
}

# 10.0.0.10 answers both methods; 10.0.0.11 answers neither. One host, two addresses, one broken NIC.
$server = [PSCustomObject]@{
    FQDN = 'sensor.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
    Details = [PSCustomObject]@{
        RequiredPortsDetails = [PSCustomObject]@{
            Results = @(
                (New-NnrRecord -TargetIP '10.0.0.10' -Success $true  -Port 135  -Name 'RPC'),
                (New-NnrRecord -TargetIP '10.0.0.10' -Success $true  -Port 3389 -Name 'RDP'),
                (New-NnrRecord -TargetIP '10.0.0.11' -Success $false -Port 135  -Name 'RPC'),
                (New-NnrRecord -TargetIP '10.0.0.11' -Success $false -Port 3389 -Name 'RDP'))
        }
    }
}

$reportData = [PSCustomObject]@{
    Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers = @($server); CAServers = @(); EntraConnectServers = @(); DomainAuditing = @()
}
$statistics = Get-mdiReportStatistics -ReportData $reportData
$issues = @(Get-mdiIssueList -Statistics $statistics -ReportData $reportData)
$nnrIssues = @($issues | Where-Object { $_.Area -eq 'Name resolution' })

# The harness has to have produced the row under test.
if ($nnrIssues.Count -eq 0) {
    throw ("no name-resolution issue was raised - the fixture does not reach the path under test. issues: " +
        (($issues | ForEach-Object { $_.Area + '/' + $_.Issue }) -join ' | '))
}
Assert-That 'exactly one name-resolution row is raised for the target' (
    $nnrIssues.Count -eq 1) "count=$($nnrIssues.Count)"
Assert-That 'and it names the address that failed' (
    $nnrIssues[0].Issue -match '10\.0\.0\.11') "issue=$($nnrIssues[0].Issue)"
Assert-That 'and NOT the address that resolved' (
    $nnrIssues[0].Issue -notmatch '10\.0\.0\.10') "issue=$($nnrIssues[0].Issue)"

Write-Host ''
Write-Host 'CONTROL - a fully healthy multi-homed target raises nothing' -ForegroundColor Cyan
$healthyServer = [PSCustomObject]@{
    FQDN = 'sensor.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
    Details = [PSCustomObject]@{
        RequiredPortsDetails = [PSCustomObject]@{
            Results = @(
                (New-NnrRecord -TargetIP '10.0.0.10' -Success $true -Port 135  -Name 'RPC'),
                (New-NnrRecord -TargetIP '10.0.0.10' -Success $true -Port 3389 -Name 'RDP'),
                (New-NnrRecord -TargetIP '10.0.0.11' -Success $true -Port 135  -Name 'RPC'),
                (New-NnrRecord -TargetIP '10.0.0.11' -Success $true -Port 3389 -Name 'RDP'))
        }
    }
}
$healthyData = [PSCustomObject]@{
    Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers = @($healthyServer); CAServers = @(); EntraConnectServers = @(); DomainAuditing = @()
}
$healthyIssues = @(Get-mdiIssueList -Statistics (Get-mdiReportStatistics -ReportData $healthyData) -ReportData $healthyData)
Assert-That 'CONTROL: no name-resolution issue when every address resolves' (
    @($healthyIssues | Where-Object { $_.Area -eq 'Name resolution' }).Count -eq 0) (
    'issues: ' + (($healthyIssues | ForEach-Object { $_.Issue }) -join ' | '))

Write-Host ''
Write-Host 'The remediation advisory must use the SAME wording as the issue list' -ForegroundColor Cyan
# The generator marks a finding covered by matching its TEXT, and lists everything it could not fix
# under "needs manual attention". Either way the two surfaces must agree word for word: if they
# drift, a finding the script DID fix reappears as manual work, or one it did not fix is silently
# marked covered. This fixture's NNR methods have no firewall rule, so the correct outcome is that
# the finding appears in the advisory - carrying the address, exactly as the issue list states it.
$remediationFile = Join-Path ([IO.Path]::GetTempPath()) ('mdi-nnr-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
try {
    [void] (New-mdiRemediationScript -ReportData $reportData -FilePath $remediationFile 3>$null 4>$null)
    $generated = [IO.File]::ReadAllText($remediationFile)
    $issueText = [string] $nnrIssues[0].Issue

    Assert-That 'the advisory carries the finding' (
        $generated -match [regex]::Escape($issueText)) (
        "issue text not found in the generated script: $issueText")
    # And specifically the ADDRESS-qualified form, not the old unqualified sentence.
    Assert-That 'and it names the failing address there too' (
        $generated -match [regex]::Escape('dual.contoso.com (10.0.0.11)')) (
        'the advisory used the unqualified wording')
    # The two surfaces must not both appear - that would mean two spellings of one fact.
    $unqualified = [regex]::Matches($generated, 'No NNR method could resolve dual\.contoso\.com(?! \()')
    Assert-That 'the unqualified wording appears nowhere' ($unqualified.Count -eq 0) (
        "found $($unqualified.Count) unqualified mention(s)")
} finally {
    Remove-Item -LiteralPath $remediationFile -Force -ErrorAction SilentlyContinue
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
