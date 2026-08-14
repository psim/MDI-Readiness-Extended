<#
    Behavioural regression test: the multi-role merge must be commutative in its DETAILS, not just in
    its check values.

    A small estate routinely runs the certification authority or Entra Connect ON a domain controller,
    so the same machine is discovered once per role and the rows are merged. The check VALUE was
    already merged pessimistically - a failure under any role survives - but the DETAIL entries were
    first-role-wins. With the healthy role discovered first, the merged server reported
    "SensorHealth: False" while its own detail row said the service was Running, and the sentence
    naming the stopped service - the only actionable text in the row - was dropped. Discovering the
    roles in the other order produced the correct detail, so the report depended on the order the
    roles happened to be found in.

    The assertions compare the two orders against each other. That is the property that matters: the
    same two role results must produce the same report.
#>

param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }

$text = [IO.File]::ReadAllText($scriptPath)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main'); if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:passed++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray }
    else { $script:failed++; Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red }
}

Write-Host 'MergeDetailsAreCommutative.Tests.ps1' -ForegroundColor Cyan

$stoppedText = 'Azure Advanced Threat Protection Sensor service is stopped'

function New-SensorRole {
    param([string] $State, [string] $DetailText, [object] $Health)
    [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
        SensorHealth = $Health
        Details = [ordered]@{ SensorHealthDetails = [PSCustomObject]@{
                Installed = $true; SensorService = $State; SensorStartMode = 'Auto'
                UpdaterService = 'Running'; Detail = $DetailText } }
    }
}
function Get-MergedDetail {
    param([object[]] $Order)
    $merged = @(Merge-mdiServerByFqdn -Server $Order)
    [PSCustomObject]@{
        Count  = $merged.Count
        Health = $merged[0].SensorHealth
        State  = [string] $merged[0].Details.SensorHealthDetails.SensorService
        Text   = [string] $merged[0].Details.SensorHealthDetails.Detail
    }
}

$healthy = New-SensorRole -State 'Running' -DetailText '' -Health $true
$broken = New-SensorRole -State 'Stopped' -DetailText $stoppedText -Health $false

$healthyFirst = Get-MergedDetail -Order @($healthy, $broken)
$brokenFirst = Get-MergedDetail -Order @($broken, $healthy)

Assert-True 'the two roles still merge into one server' `
    ($healthyFirst.Count -eq 1 -and $brokenFirst.Count -eq 1) `
    ("healthyFirst={0} brokenFirst={1}" -f $healthyFirst.Count, $brokenFirst.Count)
Assert-True 'the merged check is the failure in both orders' `
    ($healthyFirst.Health -eq $false -and $brokenFirst.Health -eq $false) `
    ("healthyFirst={0} brokenFirst={1}" -f $healthyFirst.Health, $brokenFirst.Health)

# The defect: with the healthy role first, the detail described the healthy role.
Assert-True 'the detail does not contradict the merged check' `
    ($healthyFirst.State -eq 'Stopped') ("detail said the service was '{0}'" -f $healthyFirst.State)
Assert-True 'the actionable sentence survives whichever role was discovered first' `
    ($healthyFirst.Text -eq $stoppedText) ("got '{0}'" -f $healthyFirst.Text)
Assert-True 'and the two discovery orders produce the same detail' `
    ($healthyFirst.State -eq $brokenFirst.State -and $healthyFirst.Text -eq $brokenFirst.Text) `
    ("healthyFirst='{0}'/'{1}' brokenFirst='{2}'/'{3}'" -f $healthyFirst.State, $healthyFirst.Text, $brokenFirst.State, $brokenFirst.Text)

# --- Controls ---------------------------------------------------------------------------------
# Two healthy roles must keep the healthy detail - the rule must not invent a failure.
$bothHealthy = Get-MergedDetail -Order @($healthy, (New-SensorRole -State 'Running' -DetailText 'all good' -Health $true))
Assert-True 'control: two healthy roles keep a healthy detail' `
    ($bothHealthy.State -eq 'Running' -and $bothHealthy.Health -eq $true) `
    ("state={0} health={1}" -f $bothHealthy.State, $bothHealthy.Health)

# Two FAILING roles: the result must still be a failure with a real explanation, AND it must not
# depend on which failure was discovered first - otherwise the merge is still order-dependent, just
# between two failures instead of between a failure and a success.
$otherBroken = New-SensorRole -State 'Disabled' -DetailText 'service is disabled' -Health $false
$bothBroken = Get-MergedDetail -Order @($broken, $otherBroken)
$bothBrokenReversed = Get-MergedDetail -Order @($otherBroken, $broken)
Assert-True 'control: two failing roles still report a failure with a real explanation' `
    ($bothBroken.Health -eq $false -and -not [string]::IsNullOrWhiteSpace($bothBroken.Text)) `
    ("health={0} text='{1}'" -f $bothBroken.Health, $bothBroken.Text)
Assert-True 'two failing roles give the same detail in either order' `
    ($bothBroken.Text -eq $bothBrokenReversed.Text -and $bothBroken.State -eq $bothBrokenReversed.State) `
    ("first='{0}'/'{1}' reversed='{2}'/'{3}'" -f $bothBroken.State, $bothBroken.Text, $bothBrokenReversed.State, $bothBrokenReversed.Text)

# THREE roles on one host is the documented case this merge exists for - a domain controller that
# also runs AD CS and Entra Connect. With a healthy role first and two different failures after it,
# every ordering must still agree, which is what proves the tiebreak is being applied rather than
# whichever failure happened to arrive last.
$threeRoleOrders = @(
    (, @($healthy, $broken, $otherBroken))
    (, @($healthy, $otherBroken, $broken))
    (, @($broken, $healthy, $otherBroken))
    (, @($otherBroken, $broken, $healthy))
)
$threeRole = @(foreach ($order in $threeRoleOrders) { Get-MergedDetail -Order $order })
$distinctText = @($threeRole | ForEach-Object { $_.Text } | Select-Object -Unique)
Assert-True 'three roles on one host give the same detail in every discovery order' `
    ($distinctText.Count -eq 1) (($threeRole | ForEach-Object { "'{0}'" -f $_.Text }) -join ' vs ')
Assert-True 'and that detail is one of the measured failures, not the healthy role' `
    ($distinctText[0] -in @($stoppedText, 'service is disabled')) ("got '{0}'" -f $distinctText[0])

# An UNMEASURED role must not displace a measured failure's explanation.
$unmeasured = New-SensorRole -State 'N/A' -DetailText 'could not be read' -Health 'N/A'
$unmeasuredFirst = Get-MergedDetail -Order @($unmeasured, $broken)
Assert-True 'control: a measured failure explains itself even after an unmeasured role' `
    ($unmeasuredFirst.Text -eq $stoppedText) ("got '{0}'" -f $unmeasuredFirst.Text)
# ...but against a measured SUCCESS the unmeasured role DOES win, because the merged VALUE is what
# the detail has to explain and Merge-mdiCheckValue merges that value pessimistically: a check
# measured in one role and unread in the other becomes 'N/A'. This assertion used to require the
# healthy text to survive, on the reasoning that "could not be read" is not evidence of anything.
# That left the row contradicting itself - the status read "Not tested" while its own detail
# described a successful measurement, and on the time-sync table it printed a stale skew ("-3 s")
# beside "Not tested". Two hunters found it independently and it reproduces in the real rendered
# HTML. "Could not be read" is exactly the evidence for a value that could not be read.
$healthyThenUnmeasured = Get-MergedDetail -Order @($healthy, $unmeasured)
Assert-True 'control: the merged value is unmeasured when one role could not read it' `
    ([string] $healthyThenUnmeasured.Health -eq 'N/A') ("health='{0}'" -f $healthyThenUnmeasured.Health)
Assert-True 'control: and the detail explains the unread state rather than the healthy one' `
    ($healthyThenUnmeasured.Text -eq 'could not be read' -and $healthyThenUnmeasured.State -ne 'Running') `
    ("state='{0}' text='{1}'" -f $healthyThenUnmeasured.State, $healthyThenUnmeasured.Text)
$unmeasuredThenHealthy = Get-MergedDetail -Order @($unmeasured, $healthy)
Assert-True 'control: and that is the same in either discovery order' `
    ($unmeasuredThenHealthy.Text -eq $healthyThenUnmeasured.Text -and $unmeasuredThenHealthy.State -eq $healthyThenUnmeasured.State) `
    ("first='{0}'/'{1}' reversed='{2}'/'{3}'" -f $healthyThenUnmeasured.State, $healthyThenUnmeasured.Text, $unmeasuredThenHealthy.State, $unmeasuredThenHealthy.Text)

# A detail entry with no matching check must still merge first-wins rather than being dropped.
$roleWithOrphanDetail = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; SensorHealth = $true
    Details = [ordered]@{ CapacityDetails = [PSCustomObject]@{ SampleSeconds = 30 } }
}
$orphan = @(Merge-mdiServerByFqdn -Server @($roleWithOrphanDetail, $broken))
Assert-True 'control: a detail with no matching check is still carried through the merge' `
    ($null -ne $orphan[0].Details.CapacityDetails -and $orphan[0].Details.CapacityDetails.SampleSeconds -eq 30)
Assert-True 'control: and the failing role still contributes its own detail alongside it' `
    ([string] $orphan[0].Details.SensorHealthDetails.Detail -eq $stoppedText) `
    ("got '{0}'" -f $orphan[0].Details.SensorHealthDetails.Detail)

# --- End to end: the issue list must not depend on discovery order ----------------------------
function Get-IssueTexts {
    param([object[]] $Order)
    $merged = @(Merge-mdiServerByFqdn -Server $Order)
    $report = [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @($merged[0]); CAServers = @(); EntraConnectServers = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    @(Get-mdiIssueList -Statistics $stats -ReportData $report | ForEach-Object { [string] $_.Issue } | Sort-Object)
}
Assert-True 'the issue list is identical in both discovery orders' `
    (((Get-IssueTexts -Order @($healthy, $broken)) -join '|') -eq ((Get-IssueTexts -Order @($broken, $healthy)) -join '|')) `
    ("healthyFirst=[{0}] brokenFirst=[{1}]" -f ((Get-IssueTexts -Order @($healthy, $broken)) -join '|'), ((Get-IssueTexts -Order @($broken, $healthy)) -join '|'))

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
