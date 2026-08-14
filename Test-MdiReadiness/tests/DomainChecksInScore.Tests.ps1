<#
    Behavioural regression test: domain-level directory checks belong to the score.

    These checks live on the REPORT rather than on any server object, and the score never looked at
    them. A domain measured as having no object auditing therefore left every SERVER check passing,
    and the surfaces an operator reads first all said the estate was clean:

        score card      100%  "9 of 9 checks passed"   tone ok
        readiness donut solid green, no failed segment
        servers ready   1/1   "All checks passed"

    while the verdict was NOT READY and the issue list carried a High finding for the same run. The
    console line was truthful. The loudest surfaces were not, and they were the reassuring ones.

    The assertions below read the rendered numbers and tones, never the source.
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

Write-Host 'DomainChecksInScore.Tests.ps1' -ForegroundColor Cyan

function New-DomainReport {
    param($ObjectAuditing, [switch] $OmitObjectAuditing, [switch] $ObjectAuditingUnreadable)
    $auditing = [ordered]@{
        Domain           = 'contoso.com'
        AdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
        DeletedObjects   = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
    }
    if (-not $OmitObjectAuditing) { $auditing['ObjectAuditing'] = [PSCustomObject]@{ isObjectAuditingOk = $ObjectAuditing } }
    # The EXPLICIT "this could not be read" flag, which is a different path from a value of 'N/A':
    # the flag says the query failed, the value says the query ran and returned nothing usable.
    if ($ObjectAuditingUnreadable) { $auditing['ObjectAuditingMeasured'] = $false }
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainAuditing = @([PSCustomObject] $auditing)
        DomainControllers = @([PSCustomObject]@{
                FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
                OperatingSystem = 'Windows Server 2022'
                NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true
                Details = [ordered]@{}
            })
        CAServers = @(); EntraConnectServers = @()
    }
}
function Get-Surfaces {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    $overview = Get-mdiOverviewHtml -Statistics $stats -ReportData $Report
    [PSCustomObject]@{
        Stats    = $stats
        Overview = $overview
        Issues   = @(Get-mdiIssueList -Statistics $stats -ReportData $Report)
        Ready    = (Test-mdiReadinessResult -ReportData $Report)
    }
}

# --- A domain check measured as FAILED must reach the score -----------------------------------
$failedRun = Get-Surfaces -Report (New-DomainReport -ObjectAuditing $false)
$cleanRun = Get-Surfaces -Report (New-DomainReport -ObjectAuditing $true)

Assert-True 'a domain check that failed is counted in the measured total' `
    ($failedRun.Stats.ChecksTotal -eq $cleanRun.Stats.ChecksTotal) `
    ("failed run {0}/{1}, clean run {2}/{3}" -f $failedRun.Stats.ChecksPassed, $failedRun.Stats.ChecksTotal, $cleanRun.Stats.ChecksPassed, $cleanRun.Stats.ChecksTotal)
Assert-True 'and it is NOT counted as a pass' `
    ($failedRun.Stats.ChecksPassed -eq ($cleanRun.Stats.ChecksPassed - 1)) `
    ("failed run passed={0}, clean run passed={1}" -f $failedRun.Stats.ChecksPassed, $cleanRun.Stats.ChecksPassed)
Assert-True 'so the score is no longer a clean sweep' `
    ($failedRun.Stats.ChecksPassed -lt $failedRun.Stats.ChecksTotal) `
    ("{0}/{1}" -f $failedRun.Stats.ChecksPassed, $failedRun.Stats.ChecksTotal)

# The verdict, the issue list and the score must agree that something is wrong.
Assert-True 'the verdict fails the run' ($failedRun.Ready -eq $false)
Assert-True 'the issue list names the domain finding' `
    (@($failedRun.Issues | Where-Object { [string] $_.Area -eq 'Directory auditing' }).Count -ge 1) `
    ((@($failedRun.Issues | ForEach-Object { [string] $_.Area }) -join ','))

# The rendered overview must not show a clean sweep beside that verdict.
$scorePct = [regex]::Match($failedRun.Overview, 'class="kpi-value">(\d+)%').Groups[1].Value
Assert-True 'the rendered score is below 100%' ([int] $scorePct -lt 100) ("rendered {0}%" -f $scorePct)
Assert-True 'the readiness donut carries a failed segment' `
    ($failedRun.Overview -match 'Failed') ''
Assert-True 'the donut is not drawn as an unbroken pass ring' `
    ($failedRun.Overview -notmatch '(?s)Overall readiness.*?Failed</text>\s*<text[^>]*>0<') ''

# --- Controls: the clean run must still read clean ---------------------------------------------
Assert-True 'control: with every domain check passing the run is ready' ($cleanRun.Ready -eq $true)
Assert-True 'control: and its score is a clean sweep' `
    ($cleanRun.Stats.ChecksPassed -eq $cleanRun.Stats.ChecksTotal) `
    ("{0}/{1}" -f $cleanRun.Stats.ChecksPassed, $cleanRun.Stats.ChecksTotal)
Assert-True 'control: the clean run raises no directory finding' `
    (@($cleanRun.Issues | Where-Object { [string] $_.Area -eq 'Directory auditing' }).Count -eq 0)

# --- A domain check that could not be MEASURED is unread, not failed and not passed -------------
$unmeasured = Get-Surfaces -Report (New-DomainReport -ObjectAuditing 'N/A')
Assert-True 'an unmeasured domain check is not counted as a pass' `
    ($unmeasured.Stats.ChecksPassed -eq ($cleanRun.Stats.ChecksPassed - 1)) `
    ("{0} vs clean {1}" -f $unmeasured.Stats.ChecksPassed, $cleanRun.Stats.ChecksPassed)
Assert-True 'nor as a measured failure' `
    ($unmeasured.Stats.ChecksTotal -eq ($cleanRun.Stats.ChecksTotal - 1)) `
    ("{0} vs clean {1}" -f $unmeasured.Stats.ChecksTotal, $cleanRun.Stats.ChecksTotal)
Assert-True 'it is counted as unread' `
    ($unmeasured.Stats.ChecksUnread -eq ($cleanRun.Stats.ChecksUnread + 1)) `
    ("{0} vs clean {1}" -f $unmeasured.Stats.ChecksUnread, $cleanRun.Stats.ChecksUnread)

# A check whose explicit "could not be read" flag is set takes a different path from one whose VALUE
# is unusable, and the two must reach the same answer: not a pass, not a measured failure, unread.
$unreadable = Get-Surfaces -Report (New-DomainReport -ObjectAuditing $true -ObjectAuditingUnreadable)
Assert-True 'a domain check flagged as unreadable is not counted as a pass' `
    ($unreadable.Stats.ChecksPassed -eq ($cleanRun.Stats.ChecksPassed - 1)) `
    ("{0} vs clean {1}" -f $unreadable.Stats.ChecksPassed, $cleanRun.Stats.ChecksPassed)
Assert-True 'nor as part of the measured total' `
    ($unreadable.Stats.ChecksTotal -eq ($cleanRun.Stats.ChecksTotal - 1)) `
    ("{0} vs clean {1}" -f $unreadable.Stats.ChecksTotal, $cleanRun.Stats.ChecksTotal)
Assert-True 'and it is counted as unread' `
    ($unreadable.Stats.ChecksUnread -eq ($cleanRun.Stats.ChecksUnread + 1)) `
    ("{0} vs clean {1}" -f $unreadable.Stats.ChecksUnread, $cleanRun.Stats.ChecksUnread)
Assert-True 'the enumerator marks it unmeasured even though its value reads as a pass' `
    (@(Get-mdiDomainCheckState -ReportData (New-DomainReport -ObjectAuditing $true -ObjectAuditingUnreadable) |
            Where-Object { $_.Name -eq 'Object auditing' -and $null -eq $_.Value }).Count -eq 1)

# --- A check the report does not carry at all must not be charged to the scan -------------------
$absent = Get-Surfaces -Report (New-DomainReport -OmitObjectAuditing)
Assert-True 'a domain check absent from the report is not scored at all' `
    ($absent.Stats.ChecksTotal -eq ($cleanRun.Stats.ChecksTotal - 1) -and $absent.Stats.ChecksUnread -eq $cleanRun.Stats.ChecksUnread) `
    ("absent {0}/{1} unread {2}; clean {3}/{4} unread {5}" -f $absent.Stats.ChecksPassed, $absent.Stats.ChecksTotal, $absent.Stats.ChecksUnread,
        $cleanRun.Stats.ChecksPassed, $cleanRun.Stats.ChecksTotal, $cleanRun.Stats.ChecksUnread)

# --- The enumerator is shared, so it must agree with the issue list on which checks exist -------
$states = @(Get-mdiDomainCheckState -ReportData (New-DomainReport -ObjectAuditing $false))
Assert-True 'the enumerator reports one state per domain check the report carries' ($states.Count -eq 4) ("got {0}" -f $states.Count)
Assert-True 'and marks the failing one as a measured failure' `
    (@($states | Where-Object { $_.Name -eq 'Object auditing' -and $_.Value -eq $false }).Count -eq 1) `
    ((@($states | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; '))
Assert-True 'a null report yields no states and does not throw' (@(Get-mdiDomainCheckState -ReportData $null).Count -eq 0)

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
