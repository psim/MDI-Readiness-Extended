# Seven defects from the wave 5/6 hunts, all confirmed by execution before being fixed.
#
#  1. The headline score RISED when a measurement was lost: one check going from a measured failure to
#     'N/A' took the card from "4 of 5 = 80%, warn" to "4 of 4 = 100%, green". The worse the coverage,
#     the healthier the estate looked.
#  2. The "not reachable" badge was matched with an encoder that escapes only & < > " against markup
#     that ConvertTo-Html had already encoded with NUMERIC entities, so a domain controller called
#     o'brien-dc or dc-muenchen rendered as an ordinary scanned row.
#  3. The Deleted Objects grant was scripted with dsacls AND repeated under "needs manual attention".
#  4. #requires -Module made a missing ActiveDirectory module exit 1 - the same code -FailOnIssues
#     uses for "exactly one readiness issue".
#  5/6. Get-mdiServiceState returned $null both for "not installed" and "the query failed", so the v3
#     readiness check asserted "no v2.x sensor" and "no identity roles" from reads that never happened.
#  7. Get-mdiSensorHealth drew the same conclusion from the same null.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}
function New-Report { param($Dc, $Domains = $null)
    $r = [PSCustomObject]@{ DomainControllers = @($Dc); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domains = @()
    }
    if ($Domains) { $r | Add-Member -NotePropertyName DomainAuditing -NotePropertyValue @($Domains) -Force }
    $r
}

'[score] losing a measurement must never raise the headline'
$base = @{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false
    OSVersion = $true; NPCAP = $true; PowerScheme = $true; SensorVersion = $true
}
function Get-Score {
    param($Server)
    $s = Get-mdiReportStatistics -ReportData (New-Report $Server)
    $den = $s.ChecksTotal + $s.ChecksUnread
    [PSCustomObject]@{ Pct = $(if ($den -gt 0) { [int][math]::Floor(100 * $s.ChecksPassed / $den) } else { 0 })
        Denominator = $den; Passed = $s.ChecksPassed; Unread = $s.ChecksUnread
    }
}
$measuredFail = Get-Score ([PSCustomObject]($base + @{ TimeSync = $false; Details = [PSCustomObject]@{} }))
$notMeasured = Get-Score ([PSCustomObject]($base + @{ TimeSync = 'N/A'; Details = [PSCustomObject]@{} }))
$allPass = Get-Score ([PSCustomObject]($base + @{ TimeSync = $true; Details = [PSCustomObject]@{} }))
Assert-That 'an unread check does not raise the score above a failed one' ($notMeasured.Pct -le $measuredFail.Pct) "($($notMeasured.Pct)% vs $($measuredFail.Pct)%)"
Assert-That 'the unread check stays in the denominator' ($notMeasured.Denominator -eq $measuredFail.Denominator) "($($notMeasured.Denominator) vs $($measuredFail.Denominator))"
Assert-That 'only a genuinely clean estate reaches 100%' ($allPass.Pct -eq 100 -and $notMeasured.Pct -lt 100 -and $measuredFail.Pct -lt 100)

'[badge] the match key must reproduce what ConvertTo-Html emitted'
foreach ($name in @(
        'dc-plain.contoso.com'
        ('o' + [char]39 + 'brien-dc.contoso.com')
        ('dc-caf' + [char]0xE9 + '.contoso.com')
        ('dc-m' + [char]0xFC + 'nchen.contoso.com')
        'a&b.contoso.com'
        'a<b.contoso.com'
        ('dc-' + [char]0x4E2D + [char]0x6587 + '.contoso.com')
    )) {
    $encoded = ConvertTo-mdiTableCellEncoded $name
    $fragment = (@([PSCustomObject]@{ FQDN = $name }) | ConvertTo-Html -Fragment) -join ''
    Assert-That ("the badge key matches the markup for '{0}'" -f $name) ($fragment -match [regex]::Escape($encoded)) "(key '$encoded')"
}
Assert-That 'the cell encoder is not the attribute encoder' (
    (ConvertTo-mdiTableCellEncoded "o'brien") -ne (ConvertTo-mdiHtmlEncoded "o'brien"))
Assert-That 'null and empty are handled' (
    (ConvertTo-mdiTableCellEncoded $null) -eq '' -and (ConvertTo-mdiTableCellEncoded '') -eq '')

'[remediation] a scripted domain fix is not repeated under manual attention'
$dc = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false
    OSVersion = $true; NPCAP = $true; RequiredPorts = $true
    Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
}
function New-Domain {
    param($DeletedOk = $true, $DeletedMeasured = $true, $ObjectOk = $true, $ObjectMeasured = $true)
    [PSCustomObject]@{ Domain = 'contoso.com'
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $ObjectOk }; ObjectAuditingMeasured = $ObjectMeasured
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }; ExchangeAuditingMeasured = $true
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $true
        DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $DeletedOk
            details = [PSCustomObject]@{ Detail = 'The DSA has no read access'; Container = 'CN=Deleted Objects,DC=contoso,DC=com' }
        }
        DeletedObjectsMeasured = $DeletedMeasured
    }
}
function Get-Advisory {
    param($Report)
    $out = Join-Path $env:TEMP ('rem-{0}.ps1' -f [guid]::NewGuid())
    New-mdiRemediationScript -ReportData $Report -FilePath $out 3>$null | Out-Null
    $g = Get-Content -LiteralPath $out -Raw
    Remove-Item $out -Force -ErrorAction SilentlyContinue
    $perr = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($g, [ref]$null, [ref]$perr)
    [PSCustomObject]@{ Text = $g; ParseErrors = @($perr).Count
        Advisory = @($g -split "`r?`n" | Where-Object { $_ -match '^\s*Write-Host ''    \[' })
    }
}
$scripted = Get-Advisory (New-Report -Dc $dc -Domains @(New-Domain -DeletedOk $false))
Assert-That 'the generated script parses' ($scripted.ParseErrors -eq 0)
Assert-That 'the dsacls grant is generated' ($scripted.Text -match 'dsacls\.exe')
Assert-That 'and is not repeated under manual attention' (
    @($scripted.Advisory | Where-Object { $_ -match 'Deleted Objects' }).Count -eq 0) "($($scripted.Advisory -join ' | '))"

'[remediation] ...but an unverified domain check is still surfaced'
$unverified = New-Report -Dc $dc -Domains @(New-Domain -ObjectOk 'N/A' -ObjectMeasured $false)
$st = Get-mdiReportStatistics -ReportData $unverified
Assert-That 'an unreadable domain check still raises an issue' (
    @(Get-mdiIssueList -Statistics $st -ReportData $unverified | Where-Object { $_.Issue -match 'unverified' }).Count -ge 1)
Assert-That 'and the run is not ready' ((Test-mdiReadinessResult -ReportData $unverified) -eq $false)
Assert-That 'the domain wording has one source' (
    (Get-mdiDomainCheckIssueText -CheckName 'Object auditing') -eq 'Object auditing is not configured on this domain' -and
    (Get-mdiDomainCheckIssueText -CheckName 'Object auditing' -Unverified) -match 'unverified')

'[startup] a missing module must not look like one readiness issue'
Assert-That 'the ActiveDirectory module is not a #requires' (
    ($text -notmatch '(?m)^\s*#requires\s+-Module\s+ActiveDirectory'))
$mainText = Get-Content -LiteralPath $target -Raw
Assert-That 'it is checked where the trap can see it' (
    $mainText -match 'Get-Module -Name ActiveDirectory -ListAvailable')
# A #requires that cannot be satisfied exits 1, which collides with the issue count. Proven as a process.
# Run with the preference relaxed: a native command writing to stderr is promoted to a terminating
# error under 'Stop', and here that output is the very thing being demonstrated.
$probe = Join-Path $env:TEMP ('req-{0}.ps1' -f [guid]::NewGuid())
Set-Content -Path $probe -Value "#requires -Modules NoSuchModule`ntrap { exit 255 }`nexit 7" -Encoding UTF8
$requiresExit = -1
$previousPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $probe 2>&1 | Out-Null
    $requiresExit = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previousPreference
    Remove-Item $probe -Force -ErrorAction SilentlyContinue
}
Assert-That 'an unsatisfiable #requires really does exit 1 (why this matters)' ($requiresExit -eq 1) "(got $requiresExit)"

'[services] a query that failed is not a service that is absent'
function Set-ServiceQuery {
    param([switch] $Fail)
    $script:svcFail = [bool] $Fail
    function global:Get-WmiObject {
        param($ComputerName, $Namespace, $Class, $Property, $Filter, $ErrorAction)
        if ($Class -eq 'Win32_OperatingSystem') {
            [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2022 Standard'; Version = '10.0.20348'; BuildNumber = '20348'; ProductType = 2 }
        } elseif ($Class -eq 'Win32_Service' -and $script:svcFail) {
            throw 'The RPC server is unavailable'
        } else { $null }
    }
}
Set-ServiceQuery -Fail
$r = Get-mdiServiceStateResult -ComputerName 'dc1.contoso.com' -ServiceName 'AATPSensor'
Assert-That 'a failed service query reports itself unreadable' ($r.Readable -eq $false)
Assert-That '  ...and carries the reason' (-not [string]::IsNullOrWhiteSpace([string] $r.Error))
$health = Get-mdiSensorHealth -ComputerName 'dc1.contoso.com' 3>$null
Assert-That 'sensor health is not measured when the services cannot be read' ([string] $health.isSensorHealthOk -eq 'N/A')
Assert-That '  ...and does not claim the sensor is absent' ([string] $health.details.Installed -ne 'False')
$v3 = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' 3>$null
foreach ($pattern in 'v2\.x version supports migration', 'No additional identity roles') {
    $check = @($v3.details.Checks | Where-Object { $_.Name -match $pattern })[0]
    Assert-That "'$pattern' is not asserted from an unread query" ([string] $check.Status -eq 'N/A') "(got '$($check.Status)')"
}

Set-ServiceQuery
$r2 = Get-mdiServiceStateResult -ComputerName 'dc1.contoso.com' -ServiceName 'AATPSensor'
Assert-That 'an answered query reports itself readable' ($r2.Readable -eq $true)
$health2 = Get-mdiSensorHealth -ComputerName 'dc1.contoso.com' 3>$null
Assert-That 'a genuinely absent sensor is still reported absent' ([string] $health2.details.Installed -eq 'False')
$v3b = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' 3>$null
$roles = @($v3b.details.Checks | Where-Object { $_.Name -match 'No additional identity roles' })[0]
Assert-That 'no identity roles is still stated when the queries answered' ($roles.Status -eq $true) "(got '$($roles.Status)')"
Remove-Item Function:\global:Get-WmiObject -ErrorAction SilentlyContinue

'[harness] the truncation anchor stays unique'
# The test harness cuts the script at the literal "#region Main". A second occurrence anywhere above
# the function definitions silently truncates the whole file and every test then fails with
# "term is not recognized" - which is exactly what a comment mentioning it by name once caused.
Assert-That 'the region marker appears exactly once' (
    ([regex]::Matches($mainText, '#region Main')).Count -eq 1) "(found $(([regex]::Matches($mainText,'#region Main')).Count))"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
