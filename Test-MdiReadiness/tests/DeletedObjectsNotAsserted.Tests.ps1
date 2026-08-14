<#
    -DirectoryServiceAccount is OPTIONAL. Without it, Get-mdiDeletedObjectsPermission reads the
    Deleted Objects DACL in full, reports who holds read access, and returns 'N/A' - because there was
    no account to assert against. Its own comment calls that "an answer, not a gap", and it sets
    Measured = $true to say so.

    Three of the five surfaces that read the result could not tell that 'N/A' apart from the three
    'N/A's that ARE gaps (an ambiguous trustee, an unresolvable account, a group holder - all
    Measured = $false) and charged the run for a measurement nobody asked it to take:

        verdict      NOT READY, so the script exited non-zero on a healthy forest
        issue list   [High] "... returned no usable result on this domain, so it is unverified"
        score card   the check counted as UNREAD

    while the HTML cell for the very same fact rendered a benign grey "Not applicable" - the renderer
    was the only consumer reading the Measured flag. Every DEFAULT run failed this way, which is how
    every scan in the lab runs.

    The distinction these tests pin down: "never asked" must block nothing and must not be scored as a
    check that PASSED either - counting it would be the unmeasured-treated-as-measured class from the
    other direction. Every genuine gap, and every measured failure, must keep blocking exactly as
    before. Absence of the marker means false, so legacy reports are unaffected.
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

# --- directory I/O stubs. Only the I/O is replaced; the logic under test is the real one. ---------
$script:granted = @('CONTOSO\MDI-DSA')
$script:throwOnRead = $false
Set-Item -Path function:script:Get-ADRootDSE -Value {
    param($Server, $ErrorAction)
    [PSCustomObject]@{ defaultNamingContext = 'DC=contoso,DC=com' }
}
Set-Item -Path function:script:Get-ADObject -Value {
    param($Identity, $Server, $Properties, [switch] $IncludeDeletedObjects, $ErrorAction)
    if ($script:throwOnRead) { throw 'Access is denied' }
    [PSCustomObject]@{
        nTSecurityDescriptor = [PSCustomObject]@{
            Access = @([PSCustomObject]@{
                    ActiveDirectoryRights = 'GenericRead'
                    AccessControlType     = 'Allow'
                    IdentityReference     = 'CONTOSO\MDI-DSA'
                    PropagationFlags      = 'None'
                    ObjectType            = '00000000-0000-0000-0000-000000000000'
                })
        }
    }
}
Set-Item -Path function:script:Get-mdiEffectiveDaclTrustee -Value {
    param($Ace, $RequiredMask, [switch] $ResolveSid)
    , @($script:granted)
}

# A report carrying one domain, every other check healthy, so the ONLY thing that can move the
# verdict is the Deleted Objects result handed in.
function New-Report {
    param($Deleted)
    $row = [PSCustomObject][ordered]@{
        Domain                   = 'contoso.com'
        ObjectAuditing           = [PSCustomObject]@{ isObjectAuditingOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
        ObjectAuditingMeasured   = $true
        ExchangeAuditing         = [PSCustomObject]@{ isExchangeAuditingOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
        ExchangeAuditingMeasured = $true
        AdfsAuditing             = [PSCustomObject]@{ isAdfsAuditingOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
        AdfsAuditingMeasured     = $true
        DeletedObjects           = $Deleted
        DeletedObjectsMeasured   = [bool] $Deleted.Measured
    }
    [PSCustomObject]@{
        Domain              = 'contoso.com'
        Forest              = 'contoso.com'
        DomainsInScope      = @('contoso.com')
        DomainControllers   = @([PSCustomObject]@{
                FQDN = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2022'
                AdvancedAuditing = $true; NtlmAuditing = $true; Unreachable = $false
            })
        CAServers           = @()
        EntraConnectServers = @()
        DomainAuditing      = @($row)
    }
}
# Every surface for one result, read the way the script reads them.
function Get-Surfaces {
    param($Deleted)
    $report = New-Report -Deleted $Deleted
    $stats = Get-mdiReportStatistics -ReportData $report
    $state = @(Get-mdiDomainCheckState -ReportData $report | Where-Object { $_.Name -eq 'Deleted Objects container permission' })
    [PSCustomObject]@{
        Scored  = ($state.Count -gt 0)
        State   = $(if ($state.Count -gt 0) { $state[0].Value } else { 'not-scored' })
        Unread  = [int] $stats.ChecksUnread
        Issues  = @(Get-mdiIssueList -Statistics $stats -ReportData $report |
                Where-Object { [string] $_.Issue -like '*Deleted Objects*' })
        Ready   = [bool] (Test-mdiReadinessResult -ReportData $report)
        Report  = $report
    }
}

Write-Host 'CONTROLS - every state that legitimately blocks must still block' -ForegroundColor Cyan

# 1. The account was named and IS granted: a real pass.
$script:granted = @('CONTOSO\MDI-DSA'); $script:throwOnRead = $false
$ok = Get-mdiDeletedObjectsPermission -Domain 'test.invalid' -DirectoryServiceAccount @('CONTOSO\MDI-DSA')
$okS = Get-Surfaces -Deleted $ok
Assert-That 'granted DSA is a measured pass' ([string] $ok.isDeletedObjectsPermissionOk -eq 'True') "got '$($ok.isDeletedObjectsPermissionOk)'"
Assert-That '  ...and is NOT flagged not-asserted' ((Test-mdiDomainCheckNotAsserted -Result $ok) -eq $false)
Assert-That '  ...is scored as a passed check' ($okS.Scored -and $okS.State -eq $true) "scored=$($okS.Scored) state='$($okS.State)'"
Assert-That '  ...raises no finding' ($okS.Issues.Count -eq 0) "got $($okS.Issues.Count)"
Assert-That '  ...and the run is READY' ($okS.Ready -eq $true)

# 2. The account was named and is NOT granted: a measured failure. Must still fail.
$script:granted = @('CONTOSO\SomeoneElse')
# A name-derived SID, so two DIFFERENT accounts do not resolve to the same identity. A single
# constant here made an ungranted DSA "match" an unrelated trustee and the controls passed for the
# wrong reason.
Set-Item -Path function:script:Resolve-mdiPrincipalSid -Value {
    param($Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    'S-1-5-21-1-2-3-' + [Math]::Abs(([string] $Name).ToUpperInvariant().GetHashCode() % 1000000)
}
Set-Item -Path function:script:Get-mdiPrincipalKind -Value { param($Name, $Domain) 'NonGroup' }
$bad = Get-mdiDeletedObjectsPermission -Domain 'test.invalid' -DirectoryServiceAccount @('CONTOSO\MDI-DSA')
$badS = Get-Surfaces -Deleted $bad
Assert-That 'an ungranted DSA is a measured failure' ([string] $bad.isDeletedObjectsPermissionOk -eq 'False') "got '$($bad.isDeletedObjectsPermissionOk)'"
Assert-That '  ...and is NOT flagged not-asserted' ((Test-mdiDomainCheckNotAsserted -Result $bad) -eq $false)
Assert-That '  ...raises a High finding' (@($badS.Issues | Where-Object { $_.Severity -eq 'High' }).Count -ge 1) "got $($badS.Issues.Count)"
Assert-That '  ...and the run is NOT READY' ($badS.Ready -eq $false)

# 3. A real gap: the DSA is absent from the ACL but a GROUP holds access, so nothing was established.
Set-Item -Path function:script:Get-mdiPrincipalKind -Value { param($Name, $Domain) 'Group' }
$gap = Get-mdiDeletedObjectsPermission -Domain 'test.invalid' -DirectoryServiceAccount @('CONTOSO\MDI-DSA')
$gapS = Get-Surfaces -Deleted $gap
Assert-That 'a group-holder gap is N/A' ([string] $gap.isDeletedObjectsPermissionOk -eq 'N/A') "got '$($gap.isDeletedObjectsPermissionOk)'"
Assert-That '  ...and is unmeasured' ($gap.Measured -eq $false) "got '$($gap.Measured)'"
Assert-That '  ...and is NOT flagged not-asserted' ((Test-mdiDomainCheckNotAsserted -Result $gap) -eq $false)
Assert-That '  ...raises a High unverified finding' (@($gapS.Issues | Where-Object { $_.Severity -eq 'High' }).Count -ge 1) "got $($gapS.Issues.Count)"
Assert-That '  ...and the run is NOT READY' ($gapS.Ready -eq $false)
Set-Item -Path function:script:Get-mdiPrincipalKind -Value { param($Name, $Domain) 'NonGroup' }

# 4. The container could not be read at all. The question WAS asked and was not answered.
$script:throwOnRead = $true
$unreadable = Get-mdiDeletedObjectsPermission -Domain 'test.invalid' -DirectoryServiceAccount $null
$unreadableS = Get-Surfaces -Deleted $unreadable
$script:throwOnRead = $false
Assert-That 'an unreadable container is N/A' ([string] $unreadable.isDeletedObjectsPermissionOk -eq 'N/A')
Assert-That '  ...and is unmeasured' ($unreadable.Measured -eq $false) "got '$($unreadable.Measured)'"
Assert-That '  ...and is NOT flagged not-asserted even with no DSA supplied' `
((Test-mdiDomainCheckNotAsserted -Result $unreadable) -eq $false) "got '$($unreadable.NotAsserted)'"
Assert-That '  ...raises a High finding' (@($unreadableS.Issues | Where-Object { $_.Severity -eq 'High' }).Count -ge 1) "got $($unreadableS.Issues.Count)"
Assert-That '  ...and the run is NOT READY' ($unreadableS.Ready -eq $false)

Write-Host 'THE DEFECT - a DEFAULT run, no -DirectoryServiceAccount, DACL read perfectly' -ForegroundColor Cyan
$script:granted = @('CONTOSO\MDI-DSA')
$default = Get-mdiDeletedObjectsPermission -Domain 'test.invalid' -DirectoryServiceAccount $null
$defaultS = Get-Surfaces -Deleted $default

Assert-That 'the producer answers N/A' ([string] $default.isDeletedObjectsPermissionOk -eq 'N/A') "got '$($default.isDeletedObjectsPermissionOk)'"
Assert-That '  ...and says it WAS measured' ($default.Measured -eq $true) "got '$($default.Measured)'"
Assert-That '  ...and reports who actually holds access' ([string] $default.details.Detail -like '*CONTOSO\MDI-DSA*') "got '$($default.details.Detail)'"
Assert-That '  ...and is flagged not-asserted' ((Test-mdiDomainCheckNotAsserted -Result $default) -eq $true) "got '$($default.NotAsserted)'"

# The verdict. This is the outcome that made every default run exit non-zero on a healthy forest.
Assert-That 'the run is READY' ($defaultS.Ready -eq $true) 'the verdict still blocks on a check nobody asked for'
# The issue list.
Assert-That 'no Deleted Objects finding is raised at all' ($defaultS.Issues.Count -eq 0) `
"got: $(@($defaultS.Issues | ForEach-Object { $_.Issue }) -join ' | ')"
Assert-That '  ...and specifically not the "no usable result" one' `
(@($defaultS.Issues | Where-Object { [string] $_.Issue -like '*no usable result*' }).Count -eq 0)
# The score card: not counted as unread...
Assert-That 'the check is not counted as UNREAD' ($defaultS.Unread -eq 0) "got $($defaultS.Unread)"
# ...and equally not counted as a check that passed.
Assert-That '  ...and is not scored as a PASSED check either' ($defaultS.Scored -eq $false) "state='$($defaultS.State)'"

Write-Host 'The HTML cell - the one surface that was always right - is unchanged' -ForegroundColor Cyan
$outDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi-notasserted-' + [Guid]::NewGuid().ToString('N'))
[void] (New-Item -ItemType Directory -Force -Path $outDir)
try {
    [void] (Set-MdiReadinessReport -Domain 'contoso.com' -Path $outDir -ReportData @($defaultS.Report) -SkipTrend 3>$null 4>$null 6>$null)
    $htmlFile = @(Get-ChildItem -LiteralPath $outDir -Filter '*.html' -File)[0]
    $html = [IO.File]::ReadAllText($htmlFile.FullName)
    $m = [regex]::Match($html, '<tr><td class="mono">contoso\.com</td><td>(<span class="pill[^<]*</span>)</td><td>([^<]*)</td></tr>')
    Assert-That 'the Deleted Objects row is rendered' ($m.Success)
    Assert-That '  ...as a neutral "Not applicable" pill' ($m.Success -and $m.Groups[1].Value -like '*pill na*' -and $m.Groups[1].Value -like '*Not applicable*') "got '$(if ($m.Success) { $m.Groups[1].Value })'"
    Assert-That '  ...carrying the trustees that were actually read' ($m.Success -and $m.Groups[2].Value -like '*MDI-DSA*') "got '$(if ($m.Success) { $m.Groups[2].Value })'"
} finally {
    Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'The remediation script writes no action for a question nobody asked' -ForegroundColor Cyan
$remDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi-notasserted-rem-' + [Guid]::NewGuid().ToString('N'))
[void] (New-Item -ItemType Directory -Force -Path $remDir)
try {
    $remPath = Join-Path $remDir 'remediation.ps1'
    [void] (New-mdiRemediationScript -ReportData $defaultS.Report -FilePath $remPath 3>$null 4>$null 6>$null)
    $rem = if (Test-Path -LiteralPath $remPath) { [IO.File]::ReadAllText($remPath) } else { '' }
    Assert-That 'no dsacls grant is emitted against the container' ($rem -notlike '*takeownership*' -and $rem -notlike '*/G "<DSA>":LCRP*')
    Assert-That '  ...and it is not listed as needing manual attention' ($rem -notlike '*Deleted Objects container permission returned no usable result*')
} finally {
    Remove-Item -LiteralPath $remDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Legacy reports: absence of the marker means false, so nothing changes for them' -ForegroundColor Cyan
# A report written before NotAsserted existed carries no such property at all.
$legacyGap = [PSCustomObject]@{
    isDeletedObjectsPermissionOk = 'N/A'
    Measured                     = $false
    details                      = [PSCustomObject]@{ Detail = 'legacy'; Trustees = @() }
}
Assert-That 'a legacy N/A result is not treated as not-asserted' ((Test-mdiDomainCheckNotAsserted -Result $legacyGap) -eq $false)
$legacyGapS = Get-Surfaces -Deleted $legacyGap
Assert-That '  ...so it still raises a High finding' (@($legacyGapS.Issues | Where-Object { $_.Severity -eq 'High' }).Count -ge 1)
Assert-That '  ...and still blocks the verdict' ($legacyGapS.Ready -eq $false)

$legacyOk = [PSCustomObject]@{
    isDeletedObjectsPermissionOk = $true
    Measured                     = $true
    details                      = [PSCustomObject]@{ Detail = 'legacy pass'; Trustees = @() }
}
$legacyOkS = Get-Surfaces -Deleted $legacyOk
Assert-That 'a legacy passing result is still scored as passed' ($legacyOkS.Scored -and $legacyOkS.State -eq $true) "scored=$($legacyOkS.Scored) state='$($legacyOkS.State)'"
Assert-That '  ...and the run is still READY' ($legacyOkS.Ready -eq $true)

Assert-That 'a null result is not treated as not-asserted' ((Test-mdiDomainCheckNotAsserted -Result $null) -eq $false)

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
