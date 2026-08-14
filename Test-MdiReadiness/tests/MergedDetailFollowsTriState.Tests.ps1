<#
    A host that holds two roles - a domain controller that is also the CA, or also the Entra Connect
    server - is scanned once per role and then merged by FQDN. Merge-mdiCheckValue merges the check
    VALUE pessimistically: measured-failure beats unread beats measured-pass, because both roles look
    at the same machine and one of them failing to read a setting means the setting is not reliably
    known.

    The DETAIL - the sentence that explains the check - did not follow the same order. It was merged on
    a single boolean, "did the incoming role measure a FAILURE", so an UNREAD role could not displace a
    PASSING role's text. On a DC+CA host where the DC pass read the clock and the CA pass could not,
    the value merged to 'N/A' while the detail kept the DC's success, and the real rendered row read:

        Within tolerance: Not tested | Skew: -3 s | Detail: Clock is within 3 second(s) of this computer

    "Not tested" beside the measurement it says was never taken, next to a stale skew, with the honest
    "the remote clock could not be read" sentence - the only actionable text there is - discarded.
    Two independent hunters working this file found it separately.

    Both merges now read one rank helper, Get-mdiCheckDetailRank, so they cannot drift apart again.
    The rank also has to keep the merge COMMUTATIVE: the same estate scanned twice must produce the
    same report regardless of the order the roles were discovered in, because the baseline trend diffs
    this text and an estate that had not changed was showing a change.
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

# One role's view of dc1: the TimeSync check plus the detail that explains it.
function New-Role {
    param($TimeSync, [string] $Detail, $Skew = $null)
    $d = [ordered]@{}
    $d['TimeSyncDetails'] = [PSCustomObject]@{ Detail = $Detail; SkewSeconds = $Skew }
    [PSCustomObject]@{
        FQDN     = 'dc1.contoso.com'
        TimeSync = $TimeSync
        Details  = $d
    }
}
function Get-Merged {
    param($First, $Second)
    $m = @(Merge-mdiServerByFqdn -Server @($First, $Second))
    if ($m.Count -ne 1) { throw "expected one merged server, got $($m.Count)" }
    $m[0]
}
function Get-MergedDetail {
    param($Server)
    [string] (Get-mdiDetailValue -Details $Server.Details -Name 'TimeSyncDetails').Detail
}

$passDetail = 'Clock is within 3 second(s) of this computer'
$unreadDetail = 'Not tested - the remote clock could not be read: The RPC server is unavailable.'
$failDetail = 'Clock differs by 14 minute(s) - MDI requires all sensor servers to be within 5 minutes'
$failDetail2 = 'Clock differs by 22 minute(s) - MDI requires all sensor servers to be within 5 minutes'
$unreadDetail2 = 'Not tested - access was denied reading the remote clock'

Write-Host 'The rank helper follows the same tri-state as the value merge' -ForegroundColor Cyan
Assert-That 'a measured FAILURE outranks everything' ((Get-mdiCheckDetailRank -Value $false) -gt (Get-mdiCheckDetailRank -Value 'N/A'))
Assert-That 'an UNREAD value outranks a measured pass' ((Get-mdiCheckDetailRank -Value 'N/A') -gt (Get-mdiCheckDetailRank -Value $true))
Assert-That '$null ranks as unread, not as a pass' ((Get-mdiCheckDetailRank -Value $null) -eq (Get-mdiCheckDetailRank -Value 'N/A'))
Assert-That 'an empty string ranks as unread' ((Get-mdiCheckDetailRank -Value '') -eq (Get-mdiCheckDetailRank -Value 'N/A'))
Assert-That 'the STRING False ranks as a failure' ((Get-mdiCheckDetailRank -Value 'False') -eq (Get-mdiCheckDetailRank -Value $false))
Assert-That 'the STRING True ranks as a pass' ((Get-mdiCheckDetailRank -Value 'True') -eq (Get-mdiCheckDetailRank -Value $true))
Assert-That 'unparseable text ranks as unread, never as a pass' ((Get-mdiCheckDetailRank -Value 'Unknown') -eq (Get-mdiCheckDetailRank -Value 'N/A'))

Write-Host 'THE DEFECT - a passing role and an UNREAD role on the same host' -ForegroundColor Cyan
$m = Get-Merged -First (New-Role -TimeSync $true -Detail $passDetail -Skew -3) -Second (New-Role -TimeSync 'N/A' -Detail $unreadDetail)
Assert-That 'the merged value is unmeasured' ([string] $m.TimeSync -eq 'N/A') "got '$($m.TimeSync)'"
Assert-That '  ...and the detail explains that it was not read' ((Get-MergedDetail -Server $m) -eq $unreadDetail) "got '$(Get-MergedDetail -Server $m)'"
Assert-That '  ...and does NOT claim the clock was within tolerance' ((Get-MergedDetail -Server $m) -notlike '*within 3 second*')
# The stale skew from the passing role must not survive next to "Not tested" either.
$skew = (Get-mdiDetailValue -Details $m.Details -Name 'TimeSyncDetails').SkewSeconds
Assert-That '  ...and the stale skew reading is gone' ([string]::IsNullOrEmpty([string] $skew)) "got '$skew'"

Write-Host '  ...and it is COMMUTATIVE - discovery order cannot change the report' -ForegroundColor Cyan
$mRev = Get-Merged -First (New-Role -TimeSync 'N/A' -Detail $unreadDetail) -Second (New-Role -TimeSync $true -Detail $passDetail -Skew -3)
Assert-That 'the reversed order gives the same value' ([string] $mRev.TimeSync -eq [string] $m.TimeSync)
Assert-That '  ...and the same detail' ((Get-MergedDetail -Server $mRev) -eq (Get-MergedDetail -Server $m)) "got '$(Get-MergedDetail -Server $mRev)'"

Write-Host 'CONTROLS - every ordering that was already correct must not move' -ForegroundColor Cyan
# A measured failure still beats a pass, and still supplies the actionable sentence.
$mf = Get-Merged -First (New-Role -TimeSync $true -Detail $passDetail) -Second (New-Role -TimeSync $false -Detail $failDetail)
Assert-That 'failure beats pass on the value' (($mf.TimeSync -is [bool]) -and ($mf.TimeSync -eq $false)) "got '$($mf.TimeSync)'"
Assert-That '  ...and supplies the failure detail' ((Get-MergedDetail -Server $mf) -eq $failDetail) "got '$(Get-MergedDetail -Server $mf)'"
$mfRev = Get-Merged -First (New-Role -TimeSync $false -Detail $failDetail) -Second (New-Role -TimeSync $true -Detail $passDetail)
Assert-That '  ...in either discovery order' ((Get-MergedDetail -Server $mfRev) -eq $failDetail) "got '$(Get-MergedDetail -Server $mfRev)'"

# A measured failure beats an UNREAD role: something was actually observed wrong.
$mfu = Get-Merged -First (New-Role -TimeSync 'N/A' -Detail $unreadDetail) -Second (New-Role -TimeSync $false -Detail $failDetail)
Assert-That 'failure beats unread on the value' (($mfu.TimeSync -is [bool]) -and ($mfu.TimeSync -eq $false)) "got '$($mfu.TimeSync)'"
Assert-That '  ...and supplies the failure detail' ((Get-MergedDetail -Server $mfu) -eq $failDetail) "got '$(Get-MergedDetail -Server $mfu)'"
$mfuRev = Get-Merged -First (New-Role -TimeSync $false -Detail $failDetail) -Second (New-Role -TimeSync 'N/A' -Detail $unreadDetail)
Assert-That '  ...in either discovery order' ((Get-MergedDetail -Server $mfuRev) -eq $failDetail) "got '$(Get-MergedDetail -Server $mfuRev)'"

# Two passing roles: the value is a pass and the detail describes success.
$mpp = Get-Merged -First (New-Role -TimeSync $true -Detail $passDetail) -Second (New-Role -TimeSync $true -Detail $passDetail)
Assert-That 'two passes merge to a pass' (($mpp.TimeSync -is [bool]) -and ($mpp.TimeSync -eq $true)) "got '$($mpp.TimeSync)'"
Assert-That '  ...with the passing detail' ((Get-MergedDetail -Server $mpp) -eq $passDetail)

Write-Host 'TIES - two roles of equal standing are settled by the value, not by arrival order' -ForegroundColor Cyan
# Two measured failures, each with its own truthful account.
$t1 = Get-Merged -First (New-Role -TimeSync $false -Detail $failDetail) -Second (New-Role -TimeSync $false -Detail $failDetail2)
$t2 = Get-Merged -First (New-Role -TimeSync $false -Detail $failDetail2) -Second (New-Role -TimeSync $false -Detail $failDetail)
Assert-That 'two failures pick the same detail in either order' ((Get-MergedDetail -Server $t1) -eq (Get-MergedDetail -Server $t2)) `
"got '$(Get-MergedDetail -Server $t1)' vs '$(Get-MergedDetail -Server $t2)'"
Assert-That '  ...and it is one of the two failure explanations' ((Get-MergedDetail -Server $t1) -in @($failDetail, $failDetail2))

# Two UNREAD roles, each explaining why it could not read. Same requirement.
$u1 = Get-Merged -First (New-Role -TimeSync 'N/A' -Detail $unreadDetail) -Second (New-Role -TimeSync 'N/A' -Detail $unreadDetail2)
$u2 = Get-Merged -First (New-Role -TimeSync 'N/A' -Detail $unreadDetail2) -Second (New-Role -TimeSync 'N/A' -Detail $unreadDetail)
Assert-That 'two unreads pick the same detail in either order' ((Get-MergedDetail -Server $u1) -eq (Get-MergedDetail -Server $u2)) `
"got '$(Get-MergedDetail -Server $u1)' vs '$(Get-MergedDetail -Server $u2)'"
Assert-That '  ...and it explains a failure to read' ((Get-MergedDetail -Server $u1) -like 'Not tested*')

Write-Host 'END TO END - the rendered row no longer contradicts itself' -ForegroundColor Cyan
$dcRole = New-Role -TimeSync $true -Detail $passDetail -Skew -3
$caRole = New-Role -TimeSync 'N/A' -Detail $unreadDetail
$mergedServer = Get-Merged -First $dcRole -Second $caRole
$report = [PSCustomObject]@{
    Domain              = 'contoso.com'
    Forest              = 'contoso.com'
    DomainsInScope      = @('contoso.com')
    DomainControllers   = @($mergedServer)
    CAServers           = @()
    EntraConnectServers = @()
    DomainAuditing      = @()
}
$outDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi-mergedetail-' + [Guid]::NewGuid().ToString('N'))
[void] (New-Item -ItemType Directory -Force -Path $outDir)
try {
    [void] (Set-MdiReadinessReport -Domain 'contoso.com' -Path $outDir -ReportData @($report) -SkipTrend 3>$null 4>$null 6>$null)
    $htmlFile = @(Get-ChildItem -LiteralPath $outDir -Filter '*.html' -File)[0]
    $html = [IO.File]::ReadAllText($htmlFile.FullName)
    $row = @([regex]::Matches($html, '<tr><td class="mono">dc1\.contoso\.com</td>.*?</tr>') |
            Where-Object { $_.Value -like '*Not tested*' -or $_.Value -like '*within 3 second*' } |
            ForEach-Object { $_.Value })
    $contradicting = @($row | Where-Object { $_ -like '*Not tested*' -and $_ -like '*within 3 second*' })
    Assert-That 'no rendered row says "Not tested" and "within 3 second" at once' ($contradicting.Count -eq 0) `
    "got: $($contradicting -join ' ;; ')"
    Assert-That '  ...and no row pairs "Not tested" with a stale -3 s skew' `
    (@($row | Where-Object { $_ -like '*Not tested*' -and $_ -like '*-3 s*' }).Count -eq 0) "got: $($row -join ' ;; ')"
} finally {
    Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
