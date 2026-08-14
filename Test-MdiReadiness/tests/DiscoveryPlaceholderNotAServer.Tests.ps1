<#
    A discovery placeholder is not a server, and it says what actually went wrong.

    Two producers emit a row for a role they could not enumerate: Get-mdiCAReadiness when the
    certification authorities of a domain cannot be listed, and Get-mdiEntraConnectReadiness when the
    sync server cannot be identified. The row exists so the role is reported as not-measured instead
    of rendering as "nothing to check here" - and that part always worked, because its 'N/A' marker is
    charged as an unread check.

    Nothing distinguished it from a machine, though, and it arrives inside the REAL server collections
    rather than being appended by Get-mdiReportStatistics, so it was never given Kind = 'Unmeasured'
    like the synthetic rows are. On a one-server estate whose AD CS enumeration was denied, three
    headline numbers lied at once:

        Servers scanned      2      (the estate has one server)
        Servers fully ready  1/2    (a ratio that can never be reached)
        console              "1 issue(s) found: 7/8 checks passed across 2 server(s)."

    The genuinely unreachable server - the same class of gap - was already excluded from those counts,
    so two surfaces of one idea disagreed inside a single run.

    Its finding was wrong too. The generic unread-check loop described the placeholder's 'N/A' sensor
    marker as "Sensor Health could not be read on this server, so its state is unknown", sending the
    operator to look at a sensor on a machine that does not exist, while the row's Comment carried the
    real cause (the directory read that was denied, and the -CAServer switch that works around it).

    Invariants pinned here, all asserted on BEHAVIOUR - the statistics, the issue list and the rendered
    KPI cards - never on the text of the script:

      1. a placeholder is not counted in TotalServers or ReachableServers
      2. a placeholder scores Kind = 'Unmeasured', exactly as an unreachable server does
      3. the unread check it exists to record is still charged, so the score is NOT 100%
      4. its finding names the real cause from the Comment, and does not blame a sensor
      5. the "Servers fully ready" denominator equals the real reachable population
      6. a real server is unaffected: none of the above fires when discovery succeeded
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

function New-PassingDc {
    param($Fqdn = 'dc1.contoso.com')
    $o = [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
        Comment = $null; Details = [PSCustomObject]@{}
    }
    foreach ($n in 'NtlmAuditing', 'AdvancedAuditing', 'PowerSettings') {
        $o | Add-Member -NotePropertyName $n -NotePropertyValue $true -Force
    }
    $o
}

# The exact shape Get-mdiCAReadiness emits when Cert Publishers cannot be enumerated.
function New-CaPlaceholder {
    [PSCustomObject]@{
        FQDN           = 'AD CS (not enumerated) - contoso.com'
        Domain         = 'contoso.com'
        SensorHealth   = 'N/A'
        Comment        = 'The certification authorities of this domain could not be enumerated (Access is denied), so AD CS was NOT checked here. Re-run with sufficient directory read rights, or pass -CAServer <name> to check a known CA.'
        Unreachable    = $false
        PartialFailure = $false
        IsPlaceholder  = $true
        Details        = [ordered]@{}
    }
}

# The shape Get-mdiEntraConnectReadiness emits when the sync server cannot be identified.
function New-EntraPlaceholder {
    [PSCustomObject]@{
        FQDN           = 'Entra Connect (not identified) - contoso.com'
        Domain         = 'contoso.com'
        SensorHealth   = 'N/A'
        Comment        = 'A directory-synchronization (Entra Connect) account was found in this domain but the sync server could not be identified automatically. Re-run with -EntraConnectServer <name> to verify it.'
        Unreachable    = $false
        PartialFailure = $false
        IsPlaceholder  = $true
        Details        = [ordered]@{}
    }
}

function New-UnreachableCa {
    [PSCustomObject]@{
        FQDN = 'ca1.contoso.com'; Domain = 'contoso.com'; SensorHealth = $null
        Comment = 'Server is not available: ICMP'; Unreachable = $true; PartialFailure = $false
        Details = [ordered]@{}
    }
}

function New-Report {
    param($Dc, $Ca, $Entra)
    [PSCustomObject]@{
        DomainControllers   = @($Dc | Where-Object { $_ })
        CAServers           = @($Ca | Where-Object { $_ })
        EntraConnectServers = @($Entra | Where-Object { $_ })
        DomainsInScope      = @('contoso.com')
        Domains             = @()
        ForestDiscovery     = [PSCustomObject]@{ Complete = $true }
    }
}

function Get-Facts {
    param($Report)
    $st = Get-mdiReportStatistics -ReportData $Report
    $issues = @(Get-mdiIssueList -Statistics $st -ReportData $Report)
    $html = Get-mdiOverviewHtml -Statistics $st -ReportData $Report | Out-String
    [PSCustomObject]@{
        Stats        = $st
        TotalServers = [int] $st.TotalServers
        Reachable    = [int] $st.ReachableServers
        Passed       = [int] $st.ChecksPassed
        Unread       = [int] $st.ChecksUnread
        Denominator  = [int] (Get-mdiCoverageDenominator -Measured $st.ChecksTotal -Unread $st.ChecksUnread)
        Percent      = [int] [math]::Floor((Get-mdiCoveragePercent -Passed $st.ChecksPassed -Measured $st.ChecksTotal -Unread $st.ChecksUnread))
        Issues       = $issues
        Html         = $html
    }
}

Write-Host 'Discovery placeholders are not servers' -ForegroundColor Cyan

# --- 1. AD CS enumeration denied on a one-server estate ------------------------------------------
$f = Get-Facts (New-Report -Dc (New-PassingDc) -Ca (New-CaPlaceholder))

Assert-That 'CA placeholder is not counted in TotalServers' ($f.TotalServers -eq 1) ("got $($f.TotalServers)")
Assert-That 'CA placeholder is not counted in ReachableServers' ($f.Reachable -eq 1) ("got $($f.Reachable)")

$phScore = @($f.Stats.ServerScores | Where-Object { $_.FQDN -like 'AD CS*' })
Assert-That 'CA placeholder produces exactly one score row' ($phScore.Count -eq 1) ("got $($phScore.Count)")
Assert-That 'CA placeholder scores Kind = Unmeasured' ([string] $phScore[0].Kind -eq 'Unmeasured') ("got '$([string] $phScore[0].Kind)'")

# The whole reason the row is emitted: the gap must still be charged.
Assert-That 'the unenumerated role is still charged as an unread check' ($f.Unread -ge 1) ("unread=$($f.Unread)")
Assert-That 'the check score is not a perfect 100% over an unenumerated role' ($f.Percent -lt 100) ("pct=$($f.Percent)")
Assert-That 'the placeholder is still in the check denominator' ($f.Denominator -gt $f.Passed) ("passed=$($f.Passed) den=$($f.Denominator)")

$phIssue = @($f.Issues | Where-Object { [string] $_.Server -like 'AD CS*' })
Assert-That 'CA placeholder raises exactly one finding' ($phIssue.Count -eq 1) ("got $($phIssue.Count)")
Assert-That 'the finding names the real cause (enumeration), not a sensor' (
    $phIssue.Count -eq 1 -and
    [string] $phIssue[0].Issue -like '*could not be enumerated*' -and
    [string] $phIssue[0].Issue -notlike '*Sensor Health*'
) ("got '$([string] $phIssue[0].Issue)'")
Assert-That 'the finding tells the operator how to work around it' (
    $phIssue.Count -eq 1 -and [string] $phIssue[0].Issue -like '*-CAServer*'
) ("got '$([string] $phIssue[0].Issue)'")

# The rendered card, not an internal number: this is the surface that was screenshotted wrong.
Assert-That 'the KPI card does not claim a second server was scanned' ($f.Html -notmatch '(?s)Servers scanned.{0,400}>2<') $f.Html.Length
Assert-That 'the "fully ready" ratio uses the real reachable population' ($f.Html -match '1/1') 'expected 1/1'
Assert-That 'the "fully ready" ratio is not out of 2' ($f.Html -notmatch '\b1/2\b') 'found 1/2'

# --- 2. Entra Connect placeholder behaves identically ---------------------------------------------
$e = Get-Facts (New-Report -Dc (New-PassingDc) -Entra (New-EntraPlaceholder))
Assert-That 'Entra placeholder is not counted in TotalServers' ($e.TotalServers -eq 1) ("got $($e.TotalServers)")
$eScore = @($e.Stats.ServerScores | Where-Object { $_.FQDN -like 'Entra Connect*' })
Assert-That 'Entra placeholder scores Kind = Unmeasured' (
    $eScore.Count -eq 1 -and [string] $eScore[0].Kind -eq 'Unmeasured'
) ("got '$([string] $eScore[0].Kind)'")
Assert-That 'Entra placeholder is still charged as unread' ($e.Unread -ge 1) ("unread=$($e.Unread)")
$eIssue = @($e.Issues | Where-Object { [string] $_.Server -like 'Entra Connect*' })
Assert-That 'Entra placeholder finding names the identification failure' (
    $eIssue.Count -eq 1 -and
    [string] $eIssue[0].Issue -like '*could not be identified*' -and
    [string] $eIssue[0].Issue -notlike '*Sensor Health*'
) ("got '$([string] $eIssue[0].Issue)'")

# --- 3. The placeholder is classified the same way an unreachable server is ------------------------
$u = Get-Facts (New-Report -Dc (New-PassingDc) -Ca (New-UnreachableCa))
$uScore = @($u.Stats.ServerScores | Where-Object { $_.FQDN -eq 'ca1.contoso.com' })
Assert-That 'control: an unreachable server also scores Kind = Unmeasured' (
    $uScore.Count -eq 1 -and [string] $uScore[0].Kind -eq 'Unmeasured'
) ("got '$([string] $uScore[0].Kind)'")
Assert-That 'control: the unreachable server IS a server in the count' ($u.TotalServers -eq 2) ("got $($u.TotalServers)")

# --- 4. A real estate is untouched -----------------------------------------------------------------
$ok = Get-Facts (New-Report -Dc (New-PassingDc))
Assert-That 'a clean run still counts its server' ($ok.TotalServers -eq 1) ("got $($ok.TotalServers)")
Assert-That 'a clean run still scores 100%' ($ok.Percent -eq 100) ("pct=$($ok.Percent)")
Assert-That 'a clean run raises no findings' (@($ok.Issues).Count -eq 0) ("got $(@($ok.Issues).Count)")
$okScore = @($ok.Stats.ServerScores | Where-Object { $_.FQDN -eq 'dc1.contoso.com' })
Assert-That 'a real server is still Kind = Server' (
    $okScore.Count -eq 1 -and [string] $okScore[0].Kind -eq 'Server'
) ("got '$([string] $okScore[0].Kind)'")

# --- 5. The flag is normalised, not tested for bare truthiness -------------------------------------
# A report that has been through JSON or another tool carries the flag as a STRING. Every non-empty
# string is truthy in PowerShell, so 'False' would have turned a real server into a placeholder and
# deleted it from the estate count.
$stringFalse = New-PassingDc
$stringFalse | Add-Member -NotePropertyName 'IsPlaceholder' -NotePropertyValue 'False' -Force
$sf = Get-Facts (New-Report -Dc $stringFalse)
Assert-That "IsPlaceholder='False' (string) leaves the server counted" ($sf.TotalServers -eq 1) ("got $($sf.TotalServers)")

$stringTrue = New-CaPlaceholder
$stringTrue.IsPlaceholder = 'True'
$stt = Get-Facts (New-Report -Dc (New-PassingDc) -Ca $stringTrue)
Assert-That "IsPlaceholder='True' (string) is still a placeholder" ($stt.TotalServers -eq 1) ("got $($stt.TotalServers)")

# A legacy report carries no flag at all and must keep counting as the server it is.
$legacy = New-PassingDc
$lg = Get-Facts (New-Report -Dc $legacy)
Assert-That 'a report with no IsPlaceholder property still counts its servers' ($lg.TotalServers -eq 1) ("got $($lg.TotalServers)")

# --- 6. The predicate itself ------------------------------------------------------------------------
Assert-That 'Test-mdiServerIsPlaceholder on $null is false' (-not (Test-mdiServerIsPlaceholder -Server $null))
Assert-That 'Test-mdiServerIsPlaceholder on a real server is false' (-not (Test-mdiServerIsPlaceholder -Server (New-PassingDc)))
Assert-That 'Test-mdiServerIsPlaceholder on a placeholder is true' (Test-mdiServerIsPlaceholder -Server (New-CaPlaceholder))

# --- 7. End to end, through the REAL producers ------------------------------------------------------
# Everything above builds the placeholder row by hand, which pins the CONSUMERS but leaves the
# producers free to stop marking the row - the flag could be deleted from Get-mdiCAReadiness and every
# assertion above would still pass. So the last section drives the real producer with only its two
# directory reads stubbed, and asserts the row it actually emits is recognised as a placeholder.
#
# Stubbed with Set-Item -Path function:script: - a `function global:` does NOT override a function the
# script defined for itself, and the stub would silently never be called.
Set-Item -Path function:script:Get-ADDomain -Value {
    param($Server, $ErrorAction)
    [PSCustomObject]@{ DomainSID = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3' } }
}
Set-Item -Path function:script:Get-ADGroupMember -Value {
    param($Server, $Identity, $ErrorAction)
    throw 'Access is denied'
}
Set-Item -Path function:script:Test-mdiServerReachable -Value {
    param($ComputerName) [PSCustomObject]@{ Reachable = $false; Method = 'stubbed' }
}

$emitted = @(Get-mdiCAReadiness -Domain 'contoso.com' 3>$null)
Assert-That 'the real producer emits one row when CA enumeration is denied' ($emitted.Count -eq 1) ("got $($emitted.Count)")
Assert-That 'the row the real producer emits IS marked as a placeholder' (
    $emitted.Count -eq 1 -and (Test-mdiServerIsPlaceholder -Server $emitted[0])
) ("IsPlaceholder='$([string] $emitted[0].IsPlaceholder)' on '$([string] $emitted[0].FQDN)'")

$live = Get-Facts (New-Report -Dc (New-PassingDc) -Ca $emitted)
Assert-That 'end to end: the produced placeholder is not counted as a server' ($live.TotalServers -eq 1) ("got $($live.TotalServers)")
$liveScore = @($live.Stats.ServerScores | Where-Object { $_.FQDN -like 'AD CS*' })
Assert-That 'end to end: the produced placeholder scores Kind = Unmeasured' (
    $liveScore.Count -eq 1 -and [string] $liveScore[0].Kind -eq 'Unmeasured'
) ("got '$([string] $liveScore[0].Kind)'")
Assert-That 'end to end: the produced placeholder is still charged as unread' ($live.Unread -ge 1) ("unread=$($live.Unread)")
$liveIssue = @($live.Issues | Where-Object { [string] $_.Server -like 'AD CS*' })
Assert-That 'end to end: its finding names the enumeration failure' (
    $liveIssue.Count -eq 1 -and [string] $liveIssue[0].Issue -like '*could not be enumerated*'
) ("got '$([string] $liveIssue[0].Issue)'")

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
exit 0
