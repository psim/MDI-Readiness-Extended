# [w86] A role that could not REACH a co-located host must be charged, not erased by the merge.
#
# Merge-mdiServerByFqdn merges the Unreachable flag OPTIMISTICALLY - "reached by any role means
# reached" - which is correct about the HOST but threw away a different fact: that one ROLE was never
# examined on it.
#
# On the most ordinary small-estate topology there is, the certification authority installed ON a
# domain controller, the CA pass timed out and contributed NO CAAuditing / RootCertificates /
# AdvancedAuditingCA properties at all. The DC pass then cleared Unreachable. Those checks did not
# fail and were not counted as unread - they simply left the denominator, so the score went UP.
#
# Measured before the fix: 100% (12 of 12), "All prerequisites met", 0 issues, ChecksUnread=0,
# PartialScanCount=0 - while the JSON for the same run still carried Unreachable = true and the
# comment "Server is not available: ICMP, TCP 135, WMI". The identical CA on a host that is NOT a
# domain controller was charged correctly (92%, NOT ready), so the defect appeared only when the
# roles shared a host. Test-MergeRoles could not see it because its fixture sets PartialFailure,
# which masks the condition.
#
# The host stays REACHABLE - that is what the DC pass measured - but the run is marked a PARTIAL
# failure, which is what the unread-check accounting already keys off.
#
# Probe: MDI-AB\live\w86-camerge.ps1

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-DcRow {
    param([string] $Fqdn, [bool] $Unreachable = $false, [bool] $Partial = $false)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; IP = '10.0.0.1'
        Unreachable = $Unreachable; PartialFailure = $Partial; IsPlaceholder = $false
        NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true; RequiredPorts = $true
        SensorHealth = $true; TimeSync = $true; OSVersion = $true
        Comment = $(if ($Unreachable) { 'Server is not available: ICMP, TCP 135, WMI' } else { '' })
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
    }
}
# The CA pass that could not reach the host: NO check properties at all. That absence is the whole
# defect - an absent property is neither a pass, a failure nor an unread.
function New-UnreachableCaRow {
    param([string] $Fqdn)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; IP = '10.0.0.1'
        Unreachable = $true; PartialFailure = $false; IsPlaceholder = $false
        Comment = 'Server is not available: ICMP, TCP 135, WMI'
    }
}
function New-HealthyCaRow {
    param([string] $Fqdn)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'; IP = '10.0.0.1'
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        CAAuditing = $true; RootCertificates = $true; AdvancedAuditingCA = $true
        Comment = ''
    }
}
function Get-Row {
    param($Merged, [string] $Fqdn)
    @(@($Merged) | Where-Object { [string] $_.FQDN -eq $Fqdn })[0]
}

'[w86] a CA pass that could not reach a CO-LOCATED host is charged'
$merged = @(Merge-mdiServerByFqdn -Server @((New-DcRow -Fqdn 'dc1.contoso.com'), (New-UnreachableCaRow -Fqdn 'dc1.contoso.com')))
Assert-That 'the two roles still merge to one server' ($merged.Count -eq 1) "(got $($merged.Count))"
$row = Get-Row -Merged $merged -Fqdn 'dc1.contoso.com'
Assert-That 'the HOST is still reported reachable' ($row.Unreachable -eq $false) "(Unreachable=$($row.Unreachable))"
Assert-That 'the run is marked a PARTIAL failure' ($row.PartialFailure -eq $true) "(PartialFailure=$($row.PartialFailure))"

'[w86] and it does not depend on which role was discovered first'
# Half the orderings put the unreachable role first, where the merge loop never reaches the flag
# handling at all because the first role for a key continues out of the loop.
$rev = @(Merge-mdiServerByFqdn -Server @((New-UnreachableCaRow -Fqdn 'dc1.contoso.com'), (New-DcRow -Fqdn 'dc1.contoso.com')))
$rowRev = Get-Row -Merged $rev -Fqdn 'dc1.contoso.com'
Assert-That 'CA-first also reports the host reachable' ($rowRev.Unreachable -eq $false) "(Unreachable=$($rowRev.Unreachable))"
Assert-That 'CA-first is also marked a PARTIAL failure' ($rowRev.PartialFailure -eq $true) "(PartialFailure=$($rowRev.PartialFailure))"

'[w86] CONTROL - when every role reached the host, nothing is charged'
# Without this, marking every merged row partial would satisfy everything above.
$ok = @(Merge-mdiServerByFqdn -Server @((New-DcRow -Fqdn 'dc1.contoso.com'), (New-HealthyCaRow -Fqdn 'dc1.contoso.com')))
$rowOk = Get-Row -Merged $ok -Fqdn 'dc1.contoso.com'
Assert-That 'a fully reachable host is not marked unreachable' ($rowOk.Unreachable -eq $false) "(Unreachable=$($rowOk.Unreachable))"
Assert-That 'a fully reachable host is NOT marked partial' ($rowOk.PartialFailure -eq $false) "(PartialFailure=$($rowOk.PartialFailure))"
Assert-That '  ...and the CA checks survived the merge' ($rowOk.CAAuditing -eq $true) "(CAAuditing=$($rowOk.CAAuditing))"

'[w86] CONTROL - a STANDALONE unreachable server is still simply unreachable'
# It must keep being charged the way it always was, not be reclassified as a partial scan.
$alone = @(Merge-mdiServerByFqdn -Server @((New-DcRow -Fqdn 'dc1.contoso.com'), (New-UnreachableCaRow -Fqdn 'ca1.contoso.com')))
$rowAlone = Get-Row -Merged $alone -Fqdn 'ca1.contoso.com'
Assert-That 'the standalone CA is a separate server' ($alone.Count -eq 2) "(got $($alone.Count))"
Assert-That '  ...and is still reported unreachable' ($rowAlone.Unreachable -eq $true) "(Unreachable=$($rowAlone.Unreachable))"
Assert-That '  ...and is NOT reclassified as a partial scan' ($rowAlone.PartialFailure -eq $false) "(PartialFailure=$($rowAlone.PartialFailure))"

'[w86] CONTROL - an incoming PartialFailure still propagates'
$pf = @(Merge-mdiServerByFqdn -Server @((New-DcRow -Fqdn 'dc1.contoso.com'), (New-DcRow -Fqdn 'dc1.contoso.com' -Partial $true)))
Assert-That 'a partial role still marks the merged server partial' ((Get-Row -Merged $pf -Fqdn 'dc1.contoso.com').PartialFailure -eq $true)

'[w86] END TO END - the report no longer reads 100% / All prerequisites met'
function Get-ReportHtml {
    param($Dcs, $Cas)
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainsInScope = @('contoso.com'); LdapPlanGapDomains = @()
        DomainControllers = $Dcs; CAServers = $Cas; EntraConnectServers = @()
        DomainAuditing = @(); SkippedAreas = @()
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
    }
    $outDir = Join-Path $env:TEMP ('mdicolo-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void](New-Item -ItemType Directory -Path $outDir -Force)
    try {
        Set-MdiReadinessReport -Domain 'contoso.com' -Path $outDir -ReportData $report -SkipTrend 3>$null 4>$null 6>$null | Out-Null
        $f = @(Get-ChildItem $outDir -Filter '*.html' -File)
        if ($f.Count -eq 0) { return $null }
        [IO.File]::ReadAllText($f[0].FullName)
    } finally { Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue }
}

$html = Get-ReportHtml -Dcs @(New-DcRow -Fqdn 'dc1.contoso.com') -Cas @(New-UnreachableCaRow -Fqdn 'dc1.contoso.com')
Assert-That 'the report was written' ($null -ne $html -and $html.Length -gt 500)
Assert-That 'it does NOT claim "All prerequisites met"' (-not ($html -match 'All prerequisites met')) '(it still claims a clean estate)'
Assert-That 'it does NOT claim a 100% score' (-not ($html -match '>\s*100%\s*<')) '(it still shows 100%)'
Assert-That 'the unexamined role is disclosed as not measured' ($html -match '(?i)not measured|never (?:checked|measured)') '(nothing tells the operator)'

'[w86] END TO END - CONTROL - a fully reachable estate still reads clean'
$htmlOk = Get-ReportHtml -Dcs @(New-DcRow -Fqdn 'dc1.contoso.com') -Cas @(New-HealthyCaRow -Fqdn 'dc1.contoso.com')
Assert-That 'the control report was written' ($null -ne $htmlOk -and $htmlOk.Length -gt 500)
Assert-That 'a clean estate still says "All prerequisites met"' ($htmlOk -match 'All prerequisites met') '(the clean case was broken)'

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
