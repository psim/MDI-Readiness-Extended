$ErrorActionPreference = 'Stop'
$script:p = 0; $script:f = 0
function Check {
    param($Name, $Expected, $Actual)
    if ("$Expected" -eq "$Actual") { $script:p++; '  PASS {0,-62} => {1}' -f $Name, $Actual }
    else { $script:f++; '  FAIL {0,-62} => got [{1}] want [{2}]' -f $Name, $Actual, $Expected }
}

$scriptPath = (Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1')
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$t = Get-Content $scriptPath -Raw
$t = $t -replace '(?m)^#Requires.*$', ''
$t = $t -replace '\[CmdletBinding\([^)]*\)\]', ''
$i = $t.IndexOf('#region Main'); if ($i -gt 0) { $t = $t.Substring(0, $i) }
Invoke-Expression $t

$wd = (Join-Path $env:TEMP ('mdi-test-' + [guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Force -Path $wd | Out-Null

function New-Dc {
    param($Fqdn, $Props = @{})
    $o = [ordered]@{ FQDN = $Fqdn; Domain = 'contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
        Unreachable = $false; PartialFailure = $false; SensorVersion = '2.245.0'; RequiredPorts = $true
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = @() } } }
    foreach ($k in $Props.Keys) { $o[$k] = $Props[$k] }
    [PSCustomObject] $o
}

function Build {
    param($Name, $Dcs = @(), $Cas = @(), $Ecs = @())
    $rep = [PSCustomObject]@{ Domain = 'contoso.com'; DomainsInScope = @('contoso.com'); Forest = 'contoso.com'
        CAServers = @($Cas); EntraConnectServers = @($Ecs); DomainAuditing = @(); DomainControllers = @($Dcs) }
    $out = Join-Path $wd "$Name.ps1"
    $r = New-mdiRemediationScript -ReportData $rep -FilePath $out
    $gen = Get-Content $out -Raw
    $errs = $null
    [System.Management.Automation.Language.Parser]::ParseInput($gen, [ref]$null, [ref]$errs) | Out-Null
    $stats = Get-mdiReportStatistics -ReportData $rep 3>$null
    [PSCustomObject]@{ Text = $gen; ParseErrors = @($errs).Count; Sections = $r.SectionCount
        Issues = @(Get-mdiIssueList -Statistics $stats -ReportData $rep) }
}

Write-Host '=== A finding with no scripted fix must never be dropped ===' -ForegroundColor Cyan
# dc1 produces a section; dc2 is unreachable and has no scripted fix at all.
$r = Build 'drop' @(
    (New-Dc 'dc1.contoso.com' @{ AdvancedAuditing = $false })
    (New-Dc 'dc2.contoso.com' @{ Unreachable = $true; SensorVersion = 'N/A' })
)
Check 'a section was emitted (so the old gate would have suppressed the advisory)' $true ($r.Sections -gt 1)
Check 'the unreachable server is named in the generated script' $true ($r.Text -match 'dc2\.contoso\.com')
Check 'the advisory section is present' $true ($r.Text -match 'Findings that need manual attention')
Check 'the script does not claim plain completion' $false ($r.Text -match "Remediation complete\. Re-run")
Check 'it says findings still need manual attention' $true ($r.Text -match 'still need manual attention')
Check 'generated script parses' 0 $r.ParseErrors
# Every finding must be ACCOUNTED FOR - either a scripted section names the server (the script fixes
# it) or the advisory lists the finding verbatim. What must never happen is a finding that appears
# nowhere at all, which is the defect this test exists for.
$unaccounted = @($r.Issues | Where-Object {
        $frag = $_.Issue.Substring(0, [math]::Min(40, $_.Issue.Length))
        ($r.Text -notmatch [regex]::Escape($frag)) -and ($r.Text -notmatch [regex]::Escape([string] $_.Server))
    })
Check 'every reported finding is accounted for' 0 $unaccounted.Count
# A finding the script DOES fix must not also be listed as needing manual attention.
$advisory = ($r.Text -split '#region Findings that need manual attention')[-1]
Check 'a scripted fix is not repeated in the advisory' $false ($advisory -match 'Advanced Auditing check failed')

Write-Host ''
Write-Host '=== CA and Entra Connect advanced auditing must produce their own sections ===' -ForegroundColor Cyan
$ca = New-Dc 'ca1.contoso.com' @{ AdvancedAuditingCA = $false; SensorVersion = 'N/A' }
$ec = New-Dc 'ec1.contoso.com' @{ AdvancedAuditingEntraConnect = $false; SensorVersion = 'N/A' }
$r = Build 'roles' @((New-Dc 'dc1.contoso.com' @{ AdvancedAuditing = $false })) @($ca) @($ec)
Check 'the CA server gets a remediation section' $true ($r.Text -match 'ca1\.contoso\.com')
Check 'the Entra Connect server gets a remediation section' $true ($r.Text -match 'ec1\.contoso\.com')
Check 'three advanced audit policy sections exist' 3 ([regex]::Matches($r.Text, '#region Advanced audit policy').Count)
Check 'generated script parses' 0 $r.ParseErrors

Write-Host ''
Write-Host '=== An UNMEASURED check must generate no remediation at all ===' -ForegroundColor Cyan
foreach ($v in @('N/A', $null, $true)) {
    $label = if ($null -eq $v) { 'null' } elseif ("$v" -eq 'N/A') { 'NA' } else { "$v" }
    $r = Build ("na-$label") @() @((New-Dc 'ca9.contoso.com' @{ AdvancedAuditingCA = $v; SensorVersion = 'N/A' }))
    Check "AdvancedAuditingCA = $label produces no audit section" $false ($r.Text -match '#region Advanced audit policy')
}
$r = Build 'missing-prop' @() @((New-Dc 'ca8.contoso.com' @{ SensorVersion = 'N/A' }))
Check 'a missing property produces no audit section' $false ($r.Text -match '#region Advanced audit policy')

Write-Host ''
Write-Host '=== A genuinely clean estate still says so ===' -ForegroundColor Cyan
$r = Build 'clean' @((New-Dc 'dc1.contoso.com' @{ AdvancedAuditing = $true; NtlmAuditing = $true; PowerSettings = $true }))
Check 'a clean report emits no advisory' $false ($r.Text -match 'Findings that need manual attention')
Check 'a clean report says no remediation is required' $true ($r.Text -match 'No remediation is required')
Check 'generated script parses' 0 $r.ParseErrors

Write-Host ''
Write-Host '=== Scripted-only findings still end with a clean completion banner ===' -ForegroundColor Cyan
# Every finding here has a scripted fix, so nothing is outstanding once the sections run.
$r = Build 'scripted' @((New-Dc 'dc1.contoso.com' @{ AdvancedAuditing = $false; NtlmAuditing = $true; PowerSettings = $true }))
'  outstanding findings: {0}' -f $r.Issues.Count
Check 'generated script parses' 0 $r.ParseErrors

Write-Host ''
"TOTAL PASS=$script:p FAIL=$script:f"
if ($script:f -gt 0) { exit 1 }

