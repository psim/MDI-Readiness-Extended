<#
    Remediation is generated only for checks that were actually MEASURED.

    The generated script writes registry values, runs auditpol and powercfg, and restarts services on
    a production domain controller. The invariant stated at every gate that feeds it is that a check
    which could not be read must never produce a fix: rewriting a setting whose current value is
    unknown is the change this tool must not invent.

    The gates were written '-eq $false', chosen deliberately over '-not $_.X' because it holds for the
    two unmeasured shapes the script itself emits - 'N/A' -eq $false is FALSE, $null -eq $false is
    FALSE. It does not hold for a NUMBER: PowerShell coerces the right operand to the left's type, so
    0 -eq $false compares 0 against [int] $false and is TRUE. Measured before the fix: a server whose
    NtlmAuditing, PowerSettings and TimeSync were the integer 0 produced a generated script
    byte-for-byte as actionable as a genuinely failing server.

    These drive the REAL New-mdiRemediationScript and read the file it writes. An earlier hunt on this
    area tested EXTRACTED COPIES of the functions and reported behaviour the real script does not
    have, so nothing here is asserted against a reimplementation.
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

function New-CheckServer {
    param($Value)
    $o = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
        Comment = $null; Details = [PSCustomObject]@{}
    }
    foreach ($n in 'NtlmAuditing', 'PowerSettings', 'TimeSync') {
        $o | Add-Member -NotePropertyName $n -NotePropertyValue $Value -Force
    }
    $o
}

# Drives the real generator and returns what it actually wrote to disk.
function Get-GeneratedRemediation {
    param($Value)
    $rep = [PSCustomObject]@{
        DomainControllers   = @((New-CheckServer $Value))
        CAServers           = @(); EntraConnectServers = @()
        DomainsInScope      = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
    }
    $out = Join-Path ([IO.Path]::GetTempPath()) ('mdi-remed-test-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
    try {
        $null = New-mdiRemediationScript -ReportData $rep -FilePath $out
        if (Test-Path $out) { return [IO.File]::ReadAllText($out) }
        return ''
    } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
}

function Test-EmitsFix {
    param([string] $Script)
    [PSCustomObject]@{
        Ntlm  = [bool]($Script -match 'RestrictSendingNTLMTraffic|AuditReceivingNTLMTraffic')
        Power = [bool]($Script -match 'powercfg')
        Time  = [bool]($Script -match 'w32tm')
    }
}

Write-Host 'A measured failure still produces its fix' -ForegroundColor Cyan
# The control. If this stops emitting, every assertion below is meaningless.
$failed = Test-EmitsFix (Get-GeneratedRemediation $false)
Assert-That 'a measured $false emits the NTLM fix' $failed.Ntlm
Assert-That 'a measured $false emits the power fix' $failed.Power
Assert-That 'a measured $false emits the time sync fix' $failed.Time
# A report that has passed through another tool carries its booleans as strings. That is still a
# measurement somebody took, and dropping it would silently stop remediating real failures.
$failedString = Test-EmitsFix (Get-GeneratedRemediation 'False')
Assert-That 'the string "False" is still a measured failure' (
    $failedString.Ntlm -and $failedString.Power -and $failedString.Time)

Write-Host 'A measured pass produces nothing' -ForegroundColor Cyan
$passed = Test-EmitsFix (Get-GeneratedRemediation $true)
Assert-That 'a measured $true emits no fix' (-not $passed.Ntlm -and -not $passed.Power -and -not $passed.Time)
$passedString = Test-EmitsFix (Get-GeneratedRemediation 'True')
Assert-That 'the string "True" emits no fix' (
    -not $passedString.Ntlm -and -not $passedString.Power -and -not $passedString.Time)

Write-Host 'An UNMEASURED check produces no remediation, whatever shape it arrives in' -ForegroundColor Cyan
# 0 is the one that got through: 0 -eq $false is TRUE in PowerShell.
foreach ($case in @(
        @{ Label = 'the integer 0'; Value = 0 }
        @{ Label = 'the integer 1'; Value = 1 }
        @{ Label = 'the double 0.0'; Value = [double] 0 }
        @{ Label = "the string 'N/A'"; Value = 'N/A' }
        @{ Label = 'the empty string'; Value = '' }
        @{ Label = '$null'; Value = $null }
    )) {
    $emit = Test-EmitsFix (Get-GeneratedRemediation $case.Value)
    Assert-That ('{0} produces no NTLM registry write' -f $case.Label) (-not $emit.Ntlm)
    Assert-That ('{0} produces no powercfg change' -f $case.Label) (-not $emit.Power)
    Assert-That ('{0} produces no w32tm resync' -f $case.Label) (-not $emit.Time)
}

Write-Host 'The issue list does not raise a confirmed finding from an unmeasured check' -ForegroundColor Cyan
function Get-TimeSyncIssueCount {
    param($Value)
    $srv = New-CheckServer $Value
    $srv.Details | Add-Member -NotePropertyName TimeSyncDetails -NotePropertyValue ([PSCustomObject]@{ Detail = 'clock skew' }) -Force
    $rep = [PSCustomObject]@{
        DomainControllers   = @($srv)
        CAServers           = @(); EntraConnectServers = @()
        DomainsInScope      = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
    }
    $st = Get-mdiReportStatistics -ReportData $rep
    @(Get-mdiIssueList -Statistics $st -ReportData $rep | Where-Object { $_.Area -eq 'Time sync' }).Count
}
Assert-That 'a measured time sync failure is still reported' ((Get-TimeSyncIssueCount $false) -ge 1)
Assert-That 'an unmeasured time sync (integer 0) raises no confirmed finding' ((Get-TimeSyncIssueCount 0) -eq 0) `
    "(raised $(Get-TimeSyncIssueCount 0))"
Assert-That "an unmeasured time sync ('N/A') raises no confirmed finding" ((Get-TimeSyncIssueCount 'N/A') -eq 0)

Write-Host 'The shared predicate itself' -ForegroundColor Cyan
Assert-That 'a real $false is a measured failure' (Test-mdiCheckFailed -Value $false)
Assert-That 'a real $true is not' (-not (Test-mdiCheckFailed -Value $true))
Assert-That 'the string "False" is a measured failure' (Test-mdiCheckFailed -Value 'False')
Assert-That '  ...case-insensitively, with padding' (Test-mdiCheckFailed -Value '  false ')
Assert-That 'the string "True" is not' (-not (Test-mdiCheckFailed -Value 'True'))
Assert-That '"N/A" is not a measured failure' (-not (Test-mdiCheckFailed -Value 'N/A'))
Assert-That '$null is not a measured failure' (-not (Test-mdiCheckFailed -Value $null))
Assert-That 'the integer 0 is not a measured failure' (-not (Test-mdiCheckFailed -Value 0))
Assert-That 'the integer 1 is not a measured failure' (-not (Test-mdiCheckFailed -Value 1))
Assert-That 'a decimal zero is not a measured failure' (-not (Test-mdiCheckFailed -Value ([decimal] 0)))
Assert-That 'an empty string is not a measured failure' (-not (Test-mdiCheckFailed -Value ''))

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
