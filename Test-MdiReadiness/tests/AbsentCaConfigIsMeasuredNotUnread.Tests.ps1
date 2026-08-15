<#
    A SUCCESSFUL READ THAT FOUND NOTHING WAS REPORTED AS A READ THAT FAILED.

    Get-mdiCAAuditing first reads HKLM\...\CertSvc\Configuration\Active to learn WHICH certification
    authority's audit settings to check. If that value came back empty, the function returned:

        isCaAuditingOk = 'N/A'
        details        = 'Not tested - the active certification authority name could not be read
                          from the registry'

    for BOTH of two different facts:

      * the registry could not be opened at all - genuinely unmeasured, and 'N/A' is right; and
      * the registry WAS opened, was read successfully, and simply has no Active value - which is a
        measurement, and means no active CA is configured on a server that was discovered as a CA,
        so the auditing this check exists to verify is definitively absent.

    Measured on the shipped reader, with only RegistryKey.OpenRemoteBaseKey replaced:

        Active value ABSENT after readable key   activeRows=1  activeReadable=True
                                                 activeValue=<null>  status=N/A
        CONTROL registry UNREADABLE              activeRows=0  activeReadable=<no row>
                                                 activeValue=<null>  status=N/A

    Identical output for a read that worked and a read that did not. The contract the rest of the
    function already follows makes the intent unambiguous: an ABSENT AuditFilter and a DWORD 0 are
    both measured failures (status=False), and only a registry that cannot be opened is 'N/A'.

    The cost is that a real, actionable finding is filed as an unread check: it does not count as a
    failure, raises no issue the operator must act on, and tells them to go and investigate a
    registry read that in fact succeeded.
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

# The registry reader is replaced at its boundary rather than deeper, so the shipped decision logic in
# Get-mdiCAAuditing is what is under test. Each case returns the row shape the real reader produces.
$script:activeResult = $null
$script:auditResult = $null
Set-Item -Path function:script:Get-mdiRegistryValueSet -Value {
    param($ComputerName, $ExpectedRegistrySet)
    if (([string] $ExpectedRegistrySet) -match 'AuditFilter') { return $script:auditResult }
    $script:activeResult
}

function New-Row {
    param([string] $Key, $Value, $Expected, $Readable = $true)
    [PSCustomObject]@{ regKey = $Key; value = $Value; expectedValue = $Expected; Readable = $Readable }
}

$configurationKey = 'System\CurrentControlSet\Services\CertSvc\Configuration\Active'
$auditKey = 'System\CurrentControlSet\Services\CertSvc\Configuration\Contoso Issuing CA\AuditFilter'

function Invoke-CaAuditing {
    param($ActiveResult, $AuditResult)
    $script:activeResult = $ActiveResult
    $script:auditResult = $AuditResult
    Get-mdiCAAuditing -ComputerName 'ca01.contoso.com' 3>$null
}

# The control has to behave, or nothing below means anything.
$configured = Invoke-CaAuditing -ActiveResult @(New-Row -Key $configurationKey -Value 'Contoso Issuing CA' -Expected '.*') `
    -AuditResult @(New-Row -Key $auditKey -Value 127 -Expected 127)
if ($configured.isCaAuditingOk -ne $true) {
    throw "the fully-configured control did not pass (got $($configured.isCaAuditingOk)) - the harness is not reaching the shipped logic"
}

Write-Host 'A read that succeeded and found nothing is a measurement, not a gap' -ForegroundColor Cyan
# The key opened, the reader looked, the value is not there.
$absent = Invoke-CaAuditing -ActiveResult @(New-Row -Key $configurationKey -Value $null -Expected '.*' -Readable $true) `
    -AuditResult $null
Assert-That 'an absent Active after a successful read is a measured failure' (
    $absent.isCaAuditingOk -eq $false) "isCaAuditingOk=$($absent.isCaAuditingOk)"
Assert-That 'and it is a real boolean, not the string N/A' (
    $absent.isCaAuditingOk -is [bool]) "type=$($absent.isCaAuditingOk.GetType().Name)"
Assert-That 'the detail does not claim the registry could not be read' (
    [string] $absent.details -notmatch 'could not be read') "details=$($absent.details)"
Assert-That 'the detail says what was actually established' (
    [string] $absent.details -match 'no active certification authority is configured') (
    "details=$($absent.details)")
# An empty string is the same fact as a null: the reader looked and there is nothing there.
$blank = Invoke-CaAuditing -ActiveResult @(New-Row -Key $configurationKey -Value '' -Expected '.*' -Readable $true) `
    -AuditResult $null
Assert-That 'an empty Active value is treated the same way' (
    $blank.isCaAuditingOk -eq $false) "isCaAuditingOk=$($blank.isCaAuditingOk)"

Write-Host ''
Write-Host 'CONTROLS - a read that did NOT succeed must stay unmeasured' -ForegroundColor Cyan
# No row at all: the reader could not open the key.
$noRow = Invoke-CaAuditing -ActiveResult $null -AuditResult $null
Assert-That 'CONTROL: an unreadable registry is still N/A' (
    [string] $noRow.isCaAuditingOk -eq 'N/A') "isCaAuditingOk=$($noRow.isCaAuditingOk)"
Assert-That 'CONTROL: and still says it could not be read' (
    [string] $noRow.details -match 'could not be read') "details=$($noRow.details)"

# A row that explicitly reports itself unreadable - access denied on the value.
$unreadable = Invoke-CaAuditing -ActiveResult @(New-Row -Key $configurationKey -Value $null -Expected '.*' -Readable $false) `
    -AuditResult $null
Assert-That 'CONTROL: a row flagged unreadable is still N/A' (
    [string] $unreadable.isCaAuditingOk -eq 'N/A') "isCaAuditingOk=$($unreadable.isCaAuditingOk)"

# 'N/A' is a truthy string and so is 'False'. A Readable that came back through a JSON round trip as
# the STRING 'False' must not be read as a successful read - that would turn an unmeasured result
# into a measured failure, which is the same defect in the opposite direction.
$stringFalse = Invoke-CaAuditing -ActiveResult @(New-Row -Key $configurationKey -Value $null -Expected '.*' -Readable 'False') `
    -AuditResult $null
Assert-That 'CONTROL: a string "False" Readable is not mistaken for a successful read' (
    [string] $stringFalse.isCaAuditingOk -eq 'N/A') "isCaAuditingOk=$($stringFalse.isCaAuditingOk)"

Write-Host ''
Write-Host 'CONTROLS - the contract this now matches, on the required value itself' -ForegroundColor Cyan
$auditAbsent = Invoke-CaAuditing -ActiveResult @(New-Row -Key $configurationKey -Value 'Contoso Issuing CA' -Expected '.*') `
    -AuditResult @(New-Row -Key $auditKey -Value $null -Expected 127)
Assert-That 'CONTROL: an absent AuditFilter is a measured failure' (
    $auditAbsent.isCaAuditingOk -eq $false) "isCaAuditingOk=$($auditAbsent.isCaAuditingOk)"
$auditZero = Invoke-CaAuditing -ActiveResult @(New-Row -Key $configurationKey -Value 'Contoso Issuing CA' -Expected '.*') `
    -AuditResult @(New-Row -Key $auditKey -Value 0 -Expected 127)
Assert-That 'CONTROL: a DWORD 0 AuditFilter is a measured failure' (
    $auditZero.isCaAuditingOk -eq $false) "isCaAuditingOk=$($auditZero.isCaAuditingOk)"
Assert-That 'CONTROL: a fully configured CA still passes' (
    $configured.isCaAuditingOk -eq $true) "isCaAuditingOk=$($configured.isCaAuditingOk)"
# A superset of the required audit bits is not a misconfiguration.
$superset = Invoke-CaAuditing -ActiveResult @(New-Row -Key $configurationKey -Value 'Contoso Issuing CA' -Expected '.*') `
    -AuditResult @(New-Row -Key $auditKey -Value 255 -Expected 127)
Assert-That 'CONTROL: auditing MORE than required still passes' (
    $superset.isCaAuditingOk -eq $true) "isCaAuditingOk=$($superset.isCaAuditingOk)"

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
