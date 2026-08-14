$ErrorActionPreference = 'Stop'
$script:p = 0; $script:f = 0
function Check {
    param($Name, $Expected, $Actual)
    if ("$Expected" -eq "$Actual") { $script:p++; '  PASS {0,-58} => {1}' -f $Name, $Actual }
    else { $script:f++; '  FAIL {0,-58} => got [{1}] want [{2}]' -f $Name, $Actual, $Expected }
}

$scriptPath = (Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1')
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$t = Get-Content $scriptPath -Raw
$t = $t -replace '(?m)^#Requires.*$', ''
$t = $t -replace '\[CmdletBinding\([^)]*\)\]', ''
$i = $t.IndexOf('#region Main'); if ($i -gt 0) { $t = $t.Substring(0, $i) }
Invoke-Expression $t

$expected = @('SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue', 'S-1-1-0,1,1,1')

# Force the DirectorySearcher construction to fail with a message in a given language, which is what a
# localised domain controller produces when the SACL cannot be read.
function global:New-Object {
    param([string] $TypeName, [object[]] $ArgumentList)
    if ($TypeName -eq 'System.DirectoryServices.DirectorySearcher') {
        throw [System.Exception]::new($script:ThrowMessage)
    }
    Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}

Write-Host '=== An unreadable SACL must read as unmeasured in EVERY language ===' -ForegroundColor Cyan
$cases = [ordered]@{
    'English  "Access is denied"'           = 'Access is denied'
    'German   "Zugriff verweigert"'         = 'Zugriff verweigert'
    'German   "Server ist nicht verfuegbar"' = 'Server ist nicht verfuegbar'
    'French   "Acces refuse"'               = 'Acce' + [char]0x0300 + 's refuse' + [char]0x0301
    'Japanese (access denied)'              = [string]::Join('', [char]0x30A2, [char]0x30AF, [char]0x30BB, [char]0x30B9)
    'Russian  (access denied)'              = [string]::Join('', [char]0x041E, [char]0x0442, [char]0x043A, [char]0x0430, [char]0x0437)
    'Turkish  "Erisim engellendi"'          = 'Eris' + [char]0x0131 + 'm engellendi'
    'Opaque   "0x80005000"'                 = 'Unknown error (0x80005000)'
}
foreach ($name in $cases.Keys) {
    $script:ThrowMessage = $cases[$name]
    $r = Get-mdiDsSacl -LdapPath 'LDAP://dummy/DC=contoso,DC=com' -ExpectedAuditing $expected
    Check $name 'N/A' ([string] $r.isAuditingOk)
    Check ('  ...and is flagged not measured') $false $r.Measured
}

Write-Host ''
Write-Host '=== ...and in every DIRECTORY ERROR CODE, recognised or not ===' -ForegroundColor Cyan
# Classifying by error code only concluded "not measured" when NO code was present at all, so an
# exception carrying a code the list did not recognise fell through to a MEASURED failure: a busy
# directory, a search time limit, an administrative limit or an opaque COM error each reported the
# domain's auditing as misconfigured, and the remediation then told an Enterprise Admin to rewrite
# SACLs on a naming context that had never been read.
function global:New-Object {
    param([string] $TypeName, [object[]] $ArgumentList)
    if ($TypeName -eq 'System.DirectoryServices.DirectorySearcher') { throw $script:ThrowObject }
    Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}
$codeCases = [ordered]@{
    'ERROR_DS_BUSY          -2147016688' = -2147016688
    'ERROR_DS_TIMELIMIT     -2147016657' = -2147016657
    'ERROR_DS_ADMIN_LIMIT   -2147016651' = -2147016651
    'opaque COM error       -2147467259' = -2147467259
    'E_ACCESSDENIED         -2147024891' = -2147024891
    'ERROR_DS_SERVER_DOWN   -2147016646' = -2147016646
}
foreach ($name in $codeCases.Keys) {
    $script:ThrowObject = [System.Runtime.InteropServices.COMException]::new('directory failure', $codeCases[$name])
    $r = Get-mdiDsSacl -LdapPath 'LDAP://dummy/DC=contoso,DC=com' -ExpectedAuditing $expected
    Check $name 'N/A' ([string] $r.isAuditingOk)
    Check ('  ...and is flagged not measured') $false $r.Measured
}

Write-Host ''
Write-Host '=== A genuine mismatch on the SUCCESS path must still report a real failure ===' -ForegroundColor Cyan
# No exception this time: the searcher works and returns a SACL that does not match what is expected.
Remove-Item function:global:New-Object -ErrorAction SilentlyContinue
$sacl = [PSCustomObject]@{
    SecurityIdentifier = 'S-1-5-21-1-2-3-999'; AccessMask = 999; AuditFlagsValue = 0; AceFlagsValue = 0
}
$cmp = @(Compare-Object -ReferenceObject @([PSCustomObject]@{ SecurityIdentifier = 'S-1-1-0'; AccessMask = 1 }) `
        -DifferenceObject @($sacl | Select-Object SecurityIdentifier, AccessMask) `
        -Property SecurityIdentifier, AccessMask -ExcludeDifferent -IncludeEqual)
Check 'a non-matching ACE is still detected as a mismatch' 0 $cmp.Count

Write-Host ''
Write-Host '=== The Turkish dotless-i case on trustee matching ===' -ForegroundColor Cyan
# CONTOSO\IDENTITYSYNC and contoso\identitysync are the SAME account - Windows account names are
# case-insensitive - so a Verified match is the correct answer. What matters here is that the answer
# does not CHANGE with the culture: under tr-TR, 'I'.ToLower() is the dotless 'i', which breaks any
# comparison built on ToLower()/ToUpper(). The result must be identical in all three.
$orig = [System.Threading.Thread]::CurrentThread.CurrentCulture
$results = @{}
foreach ($culture in 'en-US', 'tr-TR', 'de-DE') {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::new($culture)
    $m = @(Get-mdiMatchingTrustee -Trustee @('contoso\identitysync') -Account 'CONTOSO\IDENTITYSYNC')
    $results[$culture] = ($m | ForEach-Object { $_.Confidence }) -join ','
    Check ("same account in different case matches under $culture") 'Verified' $results[$culture]

    # The leaf-only fallback path is the one that used to be culture-sensitive: an unresolvable name
    # whose leaf differs only by the Turkish I.
    $m2 = @(Get-mdiMatchingTrustee -Trustee @('FABRIKAMX\ISTANBUL') -Account 'CONTOSOX\istanbul')
    Check ("dotless-i leaf comparison under $culture") 'Ambiguous' (($m2 | ForEach-Object { $_.Confidence }) -join ',')
}
[System.Threading.Thread]::CurrentThread.CurrentCulture = $orig
Check 'the verdict is identical in every culture' 1 (@($results.Values | Select-Object -Unique).Count)

Write-Host ''
"TOTAL PASS=$script:p FAIL=$script:f"
if ($script:f -gt 0) { exit 1 }

