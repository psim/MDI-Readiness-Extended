$ErrorActionPreference = 'Stop'
$script:p = 0; $script:f = 0
function Check {
    param($Name, $Expected, $Actual)
    if ("$Expected" -eq "$Actual") { $script:p++; '  PASS {0,-56} => {1}' -f $Name, $Actual }
    else { $script:f++; '  FAIL {0,-56} => got [{1}] want [{2}]' -f $Name, $Actual, $Expected }
}

$wd = (Join-Path $env:TEMP ('mdi-test-' + [guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Force -Path $wd | Out-Null

# Built from code points so this probe file is itself immune to the encoding problem it tests.
$umlaut = 'dc-m' + [char]0x00FC + 'nchen.contoso.com'
$cyr = [string]::Join('', [char]0x041E, [char]0x0448, [char]0x0438, [char]0x0431, [char]0x043A, [char]0x0430)
$jp = [string]::Join('', [char]0x6771, [char]0x4EAC)
$emoji = [char]0xD83D + [char]0xDE03
$sample = '{{"Target":"{0}","Detail":"{1} {2} {3}"}}' -f $umlaut, $cyr, $jp, $emoji

'PSVersion: {0}' -f $PSVersionTable.PSVersion
Write-Host ''
Write-Host '=== Probe JSON round trip: writer encoding vs Get-Content reader ===' -ForegroundColor Cyan

# OLD behaviour: UTF-8 with NO byte order mark, read back with a bare Get-Content.
$old = Join-Path $wd 'old.json'
[System.IO.File]::WriteAllText($old, $sample, (New-Object System.Text.UTF8Encoding $false))
$oldBack = (Get-Content -Path $old) -join ''
$oldParsed = $null
try { $oldParsed = $oldBack | ConvertFrom-Json } catch {}
Check 'OLD (no BOM) preserves the umlaut target' $false ($oldParsed.Target -eq $umlaut)

# NEW behaviour: UTF-8 WITH a byte order mark, same reader.
$new = Join-Path $wd 'new.json'
[System.IO.File]::WriteAllText($new, $sample, (New-Object System.Text.UTF8Encoding $true))
$newBack = (Get-Content -Path $new) -join ''
$newParsed = $newBack | ConvertFrom-Json
Check 'NEW (BOM) preserves the umlaut target' $true ($newParsed.Target -eq $umlaut)
Check 'NEW preserves Cyrillic + Japanese + emoji detail' $true ($newParsed.Detail -eq ('{0} {1} {2}' -f $cyr, $jp, $emoji))
Check 'NEW parses as JSON at all' $true ($null -ne $newParsed)
'  target read back, code points: {0}' -f (($newParsed.Target.ToCharArray() | Select-Object -First 6 | ForEach-Object { '{0:X4}' -f [int]$_ }) -join ' ')

Write-Host ''
Write-Host '=== Remediation status file round trip ===' -ForegroundColor Cyan
$msg = 'FAIL: Acc' + [char]0x00E8 + 's refus' + [char]0x00E9 + ' ' + $jp + ' ' + $emoji
$oldStatus = Join-Path $wd 'old-status.txt'
$msg | Set-Content -Path $oldStatus -Encoding ASCII
Check 'OLD (ASCII) loses the localised message' $false (((Get-Content -Path $oldStatus -Raw).Trim()) -eq $msg)
$newStatus = Join-Path $wd 'new-status.txt'
$msg | Set-Content -Path $newStatus -Encoding UTF8
Check 'NEW (UTF8) round trips the localised message' $true (((Get-Content -Path $newStatus -Raw).Trim()) -eq $msg)

Write-Host ''
Write-Host '=== The generated remediation script still parses and uses UTF8 ===' -ForegroundColor Cyan
$scriptPath = (Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1')
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$t = Get-Content $scriptPath -Raw
$t = $t -replace '(?m)^#Requires.*$', ''
$t = $t -replace '\[CmdletBinding\([^)]*\)\]', ''
$i = $t.IndexOf('#region Main'); if ($i -gt 0) { $t = $t.Substring(0, $i) }
Invoke-Expression $t

$dc = [PSCustomObject]@{
    FQDN = $umlaut; Domain = 'contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
    Unreachable = $false; PartialFailure = $false; SensorVersion = '2.245.0'; AdvancedAuditing = $false
    RequiredPorts = $true
    Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = @() } }
}
$rep = [PSCustomObject]@{ Domain = 'contoso.com'; DomainsInScope = @('contoso.com'); Forest = 'contoso.com'
    CAServers = @(); EntraConnectServers = @(); DomainAuditing = @(); DomainControllers = @($dc) }
$outFile = Join-Path $wd 'remediation.ps1'
New-mdiRemediationScript -ReportData $rep -FilePath $outFile | Out-Null
$gen = Get-Content $outFile -Raw
$errs = $null
[System.Management.Automation.Language.Parser]::ParseInput($gen, [ref]$null, [ref]$errs) | Out-Null
Check 'generated remediation script parses cleanly' 0 @($errs).Count
Check 'status file is written as UTF8, not ASCII' $false ($gen -match 'Encoding ASCII')
Check 'status file writer uses UTF8' $true ($gen -match 'Encoding UTF8')
Check 'the non-ASCII server name survives into the script' $true ($gen -match ([regex]::Escape($umlaut)))

Write-Host ''
"TOTAL PASS=$script:p FAIL=$script:f"
if ($script:f -gt 0) { exit 1 }

