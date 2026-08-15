$ErrorActionPreference = 'Stop'
$script:p = 0; $script:f = 0
function Check {
    param($Name, $Expected, $Actual)
    if ("$Expected" -eq "$Actual") { $script:p++; '  PASS {0,-66} => {1}' -f $Name, $Actual }
    else { $script:f++; '  FAIL {0,-66} => got [{1}] want [{2}]' -f $Name, $Actual, $Expected }
}

$scriptPath = (Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1')
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$t = Get-Content $scriptPath -Raw
$t = $t -replace '(?m)^#Requires.*$', ''
$t = $t -replace '\[CmdletBinding\([^)]*\)\]', ''
$i = $t.IndexOf('#region Main'); if ($i -gt 0) { $t = $t.Substring(0, $i) }
Invoke-Expression $t

# Two roles of ONE host can both report 'N/A' for different reasons: one because the server could not
# be read ("Not tested - ...", unmeasured) and one informationally (measured, verdict intact). The
# status is 'N/A' on both, so the detail rank cannot separate them, and the tie used to be settled on
# the ordinal order of the SENTENCE - which made the answer depend on its first letter.
$notTestedV2 = 'Not tested - the service list could not be read on this server: Access is denied'
$infoV2 = 'No v2.x sensor is installed - the server can be activated directly with the v3.x sensor'
$notTestedCu = 'Not tested - the operating system build could not be read on this server'
$infoCu = 'OS build 26100.9999 is newer than the builds known to this script, verify the cumulative update level manually'

function New-Check {
    param($Status, $Detail, $Requirement = 'Required', $Name = 'C')
    [PSCustomObject]@{
        Name = $Name; Requirement = $Requirement; Status = $Status; Detail = $Detail
        Remediable = $true; Measured = (Test-mdiV3DetailMeasured -Detail $Detail)
    }
}

Write-Host ''
Write-Host '=== The two details really do sort in OPPOSITE directions ===' -ForegroundColor Cyan
# Guards the premise of this whole file: if these ever sorted the same way the ordinal tie-break
# would look correct by accident and the regression below would stop proving anything.
Check 'informational v2 text sorts BEFORE "Not tested"' $true ([string]::CompareOrdinal($infoV2, $notTestedV2) -lt 0)
Check 'informational CU text sorts AFTER  "Not tested"' $true ([string]::CompareOrdinal($infoCu, $notTestedCu) -gt 0)

Write-Host ''
Write-Host '=== An unread role keeps the merged check unmeasured, whichever way the text sorts ===' -ForegroundColor Cyan
foreach ($case in @(
        @{ Label = 'v2 migration (info sorts first)'; Unread = $notTestedV2; Info = $infoV2; Req = 'Migration' },
        @{ Label = 'cumulative update (info sorts last)'; Unread = $notTestedCu; Info = $infoCu; Req = 'Required' }
    )) {
    $u = New-Check 'N/A' $case.Unread $case.Req
    $n = New-Check 'N/A' $case.Info $case.Req
    $ab = Merge-mdiSensorV3Check -First $u -Second $n
    $ba = Merge-mdiSensorV3Check -First $n -Second $u
    Check ('{0}: merged stays unmeasured (unread,info)' -f $case.Label) $false $ab.Measured
    Check ('{0}: merged stays unmeasured (info,unread)' -f $case.Label) $false $ba.Measured
    Check ('{0}: the "could not be read" text survives' -f $case.Label) $true ([string] $ab.Detail -like 'Not tested*')
    Check ('{0}: merge is commutative on Detail' -f $case.Label) $true ([string] $ab.Detail -eq [string] $ba.Detail)
    Check ('{0}: merge is commutative on Measured' -f $case.Label) $true ([string] $ab.Measured -eq [string] $ba.Measured)
    Check ('{0}: merged status is still N/A' -f $case.Label) 'N/A' $ab.Status
}

Write-Host ''
Write-Host '=== The rule is about EVIDENCE, not about this particular wording ===' -ForegroundColor Cyan
# Synthetic informational texts either side of "Not tested" in ordinal order. Both must lose.
foreach ($info in @('AAA an informational note that sorts first', 'zzz an informational note that sorts last')) {
    $u = New-Check 'N/A' 'Not tested - the registry could not be read on this server'
    $n = New-Check 'N/A' $info
    $m = Merge-mdiSensorV3Check -First $n -Second $u
    Check ('informational "{0}..." loses to unread' -f $info.Substring(0, 3)) $false $m.Measured
}

Write-Host ''
Write-Host '=== Ranked evidence still outranks the tie-break ===' -ForegroundColor Cyan
$measuredFail = New-Check $false 'Sensor 3.0 is not installed'
$unread = New-Check 'N/A' 'Not tested - the registry could not be read on this server'
$measuredPass = New-Check $true 'Sensor 3.1 is installed and running'
$mf = Merge-mdiSensorV3Check -First $unread -Second $measuredFail
Check 'a measured FAILURE still wins over an unread role' 'Sensor 3.0 is not installed' $mf.Detail
Check 'a measured failure is still reported as measured' $true $mf.Measured
Check 'merged status of a failure is false' $false $mf.Status
$mp = Merge-mdiSensorV3Check -First $measuredPass -Second $unread
Check 'an unread role still beats a measured PASS' $true ([string] $mp.Detail -like 'Not tested*')
Check 'and drags the merged check to unmeasured' $false $mp.Measured
$mm = Merge-mdiSensorV3Check -First $measuredPass -Second $measuredPass
Check 'two measured passes stay measured' $true $mm.Measured

Write-Host ''
Write-Host '=== End to end: the honest text reaches the merged detail blob ===' -ForegroundColor Cyan
function New-Blob {
    param($Chk, $State)
    [PSCustomObject]@{
        SensorState = $State; SensorV2Version = $null; MigrationEligible = $false
        Blockers = @(); ActionableBlockers = @(); UnknownChecks = @(); Checks = @($Chk)
    }
}
$blobUnread = New-Blob (New-Check 'N/A' $notTestedV2 'Migration' 'v2 migration') 'Not determined (the installed services could not be read on this server)'
$blobInfo = New-Blob (New-Check 'N/A' $infoV2 'Migration' 'v2 migration') 'No v2.x sensor (activate v3.x)'
$mergedA = Merge-mdiSensorV3ReadyDetails -First $blobUnread -Second $blobInfo
$mergedB = Merge-mdiSensorV3ReadyDetails -First $blobInfo -Second $blobUnread
$ca = @($mergedA.Checks)[0]; $cb = @($mergedB.Checks)[0]
Check 'blob merge keeps the check unmeasured (a,b)' $false $ca.Measured
Check 'blob merge keeps the check unmeasured (b,a)' $false $cb.Measured
Check 'blob merge keeps the honest sentence' $true ([string] $ca.Detail -like 'Not tested*')
Check 'blob merge is order independent' $true ([string] $ca.Detail -eq [string] $cb.Detail)

Write-Host ''
Write-Host '=== A Required check that could not be read reaches UnknownChecks ===' -ForegroundColor Cyan
# Measured drives UnknownChecks, so an unread role must not be able to delete a Required check from
# the gap list by carrying an informational sentence that happens to sort first.
$reqUnread = New-Blob (New-Check 'N/A' 'Not tested - the registry could not be read on this server' 'Required' 'Npcap removed') 'x'
$reqInfo = New-Blob (New-Check 'N/A' 'AAA informational note' 'Required' 'Npcap removed') 'x'
$reqMerged = Merge-mdiSensorV3ReadyDetails -First $reqInfo -Second $reqUnread
Check 'the unread Required check is listed as unknown' $true (@($reqMerged.UnknownChecks) -contains 'Npcap removed')

Write-Host ''
Write-Host '=== One definition of the measured rule ===' -ForegroundColor Cyan
Check '"Not tested - x" is not measured' $false (Test-mdiV3DetailMeasured -Detail 'Not tested - x')
Check 'an ordinary sentence is measured' $true (Test-mdiV3DetailMeasured -Detail 'Sensor 3.1 installed')
Check 'a null detail does not throw' $true (Test-mdiV3DetailMeasured -Detail $null)

Write-Host ''
"TOTAL PASS=$script:p FAIL=$script:f"
if ($script:f -gt 0) { exit 1 }
