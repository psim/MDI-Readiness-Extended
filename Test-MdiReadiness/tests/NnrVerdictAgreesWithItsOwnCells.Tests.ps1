<#
    The NNR matrix drew a target's method cells as "Blocked" and its Resolvable verdict as
    "Not tested", on the same row, at the same time.

    The rows of that table are admitted by SCOPE - Get-mdiRequiredPortsHtml selects
    "$_.Scope -eq 'NetworkDevice'" - while the Resolvable column was decided by the record's own
    GROUP field ("$_.Group -eq 'NNR'"). Two different fields answering one question, so a record
    that kept its Scope but lost its Group was still drawn as a row, its method cells still
    rendered the real measurements, and the verdict beside them was computed from an EMPTY set,
    which renders "Not tested".

    Measured on the shipped function before the fix, one target with both primary methods REFUSED
    and nothing differing but the Group field:

        Group 'NNR'   cells Blocked,Blocked   verdict "No"          (red)
        Group $null   cells Blocked,Blocked   verdict "Not tested"  (muted)
        Group ''      cells Blocked,Blocked   verdict "Not tested"  (muted)
        Group 12345   cells Blocked,Blocked   verdict "Not tested"  (muted)

    A target whose every primary name-resolution method was measured shut therefore reported that
    nothing had been tested, contradicted by its own cells one column to the left. That is a
    measured failure presented as an absence of evidence - the direction this script exists to
    prevent - and it points the operator away from the very failure that lowers the "active name
    resolution success rate" in the portal.

    Group cannot be the authority here. It is stamped from the PLAN, makes the full JSON round trip
    to the sensor and back, and nothing re-stamps it afterwards - the identical path documented on
    Test-mdiRequirementIsMandatory, which needed a fix for exactly this reason. Get-mdiPortResultRecord
    normalises only Success and Applicable, so Group reaches the report unprotected. An empty Group
    is a real SHIPPED value too: NnrReverseDns carries Scope NetworkDevice with Group '' because it
    is recommended rather than primary.

    The fix decides "primary method" from the shipped definitions by Id - the same authority the
    method cells are already matched against - falling back to the record's own Group only for an Id
    the shipped table does not know, so a method added in a later version still counts.

    This test pins that a target whose primary methods were MEASURED does not report "Not tested",
    whatever its Group field says, and that a target which genuinely was not measured still does.
#>

$ErrorActionPreference = 'Stop'
$script:pass = 0
$script:fail = 0

# The suite runner counts assertions by matching lines that BEGIN with PASS or FAIL, so every
# assertion has to emit one. A file that prints only a summary reports 0/0 and is recorded as
# having run no assertions at all, which the tree gate treats as RED - correctly, because a test
# that asserts nothing cannot pin anything.
function Assert-Equal {
    param($Expected, $Actual, [string] $Because)
    if ([string] $Expected -eq [string] $Actual) {
        $script:pass++
        "  PASS  $Because"
    } else {
        $script:fail++
        "  FAIL  $Because (expected '$Expected', got '$Actual')"
    }
}

function Resolve-ProductScript {
    $dir = $PSScriptRoot
    while ($dir) {
        $sibling = Join-Path $dir 'Test-MdiReadiness.ps1'
        if (Test-Path -LiteralPath $sibling) { return (Resolve-Path -LiteralPath $sibling).Path }
        $nested = Join-Path $dir 'Test-MdiReadiness\Test-MdiReadiness.ps1'
        if (Test-Path -LiteralPath $nested) { return (Resolve-Path -LiteralPath $nested).Path }
        $parent = Split-Path -Parent $dir
        if ($parent -eq $dir) { break }
        $dir = $parent
    }
    throw 'Could not resolve Test-MdiReadiness.ps1 from $PSScriptRoot (sibling first, then parent).'
}

$product = Resolve-ProductScript
$text = Get-Content -LiteralPath $product -Raw
$cut = $text.IndexOf('#region Main')
if ($cut -lt 0) { throw 'Could not find #region Main' }
. ([scriptblock]::Create($text.Substring(0, $cut)))

function New-NnrRecord {
    param($Id, $Port, $Protocol, $Target, $TargetIP, $Success, $Detail, $Group)
    [PSCustomObject]@{
        Id = $Id; Name = "NNR - $Id"; Protocol = $Protocol; Port = $Port
        Scope = 'NetworkDevice'; Group = $Group; Requirement = 'AtLeastOne'
        Target = $Target; TargetIP = $TargetIP
        Applicable = $true; Success = $Success; LatencyMs = $null; Detail = $Detail
    }
}

function New-ServerWith {
    param($Records)
    [PSCustomObject]@{
        FQDN = 'mem01.mdilab.local'; Domain = 'mdilab.local'; OS = 'Windows Server 2022'
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{
                ProbedFrom = 'Sensor server (outbound)'
                FailedRequired = @(); NnrFailedTargets = @()
                Results = @($Records)
            }
        }
    }
}

# The Resolvable verdict for a target, read out of the NNR matrix section specifically. The report
# carries several tables naming the same target, so the section is isolated before the row is read.
function Get-NnrVerdict {
    param($Html, $TargetName)
    $t = [string] $Html
    $start = $t.IndexOf('Network Name Resolution (NNR) matrix')
    if ($start -lt 0) { return '<no NNR matrix>' }
    $end = $t.IndexOf('<h4', $start + 10)
    if ($end -lt 0) { $end = $t.Length }
    foreach ($r in ($t.Substring($start, $end - $start) -split '<tr>')) {
        if ($r -notlike "*$TargetName*") { continue }
        $cells = [regex]::Matches($r, '<td[^>]*>(.*?)</td>')
        if ($cells.Count -lt 3) { continue }
        return $cells[$cells.Count - 1].Groups[1].Value
    }
    '<no row>'
}

$target = 'memfab01.fabrikam.local'
$targetIp = '10.10.1.51'

# --- a target whose primary methods were MEASURED SHUT is never reported as untested -------------
foreach ($group in @('NNR', $null, '', 12345, @('NNR'), 'Nnr')) {
    $label = if ($null -eq $group) { '$null' } elseif ($group -is [array]) { '@(NNR)' } elseif ("$group" -eq '') { "''" } else { "$group" }
    $srv = New-ServerWith -Records @(
        (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
        (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group $group)
    )
    $verdict = Get-NnrVerdict -Html (Get-mdiRequiredPortsHtml -Server @($srv)) -TargetName $target
    Assert-Equal -Expected 'No' -Actual $verdict `
        -Because ("both primary methods measured refused with Group {0} must read No, not an absence of evidence" -f $label)
}

# --- a target whose primary methods were MEASURED OPEN is never reported as untested -------------
foreach ($group in @('NNR', $null, '', 12345)) {
    $label = if ($null -eq $group) { '$null' } elseif ("$group" -eq '') { "''" } else { "$group" }
    $srv = New-ServerWith -Records @(
        (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $true -Detail 'Open' -Group $group)
        (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $true -Detail 'Open' -Group $group)
    )
    $verdict = Get-NnrVerdict -Html (Get-mdiRequiredPortsHtml -Server @($srv)) -TargetName $target
    Assert-Equal -Expected 'Yes' -Actual $verdict `
        -Because ("both primary methods measured open with Group {0} must read Yes" -f $label)
}

# --- a target that genuinely was NOT measured still reports "Not tested" -------------------------
# The fix must not turn the honest untested case into a verdict. Success $null and a "Not tested"
# detail is what a probe that never ran records.
$srvUnmeasured = New-ServerWith -Records @(
    (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $null -Detail 'Not tested - no route to host' -Group 'NNR')
    (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $null -Detail 'Not tested - no route to host' -Group 'NNR')
)
Assert-Equal -Expected 'Not tested' `
    -Actual (Get-NnrVerdict -Html (Get-mdiRequiredPortsHtml -Server @($srvUnmeasured)) -TargetName $target) `
    -Because 'a target whose primary methods never ran must still read Not tested'

# --- reverse DNS is RECOMMENDED, not primary, and must not decide the verdict alone --------------
# NnrReverseDns ships with Group '' deliberately. A target where only reverse DNS succeeded has had
# no primary method succeed, so it must not read Yes on the strength of that one row.
$srvReverseOnly = New-ServerWith -Records @(
    (New-NnrRecord -Id 'NnrReverseDns' -Port 53 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $true -Detail 'Resolved' -Group '')
    (New-NnrRecord -Id 'NnrRpc' -Port 135 -Protocol 'TCP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group 'NNR')
    (New-NnrRecord -Id 'NnrNetBios' -Port 137 -Protocol 'UDP' -Target $target -TargetIP $targetIp -Success $false -Detail 'Connection refused' -Group 'NNR')
)
Assert-Equal -Expected 'No' `
    -Actual (Get-NnrVerdict -Html (Get-mdiRequiredPortsHtml -Server @($srvReverseOnly)) -TargetName $target) `
    -Because 'a successful reverse DNS lookup is recommended, not primary, and must not make a target resolvable'

Write-Host ("assertions passed={0} failed={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
