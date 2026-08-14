<#
    A port probe that never ran must never be presented as a port that is shut, and a report must be
    the same whichever order the roles were discovered in.

    Seven defects in the port/NNR pipeline, all reproduced against the shipped script, all of one of
    the campaign's two root-cause classes:

    UNMEASURED PRESENTED AS MEASURED. Test-mdiProbeWasMeasured is the shared predicate for "this record
    carries a measurement", and it exists because the same test had been written out longhand at
    several sites and they drifted. Two more longhand copies were still in place - the ports table
    cell and the NNR blocking classifier - and both missed the case the shared predicate was written
    to catch: a record whose Success normalised to $null. `-not $null` is $true, so:
      * the ports table painted a red "0/1 open" cell - the BLOCKED presentation - for a probe the
        KPI, the issue list and the verdict on the same page all correctly called untested. Red means
        "open your firewall", so this is the one wrong answer that costs a change request;
      * an NNR target nothing had been measured against was classified 'NnrMeasured' - "no NNR method
        could resolve X" - instead of 'NnrUntested'.

    ORDER DEPENDENCE. A host that is a domain controller AND a CA AND Entra Connect is discovered
    three times and merged. The merge took ProbedFrom first-wins, and kept first-seen order for the
    result and failure lists - so the same estate scanned twice produced two byte-different
    remediation scripts and two different claims about which DIRECTION had been probed. The
    baseline/trend feature diffs that text, so an estate that had not changed showed a change.

    Plus: an NNR record with an empty Target threw out of Get-mdiIssueList, so NO HTML REPORT WAS
    WRITTEN AT ALL; a string Port sorted lexically (10, 135, 3389, 389, 53, 9); and a row took its
    colour from $probeRecords[0] - the first record across every server - so a genuinely blocked
    REQUIRED port was painted amber because a different server's probe for that port was optional.
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

function New-Rec {
    param(
        [string] $Id = 'Ldap', [string] $Protocol = 'TCP', $Port = 389,
        [string] $Server = 'dc1.contoso.com', [string] $Target = 'dc2.contoso.com',
        [string] $TargetIP = '10.0.0.2', [string] $Group = 'Directory',
        [string] $Requirement = 'Required', $Applicable = $true, $Success = $null,
        [string] $Detail = 'Connection refused'
    )
    [PSCustomObject]@{
        Id = $Id; Name = $Id; Protocol = $Protocol; Port = $Port; Scope = 'DomainController'
        Group = $Group; Requirement = $Requirement; Server = $Server; Target = $Target
        TargetIP = $TargetIP; Applicable = $Applicable; Success = $Success; Detail = $Detail
    }
}

Write-Host 'A probe whose Success is not a real boolean was never measured' -ForegroundColor Cyan
# This is the shared predicate the two longhand copies were missing.
$unmeasured = New-Rec -Success $null -Detail 'Connection refused'
Assert-That 'Success = $null is not a measurement' ((Test-mdiProbeWasMeasured -Record $unmeasured) -eq $false) 'predicate says measured'
foreach ($s in '', 'N/A', 'Unknown', 0, 1) {
    $r = New-Rec -Success $s
    Assert-That "  Success = '$s' is not a measurement" ((Test-mdiProbeWasMeasured -Record $r) -eq $false) 'predicate says measured'
}
Assert-That 'a real $false IS a measurement' ((Test-mdiProbeWasMeasured -Record (New-Rec -Success $false)) -eq $true) 'predicate says unmeasured'
Assert-That 'a real $true IS a measurement' ((Test-mdiProbeWasMeasured -Record (New-Rec -Success $true)) -eq $true) 'predicate says unmeasured'

Write-Host 'Such a probe is never counted as blocked by the blocking classifier' -ForegroundColor Cyan
$blocking = @(Get-mdiBlockingPortFailure -Record @($unmeasured))
Assert-That 'nothing is reported as measured-blocked' (@($blocking | Where-Object { $_.BlockingKind -eq 'Required' }).Count -eq 0) "got $($blocking.BlockingKind -join ',')"
$unmeasuredRequired = @(Get-mdiUnmeasuredRequiredProbe -Record @($unmeasured))
Assert-That '  ...and it IS reported as an unmeasured required probe' ($unmeasuredRequired.Count -eq 1) "got $($unmeasuredRequired.Count)"
# A genuinely blocked required port must still block, or the fix has hidden a real failure.
$reallyBlocked = @(Get-mdiBlockingPortFailure -Record @((New-Rec -Success $false)))
Assert-That 'a genuinely blocked required port still blocks' (@($reallyBlocked | Where-Object { $_.BlockingKind -eq 'Required' }).Count -eq 1) "got $($reallyBlocked.BlockingKind -join ',')"

Write-Host 'An NNR target nothing was measured against is Untested, not Measured' -ForegroundColor Cyan
$nnrUnmeasured = @(
    New-Rec -Id 'NnrRpc' -Group 'NNR' -Requirement 'AtLeastOne' -Port 135 -Success $null -Detail 'Connection refused'
    New-Rec -Id 'NnrNetBios' -Group 'NNR' -Requirement 'AtLeastOne' -Port 137 -Success $null -Detail 'Connection refused'
)
$nnrBlock = @(Get-mdiBlockingPortFailure -Record $nnrUnmeasured)
Assert-That 'the group is classified NnrUntested' (@($nnrBlock | Where-Object { $_.BlockingKind -eq 'NnrUntested' }).Count -eq 1) "got $($nnrBlock.BlockingKind -join ',')"
Assert-That '  ...and never NnrMeasured' (@($nnrBlock | Where-Object { $_.BlockingKind -eq 'NnrMeasured' }).Count -eq 0) "got $($nnrBlock.BlockingKind -join ',')"
# A target measured and genuinely unresolvable must still be NnrMeasured.
$nnrFailed = @(
    New-Rec -Id 'NnrRpc' -Group 'NNR' -Requirement 'AtLeastOne' -Port 135 -Success $false -Detail 'Connection refused'
    New-Rec -Id 'NnrNetBios' -Group 'NNR' -Requirement 'AtLeastOne' -Port 137 -Success $false -Detail 'Connection refused'
)
$nnrFailedBlock = @(Get-mdiBlockingPortFailure -Record $nnrFailed)
Assert-That 'a measured, unresolvable target is still NnrMeasured' (@($nnrFailedBlock | Where-Object { $_.BlockingKind -eq 'NnrMeasured' }).Count -eq 1) "got $($nnrFailedBlock.BlockingKind -join ',')"
# One sibling succeeding rescues the target.
$nnrOk = @(
    New-Rec -Id 'NnrRpc' -Group 'NNR' -Requirement 'AtLeastOne' -Port 135 -Success $true -Detail 'Open'
    New-Rec -Id 'NnrNetBios' -Group 'NNR' -Requirement 'AtLeastOne' -Port 137 -Success $false -Detail 'Connection refused'
)
Assert-That 'one successful NNR method rescues the target' (@(Get-mdiBlockingPortFailure -Record $nnrOk).Count -eq 0) 'the group blocked anyway'

Write-Host 'An NNR record with no Target does not abort the whole report' -ForegroundColor Cyan
foreach ($t in '', '   ') {
    $threw = $null
    $out = $null
    try { $out = Get-mdiNnrIssueText -Target $t } catch { $threw = $_.Exception.Message }
    Assert-That "Get-mdiNnrIssueText with Target='$t' does not throw" ($null -eq $threw) "threw: $threw"
    Assert-That "  ...and still produces text" (-not [string]::IsNullOrWhiteSpace($out)) "got '$out'"
}
$threwNull = $null
try { [void] (Get-mdiNnrIssueText -Target $null) } catch { $threwNull = $_.Exception.Message }
Assert-That 'Get-mdiNnrIssueText with a $null Target does not throw' ($null -eq $threwNull) "threw: $threwNull"
Assert-That 'a real target is still named' ((Get-mdiNnrIssueText -Target 'dc2.contoso.com') -like '*dc2.contoso.com*') 'target not named'

Write-Host 'The merge is commutative' -ForegroundColor Cyan
function New-Details {
    param([string] $ProbedFrom, $Records, $Failed = $null, $Nnr = $null)
    [PSCustomObject]@{
        ProbedFrom = $ProbedFrom
        # Distinct per side. With identical lists on both sides a first-seen union and a sorted union
        # are indistinguishable, and the order-dependence would go unnoticed.
        FailedRequired = @(if ($null -ne $Failed) { $Failed } else { @('TCP/389 to dc2.contoso.com') })
        NnrFailedTargets = @(if ($null -ne $Nnr) { $Nnr } else { @('dc2.contoso.com') })
        Results = @($Records)
    }
}
$a = New-Details -ProbedFrom 'This computer (inbound to the server)' `
    -Failed @('TCP/389 to dc2.contoso.com', 'TCP/53 to dc2.contoso.com') `
    -Nnr @('dc2.contoso.com') `
    -Records @((New-Rec -Port 389 -Success $false), (New-Rec -Id 'Dns' -Port 53 -Success $false))
$b = New-Details -ProbedFrom 'Sensor server (outbound)' `
    -Failed @('TCP/443 to contoso.atp.azure.com', 'TCP/444 to contoso.atp.azure.com') `
    -Nnr @('aaa.contoso.com') `
    -Records @((New-Rec -Id 'Https' -Port 443 -Target 'contoso.atp.azure.com' -TargetIP '' -Success $false), (New-Rec -Id 'Sensor' -Port 444 -Target 'contoso.atp.azure.com' -TargetIP '' -Success $false))
$ab = Merge-mdiRequiredPortsDetails -First $a -Second $b
$ba = Merge-mdiRequiredPortsDetails -First $b -Second $a
Assert-That 'ProbedFrom does not depend on merge order' ($ab.ProbedFrom -eq $ba.ProbedFrom) "A,B='$($ab.ProbedFrom)' B,A='$($ba.ProbedFrom)'"
Assert-That '  ...and reports the direction MDI requires' ($ab.ProbedFrom -eq 'Sensor server (outbound)') "got '$($ab.ProbedFrom)'"
Assert-That 'the failed-port list order does not depend on merge order' (($ab.FailedRequired -join '|') -eq ($ba.FailedRequired -join '|')) "A,B='$($ab.FailedRequired -join '|')' B,A='$($ba.FailedRequired -join '|')'"
Assert-That '  ...and no failed port is lost' ($ab.FailedRequired.Count -eq 4) "got $($ab.FailedRequired.Count): $($ab.FailedRequired -join '|')"
Assert-That 'the NNR failed-target order does not depend on merge order' (($ab.NnrFailedTargets -join '|') -eq ($ba.NnrFailedTargets -join '|')) "A,B='$($ab.NnrFailedTargets -join '|')' B,A='$($ba.NnrFailedTargets -join '|')'"
$abKeys = @($ab.Results | ForEach-Object { '{0}/{1}/{2}' -f $_.Protocol, $_.Port, $_.Target })
$baKeys = @($ba.Results | ForEach-Object { '{0}/{1}/{2}' -f $_.Protocol, $_.Port, $_.Target })
Assert-That 'the merged result ORDER does not depend on merge order' (($abKeys -join '|') -eq ($baKeys -join '|')) "A,B='$($abKeys -join '|')' B,A='$($baKeys -join '|')'"
Assert-That '  ...and no record is lost' ($ab.Results.Count -eq 4) "got $($ab.Results.Count)"

Write-Host 'Ports sort numerically even when they arrive as strings' -ForegroundColor Cyan
$stringPorts = New-Details -ProbedFrom 'Sensor server (outbound)' -Records @(
    (New-Rec -Id 'P9' -Port '9' -Success $false), (New-Rec -Id 'P10' -Port '10' -Success $false)
    (New-Rec -Id 'P53' -Port '53' -Success $false), (New-Rec -Id 'P389' -Port '389' -Success $false)
    (New-Rec -Id 'P3389' -Port '3389' -Success $false)
)
$mergedPorts = Merge-mdiRequiredPortsDetails -First $stringPorts -Second $null
$order = @($mergedPorts.Results | ForEach-Object { [string] $_.Port })
Assert-That 'string ports are ordered 9,10,53,389,3389' (($order -join ',') -eq '9,10,53,389,3389') "got '$($order -join ',')'"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
