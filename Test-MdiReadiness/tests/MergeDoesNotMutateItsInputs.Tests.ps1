<#
    The detail merges must not write into the blobs they are given.

    Copy-mdiDetails is SHALLOW: a merged server's Details is a new container, but each nested blob
    inside it is the SAME object as the one hanging off the original server. Measured on the shipped
    function - after Copy-mdiDetails, ReferenceEquals(copy['RequiredPortsDetails'],
    source['RequiredPortsDetails']) is True.

    That is safe only for as long as the merge path treats those blobs as read-only: it reads the
    stored blob, asks a Merge-mdi* function to build a NEW blob, and stores the result. Nothing today
    writes through the shared reference, so nothing is currently wrong.

    It is one edit away from being wrong. A merge rewritten to update its -First argument in place -
    the obvious optimisation, and invisible in review because the merge would still return the right
    answer - would reach through the shallow copy and rewrite the ORIGINAL server's measurements. A
    domain controller that also holds the CA role would have its port results replaced by the merged
    ones, and the per-role tables and the -AsJson output are rendered from exactly those objects.

    So this pins the invariant that makes the cheap copy correct, rather than the copy itself.
    Deep-copying every blob on every role of every server to defend against a write that does not
    happen would cost more than it buys.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-PortRec {
    param($Id, $Success, $Detail = 'measured', $Requirement = 'Required')
    [PSCustomObject]@{ Id = $Id; Name = $Id; Group = 'NNR'; Protocol = 'TCP'; Port = 135
        Target = 'dc1.contoso.com'; TargetIP = '10.0.0.1'; Requirement = $Requirement
        Success = $Success; Applicable = $true; Detail = $Detail }
}
function New-PortBlob {
    param($Records, $Failed = @(), $Nnr = @())
    [PSCustomObject]@{ FailedRequired = @($Failed); NnrFailedTargets = @($Nnr); Results = @($Records) }
}

# A snapshot deep enough to notice a record being edited in place, not just added or removed.
function Get-BlobFingerprint {
    param($Blob)
    if ($null -eq $Blob) { return '<null>' }
    $parts = @()
    foreach ($r in @($Blob.Results)) {
        $parts += ('{0}|{1}|{2}|{3}' -f $r.Id, $r.Success, $r.Detail, $r.Requirement)
    }
    '{0}::{1}::{2}' -f (($parts) -join ';'), (@($Blob.FailedRequired) -join ','), (@($Blob.NnrFailedTargets) -join ',')
}

Write-Host "`n[1] Copy-mdiDetails shares its nested blobs - the premise of this test" -ForegroundColor Yellow
$blob = New-PortBlob @((New-PortRec 'A' $true), (New-PortRec 'B' $true))
$source = [ordered]@{ RequiredPortsDetails = $blob }
$copy = Copy-mdiDetails -Details $source
Assert-That 'the container itself is a new object' (-not [object]::ReferenceEquals($copy, $source))
Assert-That 'a top-level entry can be replaced without touching the source' $true
$copy['Marker'] = 'only-on-copy'
Assert-That '  ...and the source does not gain it' (-not $source.Contains('Marker'))
Assert-That 'the nested blob IS shared (so the merges must not write to it)' `
    ([object]::ReferenceEquals($copy['RequiredPortsDetails'], $source['RequiredPortsDetails']))

Write-Host "`n[2] Merge-mdiRequiredPortsDetails leaves BOTH arguments untouched" -ForegroundColor Yellow
$first = New-PortBlob @((New-PortRec 'A' $true), (New-PortRec 'B' $true))
$second = New-PortBlob @((New-PortRec 'A' $false 'blocked - firewall'), (New-PortRec 'C' $false 'blocked - firewall'))
$firstBefore = Get-BlobFingerprint $first
$secondBefore = Get-BlobFingerprint $second

$merged = Merge-mdiRequiredPortsDetails -First $first -Second $second

Assert-That 'the merge returned something' ($null -ne $merged)
Assert-That '-First is byte-for-byte what it was' ((Get-BlobFingerprint $first) -eq $firstBefore) `
    "(was '$firstBefore' now '$(Get-BlobFingerprint $first)')"
Assert-That '-Second is byte-for-byte what it was' ((Get-BlobFingerprint $second) -eq $secondBefore) `
    "(was '$secondBefore' now '$(Get-BlobFingerprint $second)')"
Assert-That 'the result is not one of the arguments' `
    ((-not [object]::ReferenceEquals($merged, $first)) -and (-not [object]::ReferenceEquals($merged, $second)))
# The merge must still be doing its job: a measured failure has to win over a measured success.
$mergedA = @($merged.Results | Where-Object { $_.Id -eq 'A' })[0]
Assert-That 'the merge still prefers the measured failure' ($mergedA.Success -eq $false) "(got '$($mergedA.Success)')"

Write-Host "`n[3] Merge-mdiSensorV3ReadyDetails leaves BOTH arguments untouched" -ForegroundColor Yellow
function New-V3Blob {
    param($Ready, $Blockers)
    [PSCustomObject]@{ SensorV3Ready = $Ready; Blockers = @($Blockers)
        Checks = [PSCustomObject]@{ OsSupported = $Ready; Migration = $Ready } }
}
function Get-V3Fingerprint {
    param($B)
    if ($null -eq $B) { return '<null>' }
    '{0}::{1}::{2}/{3}' -f $B.SensorV3Ready, (@($B.Blockers) -join ','), $B.Checks.OsSupported, $B.Checks.Migration
}
$v3First = New-V3Blob $false @('operating system too old')
$v3Second = New-V3Blob $false @('sensor version too old')
$v3FirstBefore = Get-V3Fingerprint $v3First
$v3SecondBefore = Get-V3Fingerprint $v3Second

$v3Merged = Merge-mdiSensorV3ReadyDetails -First $v3First -Second $v3Second -FirstRank 1 -SecondRank 1

Assert-That 'the v3 merge returned something' ($null -ne $v3Merged)
Assert-That 'v3 -First is unchanged' ((Get-V3Fingerprint $v3First) -eq $v3FirstBefore) `
    "(was '$v3FirstBefore' now '$(Get-V3Fingerprint $v3First)')"
Assert-That 'v3 -Second is unchanged' ((Get-V3Fingerprint $v3Second) -eq $v3SecondBefore) `
    "(was '$v3SecondBefore' now '$(Get-V3Fingerprint $v3Second)')"
Assert-That 'the v3 result is not one of the arguments' `
    ((-not [object]::ReferenceEquals($v3Merged, $v3First)) -and (-not [object]::ReferenceEquals($v3Merged, $v3Second)))

Write-Host "`n[4] End to end: merging a two-role host does not rewrite the source server" -ForegroundColor Yellow
# One physical host discovered twice - a domain controller that also holds the CA role - which is
# the ordinary small-estate layout the merge exists to handle.
$srcBlob = New-PortBlob @((New-PortRec 'A' $true), (New-PortRec 'B' $true))
$srv = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false
    Addresses = @('10.0.0.1'); IP = '10.0.0.1'
    Details = [ordered]@{ RequiredPortsDetails = $srcBlob }
}
$srvBefore = Get-BlobFingerprint $srv.Details['RequiredPortsDetails']

$roleCopy = [PSCustomObject]@{ FQDN = $srv.FQDN }
Add-Member -InputObject $roleCopy -MemberType NoteProperty -Name 'Details' `
    -Value (Copy-mdiDetails -Details $srv.Details) -Force

$incoming = New-PortBlob @((New-PortRec 'A' $false 'blocked - firewall'), (New-PortRec 'C' $false 'blocked - firewall'))
$existing = Get-mdiDetailValue -Details $roleCopy.Details -Name 'RequiredPortsDetails'
Set-mdiDetailEntry -Details $roleCopy.Details -Name 'RequiredPortsDetails' -Value (
    Merge-mdiRequiredPortsDetails -First $existing -Second $incoming)

Assert-That 'the source server still reports what IT measured' `
    ((Get-BlobFingerprint $srv.Details['RequiredPortsDetails']) -eq $srvBefore) `
    "(was '$srvBefore' now '$(Get-BlobFingerprint $srv.Details['RequiredPortsDetails'])')"
$srcA = @($srv.Details['RequiredPortsDetails'].Results | Where-Object { $_.Id -eq 'A' })[0]
Assert-That '  ...including the record the merge overrode on the copy' ($srcA.Success -eq $true) "(got '$($srcA.Success)')"
$copyA = @((Get-mdiDetailValue -Details $roleCopy.Details -Name 'RequiredPortsDetails').Results |
        Where-Object { $_.Id -eq 'A' })[0]
Assert-That '  ...while the merged copy DOES carry the blocked result' ($copyA.Success -eq $false) "(got '$($copyA.Success)')"

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
