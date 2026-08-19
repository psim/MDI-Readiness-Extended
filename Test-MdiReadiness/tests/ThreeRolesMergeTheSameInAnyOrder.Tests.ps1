<#
    A host discovered in THREE roles merges to the same row in any order.

    Merge-mdiServerByFqdn folds every discovered role of one physical host into a single row, and its
    existing regression tests all use TWO roles. Two roles only ever exercise "create the target, then
    merge once". The third role is where the state that has actually caused defects lives:

      * by then $target.Details was built by an EARLIER MERGE rather than copied from a source, so the
        blob being merged into is one this function produced;
      * the branch that takes a detail entry the target has never seen stores the incoming role's blob
        BY REFERENCE, while the first-role branch beside it takes a copy;
      * $detailRankSource has to carry the authority of an already-merged entry forward, or a third
        role displaces a merged explanation on a rank the merge has already absorbed.

    Two properties are pinned, both of which the report depends on:

      COMMUTATIVE  - all six discovery orders must produce the same row. This is not cosmetic: the
      baseline/trend comparison diffs this text, so an estate that has not changed would otherwise
      appear to have changed depending only on the order the roles happened to be enumerated in.

      NON-MUTATING - the per-role tables and the -AsJson output are rendered from the ROLE objects,
      so folding them must not rewrite what each role measured.

    Both are mutation-proved. Against the shipped tree this file passes; with the port merge's rank
    comparison disabled it reports two failures, and with the ordinal tie-break between two equally
    evidenced failures removed it reports one - the orders stop agreeing. A test that stays green
    while the thing it names is broken is worse than no test, so neither assertion is taken on trust.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
# Guarded rather than resolved unconditionally: in the flat release stage the parent directory does
# not hold the script, and an unguarded resolve throws BEFORE the first assertion runs - which reads
# as a quiet test rather than a dead one.
if (-not (Test-Path -LiteralPath $target)) {
    $parent = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
    if (Test-Path -LiteralPath $parent) { $target = $parent }
}
if (-not (Test-Path -LiteralPath $target)) { Write-Host 'FAIL  the product script could not be located'; exit 1 }

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
    param($Records)
    [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @($Records) }
}
function New-Role {
    param($SensorHealth, $Details)
    [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false
        Addresses = @('10.0.0.1'); IP = '10.0.0.1'; SensorHealth = $SensorHealth; Details = $Details }
}

# Three roles of ONE host - the ordinary small-estate layout where a domain controller also holds the
# CA and Entra Connect roles. Each contributes a detail entry the others lack, they disagree on a
# check, and two of them measure the SAME probe as failed for different stated reasons.
function Build-Roles {
    @(
        (New-Role $true ([ordered]@{
                    RequiredPortsDetails = (New-PortBlob @((New-PortRec 'A' $true), (New-PortRec 'B' $true)))
                })),
        (New-Role $false ([ordered]@{
                    RequiredPortsDetails = (New-PortBlob @((New-PortRec 'A' $false 'blocked - firewall')))
                    SensorHealthDetails  = [PSCustomObject]@{ Detail = 'service is stopped' }
                })),
        (New-Role $false ([ordered]@{
                    RequiredPortsDetails = (New-PortBlob @(
                            (New-PortRec 'A' $false 'connection timed out'),
                            (New-PortRec 'C' $false 'blocked - firewall')))
                    SensorHealthDetails  = [PSCustomObject]@{ Detail = 'service is disabled' }
                }))
    )
}

function Get-RowFingerprint {
    param($Row)
    $ports = Get-mdiDetailValue -Details $Row.Details -Name 'RequiredPortsDetails'
    $recs = @($ports.Results | ForEach-Object { '{0}:{1}:{2}' -f $_.Id, $_.Success, $_.Detail } | Sort-Object)
    $sh = Get-mdiDetailValue -Details $Row.Details -Name 'SensorHealthDetails'
    'SensorHealth={0}|ports={1}|sh={2}' -f $Row.SensorHealth, ($recs -join ','), $sh.Detail
}

function Get-RoleFingerprint {
    param($Role)
    $p = Get-mdiDetailValue -Details $Role.Details -Name 'RequiredPortsDetails'
    $s = Get-mdiDetailValue -Details $Role.Details -Name 'SensorHealthDetails'
    '{0}|{1}' -f (@($p.Results | ForEach-Object { '{0}:{1}:{2}' -f $_.Id, $_.Success, $_.Detail }) -join ','), $s.Detail
}

"`n[1] All six discovery orders produce the same merged row"
$orders = @(@(0, 1, 2), @(0, 2, 1), @(1, 0, 2), @(1, 2, 0), @(2, 0, 1), @(2, 1, 0))
$prints = [ordered]@{}
foreach ($order in $orders) {
    $roles = Build-Roles
    $out = @(Merge-mdiServerByFqdn -Server @($order | ForEach-Object { $roles[$_] }))
    $label = ($order -join '')
    Assert-That "order $label folds three roles into one row" ($out.Count -eq 1) "(got $($out.Count))"
    if ($out.Count -eq 1) { $prints[$label] = Get-RowFingerprint $out[0] }
}
$distinct = @($prints.Values | Sort-Object -Unique)
Assert-That 'and all six agree on what that row says' ($distinct.Count -eq 1) "(got $($distinct.Count) distinct results)"
if ($distinct.Count -gt 1) { foreach ($k in $prints.Keys) { "        order $k -> $($prints[$k])" } }

"`n[2] Folding the roles does not rewrite what each role measured"
$roles = Build-Roles
$before = @($roles | ForEach-Object { Get-RoleFingerprint $_ })
$null = @(Merge-mdiServerByFqdn -Server $roles)
$after = @($roles | ForEach-Object { Get-RoleFingerprint $_ })
for ($r = 0; $r -lt $before.Count; $r++) {
    Assert-That "role $($r + 1) still reports what it measured" ($before[$r] -eq $after[$r]) `
        "(was '$($before[$r])' now '$($after[$r])')"
}

"`n[3] Every probe survives the fold, and the failure wins the clash"
$roles = Build-Roles
$out = @(Merge-mdiServerByFqdn -Server $roles)
$ports = Get-mdiDetailValue -Details $out[0].Details -Name 'RequiredPortsDetails'
$ids = @($ports.Results | ForEach-Object { [string] $_.Id } | Sort-Object -Unique)
Assert-That 'A, B and C are all present' (($ids -join ',') -eq 'A,B,C') "(got '$($ids -join ',')')"
$a = @($ports.Results | Where-Object { $_.Id -eq 'A' })[0]
Assert-That 'the blocked measurement of A beats the open one' ($a.Success -eq $false) "(got '$($a.Success)')"
Assert-That 'a failing check under any role fails for the merged host' ($out[0].SensorHealth -eq $false) `
    "(got '$($out[0].SensorHealth)')"

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
