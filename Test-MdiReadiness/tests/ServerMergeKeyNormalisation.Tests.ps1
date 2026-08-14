<#
    One physical server must be counted once, however its name was spelled where it was discovered.

    A domain controller can be discovered several times over: from the DC inventory, because it also
    holds the CA role, because it runs Entra Connect, or as an NNR target. Merge-mdiServerByFqdn folds
    those records into one row, and it already normalised case and the trailing dot of an absolute DNS
    name. It did not trim surrounding whitespace - and whitespace is not part of a DNS name. A
    directory attribute read with a stray leading space, an operator-supplied -NnrTargetComputer with a
    trailing one, or a name split out of a comma-separated list therefore keyed differently from the
    same host discovered elsewhere.

    The consequence is the opposite of a harmless duplicate. The two halves of one server carry
    DIFFERENT verdicts, because each was populated by a different role's checks. The healthy-looking
    half joins the ready count and the estate total grows by one, so discovering a server a second time
    under a slightly different spelling made the readiness percentage go UP.

    These tests assert the merged OUTCOME - how many rows, and which verdict survives - not the text of
    the key expression.
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

function New-Row {
    param([string] $Fqdn, [object] $Ntlm, [string] $Role)
    [PSCustomObject]@{
        FQDN         = $Fqdn
        Role         = $Role
        NtlmAuditing = $Ntlm
        Details      = [PSCustomObject]@{}
    }
}
function Get-Merged {
    param([string] $A, [string] $B)
    # The first spelling PASSES, the second FAILS. If they merge, the pessimistic (failing) verdict
    # must win - one server, one answer, and never the flattering one.
    @(Merge-mdiServerByFqdn -Server @((New-Row -Fqdn $A -Ntlm $true -Role 'DC'), (New-Row -Fqdn $B -Ntlm $false -Role 'CA')))
}

Write-Host 'The same host under a different spelling merges into one row' -ForegroundColor Cyan
$sameHost = @(
    @{ Name = 'identical (the control)'; A = 'dc1.contoso.com'; B = 'dc1.contoso.com' }
    @{ Name = 'case differs'; A = 'DC1.CONTOSO.COM'; B = 'dc1.contoso.com' }
    @{ Name = 'trailing dot (absolute form)'; A = 'dc1.contoso.com.'; B = 'dc1.contoso.com' }
    @{ Name = 'leading space'; A = ' dc1.contoso.com'; B = 'dc1.contoso.com' }
    @{ Name = 'trailing space'; A = 'dc1.contoso.com '; B = 'dc1.contoso.com' }
    @{ Name = 'surrounding tabs'; A = "`tdc1.contoso.com`t"; B = 'dc1.contoso.com' }
    @{ Name = 'trailing dot AND a space'; A = 'dc1.contoso.com. '; B = 'dc1.contoso.com' }
    @{ Name = 'space, dot, and mixed case together'; A = ' DC1.Contoso.Com. '; B = 'dc1.contoso.com' }
)
foreach ($c in $sameHost) {
    $m = @(Get-Merged -A $c.A -B $c.B)
    Assert-That "$($c.Name): counted as ONE server" ($m.Count -eq 1) "got $($m.Count) rows"
    if ($m.Count -eq 1) {
        # A merged server must not be able to look healthier than its worst measured half.
        Assert-That "  ...and the FAILING verdict wins" ($m[0].NtlmAuditing -eq $false) "got '$($m[0].NtlmAuditing)'"
    }
}

Write-Host 'Genuinely different hosts are still kept apart' -ForegroundColor Cyan
$different = @(
    @{ Name = 'two different servers'; A = 'dc1.contoso.com'; B = 'dc2.contoso.com' }
    @{ Name = 'same label, different domain'; A = 'dc1.contoso.com'; B = 'dc1.fabrikam.com' }
    @{ Name = 'a short name against an FQDN'; A = 'dc1'; B = 'dc1.contoso.com' }
    @{ Name = 'two unusable names'; A = ''; B = '' }
    @{ Name = 'two whitespace-only names'; A = '   '; B = "`t" }
    @{ Name = 'dots only'; A = '.'; B = '..' }
)
foreach ($c in $different) {
    $m = @(Get-Merged -A $c.A -B $c.B)
    Assert-That "$($c.Name): kept as TWO rows" ($m.Count -eq 2) "got $($m.Count) rows"
}

Write-Host 'A whitespace-padded duplicate cannot inflate the estate or the score' -ForegroundColor Cyan
# Three discoveries of ONE server: two ready, one failing. Before the fix this was three servers,
# two of them "ready", so finding the same machine again improved the reported readiness.
$threeWays = @(
    New-Row -Fqdn 'dc1.contoso.com' -Ntlm $true -Role 'DC'
    New-Row -Fqdn ' dc1.contoso.com ' -Ntlm $true -Role 'CA'
    New-Row -Fqdn 'DC1.contoso.com.' -Ntlm $false -Role 'EntraConnect'
)
$mergedThree = @(Merge-mdiServerByFqdn -Server $threeWays)
Assert-That 'three discoveries of one server produce one row' ($mergedThree.Count -eq 1) "got $($mergedThree.Count) rows"
Assert-That '  ...carrying the failing verdict' ($mergedThree[0].NtlmAuditing -eq $false) "got '$($mergedThree[0].NtlmAuditing)'"

# And the same three spellings alongside a genuinely separate server: two rows, not four.
$plusOther = @($threeWays + @(New-Row -Fqdn 'dc2.contoso.com' -Ntlm $true -Role 'DC'))
$mergedPlus = @(Merge-mdiServerByFqdn -Server $plusOther)
Assert-That 'a real second server is still counted' ($mergedPlus.Count -eq 2) "got $($mergedPlus.Count) rows"

Write-Host 'An unmeasured half never overwrites a measured failure' -ForegroundColor Cyan
$naFirst = @(Merge-mdiServerByFqdn -Server @(
        (New-Row -Fqdn ' dc1.contoso.com' -Ntlm 'N/A' -Role 'DC')
        (New-Row -Fqdn 'dc1.contoso.com' -Ntlm $false -Role 'CA')
    ))
Assert-That "'N/A' then \$false merges to one row" ($naFirst.Count -eq 1) "got $($naFirst.Count) rows"
Assert-That '  ...and the measured failure survives' ($naFirst[0].NtlmAuditing -eq $false) "got '$($naFirst[0].NtlmAuditing)'"
# ...and the answer must not depend on which role happened to be discovered first.
$naSecond = @(Merge-mdiServerByFqdn -Server @(
        (New-Row -Fqdn 'dc1.contoso.com' -Ntlm $false -Role 'CA')
        (New-Row -Fqdn ' dc1.contoso.com' -Ntlm 'N/A' -Role 'DC')
    ))
Assert-That '  ...in either discovery order' ($naSecond[0].NtlmAuditing -eq $false) "got '$($naSecond[0].NtlmAuditing)'"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
