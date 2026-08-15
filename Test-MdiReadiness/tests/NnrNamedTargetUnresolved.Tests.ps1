# [w83] A Network Name Resolution target the OPERATOR named that resolves to no address must not
# vanish silently.
#
# Resolve-mdiNnrTarget drops such a host from the probe plan with nothing but a warning (the
# Write-mdiWarning at the 'Unable to resolve the NNR target computer' line). Nothing was recorded on
# the report, so the verdict, the issue list, the score and the exit code could not see it: the run
# answered "can my sensors resolve this workstation?" without ever having asked.
#
# This is the same defect shape as LdapPlanGapDomains, one step earlier, and it matters more rather
# than less - the operator named this host explicitly with -NnrTargetComputer.
#
# Two halves are tested here, because either alone would let the defect back in:
#   1. the RESOLVER really does drop an unresolvable named target (real Resolve-mdiNnrTarget);
#   2. the VERDICT and the ISSUE LIST really do act on the recorded gap (real functions).

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-Srv {
    param([string] $Fqdn, [string] $Domain)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = $Domain
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true; RequiredPorts = $true
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
    }
}
function New-Audit {
    param([string] $Domain)
    [PSCustomObject]@{
        Domain = $Domain
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }; ObjectAuditingMeasured = $true
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }; ExchangeAuditingMeasured = $true
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $true
        DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; NotAsserted = $false }; DeletedObjectsMeasured = $true
    }
}
function New-Report {
    param([string[]] $Unresolved = @())
    [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainsInScope = @('contoso.com')
        LdapPlanGapDomains = @()
        NnrUnresolvedTargets = $Unresolved
        DomainControllers = @(New-Srv -Fqdn 'dc1.contoso.com' -Domain 'contoso.com')
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(New-Audit -Domain 'contoso.com')
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
        SkippedAreas = @()
    }
}
function Get-Outcome {
    param([object] $Report)
    $verdict = Test-mdiReadinessResult -ReportData $Report 3>$null 4>$null
    $stats = Get-mdiReportStatistics -ReportData $Report
    $issues = @(Get-mdiIssueList -Statistics $stats -ReportData $Report)
    [PSCustomObject]@{ Ready = [bool] $verdict; Issues = $issues; Count = $issues.Count }
}

'[w83] the resolver really does drop an unresolvable named target'
# Get-mdiComputerAddress is the only thing standing between a name and an address, so it is stubbed
# script-scoped (a `function global:` would NOT override it) to make resolution fail deterministically
# without touching DNS. Get-ADComputer is stubbed to throw, which is the path a non-domain-joined
# workstation name takes anyway.
Set-Item -Path function:script:Get-ADComputer -Value { param($Identity, $Properties, $ErrorAction, $Server) throw 'not found' }
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param([string] $ComputerName, [string] $KnownAddress)
    if ($ComputerName -match '^ghost') { return @() }
    @('10.0.0.9')
}
$dcInv = @([PSCustomObject]@{ Name = 'dc1.contoso.com'; IP = '10.0.0.1' })

$resolvedOk = @(Resolve-mdiNnrTarget -DomainControllers $dcInv -NnrTargetComputer @('ws1') -Domain 'contoso.com' -MaxTargets 5 3>$null)
Assert-That 'a resolvable named target produces a probe target' ($resolvedOk.Count -ge 1) "(got $($resolvedOk.Count))"

$resolvedGhost = @(Resolve-mdiNnrTarget -DomainControllers $dcInv -NnrTargetComputer @('ghost1') -Domain 'contoso.com' -MaxTargets 5 3>$null)
Assert-That 'an unresolvable named target produces NO probe target' ($resolvedGhost.Count -eq 0) "(got $($resolvedGhost.Count))"

$mixed = @(Resolve-mdiNnrTarget -DomainControllers $dcInv -NnrTargetComputer @('ws1', 'ghost1') -Domain 'contoso.com' -MaxTargets 5 3>$null)
Assert-That 'a mixed list keeps only the resolvable one' ($mixed.Count -eq 1 -and [string] $mixed[0].Name -match 'ws1') `
    "(got $($mixed.Count): $((@($mixed | ForEach-Object { $_.Name })) -join ', '))"

'[w83] a named target that resolved to nothing costs the run its READY verdict'
$clean = Get-Outcome -Report (New-Report)
Assert-That 'the control run is READY' ($clean.Ready) "(issues: $(($clean.Issues | ForEach-Object { $_.Issue }) -join ' | '))"
Assert-That 'the control run raises no issue' ($clean.Count -eq 0) "(count $($clean.Count))"

$gap = Get-Outcome -Report (New-Report -Unresolved @('ghost1'))
Assert-That 'an unresolved named NNR target is NOT ready' (-not $gap.Ready)
Assert-That 'the issue list is not empty' ($gap.Count -gt 0) "(count $($gap.Count))"

$named = @($gap.Issues | Where-Object { [string] $_.Server -eq 'ghost1' -and [string] $_.Issue -match 'could not be resolved to an address' })
Assert-That 'the unresolved target is named in the issue list' ($named.Count -eq 1) `
    "(matched $($named.Count) of: $(($gap.Issues | ForEach-Object { "$($_.Server)/$($_.Area)" }) -join ', '))"
Assert-That "the gap is filed as 'Not measured', not as an observed failure" `
    ($named.Count -eq 1 -and [string] $named[0].Area -eq 'Not measured') "(area '$(if ($named.Count) { $named[0].Area })')"
Assert-That 'the finding says no sensor was asked' `
    ($named.Count -eq 1 -and [string] $named[0].Issue -match 'no sensor was asked to resolve it')

'[w83] every unresolved target is reported, not just the first'
$two = Get-Outcome -Report (New-Report -Unresolved @('ghost1', 'ghost2'))
$twoNamed = @($two.Issues | Where-Object { [string] $_.Issue -match 'could not be resolved to an address' })
Assert-That 'both unresolved targets produce a finding' ($twoNamed.Count -eq 2) `
    "(got $($twoNamed.Count): $(($twoNamed | ForEach-Object { $_.Server }) -join ', '))"

'[w83] blank entries are not reported as hosts'
$blank = Get-Outcome -Report (New-Report -Unresolved @('', '   ', $null))
Assert-That 'a blank list raises no phantom finding' ($blank.Count -eq 0) `
    "(issues: $(($blank.Issues | ForEach-Object { "'$($_.Server)'" }) -join ', '))"
Assert-That 'a blank list does not cost the run its READY verdict' ($blank.Ready)

'[w83] the verdict and the issue list cannot diverge'
foreach ($case in @(
        @{ Name = 'none'; R = (New-Report) },
        @{ Name = 'one'; R = (New-Report -Unresolved @('ghost1')) },
        @{ Name = 'two'; R = (New-Report -Unresolved @('ghost1', 'ghost2')) }
    )) {
    $o = Get-Outcome -Report $case.R
    $consistent = ($o.Ready -and $o.Count -eq 0) -or ((-not $o.Ready) -and $o.Count -gt 0)
    Assert-That "  verdict and issue list agree ($($case.Name))" $consistent "(ready=$($o.Ready) issues=$($o.Count))"
}

'[w83] the gap is recorded on the report at all'
# The half that the probe-plan code owns: if Main stops recording the field, everything above still
# passes while the real script silently regresses.
Assert-That 'main records NnrUnresolvedTargets on the report' ($full -match 'NnrUnresolvedTargets\s+=')
Assert-That 'main computes the gap through the shared function' ($full -match 'Get-mdiUnresolvedNnrTarget -Requested \$NnrTargetComputer')
Assert-That 'the verdict reads the field' `
    ($full.Substring($full.IndexOf('function Test-mdiReadinessResult')) -match 'NnrUnresolvedTargets')
$issueStart = $full.IndexOf('function Get-mdiIssueList')
$issueEnd = $full.IndexOf('function Test-mdiReadinessResult')
Assert-That 'the issue list reads the field' `
    ($issueStart -ge 0 -and $issueEnd -gt $issueStart -and ($full.Substring($issueStart, $issueEnd - $issueStart) -match 'NnrUnresolvedTargets'))

'[w83] the gap computation is correct, executed rather than described'
# This block used to lift two assignment statements out of the PARSED script and Invoke-Expression
# them, because the computation lived inline in Main and nothing else could reach it. It is now the
# shipped function Get-mdiUnresolvedNnrTarget, so it is CALLED directly - which is strictly better
# evidence: the same code path Main uses, with no reconstruction of its surrounding variables.
#
# The move happened because the inline version was wrong in a way this arrangement could not catch:
# it matched every request on its leftmost DNS label, so an unresolved host.beta.contoso.com was
# masked by a resolved host.alpha.contoso.com and vanished from the verdict and the exit code. The
# same-label case below is that defect, and it is now covered here as well as in
# NnrGapIsNotHiddenBySharedLabel.Tests.ps1.
$cases = @(
    @{ Name = 'short name resolved to its FQDN is NOT a gap'; Named = @('ws1'); Resolved = @('ws1.contoso.com'); Expect = @() }
    @{ Name = 'unresolved name IS a gap'; Named = @('ghost1'); Resolved = @(); Expect = @('ghost1') }
    @{ Name = 'mixed list reports only the unresolved one'; Named = @('ws1', 'ghost1'); Resolved = @('ws1.contoso.com'); Expect = @('ghost1') }
    @{ Name = 'exact FQDN match is NOT a gap'; Named = @('ws1.contoso.com'); Resolved = @('ws1.contoso.com'); Expect = @() }
    @{ Name = 'trailing dot is NOT a gap'; Named = @('ws1.contoso.com.'); Resolved = @('ws1.contoso.com'); Expect = @() }
    @{ Name = 'blank entries are never a gap'; Named = @('', '   '); Resolved = @(); Expect = @() }
    @{ Name = 'a different host IS a gap'; Named = @('ws2'); Resolved = @('ws1.contoso.com'); Expect = @('ws2') }
    @{ Name = 'a multi-homed host resolved twice is NOT a gap'; Named = @('ws1'); Resolved = @('ws1.contoso.com', 'ws1.contoso.com'); Expect = @() }
    @{ Name = 'a same-label host in another domain does NOT mask an unresolved one'
        Named = @('host.alpha.contoso.com', 'host.beta.contoso.com'); Resolved = @('host.alpha.contoso.com')
        Expect = @('host.beta.contoso.com') }
)
foreach ($case in $cases) {
    $got = @(Get-mdiUnresolvedNnrTarget -Requested $case.Named -Resolved $case.Resolved | ForEach-Object { [string] $_ })
    $want = @($case.Expect)
    $same = ($got.Count -eq $want.Count) -and
        (($got | Sort-Object) -join '|') -eq (($want | Sort-Object) -join '|')
    Assert-That "  $($case.Name)" $same "(got [$($got -join ', ')] want [$($want -join ', ')])"
}

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
