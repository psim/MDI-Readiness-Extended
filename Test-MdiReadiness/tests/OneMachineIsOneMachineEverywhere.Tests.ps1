<#
    THE MERGE KNEW TWO RECORDS WERE ONE MACHINE. THE COUNTERS DID NOT.

    Merge-mdiServerByFqdn normalises a server's identity carefully - case, trailing dot, surrounding
    whitespace, and a dotless short name qualified by the record's own domain - so one physical host
    discovered under two spellings produces ONE row.

    The probe-population counters in Get-mdiReportStatistics de-duplicated the raw FQDN string with
    Select-Object -Unique instead. Measured on the shipped functions with one reachable domain
    controller supplied as "DC01.CONTOSO.COM" and "dc01.contoso.com":

        TotalServers=1  PortCandidateHostCount=2  PortDistinctTargetCount=1
        qualifier=' (network probes used a sample: ports 1 of 2 host(s), raise
                     -MaxLdapTargetsPerDomain; name resolution 1 of 2 host(s), raise -MaxNnrTargets)'

    The same for the trailing-dot and short-name spellings. So one report said, on one page, that it
    had scanned one server AND that it had probed only half the estate - and told the operator to
    raise the sampling limits. That advice cannot change the result, because the "missing" host is an
    alias of the one already probed, and a reader has no way to tell it from a genuine sample. The
    sampling disclosure exists precisely so a partial probe cannot be read as a full one; a false
    positive in it spends the operator's trust on nothing.

    The identity rule now lives in Get-mdiServerIdentityKey and BOTH the merge and the counters call
    it, so they cannot drift apart again.
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

function New-Dc {
    param([string] $Fqdn, [string] $Domain = 'contoso.com')
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = $Domain; Unreachable = $false; PartialFailure = $false
        OSVersionOk = $true; PowerSettings = $true
        Details = [PSCustomObject]@{
            RequiredPortsDetails = [PSCustomObject]@{
                Results = @(
                    [PSCustomObject]@{
                        Id = 'Ldap'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389
                        Scope = 'DomainController'; Group = 'LDAP'; Requirement = 'Required'
                        Target = 'dc01.contoso.com'; TargetIP = '10.42.0.11'
                        Applicable = $true; Success = $true; Detail = 'Connected'
                    },
                    [PSCustomObject]@{
                        Id = 'NnrDns'; Name = 'DNS'; Protocol = 'UDP'; Port = 53
                        Scope = 'Nnr'; Group = 'NNR'; Requirement = 'AtLeastOne'
                        Target = 'dc01.contoso.com'; TargetIP = '10.42.0.11'
                        Applicable = $true; Success = $true; Detail = 'Resolved'
                    })
            }
        }
    }
}

function Get-Counts {
    param([string[]] $Spelling)
    $reportData = [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @($Spelling | ForEach-Object { New-Dc -Fqdn $_ })
        CAServers = @(); EntraConnectServers = @(); DomainAuditing = @(); NnrTargetComputer = @()
    }
    Get-mdiReportStatistics -ReportData $reportData
}

# The control has to behave, or nothing below means anything: two records spelled IDENTICALLY were
# always counted as one host.
$control = Get-Counts -Spelling @('dc01.contoso.com', 'dc01.contoso.com')
if ([int] $control.TotalServers -ne 1) {
    throw "the identical-spelling control did not merge to one server (TotalServers=$($control.TotalServers)) - the harness is wrong"
}
if ([int] $control.PortCandidateHostCount -ne 1) {
    throw "the identical-spelling control already counts $($control.PortCandidateHostCount) candidate hosts - the harness is wrong"
}

Write-Host 'One machine spelled two ways is one machine to the counters, not just to the merge' -ForegroundColor Cyan
foreach ($case in @(
        @{ N = 'differing case'; S = @('DC01.CONTOSO.COM', 'dc01.contoso.com') },
        @{ N = 'absolute form with a trailing dot'; S = @('dc01.contoso.com.', 'dc01.contoso.com') },
        @{ N = 'short name qualified by its own domain'; S = @('dc01', 'dc01.contoso.com') },
        @{ N = 'surrounding whitespace'; S = @(' dc01.contoso.com ', 'dc01.contoso.com') })) {

    $stats = Get-Counts -Spelling $case.S
    # The merge is the reference answer: whatever it says the machine count is, the counters must agree.
    Assert-That "$($case.N): the merge still sees one server" (
        [int] $stats.TotalServers -eq 1) "totalServers=$($stats.TotalServers)"
    Assert-That "  ...and the ports candidate population agrees" (
        [int] $stats.PortCandidateHostCount -eq 1) "portCandidateHostCount=$($stats.PortCandidateHostCount)"
    Assert-That "  ...and the NNR candidate population agrees" (
        [int] $stats.NnrCandidateCount -eq 1) "nnrCandidateCount=$($stats.NnrCandidateCount)"
    # The invariant the whole sampling disclosure rests on.
    Assert-That "  ...so the probed count is not less than the population" (
        [int] $stats.PortDistinctTargetCount -ge [int] $stats.PortCandidateHostCount) (
        "probed=$($stats.PortDistinctTargetCount) population=$($stats.PortCandidateHostCount)")
}

Write-Host ''
Write-Host 'CONTROLS - genuinely different machines must still count separately' -ForegroundColor Cyan
$two = Get-Counts -Spelling @('dc01.contoso.com', 'dc02.contoso.com')
Assert-That 'CONTROL: two different hosts are two servers' (
    [int] $two.TotalServers -eq 2) "totalServers=$($two.TotalServers)"
Assert-That 'CONTROL: and two candidate hosts' (
    [int] $two.PortCandidateHostCount -eq 2) "portCandidateHostCount=$($two.PortCandidateHostCount)"

# The same short name in two different domains is two different machines, and the identity rule must
# not collapse them - qualifying with the record's OWN domain is what keeps them apart.
$reportData = [PSCustomObject]@{
    Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com', 'fabrikam.com')
    DomainControllers = @((New-Dc -Fqdn 'dc01' -Domain 'contoso.com'), (New-Dc -Fqdn 'dc01' -Domain 'fabrikam.com'))
    CAServers = @(); EntraConnectServers = @(); DomainAuditing = @(); NnrTargetComputer = @()
}
$crossDomain = Get-mdiReportStatistics -ReportData $reportData
Assert-That 'CONTROL: the same short name in two domains is two servers' (
    [int] $crossDomain.TotalServers -eq 2) "totalServers=$($crossDomain.TotalServers)"
Assert-That 'CONTROL: and two candidate hosts' (
    [int] $crossDomain.PortCandidateHostCount -eq 2) "portCandidateHostCount=$($crossDomain.PortCandidateHostCount)"

Write-Host ''
Write-Host 'The identity rule itself' -ForegroundColor Cyan
Assert-That 'case is not part of a DNS name' (
    (Get-mdiServerIdentityKey -Server (New-Dc -Fqdn 'DC01.CONTOSO.COM')) -eq 'dc01.contoso.com')
Assert-That 'a trailing dot is not part of a DNS name' (
    (Get-mdiServerIdentityKey -Server (New-Dc -Fqdn 'dc01.contoso.com.')) -eq 'dc01.contoso.com')
Assert-That 'surrounding whitespace is not part of a DNS name' (
    (Get-mdiServerIdentityKey -Server (New-Dc -Fqdn '  dc01.contoso.com  ')) -eq 'dc01.contoso.com')
Assert-That 'a short name is qualified by the record own domain' (
    (Get-mdiServerIdentityKey -Server (New-Dc -Fqdn 'DC01' -Domain 'CONTOSO.COM')) -eq 'dc01.contoso.com')
# It must never INVENT an identity: with no domain to qualify from, the short name stays as it is.
Assert-That 'a short name with no domain is left alone rather than guessed at' (
    (Get-mdiServerIdentityKey -Server (New-Dc -Fqdn 'dc01' -Domain '')) -eq 'dc01')
Assert-That 'a name that is nothing but dots yields no key' (
    (Get-mdiServerIdentityKey -Server (New-Dc -Fqdn '..')) -eq '')
Assert-That 'an empty name yields no key' (
    (Get-mdiServerIdentityKey -Server (New-Dc -Fqdn '   ')) -eq '')
Assert-That 'a null server yields no key rather than throwing' (
    (Get-mdiServerIdentityKey -Server $null) -eq '')

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
