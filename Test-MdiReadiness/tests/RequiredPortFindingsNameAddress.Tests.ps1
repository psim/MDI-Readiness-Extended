<#
    A required-port finding must name the address that actually failed.

    The finding named the host but not the NIC, and on a multi-homed domain controller it could attach
    the HEALTHY address to the failed row. The operator was then sent to a NIC that was never probed,
    while the address that actually refused the connection went unnamed - so the one row
    that exists to say where to look pointed somewhere else.

    Pinned here: the issue names the host and the failing address, the issue list emits one actionable
    port finding naming that address, the required-port HTML names it too, and the HTML does not attach
    the healthy address to the failed row.
#>

$ErrorActionPreference = 'Stop'
$canonical = $(if ($env:MDI_CANONICAL) { $env:MDI_CANONICAL } else { $c = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1'; if (Test-Path -LiteralPath $c) { $c } else { Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1' } })
$loaded = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $loaded)) { $loaded = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$loadedHash = (Get-FileHash -LiteralPath $loaded -Algorithm SHA256).Hash
$canonicalHash = $(if (Test-Path -LiteralPath $canonical) { (Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash } else { '<canonical not found>' })
"LOADED_PATH=$loaded"
"LOADED_SHA256=$loadedHash"
"CANONICAL_SHA256=$canonicalHash"
"HASH_MATCH=$($loadedHash -eq $canonicalHash)"
# NOT fatal when the hashes differ. Run-Suite.ps1 deliberately runs every test against an ISOLATED
# SNAPSHOT of the tree, so the canonical file legitimately moves on while the suite is running - and
# throwing here killed the file before a single assertion ran. Five tests reported "no assertions"
# in a suite where they passed standalone, which reads as a quiet file rather than as a dead one.
# The disclosure above is what actually guards against loading a stale copy; the hard guard below
# proves the loaded file is the product script rather than proving it is byte-current.
if ($loadedHash -ne $canonicalHash) {
    "NOTE=loaded copy differs from the canonical file (expected inside an isolated suite copy)"
}
$text = [IO.File]::ReadAllText($loaded) -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
# The guard that actually matters: the file loaded must BE the product script. A stale or truncated
# copy sitting next to a test has silently satisfied a whole test file here before.
if ($text -notmatch '(?m)^function ConvertTo-mdiBoolean') { throw "The file loaded from $loaded is not the Test-MdiReadiness product script." }
$main = $text.IndexOf('#region Main'); if ($main -gt 0) { $text = $text.Substring(0, $main) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
$script:pass = 0; $script:fail = 0
function Assert-That([string] $Name, [bool] $Condition, [string] $Detail = '') {
    if ($Condition) { $script:pass++; "  PASS  $Name" }
    else { $script:fail++; "  FAIL  $Name $Detail" }
}
function New-PortRecord([string] $Address, [bool] $Success) {
    [PSCustomObject]@{
        Id = 'LdapTcp'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389
        Scope = 'DomainController'; Group = 'Directory'; Requirement = 'Required'
        Target = 'dc1.example.test'; TargetIP = $Address; Applicable = $true; Success = $Success
        Detail = $(if ($Success) { 'Connected' } else { 'Closed - connection refused' })
    }
}
$failedAddress = '2001:db8::11'
$failed = New-PortRecord -Address $failedAddress -Success $false

'[issue wording] the exact endpoint behind a required failure is named'
$issueText = Get-mdiPortIssueText -Record $failed
Assert-That 'the issue names the host' ($issueText -match 'dc1\.example\.test') "issue=[$issueText]"
Assert-That 'the issue names the failing address' ($issueText -match [regex]::Escape($failedAddress)) "issue=[$issueText]"

'[issue list and HTML] operator-facing shipped renderers retain the address'
$server = [PSCustomObject]@{
    FQDN = 'sensor.example.test'; Domain = 'example.test'; Unreachable = $false
    PartialFailure = $false; RequiredPorts = $false
    Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{
            Results = @((New-PortRecord -Address '2001:db8::10' -Success $true), $failed)
            FailedRequired = @(); NnrFailedTargets = @()
        } }
}
$report = [PSCustomObject]@{
    Domain = 'example.test'; Forest = 'example.test'; DomainsInScope = @('example.test')
    DomainControllers = @($server); CAServers = @(); EntraConnectServers = @(); DomainAuditing = @()
    ForestDiscovery = [PSCustomObject]@{ Complete = $true }
    LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
}
$statistics = Get-mdiReportStatistics -ReportData $report
$issues = @(Get-mdiIssueList -Statistics $statistics -ReportData $report |
        Where-Object { $_.Area -eq 'Network' -and $_.Issue -like 'A required network probe*' })
Assert-That 'the issue list emits one actionable port finding' ($issues.Count -eq 1) "count=$($issues.Count)"
Assert-That 'the emitted issue names the failing address' (
    $issues.Count -eq 1 -and $issues[0].Issue -match [regex]::Escape($failedAddress)) "issue=[$($issues.Issue -join '|')]"
$html = Get-mdiRequiredPortsHtml -Server @($server)
Assert-That 'the required-port HTML names the failing address' ($html.Contains($failedAddress))
Assert-That 'the HTML does not attach the healthy address to the failed row' (
    $html.Contains('dc1.example.test (2001:db8::11)')) 'qualified failing target absent'

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail) { exit 1 }
