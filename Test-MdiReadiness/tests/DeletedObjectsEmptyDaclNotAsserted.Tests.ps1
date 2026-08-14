<#
    A container DACL that was read successfully and simply grants read to nobody made two
    operator-visible surfaces disagree about the same fact.

    Get-mdiDeletedObjectsPermission has an early return for "no qualifying trustee". When NotAsserted
    was introduced - to separate "the DACL was read in full but no account was supplied to assert
    against" from a real measurement gap - only the main return path carried it. The early return did
    not, and Test-mdiDomainCheckNotAsserted returns $false when the property is ABSENT, so the flag
    defaulted to the wrong answer.

    Measured on the DEFAULT invocation (-DirectoryServiceAccount is optional, so this is the common
    case): the HTML cell rendered a benign grey "Not applicable" because the renderer reads Measured,
    while Test-mdiDomainCheckPassed returned False and the issue list raised a High
    "Deleted Objects container permission returned no usable result on this domain, so it is
    unverified". One fact, two answers, and the operator has no way to tell which is right.

    The flag now carries ($descriptorWasRead -and -not $DirectoryServiceAccount). Both halves matter,
    and both are asserted below:
      - with an account supplied the answer is a definite FAILURE and must still be asserted;
      - when the descriptor could not be read at all it is a genuine gap and must keep counting as an
        unread check rather than being excused as a question nobody asked.

    This is a BEHAVIOURAL test. It calls the real Get-mdiDeletedObjectsPermission, the real
    Test-mdiDomainCheckPassed, the real Get-mdiIssueList and the real report renderer, and asserts on
    what an operator actually reads on each surface.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

# Make the script take the ActiveDirectory-module read path without one being installed.
function Get-Module {
    [CmdletBinding()]
    param([Parameter(Position = 0)] [string[]] $Name, [switch] $ListAvailable, [switch] $All, [switch] $Refresh)
    if ($ListAvailable -and @($Name) -contains 'ActiveDirectory') { [PSCustomObject]@{ Name = 'ActiveDirectory' }; return }
    Microsoft.PowerShell.Core\Get-Module @PSBoundParameters
}

. $target -Domain 'probe.invalid' -WhatIf -SkipCA -SkipEntraConnect -SkipNetworkPorts -SkipRemediationScript -SkipTrend 3>$null 4>$null | Out-Null

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Set-Item -Path function:script:Get-ADRootDSE -Value {
    [PSCustomObject]@{ defaultNamingContext = 'DC=contoso,DC=test' }
}
# Force the directory-module path; the DirectoryEntry route is not what this defect lived on.
Set-Item -Path function:script:New-Object -Value {
    param(
        [Parameter(Position = 0)] [string] $TypeName,
        [Parameter(Position = 1)] [object[]] $ArgumentList,
        [hashtable] $Property
    )
    if ($TypeName -eq 'System.DirectoryServices.DirectoryEntry') { throw 'forced directory-module fallback' }
    $p = @{ TypeName = $TypeName }
    if ($PSBoundParameters.ContainsKey('ArgumentList')) { $p.ArgumentList = $ArgumentList }
    if ($PSBoundParameters.ContainsKey('Property')) { $p.Property = $Property }
    Microsoft.PowerShell.Utility\New-Object @p
}

$outDir = $env:TEMP

# Drives every surface from one result the way a real run does.
function Get-SurfaceView {
    param($Result)

    $row = [PSCustomObject]@{
        Domain           = 'contoso.test'
        ObjectAuditing   = [PSCustomObject]@{ isObjectAuditingOk = $true }; ObjectAuditingMeasured = $true
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }; ExchangeAuditingMeasured = $true
        AdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $true
        DeletedObjects   = $Result; DeletedObjectsMeasured = $Result.Measured
    }
    $report = [PSCustomObject]@{
        Domain          = 'contoso.test'; Forest = 'contoso.test'; DomainsInScope = @('contoso.test')
        ForestDiscovery = [PSCustomObject]@{ Complete = $true }
        DomainAuditing  = @($row)
        DomainControllers = @([PSCustomObject]@{ FQDN = 'dc1.contoso.test'; Domain = 'contoso.test'; PowerScheme = $true; Details = [PSCustomObject]@{} })
        CAServers       = @(); EntraConnectServers = @()
        LdapPlanGapDomains = @(); SkippedAreas = @(); NnrTargetComputer = @(); MaxNnrTargets = 5
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    $issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report | Where-Object { $_.Issue -like 'Deleted Objects*' })

    $htmlFile = Set-MdiReadinessReport -Domain 'contoso.test' -Path $outDir -ReportData $report -SkipTrend
    $html = [IO.File]::ReadAllText([string] $htmlFile)
    Remove-Item -LiteralPath $htmlFile -Force -ErrorAction SilentlyContinue
    $jsonFile = Join-Path $outDir 'mdi-contoso.test.json'
    if ([IO.File]::Exists($jsonFile)) { Remove-Item -LiteralPath $jsonFile -Force -ErrorAction SilentlyContinue }

    $match = [regex]::Match($html, '(?s)<tr><td class="mono">contoso\.test</td><td><span class="pill ([^"]+)">([^<]+)</span></td><td>The container.*?</td></tr>')

    [PSCustomObject]@{
        Status      = $Result.isDeletedObjectsPermissionOk
        Measured    = $Result.Measured
        HasFlag     = ($null -ne $Result.PSObject.Properties['NotAsserted'])
        NotAsserted = (Test-mdiDomainCheckNotAsserted -Result $Result)
        CheckPassed = (Test-mdiDomainCheckPassed -Result $Result -Value $Result.isDeletedObjectsPermissionOk)
        IssueCount  = $issues.Count
        IssueText   = ($issues | ForEach-Object { '{0}|{1}' -f $_.Severity, $_.Issue }) -join '; '
        HtmlFound   = $match.Success
        HtmlPill    = $(if ($match.Success) { $match.Groups[1].Value } else { '' })
        HtmlText    = $(if ($match.Success) { $match.Groups[2].Value } else { '' })
    }
}

# A readable DACL that grants read to nobody.
Set-Item -Path function:script:Get-ADObject -Value {
    [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
}

Write-Host 'Default run: DACL read, nobody qualifies, no account to assert against' -ForegroundColor Cyan
$default = Get-SurfaceView -Result (Get-mdiDeletedObjectsPermission -Domain 'contoso.test')

Assert-That 'the DACL counts as read' ($default.Measured -eq $true)
Assert-That 'the status is N/A, not a failure' ([string] $default.Status -eq 'N/A')
Assert-That 'the result carries NotAsserted at all' $default.HasFlag 'the early return dropped the flag and consumers defaulted it to $false'
Assert-That 'it is recognised as not asserted' ($default.NotAsserted -eq $true)
Assert-That 'the HTML renders it as Not applicable' ($default.HtmlFound -and $default.HtmlPill -eq 'na') "pill=$($default.HtmlPill)"
Assert-That 'the domain check AGREES with the HTML and passes' ($default.CheckPassed -eq $true) 'the HTML said Not applicable while the verdict counted a failure'
Assert-That 'the issue list AGREES and raises nothing' ($default.IssueCount -eq 0) "raised: $($default.IssueText)"

Write-Host 'An account WAS supplied: the same empty DACL is a real failure' -ForegroundColor Cyan
$asserted = Get-SurfaceView -Result (Get-mdiDeletedObjectsPermission -Domain 'contoso.test' -DirectoryServiceAccount 'CONTOSO\mdisvc')

Assert-That 'the status is a definite failure' ($asserted.Status -eq $false) "status=$($asserted.Status)"
Assert-That 'it is NOT excused as unasserted' ($asserted.NotAsserted -eq $false) 'a missing grant would be silently forgiven'
Assert-That 'the domain check fails' ($asserted.CheckPassed -eq $false)
Assert-That 'the issue list raises it' ($asserted.IssueCount -ge 1)
Assert-That 'the HTML does not render it as Not applicable' ($asserted.HtmlFound -and $asserted.HtmlPill -ne 'na') "pill=$($asserted.HtmlPill)"

Write-Host 'The descriptor could not be read at all: still a genuine gap' -ForegroundColor Cyan
Set-Item -Path function:script:Get-ADObject -Value {
    [PSCustomObject]@{ nTSecurityDescriptor = $null }
}
$unread = Get-mdiDeletedObjectsPermission -Domain 'contoso.test'

Assert-That 'the DACL does not count as read' ($unread.Measured -eq $false)
Assert-That 'the status is N/A' ([string] $unread.isDeletedObjectsPermissionOk -eq 'N/A')
Assert-That 'an unread descriptor is NOT excused as unasserted' ((Test-mdiDomainCheckNotAsserted -Result $unread) -eq $false) 'a real measurement gap would stop counting as an unread check'

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
