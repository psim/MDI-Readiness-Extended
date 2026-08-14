# [w80] A domain whose NAME collides with a status word must keep its own styling.
#
# The domain-auditing table is produced by ConvertTo-Html -Fragment and then styled with a chain of
# unanchored -replace calls. The status patterns match a bare '<td>True</td>' ANYWHERE in the row,
# and the Domain name is the first cell - so a domain actually named 'True' was claimed by the status
# rule, painted green as though it were a passing check, and then no longer matched '<tr><td>', so it
# lost its monospace styling too.
#
# Proven against the REAL renderer: Set-MdiReadinessReport is called and the HTML it writes to disk is
# read back. See MDI-AB\live\w80-html-verify-realrenderer.ps1 for the probe that found it.

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
    param([string] $Domain, [bool] $AdfsMeasured = $true)
    [PSCustomObject]@{
        Domain = $Domain
        ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }; ObjectAuditingMeasured = $true
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }; ExchangeAuditingMeasured = $true
        AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }; AdfsAuditingMeasured = $AdfsMeasured
        DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; NotAsserted = $false }; DeletedObjectsMeasured = $true
    }
}

function Get-ReportHtml {
    param([string[]] $DomainNames, [string[]] $ServerNames)
    $servers = if ($ServerNames) {
        @($ServerNames | ForEach-Object { New-Srv -Fqdn $_ -Domain $DomainNames[0] })
    } else {
        @($DomainNames | ForEach-Object { New-Srv -Fqdn ("dc-$_") -Domain $_ })
    }
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainsInScope = $DomainNames
        LdapPlanGapDomains = @()
        DomainControllers = $servers
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @($DomainNames | ForEach-Object { New-Audit -Domain $_ -AdfsMeasured:$false })
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
        SkippedAreas = @()
    }
    $outDir = Join-Path $env:TEMP ('mdihtml-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void](New-Item -ItemType Directory -Path $outDir -Force)
    try {
        Set-MdiReadinessReport -Domain 'contoso.com' -Path $outDir -ReportData $report -SkipTrend 3>$null 4>$null 6>$null | Out-Null
        $file = @(Get-ChildItem $outDir -Filter '*.html' -File)
        if ($file.Count -eq 0) { return $null }
        [IO.File]::ReadAllText($file[0].FullName)
    } finally { Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue }
}

'[w80] the report is still produced'
$html = Get-ReportHtml -DomainNames @('True', 'False', 'N/A', 'contoso.com')
Assert-That 'the renderer wrote an HTML report' ($null -ne $html -and $html.Length -gt 500) "(length $(if ($html) { $html.Length } else { 0 }))"

'[w80] no data row starts with a status-styled cell'
# The decisive assertion. The first cell of a row is a NAME, never a status, so it must never carry
# the green/red/grey/muted status classes.
$firstCellStatus = [regex]::Matches($html, '<tr><td class="(green|red|muted-cell|grey)"')
Assert-That 'no row has a status class on its first cell' ($firstCellStatus.Count -eq 0) `
    "($($firstCellStatus.Count) row(s): $((($firstCellStatus | Select-Object -First 3) | ForEach-Object { $_.Value }) -join ' | '))"

'[w80] a domain named after a status word keeps its own styling'
foreach ($name in @('True', 'False', 'N/A')) {
    $encoded = [regex]::Escape((ConvertTo-mdiHtmlEncoded $name))
    $rowCell = [regex]::Matches($html, ('<tr><td[^>]*>' + $encoded + '</td>'))
    Assert-That "  the row for the domain named '$name' exists" ($rowCell.Count -ge 1) "(found $($rowCell.Count))"
    $mono = @($rowCell | Where-Object { $_.Value -match 'class="mono"' }).Count
    Assert-That "  the domain named '$name' is rendered as a name, not a status" ($mono -eq $rowCell.Count) `
        "(mono $mono of $($rowCell.Count): $((($rowCell | Select-Object -First 2) | ForEach-Object { $_.Value }) -join ' | '))"
}

'[w80] a domain name is never rewritten into different text'
# 'Not tested' and 'Not applicable' are cell VALUES the renderer produces; a domain NAME must never be
# replaced by one of them.
Assert-That 'no first cell was rewritten to "Not tested"' `
    (-not ($html -match '<tr><td[^>]*>Not tested</td>'))
Assert-That 'no first cell was rewritten to "Not applicable"' `
    (-not ($html -match '<tr><td[^>]*>Not applicable</td>'))

'[w80] the status styling still works where it belongs'
# The control. Without it, deleting the status replacements altogether would satisfy everything above.
Assert-That 'passing checks are still painted green' ([regex]::Matches($html, '<td class="green">True</td>').Count -gt 0) `
    "(green cells: $([regex]::Matches($html, '<td class="green">True</td>').Count))"
Assert-That 'unread domain settings still render as "Not tested"' `
    ($html -match '<td class="muted-cell"[^>]*>Not tested</td>')
Assert-That 'absent roles still render as "Not applicable"' `
    ($html -match '<td class="grey"[^>]*>Not applicable</td>')

'[w80] ordinary domains are unaffected'
$plain = Get-ReportHtml -DomainNames @('contoso.com', 'child.contoso.com')
Assert-That 'an ordinary domain is monospaced' ($plain -match '<tr><td class="mono">contoso\.com</td>')
Assert-That 'an ordinary report has no status-styled first cell' `
    ([regex]::Matches($plain, '<tr><td class="(green|red|muted-cell|grey)"').Count -eq 0)

'[w80] the SERVER table has the same protection'
# The server table is built by its own copy of the same -replace chain, and had the same ordering
# defect. Its first cell is the FQDN.
$srvHtml = Get-ReportHtml -DomainNames @('contoso.com') -ServerNames @('True', 'False', 'N/A', 'dc1.contoso.com')
Assert-That 'the server report was written' ($null -ne $srvHtml -and $srvHtml.Length -gt 500)
Assert-That 'no server row has a status class on its first cell' `
    ([regex]::Matches($srvHtml, '<tr><td class="(green|red|muted-cell|grey)"').Count -eq 0) `
    "($([regex]::Matches($srvHtml, '<tr><td class="(green|red|muted-cell|grey)"').Count) row(s))"
foreach ($name in @('True', 'False')) {
    $enc = [regex]::Escape((ConvertTo-mdiHtmlEncoded $name))
    $cells = [regex]::Matches($srvHtml, ('<tr><td[^>]*>' + $enc + '</td>'))
    $mono = @($cells | Where-Object { $_.Value -match 'class="mono"' }).Count
    Assert-That "  a server named '$name' is rendered as a name, not a status" ($cells.Count -ge 1 -and $mono -eq $cells.Count) `
        "(mono $mono of $($cells.Count): $((($cells | Select-Object -First 2) | ForEach-Object { $_.Value }) -join ' | '))"
}
Assert-That 'server status cells are still painted green' `
    ([regex]::Matches($srvHtml, '<td class="green">True</td>').Count -gt 0)

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
