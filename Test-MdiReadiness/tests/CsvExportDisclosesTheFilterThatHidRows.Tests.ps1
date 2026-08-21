<#
    THE EXPORTED FILE SAID NOTHING ABOUT THE FILTER THAT EMPTIED IT.

    The report page filters table rows as you type and shows "n of m row(s) shown" beside the box.
    The product states why that counter exists, in its own words: "Without it a filter that matches
    one healthy server looks exactly like a report with one healthy server in it, and the failures
    the reader came to find are gone from the screen with nothing to say so."

    The CSV button exports the visible rows of the active panel, and in modern view it deliberately
    skips the rows the filter hid - that part is correct, it exports what the reader is looking at.
    What it did NOT do was carry the counter's disclosure into the file. The counter stays on the
    screen; the CSV is the copy that gets attached to mail as evidence.

    Measured on the shipped page under jsdom, three domain controllers with one of them unhealthy,
    the filter "dcfab01" typed into the domain controllers card:

        on screen                    "1 of 3 row(s) shown", 2 rows hidden
        CSV without the filter       14 lines, domain controller table = header + 3 rows
        CSV with the filter          12 lines, domain controller table = header + 1 row
        anything in the CSV saying rows were withheld    NOTHING - no "filter", no "row(s) shown"

    So a filtered export was indistinguishable from a report of a healthy estate, which is exactly
    the reading the on-screen counter was added to prevent.

    Pinned here: with a filter applied, the export emits one disclosure line naming the filter text
    and the counter, before any table; the line is CSV-quoted like every other cell; the deliberate
    modern-view row skip is unchanged; and classic view - which clears every filter and exports the
    whole report - emits no such line. The assertions run against the RENDERED page as well as the
    source, so a fix that exists only in the generator but never reaches a report would still fail.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
# Sibling first: the suite copies the test and the product script into one flat isolated directory,
# so the copy beside this file is the one under test. The parent fallback lets the file also run
# straight from the repository.
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$target = [IO.Path]::GetFullPath($target)

$text = [IO.File]::ReadAllText($target)
if ($text -notmatch '(?m)^function Set-MdiReadinessReport') {
    throw "The file loaded from $target is not the Test-MdiReadiness product script."
}
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main')
if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:passed++
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray
    } else {
        $script:failed++
        Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red
    }
}

Write-Host 'CsvExportDisclosesTheFilterThatHidRows.Tests.ps1' -ForegroundColor Cyan

# ---- the export handler, isolated by two stable anchors -----------------------------------------
$startAnchor = 'var csvBtn = document.getElementById("csvBtn");'
$endAnchor = 'URL.revokeObjectURL(link.href);'
$start = $text.IndexOf($startAnchor)
$end = $text.IndexOf($endAnchor, [Math]::Max($start, 0))
Assert-True 'the CSV export handler is present in the product' (($start -ge 0) -and ($end -gt $start)) ("start=$start end=$end")
$handler = if (($start -ge 0) -and ($end -gt $start)) { $text.Substring($start, $end - $start) } else { '' }

Assert-True 'the export still skips rows the filter hid, in modern view only' `
    ($handler -match '\!isClassic\s*&&\s*row\.style\.display\s*===\s*"none"') `
    'the deliberate modern-view skip must not be removed by this fix'

Assert-True 'the export emits a disclosure naming the filter' `
    ($handler -cmatch 'rows hidden by the filter are NOT included') `
    'no disclosure line found in the export handler'

Assert-True 'the disclosure repeats the on-screen counter' `
    ($handler -match 'filter-count') `
    'the note must carry the same "n of m row(s) shown" text the screen shows'

Assert-True 'the disclosure names the text that was typed' `
    ($handler -match 'box\.value') `
    'the note must name the filter text'

Assert-True 'the disclosure is skipped when there is nothing typed' `
    ($handler -match 'if\s*\(\!box\.value\)\s*\{\s*return;') `
    'an unfiltered export must be byte-identical to what it always was'

# The note belongs to modern view only. Classic clears every filter and exports the whole report, so
# a note there would describe a filter that is no longer applied.
$noteIndex = $handler.IndexOf('rows hidden by the filter are NOT included')
$classicGuard = $handler.IndexOf('if (!isClassic) {')
Assert-True 'the disclosure sits inside the modern-view branch' `
    (($classicGuard -ge 0) -and ($noteIndex -gt $classicGuard)) `
    ("guard=$classicGuard note=$noteIndex")

Assert-True 'the disclosure is quoted like every other CSV cell' `
    ($handler -match "note\.replace\(/\`"/g") `
    'an unescaped quote in the filter text would break the line it is meant to explain'

# ---- and it has to reach a real report ----------------------------------------------------------
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mdi-csvnote-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
try {
    $dc = [pscustomobject]@{
        FQDN = 'dc01.contoso.local'; Domain = 'contoso.local'; Comment = ''
        Details = [pscustomobject]@{
            SensorHealthDetails = [pscustomobject]@{
                Installed = $true; SensorService = 'Running'; SensorStartMode = 'Automatic'
                UpdaterService = 'Running'; Detail = 'All services running'; Issues = @()
            }
            TimeSyncDetails = [pscustomobject]@{
                SkewSeconds = 12; RemoteUtc = '2026-08-21 09:00:00Z'; Detail = 'Clock within tolerance'
            }
        }
        SensorVersion = '2.0'; CapturingComponent = 'Npcap'; MachineType = 'Physical'
        OS = 'Windows Server 2022'; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
        NtlmAuditing = $true; SensorHealth = $true; TimeSync = $true
    }
    $report = [pscustomobject]@{
        Domain = 'contoso.local'; Forest = 'contoso.local'; DomainsInScope = @('contoso.local')
        DomainControllers = @($dc); CAServers = @(); EntraConnectServers = @()
        DomainSchemaVersion = [pscustomobject]@{ details = 'Windows Server 2016'; schemaVersion = 87 }
        DomainObjectAuditing = [pscustomobject]@{ isObjectAuditingOk = $true }
        DomainExchangeAuditing = [pscustomobject]@{ isExchangeAuditingOk = 'N/A' }
        DomainAdfsAuditing = [pscustomobject]@{ isAdfsAuditingOk = 'N/A' }
        DomainDeletedObjects = [pscustomobject]@{ isDeletedObjectsPermissionOk = $true; details = [pscustomobject]@{ Detail = 'OK' } }
    }
    $htmlPath = Set-MdiReadinessReport -Domain 'contoso.local' -Path $scratch -ReportData $report -SkipTrend 3>$null
    $html = [IO.File]::ReadAllText($htmlPath)
    Assert-True 'the rendered report carries the disclosure' `
        ($html -cmatch 'rows hidden by the filter are NOT included') `
        'the generator emits it but no report contains it'
    Assert-True 'the rendered report still carries the filter counter it quotes' `
        ($html -match 'filter-count') 'the note reads the counter element by class'
}
finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("RESULT pass={0} fail={1}" -f $script:passed, $script:failed)
if ($script:failed -gt 0) { exit 1 }
