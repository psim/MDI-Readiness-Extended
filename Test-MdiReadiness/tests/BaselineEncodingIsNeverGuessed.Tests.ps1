<#
    A BASELINE IN THE WRONG ENCODING WAS SILENTLY CORRUPTED, PERMANENTLY.

    Get-mdiBaselineHistory reads the trend file as UTF-8 - correctly, because Get-Content on Windows
    PowerShell 5.1 would fall back to the ANSI code page. But the default UTF8Encoding REPLACES every
    invalid byte with U+FFFD instead of failing, so a file that is not UTF-8 at all was accepted
    without a word.

    Measured on a baseline whose only non-ASCII character was the umlaut in dc-muenchen, saved as
    Windows-1252:

        PYTHON_BEFORE=UnicodeDecodeError: 'utf-8' codec can't decode byte 0xfc in position 269
        WARNINGS=0
        READ_SERVER=dc-m<U+FFFD>nchen.contoso.com
        SERVER_EQUAL=False
        PILL=Not comparable with the previous run - the set of servers changed
        DISK_CONTAINS_REPLACEMENT=True

    Python refused the file outright; the shipped reader accepted it, invented a server name that
    does not exist, lost the delta pill because the "set of servers changed", and then REWROTE the
    replacement character back into the file as well-formed UTF-8. The operator's history was
    destroyed by a run that reported nothing wrong, and no later run can recover it.

    Two things had to change: decode strictly, and - having failed - leave the file alone. Rewriting
    an unreadable history with this run alone would cost every previous run, which is the same damage
    by a different route.

    The control matters as much as the defect: a plain UTF-8 baseline, with or without a BOM, must
    still round-trip and still produce its delta pill.
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

$script:warnings = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiWarning -Value {
    param($Message)
    [void] $script:warnings.Add([string] $Message)
}

# The umlaut is the whole point: it is one byte in Windows-1252 and two in UTF-8.
$umlautServer = "dc-m$([char]0xFC)nchen.contoso.com"

function New-Statistics {
    param([string[]] $Server, [int] $Passed = 8)
    [PSCustomObject]@{
        CheckTotals = @{ 'Check1' = 5; 'Check2' = 5 }
        Servers = @($Server | ForEach-Object { [PSCustomObject]@{ FQDN = $_ } })
        ChecksPassed = $Passed; ChecksTotal = 10; ChecksUnread = 0
        TotalServers = @($Server).Count; ServerScores = @(1)
        PartialScanCount = 0
    }
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('mdi-baseline-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
[void] (New-Item -ItemType Directory -Path $root -Force)

try {
    # A real baseline, produced by the shipped writer, so the fixture is the genuine document shape.
    $seedPath = Join-Path $root 'seed'
    [void] (New-Item -ItemType Directory -Path $seedPath -Force)
    [void] (Get-mdiBaselineHistory -BaselinePath $seedPath -Domain 'contoso.com' -Statistics (New-Statistics -Server @($umlautServer) -Passed 6) 3>$null)
    $seedFile = @(Get-ChildItem -LiteralPath $seedPath -Filter '*.json')[0]
    $seedJson = [IO.File]::ReadAllText($seedFile.FullName, [Text.Encoding]::UTF8)
    if ($seedJson -notmatch [regex]::Escape($umlautServer)) {
        throw 'the seed baseline does not contain the umlaut server - the fixture is wrong'
    }

    function New-Case {
        param([string] $Name, [System.Text.Encoding] $Encoding)
        $dir = Join-Path $root $Name
        [void] (New-Item -ItemType Directory -Path $dir -Force)
        $file = Join-Path $dir $seedFile.Name
        [IO.File]::WriteAllText($file, $seedJson, $Encoding)
        $file
    }

    Write-Host 'A baseline that is not valid UTF-8 must be refused, not reinterpreted' -ForegroundColor Cyan
    $ansiFile = New-Case -Name 'ansi' -Encoding ([Text.Encoding]::GetEncoding(1252))
    $ansiBytesBefore = [IO.File]::ReadAllBytes($ansiFile)

    # The fixture must genuinely be invalid UTF-8, or this measures nothing.
    $strict = New-Object System.Text.UTF8Encoding @($false, $true)
    $reallyInvalid = $false
    try { [void] $strict.GetString($ansiBytesBefore) } catch { $reallyInvalid = $true }
    if (-not $reallyInvalid) { throw 'the Windows-1252 fixture decoded cleanly as UTF-8 - the fixture is wrong' }

    $script:warnings.Clear()
    $ansiResult = Get-mdiBaselineHistory -BaselinePath (Split-Path $ansiFile -Parent) -Domain 'contoso.com' `
        -Statistics (New-Statistics -Server @($umlautServer) -Passed 8) 3>$null

    Assert-That 'the operator is warned' (
        @($script:warnings | Where-Object { $_ -match 'not valid UTF-8' }).Count -ge 1) (
        'warnings: ' + ($script:warnings -join ' | '))
    Assert-That 'the file is left EXACTLY as it was, not rewritten' (
        [System.Linq.Enumerable]::SequenceEqual([byte[]] $ansiBytesBefore, [byte[]] ([IO.File]::ReadAllBytes($ansiFile)))) (
        'the unreadable baseline was overwritten')
    # The decisive one: no replacement character may ever reach the file. Checked as BYTES - the file
    # is still Windows-1252, so decoding it as UTF-8 here would produce U+FFFD in this test's own
    # reader and prove nothing. EF BF BD is U+FFFD encoded as UTF-8, which is what a corrupting
    # rewrite would have left behind.
    $ansiBytesAfter = [IO.File]::ReadAllBytes($ansiFile)
    $hasReplacementBytes = $false
    for ($i = 0; $i -lt $ansiBytesAfter.Length - 2; $i++) {
        if ($ansiBytesAfter[$i] -eq 0xEF -and $ansiBytesAfter[$i + 1] -eq 0xBF -and $ansiBytesAfter[$i + 2] -eq 0xBD) {
            $hasReplacementBytes = $true; break
        }
    }
    Assert-That 'no U+FFFD was written into the history' (-not $hasReplacementBytes) (
        'a replacement character is now in the operator history')
    Assert-That 'and the run still gets its own result object' (
        $null -ne $ansiResult -and $null -ne $ansiResult.Current) 'the run lost its own entry'

    Write-Host ''
    Write-Host 'CONTROLS - a valid baseline must still work exactly as before' -ForegroundColor Cyan
    foreach ($case in @(
            @{ N = 'utf8-with-bom'; E = (New-Object System.Text.UTF8Encoding $true) },
            @{ N = 'utf8-no-bom'; E = (New-Object System.Text.UTF8Encoding $false) })) {

        $file = New-Case -Name $case.N -Encoding $case.E
        $script:warnings.Clear()
        $result = Get-mdiBaselineHistory -BaselinePath (Split-Path $file -Parent) -Domain 'contoso.com' `
            -Statistics (New-Statistics -Server @($umlautServer) -Passed 8) 3>$null

        Assert-That "CONTROL ($($case.N)): the existing run is read back" (
            @($result.History).Count -ge 2) "history=$(@($result.History).Count)"
        Assert-That "CONTROL ($($case.N)): no encoding warning" (
            @($script:warnings | Where-Object { $_ -match 'not valid UTF-8' }).Count -eq 0) (
            'warnings: ' + ($script:warnings -join ' | '))
        # The umlaut survives, so the trend still sees ONE machine rather than two.
        $onDisk = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8)
        Assert-That "CONTROL ($($case.N)): the umlaut server name survives the round trip" (
            $onDisk -match [regex]::Escape($umlautServer)) 'the server name was mangled'
        Assert-That "CONTROL ($($case.N)): and no replacement character appears" (
            $onDisk -notmatch [regex]::Escape([string] [char] 0xFFFD))
        # And the run was really appended - the healthy path must still write. Assigned BEFORE it is
        # wrapped: ConvertFrom-Json emits a JSON array as a single pipeline object in Windows
        # PowerShell, so @(... | ConvertFrom-Json) nests the whole history into one element and the
        # count is always 1. The shipped code carries a comment about exactly this trap; this test
        # fell into it on the first attempt.
        $reread = $onDisk | ConvertFrom-Json
        Assert-That "CONTROL ($($case.N)): the new run was appended" (
            @($reread).Count -ge 2) "entries=$(@($reread).Count)"
    }

    Write-Host ''
    Write-Host 'CONTROLS - other unreadable files keep their existing behaviour' -ForegroundColor Cyan
    # Valid UTF-8 but not valid JSON: this is a different failure and must still start a new history
    # rather than being treated as an encoding problem.
    $brokenDir = Join-Path $root 'brokenjson'
    [void] (New-Item -ItemType Directory -Path $brokenDir -Force)
    $brokenFile = Join-Path $brokenDir $seedFile.Name
    [IO.File]::WriteAllText($brokenFile, '{ this is not json', (New-Object System.Text.UTF8Encoding $true))
    $script:warnings.Clear()
    $brokenResult = Get-mdiBaselineHistory -BaselinePath $brokenDir -Domain 'contoso.com' `
        -Statistics (New-Statistics -Server @($umlautServer)) 3>$null
    Assert-That 'CONTROL: malformed JSON still starts a new history' (
        @($script:warnings | Where-Object { $_ -match 'Starting a new baseline history' }).Count -ge 1) (
        'warnings: ' + ($script:warnings -join ' | '))
    Assert-That 'CONTROL: and it is not reported as an encoding problem' (
        @($script:warnings | Where-Object { $_ -match 'not valid UTF-8' }).Count -eq 0) (
        'warnings: ' + ($script:warnings -join ' | '))
    $brokenReread = [IO.File]::ReadAllText($brokenFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
    Assert-That 'CONTROL: the malformed file IS replaced, since nothing was readable to lose' (
        @($brokenReread).Count -ge 1) 'the new history was not written'
    Assert-That 'CONTROL: and the run still returns its own entry' ($null -ne $brokenResult.Current)

    # A first run with no file at all must still create one.
    $freshDir = Join-Path $root 'fresh'
    [void] (New-Item -ItemType Directory -Path $freshDir -Force)
    $script:warnings.Clear()
    [void] (Get-mdiBaselineHistory -BaselinePath $freshDir -Domain 'contoso.com' -Statistics (New-Statistics -Server @($umlautServer)) 3>$null)
    Assert-That 'CONTROL: a first run creates the baseline' (
        @(Get-ChildItem -LiteralPath $freshDir -Filter '*.json').Count -eq 1)
    Assert-That 'CONTROL: with no warning' (
        @($script:warnings | Where-Object { $_ -match 'not valid UTF-8|Starting a new' }).Count -eq 0) (
        'warnings: ' + ($script:warnings -join ' | '))
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
