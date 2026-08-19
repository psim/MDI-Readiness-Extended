<#
    A baseline the script cannot read must never cost the operator their history.

    Get-mdiBaselineHistory reads a file written by a PREVIOUS run. Between runs that file is just a
    file on disk, so by the time it is read again it can be anything: truncated by a crash or a full
    disk, half-synced by OneDrive, quarantined and stubbed by an antivirus product, hand-edited,
    restored from a backup, or written under a Western code page by an older tool.

    Two contracts are pinned here, and the second is the one with teeth.

    IT MUST NOT FAIL THE SCAN. The function's own comment says so - "The trend is a nice-to-have: it
    must never fail the scan" - and a forest scan that dies on a stale trend file is a scan the
    operator cannot complete. Sixteen shapes of broken file are put in front of it, and in every case
    the run must come back with its own entry intact and a chart that still draws.

    IT MUST NOT REWRITE WHAT IT COULD NOT READ. This is the expensive one. The history is the only
    record of where the estate has been. If an undecodable file is treated as "no history" and then
    rewritten with this run alone, every previous run is destroyed - permanently, and by a run that
    reports nothing wrong. The file is read with a STRICT UTF-8 decoder precisely so that this case
    is detected rather than silently reinterpreted.

    Mutation-proved: replacing the strict decoder with a lax one - the obvious simplification, and
    invisible in review because the function still returns a perfectly good result - rewrites the
    unreadable 24-byte history into an 887-byte file containing only the current run. This file goes
    red on exactly that assertion.
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
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$checkTotals = [ordered]@{}
$checkTotals['SensorHealth'] = [PSCustomObject]@{ Pass = 1; Total = 2; Unread = 0 }
$checkTotals['PowerScheme'] = [PSCustomObject]@{ Pass = 2; Total = 2; Unread = 0 }
$stats = [PSCustomObject]@{
    CheckTotals   = $checkTotals
    Servers       = @([PSCustomObject]@{ FQDN = 'dc1.contoso.com' }, [PSCustomObject]@{ FQDN = 'dc2.contoso.com' })
    ServerScores  = @(
        [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Passed = 2; Total = 2; Failed = 0; Unread = 0 }
        [PSCustomObject]@{ FQDN = 'dc2.contoso.com'; Passed = 1; Total = 2; Failed = 1; Unread = 0 }
    )
    ChecksPassed  = 3; ChecksTotal = 4; ChecksUnread = 0
    TotalServers  = 2; PortsOpen = 10; PortsTotal = 12; PortsBlocked = 2; PortsUntested = 0
    V3Unevaluated = 0; V3Ready = 1; V3NotReady = 1
    NnrRecords    = @()
}

$corruptions = [ordered]@{
    'truncated json'          = '{"History":[{"Timestamp":"2026-08-01T10:00:00","ChecksPassed":1'
    'empty file'              = ''
    'whitespace only'         = "   `r`n  "
    'a json array not object' = '[1,2,3]'
    'a bare string'           = '"hello"'
    'a json null'             = 'null'
    'History is a string'     = '{"History":"not an array"}'
    'History holds nulls'     = '{"History":[null,null]}'
    'entries missing fields'  = '{"History":[{"Timestamp":"2026-08-01T10:00:00"},{}]}'
    'wrong field types'       = '{"History":[{"Timestamp":12345,"ChecksPassed":"many","ChecksTotal":[1,2],"ServerNames":"dc1"}]}'
    'numbers beyond int32'    = '{"History":[{"Timestamp":"2026-08-01T10:00:00","ChecksPassed":3000000000,"ChecksTotal":9223372036854775807}]}'
    'unparseable timestamp'   = '{"History":[{"Timestamp":"not a date","ChecksPassed":1,"ChecksTotal":2}]}'
    'not json at all'         = 'This file was replaced by something else entirely.'
    'html error page'         = '<!DOCTYPE html><html><body>403 Forbidden</body></html>'
    'nul bytes'               = "{`0`0`"History`":[]}"
    'deeply nested'           = ('{"History":[' + ('{"Timestamp":"2026-08-01T10:00:00","ChecksPassed":1,"ChecksTotal":2},' * 200).TrimEnd(',') + ']}')
}

$root = Join-Path ([System.IO.Path]::GetTempPath()) ('mdibase-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $root -Force | Out-Null

try {
    "`n[1] A broken baseline never fails the scan, and never loses this run"
    foreach ($name in $corruptions.Keys) {
        $dir = Join-Path $root ($name -replace '[^\w]', '_')
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $file = Join-Path $dir ('mdi-baseline-{0}.json' -f (ConvertTo-mdiSafeFileName 'contoso.com'))
        [System.IO.File]::WriteAllText($file, $corruptions[$name])

        $r = $null; $threw = $null
        try { $r = Get-mdiBaselineHistory -BaselinePath $dir -Domain 'contoso.com' -Forest 'contoso.com' -Statistics $stats }
        catch { $threw = $_.Exception.Message }
        Assert-That "survives: $name" ($null -eq $threw) "(threw: $threw)"
        if ($null -ne $threw) { continue }
        Assert-That "  ...and still returns this run: $name" `
            ($null -ne $r -and $null -ne $r.Current -and @($r.History).Count -ge 1) "(history=$(@($r.History).Count))"
        Assert-That "  ...with no null entries: $name" (@($r.History | Where-Object { $null -eq $_ }).Count -eq 0) ''
    }

    "`n[2] A directory where the baseline file should be is not fatal"
    $dir = Join-Path $root 'file_is_a_directory'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $dir ('mdi-baseline-{0}.json' -f (ConvertTo-mdiSafeFileName 'contoso.com'))) -Force | Out-Null
    $threw = $null; $r = $null
    try { $r = Get-mdiBaselineHistory -BaselinePath $dir -Domain 'contoso.com' -Forest 'contoso.com' -Statistics $stats }
    catch { $threw = $_.Exception.Message }
    Assert-That 'survives a directory where the baseline file should be' ($null -eq $threw) "(threw: $threw)"
    if ($null -eq $threw) { Assert-That '  ...and still returns this run' ($null -ne $r.Current) '' }

    "`n[3] The trend chart draws from whatever survived, with no non-finite value on the page"
    foreach ($name in $corruptions.Keys) {
        $dir = Join-Path $root ($name -replace '[^\w]', '_')
        $r = Get-mdiBaselineHistory -BaselinePath $dir -Domain 'contoso.com' -Forest 'contoso.com' -Statistics $stats
        $threw = $null; $svg = $null
        try { $svg = New-mdiTrendChart -History @($r.History) } catch { $threw = $_.Exception.Message }
        Assert-That "the chart draws after: $name" ($null -eq $threw) "(threw: $threw)"
        if ($null -eq $threw -and $null -ne $svg) {
            Assert-That "  ...carrying no NaN or Infinity: $name" (([string] $svg) -notmatch 'NaN|Infinity') ''
        }
    }

    "`n[4] A file that cannot be DECODED is left on disk, not overwritten"
    # Genuinely invalid UTF-8 - a lone 0xFC, which is what a history saved under a Western code page
    # looks like the moment a server name carries an umlaut. NUL bytes do not test this: NUL is
    # perfectly valid UTF-8, so a case list that stops there never reaches the branch that matters.
    $dir = Join-Path $root 'invalid_utf8'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $file = Join-Path $dir ('mdi-baseline-{0}.json' -f (ConvertTo-mdiSafeFileName 'contoso.com'))
    $rawBytes = [byte[]] (@(0x7B, 0x22, 0x48, 0x69, 0x73, 0x74, 0x6F, 0x72, 0x79, 0x22, 0x3A, 0x5B, 0x5D, 0x2C, 0x22, 0x78, 0x22, 0x3A, 0x22) +
        @(0xFC, 0xFE, 0xFF) + @(0x22, 0x7D))
    [System.IO.File]::WriteAllBytes($file, $rawBytes)
    $beforeBytes = [System.IO.File]::ReadAllBytes($file)

    $threw = $null; $r = $null
    try { $r = Get-mdiBaselineHistory -BaselinePath $dir -Domain 'contoso.com' -Forest 'contoso.com' -Statistics $stats }
    catch { $threw = $_.Exception.Message }
    Assert-That 'an undecodable history does not fail the scan' ($null -eq $threw) "(threw: $threw)"
    if ($null -eq $threw) {
        Assert-That '  ...and this run is still reported' ($null -ne $r.Current) ''
        $afterBytes = [System.IO.File]::ReadAllBytes($file)
        $same = ($afterBytes.Length -eq $beforeBytes.Length)
        if ($same) {
            for ($b = 0; $b -lt $beforeBytes.Length; $b++) {
                if ($afterBytes[$b] -ne $beforeBytes[$b]) { $same = $false; break }
            }
        }
        Assert-That '  ...and the unreadable file is left byte-for-byte untouched' $same `
            "(was $($beforeBytes.Length) bytes, now $($afterBytes.Length))"
    }
} finally {
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
