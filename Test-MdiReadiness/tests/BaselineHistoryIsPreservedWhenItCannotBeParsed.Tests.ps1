<#
    [w121] A baseline history that cannot be READ must not be destroyed by the run that could not
    read it - whichever way it is unreadable.

    Get-mdiBaselineHistory already refuses to overwrite a file that cannot be DECODED, and says why:
    the rewrite "would replace a merely-unreadable file with one containing this run alone - so a
    wrong code page would cost every previous run permanently". The history is "the operator's only
    record of where the estate has been".

    That reason is not specific to code pages, and the split was measured:

        DecoderFallbackException -> warn, RETURN EARLY, file left untouched
        anything else            -> warn "Starting a new baseline history", fall through to the
                                    rewrite, which REPLACES the file with this run alone

    A history truncated by a full disk, or half-written by a run that was killed, decodes as
    perfectly good UTF-8 and fails at ConvertFrom-Json instead. It therefore took the SECOND branch.
    Measured on the shipped v1.1.8, real files in real folders, bytes compared before and after:

        invalid UTF-8 (cp1252)      11 ->   11 bytes   left untouched      (documented)
        valid UTF-8, TRUNCATED     183 ->  659 bytes   DESTROYED           <<< the defect

    - and the only thing the operator was told was "Starting a new baseline history", which reads as
    routine. A half-written file is arguably the MORE likely damage of the two: the exclusive lock in
    this same function exists precisely because runs collide.

    THE CONTRACT PINNED HERE. An unparseable history is MOVED ASIDE, not overwritten: its bytes
    survive next to it and the warning says where they went. That is deliberately NOT the decoder
    branch's answer - the trend RESUMES on this run rather than being blocked until someone repairs
    the file by hand, because nothing has been lost by resuming.

    AND WHAT MUST NOT MOVE. The decoder branch keeps its own behaviour exactly: still left untouched,
    still no copy taken, still refused the trend. An empty or whitespace-only file has nothing to
    lose and must not litter the folder with a copy of nothing. A file that PARSES is untouched by
    all of this. The existing "Starting a new baseline history" warning is still raised, because a
    new history is still what is being started - EstateIdentityInTrend and BaselineEncodingIsNever-
    Guessed both assert it, and this fix must not make two tests contradict each other.

    Run under Windows PowerShell 5.1.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path -LiteralPath $target)) {
    $parent = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
    if (Test-Path -LiteralPath $parent) { $target = $parent }
}
# Staging fallback, expressed RELATIVE to this file so it carries no machine-specific path. Once the
# file lives in tests\ the sibling resolve above wins and this is never taken.
if (-not (Test-Path -LiteralPath $target)) {
    $staged = Join-Path (Split-Path (Split-Path $here -Parent) -Parent) 'MDI-Repo\Test-MdiReadiness\Test-MdiReadiness.ps1'
    if (Test-Path -LiteralPath $staged) { $target = $staged }
}
if (-not (Test-Path -LiteralPath $target)) { Write-Host 'FAIL  the product script could not be located'; exit 1 }

$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

# Captured, not silenced: half of this contract is what the operator is TOLD.
$script:warnings = New-Object System.Collections.ArrayList
function Write-mdiWarning { param($Message) [void] $script:warnings.Add([string] $Message) }
function Write-mdiVerbose { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$checkTotals = [ordered]@{}
$checkTotals['SensorHealth'] = [PSCustomObject]@{ Pass = 1; Total = 2; Unread = 0 }
$stats = [PSCustomObject]@{
    CheckTotals   = $checkTotals
    Servers       = @([PSCustomObject]@{ FQDN = 'dc1.contoso.com' })
    ServerScores  = @([PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Passed = 1; Total = 2; Failed = 1; Unread = 0 })
    ChecksPassed  = 1; ChecksTotal = 2; ChecksUnread = 0
    TotalServers  = 1; PortsOpen = 4; PortsTotal = 4; PortsBlocked = 0; PortsUntested = 0
    V3Unevaluated = 0; V3Ready = 1; V3NotReady = 0
    NnrRecords    = @()
    PartialScanCount = 0
}

$goodHistory = @'
[
  {
    "Timestamp": "2026-08-19T09:00:00",
    "ScriptVersion": "1.1.5",
    "Domain": "contoso.com",
    "Forest": "contoso.com",
    "CheckNames": ["SensorHealth"],
    "ServerNames": ["dc1.contoso.com"],
    "ChecksPassed": 1,
    "ChecksTotal": 2,
    "ChecksUnread": 0,
    "ServersTotal": 1,
    "ServersReady": 0,
    "PortsOpen": 4,
    "PortsTotal": 4,
    "NnrResolvable": 1,
    "NnrTargets": 1,
    "V3Ready": 1,
    "V3Evaluated": 1,
    "V3Unevaluated": 0
  }
]
'@

$root = Join-Path ([System.IO.Path]::GetTempPath()) ('w121-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $root -Force | Out-Null

function New-Case {
    param([string] $Name)
    $dir = Join-Path $root ($Name -replace '[^\w]', '_')
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $dir
}
function Get-HistoryFile {
    param([string] $Dir)
    Join-Path $Dir ('mdi-baseline-{0}.json' -f (ConvertTo-mdiSafeFileName 'contoso.com'))
}
function Invoke-Baseline {
    param([string] $Dir)
    $script:warnings.Clear()
    Get-mdiBaselineHistory -BaselinePath $Dir -Domain 'contoso.com' -Forest 'contoso.com' -Statistics $stats
}
function Get-PreservedCopy {
    param([string] $Dir)
    @(Get-ChildItem -LiteralPath $Dir -File | Where-Object { $_.Name -like '*damaged*' })
}

# Shapes that DECODE as valid UTF-8 but do NOT parse as JSON. The precondition is asserted rather
# than assumed: a shape that quietly started parsing would make every assertion below vacuous.
$unparseable = [ordered]@{
    'truncated by a full disk' = $goodHistory.Substring(0, 180)
    'not json at all'          = 'This file was replaced by something else entirely.'
    'an html error page'       = '<!DOCTYPE html><html><body>403 Forbidden</body></html>'
}

try {
    "`n[0] PRECONDITION - each shape decodes as UTF-8 but fails to parse"
    foreach ($name in $unparseable.Keys) {
        $decoded = $true; $parsed = $true
        $bytes = [Text.Encoding]::UTF8.GetBytes($unparseable[$name])
        try { [void] ([Text.UTF8Encoding]::new($false, $true)).GetString($bytes) } catch { $decoded = $false }
        try { [void] ($unparseable[$name] | ConvertFrom-Json) } catch { $parsed = $false }
        Assert-That "decodes but does not parse: $name" ($decoded -and -not $parsed) "(decoded=$decoded parsed=$parsed)"
    }

    "`n[1] THE DEFECT - an unparseable history is preserved, not destroyed"
    foreach ($name in $unparseable.Keys) {
        $dir = New-Case "unparseable_$name"
        $file = Get-HistoryFile $dir
        [IO.File]::WriteAllText($file, $unparseable[$name], (New-Object Text.UTF8Encoding($true)))
        $before = [IO.File]::ReadAllBytes($file)

        $r = $null; $threw = $null
        try { $r = Invoke-Baseline $dir } catch { $threw = $_.Exception.Message }
        Assert-That "the scan survives: $name" ($null -eq $threw) "(threw: $threw)"
        if ($null -ne $threw) { continue }

        $copies = Get-PreservedCopy $dir
        Assert-That "  the original bytes are preserved: $name" ($copies.Count -eq 1) "(found $($copies.Count) preserved file(s))"
        if ($copies.Count -eq 1) {
            $kept = [IO.File]::ReadAllBytes($copies[0].FullName)
            $same = $kept.Length -eq $before.Length
            if ($same) { for ($k = 0; $k -lt $before.Length; $k++) { if ($kept[$k] -ne $before[$k]) { $same = $false; break } } }
            Assert-That "  preserved byte-for-byte: $name" $same "(before=$($before.Length) kept=$($kept.Length))"
            Assert-That "  the warning names where they went: $name" `
                (@($script:warnings | Where-Object { $_ -like ('*' + $copies[0].Name + '*') }).Count -ge 1) `
                ('warnings: ' + ($script:warnings -join ' | '))
        }

        Assert-That "  the trend RESUMES rather than being blocked: $name" `
            ((Test-Path -LiteralPath $file) -and @($r.History).Count -ge 1) "(history=$(@($r.History).Count))"
        Assert-That "  the history file no longer holds the damage: $name" `
            ([IO.File]::ReadAllText($file) -notlike '*403 Forbidden*') ''
        Assert-That "  the existing 'starting a new history' warning is still raised: $name" `
            (@($script:warnings | Where-Object { $_ -match 'Starting a new baseline history' }).Count -ge 1) `
            ('warnings: ' + ($script:warnings -join ' | '))
        Assert-That "  the preserved copy is not itself a history file: $name" `
            (@(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File).Count -eq 1) `
            ('json files: ' + (@(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File).Name -join ', '))
    }

    "`n[2] UNCHANGED - a file that cannot be DECODED keeps the decoder branch's answer"
    $dir = New-Case 'invalid_utf8'
    $file = Get-HistoryFile $dir
    # Lone 0xFC - valid Windows-1252, invalid UTF-8.
    [IO.File]::WriteAllBytes($file, ([byte[]] (0x5B, 0x7B, 0x22, 0x44, 0x22, 0x3A, 0x22, 0xFC, 0x22, 0x7D, 0x5D)))
    $before = [IO.File]::ReadAllBytes($file)
    $r = Invoke-Baseline $dir
    $after = [IO.File]::ReadAllBytes($file)
    $same = $before.Length -eq $after.Length
    if ($same) { for ($k = 0; $k -lt $before.Length; $k++) { if ($after[$k] -ne $before[$k]) { $same = $false; break } } }
    Assert-That 'an undecodable history is still left untouched' $same "(before=$($before.Length) after=$($after.Length))"
    Assert-That '  ...and no copy is taken of it' ((Get-PreservedCopy $dir).Count -eq 0) ''
    Assert-That '  ...and it still says the file is not valid UTF-8' `
        (@($script:warnings | Where-Object { $_ -match 'not valid UTF-8' }).Count -ge 1) `
        ('warnings: ' + ($script:warnings -join ' | '))
    Assert-That '  ...and the trend is still refused for this run' (@($r.History).Count -eq 0) "(history=$(@($r.History).Count))"

    "`n[3] UNCHANGED - a file with nothing to lose does not litter the folder"
    # NOT a test of the zero-length guard, and it must not be read as one. An empty or whitespace-only
    # file does not make ConvertFrom-Json throw under 5.1, so it never reaches the preservation branch
    # at all - these two cases are here as CONTROLS, to pin that the change did not start producing
    # .damaged copies on the ordinary first-run and empty-file paths. The guard itself covers a file
    # that vanished or was truncated to nothing between the read and the move, which is a race this
    # test cannot stage deterministically; it is defensive and is documented as such at the guard.
    foreach ($empty in @{ 'an empty file' = ''; 'whitespace only' = "   `r`n  " }.GetEnumerator()) {
        $dir = New-Case ('nothing_to_lose_' + $empty.Key)
        $file = Get-HistoryFile $dir
        [IO.File]::WriteAllText($file, $empty.Value)
        $r = Invoke-Baseline $dir
        Assert-That "no copy is taken of: $($empty.Key)" ((Get-PreservedCopy $dir).Count -eq 0) ''
        Assert-That "  ...and this run is still recorded: $($empty.Key)" (@($r.History).Count -ge 1) "(history=$(@($r.History).Count))"
    }

    "`n[4] UNCHANGED - a history that PARSES is appended to and never copied aside"
    $dir = New-Case 'valid_history'
    $file = Get-HistoryFile $dir
    [IO.File]::WriteAllText($file, $goodHistory, (New-Object Text.UTF8Encoding($true)))
    $r = Invoke-Baseline $dir
    Assert-That 'a valid history is appended to' (@($r.History).Count -eq 2) "(history=$(@($r.History).Count))"
    Assert-That '  ...with no copy taken' ((Get-PreservedCopy $dir).Count -eq 0) ''
    Assert-That '  ...and no "starting a new history" warning' `
        (@($script:warnings | Where-Object { $_ -match 'Starting a new baseline history' }).Count -eq 0) `
        ('warnings: ' + ($script:warnings -join ' | '))

    "`n[5] THE FALLBACK - if the damaged file cannot be moved aside it is still not overwritten"
    $dir = New-Case 'move_refused'
    $file = Get-HistoryFile $dir
    [IO.File]::WriteAllText($file, $goodHistory.Substring(0, 180), (New-Object Text.UTF8Encoding($true)))
    $before = [IO.File]::ReadAllBytes($file)
    # SHARE ReadWrite, deliberately, and NOT ReadWrite-plus-Delete. This is the shape of a file held
    # open by a backup agent or a sync client: File.Move needs delete access the open handle does not
    # grant, so the move fails while the file itself is still there.
    #
    # FileShare.None was tried first and proved nothing, because it blocks the rewrite as well as the
    # move. STATED ACCURATELY, because it matters for what this section does and does not prove:
    # even under ReadWrite the rewrite does not succeed either - Write-mdiReportFile waits 20s for
    # its own exclusive open and then reports "still locked by another process". So the BYTES are
    # protected here by two independent things, and this test cannot separate them.
    #
    # What the early return genuinely contributes, and what the third assertion below pins, is the
    # HONEST ANSWER: without it the run stalls for twenty seconds and then tells the operator it was
    # "starting a new baseline history" over a file it had neither moved nor written. Deleting the
    # branch is caught by that assertion, not by the byte comparison.
    $handle = [IO.File]::Open($file, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    $threw = $null
    try { [void] (Invoke-Baseline $dir) } catch { $threw = $_.Exception.Message }
    finally { $handle.Close(); $handle.Dispose() }
    $after = [IO.File]::ReadAllBytes($file)
    $same = $before.Length -eq $after.Length
    if ($same) { for ($k = 0; $k -lt $before.Length; $k++) { if ($after[$k] -ne $before[$k]) { $same = $false; break } } }
    Assert-That 'the scan survives a baseline file that cannot be moved' ($null -eq $threw) "(threw: $threw)"
    Assert-That '  ...and the history it could not move is left intact, not overwritten' $same "(before=$($before.Length) after=$($after.Length))"
    Assert-That '  ...and the operator is told it was left alone' `
        (@($script:warnings | Where-Object { $_ -match 'could not be moved aside' }).Count -ge 1) `
        ('warnings: ' + ($script:warnings -join ' | '))
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

""
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
