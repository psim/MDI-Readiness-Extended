<#
    THE DEFECT THIS TEST PINS

    The run told the operator where its artefacts went by RE-DERIVING the path instead of asking the
    writer what it had written.

        Write-mdiReportFile          [IO.File]::WriteAllText(...)          <- LITERAL
        New-mdiRemediationScript     Path = (Resolve-Path -Path $x).Path   <- WILDCARD-EXPANDING
        Set-MdiReadinessReport       $jsonReportFilePath = (Resolve-Path -Path $x).Path
        Set-MdiReadinessReport       (Resolve-Path -Path $x).Path          <- the return value

    Those are two different functions of the same string, so the path the run REPORTED was not the
    path the run WROTE. -Path is free text and ConvertTo-mdiSafeFileName only sanitises the FILE
    name, never the folder, so a perfectly ordinary folder - 'Reports [nightly]', 'MDI [2026-08]',
    'dc[12]' - reaches Resolve-Path as a wildcard PATTERN.

    Measured on the shipped functions before the fix (MDI-AB\live\outputhonesty-01-wildcardpath.ps1):

      folder 'out[1]'
        file on disk (literal)   True, 11891 bytes
        returned .Path           <null>
        console                  "Remediation script written to  with 1 section(s). Review it before running."
                                 "  Remediation:  (1 section(s), review before running)"

      folder 'reports [nightly]'
        JSON on disk             1313 bytes
        $jsonReportFilePath      $null
        run                      DIED - "Cannot bind argument to parameter 'Path' because it is null"
                                 (Split-Path -Leaf on the null, building the report's own JSON link),
                                 leaving the JSON on disk with no HTML beside it

      folders dc1\ and dc2\ present, this run writing into dc[12]\
        Resolve-Path count       2   -> BOTH SIBLINGS
        console                  "  Report: ...\dc1\mdi-contoso.com.html"   <- a STALE report from a
                                 different scan, while the file this run produced was never named

    The same wildcard-vs-literal split ran through the preflight: Test-Path -Path said an existing
    folder did not exist, and Remove-Item -Path -ErrorAction SilentlyContinue matched nothing, so
    every run left a hidden 0-byte .mdi-write-test-<8 hex> file in the operator's report folder -
    a file the run wrote, in no inventory, never cleaned up (measured: 2 files after 2 preflights).
    On a pattern that is not merely unmatched but INVALID ('MDI [2026-08]' contains the reversed
    range 6-0) the same Remove-Item raised a WildcardPatternException that -ErrorAction
    SilentlyContinue does not suppress, and the run aborted with

        The output folder ... is not writable: ... The specified wildcard character pattern is not valid

    one line after New-Item had SUCCEEDED in creating a file in that very folder.

    THE FIX

    Write-mdiReportFile RETURNS the rooted path it wrote, and that is the only way a caller may learn
    where an artefact went. There is no second expression left that could drift, so the reported path
    and the written path cannot disagree. The path-as-pattern sites became -LiteralPath.

    WHAT MUST NOT REGRESS IN THE OTHER DIRECTION

    The rooting contract is unchanged: a relative -Path must still be reported as an ABSOLUTE path
    anchored on the PowerShell provider location (that is what PathRelativeToProviderLocation.Tests
    pins), and an ordinary folder name must behave exactly as before.
#>

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
# The PRODUCT copy first. tests\ is a subfolder of the product folder, and a duplicate
# Test-MdiReadiness.ps1 is kept beside the tests; when the two drift, the one next to the tests is
# the stale one, and a test that silently loads it measures code that is not shipped.
$target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
if (-not (Test-Path -LiteralPath $target)) { $target = Join-Path $here 'Test-MdiReadiness.ps1' }
if (-not (Test-Path -LiteralPath $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$script:pass = 0
$script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host ("  FAIL  {0} {1}" -f $Name, $Detail) -ForegroundColor Red }
}

# Stale copies of the product script exist elsewhere in the workspace, so the file this test loaded
# is identified rather than assumed. A mismatch is a NOTE, never a throw: killing the run here would
# take every assertion below with it.
$sibling = Join-Path $here 'Test-MdiReadiness.ps1'
Write-Host ("  NOTE  loaded {0}" -f $target)
Write-Host ("  NOTE  sha256 {0}" -f (Get-FileHash -LiteralPath $target).Hash)
if ((Test-Path -LiteralPath $sibling) -and
    ((Get-FileHash -LiteralPath $sibling).Hash -ne (Get-FileHash -LiteralPath $target).Hash)) {
    Write-Host ("  NOTE  the copy beside the tests differs and was NOT used: {0}" -f $sibling) -ForegroundColor Yellow
}

$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body

Assert-That 'the file loaded IS the product script' `
    ((Get-Command Write-mdiReportFile -ErrorAction SilentlyContinue) -and
        (Get-Command Set-MdiReadinessReport -ErrorAction SilentlyContinue) -and
        (Get-Command New-mdiRemediationScript -ErrorAction SilentlyContinue)) `
    'the writers were not defined by the file this test loaded'

Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$sandbox = Join-Path ([IO.Path]::GetTempPath()) ('mdi-artefactpath-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))
[void][IO.Directory]::CreateDirectory($sandbox)

function New-ProbeReport {
    param([bool] $Healthy = $false)
    [PSCustomObject]@{
        ScriptVersion       = 'test'
        Domain              = 'contoso.com'
        Forest              = 'contoso.com'
        DomainsInScope      = @('contoso.com')
        LdapPlanGapDomains  = @()
        DomainControllers   = @([PSCustomObject]@{
                FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; OperatingSystemVersion = '10.0 (20348)'
                PowerScheme = $Healthy; PowerSchemeMeasured = $true
                PowerSchemeName = $(if ($Healthy) { 'High performance' } else { 'Balanced' })
                NtlmAuditing = $true; AdvancedAuditing = $true; Comment = ''
            })
        CAServers           = @()
        EntraConnectServers = @()
        DomainAuditing      = @()
        ForestDiscovery     = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
        SkippedAreas        = @()
    }
}

# A file is only an artefact if it EXISTS and has content. "The path is a non-empty string" would
# have passed on a path pointing at a sibling run's file, which is one of the shapes this pins.
function Test-NamesARealFile {
    param([object] $Claimed, [string] $Expected)
    if ($null -eq $Claimed) { return $false }
    if (@($Claimed).Count -ne 1) { return $false }
    $p = [string] $Claimed
    if ([string]::IsNullOrWhiteSpace($p)) { return $false }
    if (-not [IO.Path]::IsPathRooted($p)) { return $false }
    if (-not [IO.File]::Exists($p)) { return $false }
    if ((New-Object IO.FileInfo $p).Length -le 0) { return $false }
    [string]::Equals($p, $Expected, [StringComparison]::OrdinalIgnoreCase)
}

try {
    # 'reports [nightly]' rather than a contrived string: a dated or labelled report folder is the
    # ordinary way an operator organises scans. [ and ] are the reachable metacharacters here -
    # Windows rejects * and ? in a file name outright, so they can never appear in a real -Path,
    # while brackets are perfectly legal and are what PowerShell reads as a character class.
    $wildDirs = @('out[1]', 'reports [nightly]', 'MDI [2026-08]', 'runs[a-z]')

    Write-Host ''
    Write-Host 'Write-mdiReportFile reports the path it actually wrote' -ForegroundColor Cyan
    foreach ($d in $wildDirs) {
        $dir = Join-Path $sandbox $d
        [void][IO.Directory]::CreateDirectory($dir)
        $file = Join-Path $dir 'mdi-contoso.com.json'
        $returned = Write-mdiReportFile -Content '{"report":"json"}' -FilePath $file
        Assert-That ("'$d' - the writer names the file it created") `
            (Test-NamesARealFile -Claimed $returned -Expected $file) `
            ("returned '{0}', on disk={1}" -f $returned, [IO.File]::Exists($file))
    }

    Write-Host ''
    Write-Host 'New-mdiRemediationScript reports the script it actually wrote' -ForegroundColor Cyan
    # This is the artefact the operator is told to review and run as Domain Admin, so a blank path in
    # "Remediation script written to  with 1 section(s)" is the worst place for this to land.
    foreach ($d in $wildDirs) {
        $dir = Join-Path $sandbox $d
        $file = Join-Path $dir 'Fix-MdiReadiness-contoso.com.ps1'
        $rem = New-mdiRemediationScript -ReportData (New-ProbeReport) -FilePath $file 3>$null 4>$null 6>$null
        Assert-That ("'$d' - the result names the script that exists on disk") `
            (Test-NamesARealFile -Claimed $rem.Path -Expected $file) `
            ("returned '{0}', on disk={1}" -f $rem.Path, [IO.File]::Exists($file))
        # The console line Main builds from it must not be able to name nothing.
        $line = 'Remediation script written to {0} with {1} section(s). Review it before running.' -f $rem.Path, $rem.SectionCount
        Assert-That ("'$d' - the sentence Main prints names a path") `
            ($line -notmatch 'written to\s+with') ("line was '{0}'" -f $line)
    }

    Write-Host ''
    Write-Host 'Set-MdiReadinessReport reports the HTML it actually wrote' -ForegroundColor Cyan
    foreach ($d in $wildDirs) {
        $dir = Join-Path $sandbox ($d + ' set')
        [void][IO.Directory]::CreateDirectory($dir)
        $expectedHtml = Join-Path $dir 'mdi-contoso.com.html'
        $expectedJson = Join-Path $dir 'mdi-contoso.com.json'
        $returned = Set-MdiReadinessReport -Domain 'contoso.com' -Path $dir -ReportData (New-ProbeReport) -SkipTrend 3>$null 4>$null 6>$null
        Assert-That ("'$d' - the returned report path is the file on disk") `
            (Test-NamesARealFile -Claimed $returned -Expected $expectedHtml) `
            ("returned '{0}', on disk={1}" -f $returned, [IO.File]::Exists($expectedHtml))
        Assert-That ("'$d' - the JSON was written beside it") `
            ([IO.File]::Exists($expectedJson) -and (New-Object IO.FileInfo $expectedJson).Length -gt 0) `
            'the machine-readable report is missing'
        # The report's own "Full details" link is built from the JSON path the writer reported. When
        # that came back $null the run died on Split-Path before any HTML existed at all.
        if ([IO.File]::Exists($expectedHtml)) {
            $html = [IO.File]::ReadAllText($expectedHtml)
            $m = [regex]::Match($html, '<span>Full details <a href="([^"]*)">([^<]*)</a></span>')
            Assert-That ("'$d' - the report links to the JSON file that exists") `
                ($m.Success -and $m.Groups[1].Value -eq 'mdi-contoso.com.json' -and $m.Groups[2].Value -eq 'mdi-contoso.com.json') `
                ("href='{0}' text='{1}'" -f $m.Groups[1].Value, $m.Groups[2].Value)
        } else {
            Assert-That ("'$d' - the report links to the JSON file that exists") $false 'no HTML was produced'
        }
    }

    Write-Host ''
    Write-Host 'A wildcard folder must never be reported as a SIBLING run''s file' -ForegroundColor Cyan
    # The dangerous shape: dc1\ and dc2\ hold reports from earlier scans, this run writes into
    # dc[12]\, and the pattern matches both siblings. Reporting either of them sends the operator to
    # a stale report from a different scan while this run's report is never named.
    $collide = Join-Path $sandbox 'collide'
    [void][IO.Directory]::CreateDirectory($collide)
    $sibA = Join-Path $collide 'dc1'; $sibB = Join-Path $collide 'dc2'; $mine = Join-Path $collide 'dc[12]'
    foreach ($d in @($sibA, $sibB, $mine)) { [void][IO.Directory]::CreateDirectory($d) }
    [IO.File]::WriteAllText((Join-Path $sibA 'mdi-contoso.com.html'), '<html>STALE RUN A</html>')
    [IO.File]::WriteAllText((Join-Path $sibB 'mdi-contoso.com.html'), '<html>STALE RUN B</html>')
    $expectedMine = Join-Path $mine 'mdi-contoso.com.html'
    $returned = Set-MdiReadinessReport -Domain 'contoso.com' -Path $mine -ReportData (New-ProbeReport -Healthy $true) -SkipTrend 3>$null 4>$null 6>$null
    Assert-That 'the run names its OWN report, not a sibling folder''s' `
        (Test-NamesARealFile -Claimed $returned -Expected $expectedMine) `
        ("returned '{0}', expected '{1}'" -f $returned, $expectedMine)
    Assert-That '  ...and the file it names is the one this run produced' `
        ($null -ne $returned -and [IO.File]::ReadAllText([string] $returned) -notmatch 'STALE RUN') `
        'the operator was pointed at a report from a different scan'
    Assert-That '  ...leaving the sibling reports untouched' `
        (([IO.File]::ReadAllText((Join-Path $sibA 'mdi-contoso.com.html')) -eq '<html>STALE RUN A</html>') -and
            ([IO.File]::ReadAllText((Join-Path $sibB 'mdi-contoso.com.html')) -eq '<html>STALE RUN B</html>')) `
        'a wildcard write reached a sibling folder'

    Write-Host ''
    Write-Host 'The write-access preflight leaves nothing behind' -ForegroundColor Cyan
    # The preflight is executed VERBATIM from the product file rather than retyped, because the
    # defect was in the exact cmdlet parameters it uses.
    $lines = [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $target).ProviderPath)
    $s = -1; $e = -1
    for ($n = 0; $n -lt $lines.Count; $n++) {
        if ($s -lt 0 -and $lines[$n] -match '^\s*if \(Test-Path -(Literal)?Path \$Path\) \{') { $s = $n }
        if ($s -ge 0 -and $lines[$n] -match 'is not writable') { $e = $n + 1; break }
    }
    Assert-That 'the preflight block was located in the product file' (($s -ge 0) -and ($e -gt $s)) 'the test could not lift it'
    if ($s -ge 0 -and $e -gt $s) {
        $preflight = ($lines[$s..$e] -join "`r`n")
        function Invoke-Preflight { param([string] $Path) Invoke-Expression $preflight }
        foreach ($d in @('MDI [2026-08]', 'reports [nightly]', 'plain-folder')) {
            $dir = Join-Path $sandbox ('pre-' + ($d -replace '[^\w]', '_'))
            $dir = Join-Path $dir $d
            $err = $null
            try { Invoke-Preflight -Path $dir } catch { $err = $_ }
            Assert-That ("'$d' - a writable folder is not called unwritable") ($null -eq $err) `
                ("threw '{0}'" -f $(if ($err) { $err.Exception.Message } else { '' }))
            $leaked = @()
            if ([IO.Directory]::Exists($dir)) { $leaked = @([IO.Directory]::GetFiles($dir, '.mdi-write-test-*')) }
            Assert-That ("'$d' - no write-test file is left in the report folder") ($leaked.Count -eq 0) `
                ("{0} left behind: {1}" -f $leaked.Count, (($leaked | ForEach-Object { Split-Path $_ -Leaf }) -join ', '))
        }
    }

    Write-Host ''
    Write-Host 'CONTROL - an ordinary folder is unaffected' -ForegroundColor Cyan
    $plain = Join-Path $sandbox 'plain reports'
    [void][IO.Directory]::CreateDirectory($plain)
    $plainHtml = Join-Path $plain 'mdi-contoso.com.html'
    $plainRem = Join-Path $plain 'Fix-MdiReadiness-contoso.com.ps1'
    $rem = New-mdiRemediationScript -ReportData (New-ProbeReport) -FilePath $plainRem 3>$null 4>$null 6>$null
    $returned = Set-MdiReadinessReport -Domain 'contoso.com' -Path $plain -ReportData (New-ProbeReport) -Remediation $rem -SkipTrend 3>$null 4>$null 6>$null
    Assert-That 'an ordinary folder still reports its HTML correctly' (Test-NamesARealFile -Claimed $returned -Expected $plainHtml) ("returned '{0}'" -f $returned)
    Assert-That 'an ordinary folder still reports its remediation script correctly' (Test-NamesARealFile -Claimed $rem.Path -Expected $plainRem) ("returned '{0}'" -f $rem.Path)

    Write-Host ''
    Write-Host 'CONTROL - a relative path is still reported as an absolute one' -ForegroundColor Cyan
    # The rooting contract must survive: the reported path is anchored on the PowerShell provider
    # location, not on the process directory, and never handed back as './name'.
    $relHome = Join-Path $sandbox 'relative-home'
    [void][IO.Directory]::CreateDirectory($relHome)
    $oldLoc = (Get-Location).Path
    try {
        Set-Location -LiteralPath $relHome
        $returned = Write-mdiReportFile -Content '{"a":1}' -FilePath (Join-Path -Path '.' -ChildPath 'mdi-rel.json')
        Assert-That 'a relative path comes back rooted, and names the real file' `
            (Test-NamesARealFile -Claimed $returned -Expected (Join-Path $relHome 'mdi-rel.json')) `
            ("returned '{0}'" -f $returned)
    } finally { Set-Location -LiteralPath $oldLoc }

    Write-Host ''
    Write-Host 'The reported path cannot be re-derived anywhere' -ForegroundColor Cyan
    # Structural, and deliberately narrow: it is the wildcard-expanding -Path form of Resolve-Path on
    # an artefact path that caused this. Re-introducing it at any of the three call sites brings the
    # whole family back, so no live occurrence is allowed to exist.
    $live = @($lines | Where-Object { $_ -match 'Resolve-Path\s+-Path' -and $_ -notmatch '^\s*#' })
    Assert-That 'no live (Resolve-Path -Path ...) survives on an artefact path' ($live.Count -eq 0) `
        ("found: {0}" -f (($live | ForEach-Object { $_.Trim() }) -join ' || '))

} finally {
    [GC]::Collect()
    Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
    if ([IO.Directory]::Exists($sandbox)) { & cmd /c ('rmdir /s /q "{0}"' -f $sandbox) 2>&1 | Out-Null }
}

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
