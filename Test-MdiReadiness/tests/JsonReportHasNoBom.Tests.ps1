<#
    The JSON report must be readable by the automation it exists for; the .ps1 and .html must stay
    readable by Windows PowerShell 5.1. One encoding cannot do both, so Write-mdiReportFile chooses
    per artefact.

    Every report file went out as UTF-8 WITH a byte-order mark. The mark is required for the .ps1
    and .html - Get-Content's default encoding in Windows PowerShell 5.1 is ANSI, so without it a
    server name like dc-muenchen (umlaut) is mangled on the way back in and the generated
    remediation script is parsed as Windows-1252. But node's JSON.parse, python's json.load and jq
    all reject a leading BOM outright, so the JSON report - the machine-readable artefact, whose
    entire purpose is being consumed by other tools - could not be parsed by them at all.

    Measured on the shipped writer before the fix:

        PERSISTED_FIRST_BYTES  = EF BB BF
        node  JSON.parse       -> SyntaxError: Unexpected token '', ""{
        python json.load       -> json.decoder.JSONDecodeError: Unexpected UTF-8 BOM
        same bytes, no mark    -> parsed, in both

    And the two surfaces of one document disagreed: the -AsJson copy on stdout never carried a mark
    and parsed cleanly, so the file on disk was the broken one.

    Asserted on the REAL BYTES the REAL writer produces, because this defect is invisible to any
    assertion made on decoded text - [IO.File]::ReadAllText with a UTF8 decoder silently skips the
    mark, which is exactly why it survived so long.

    The controls carry equal weight and are why this cannot be "fixed" by dropping the mark
    everywhere:
      - .ps1 and .html must STILL be written with the mark;
      - a .json holding non-ASCII must still round-trip through the reader the script itself uses;
      - an EXISTING baseline written with a mark must still be readable, or every operator's
        history breaks on upgrade.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = (Resolve-Path -LiteralPath $target).ProviderPath

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$raw = [IO.File]::ReadAllText($target)
$i = $raw.IndexOf('#region Main')
if ($i -lt 0) { throw 'no #region Main in the canonical script' }
$pre = $raw.Substring(0, $i)
$pre = $pre -replace '(?m)^\s*#Requires.*$', ''
$pre = $pre -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
Invoke-Expression $pre

if (-not (Get-Command Write-mdiReportFile -ErrorAction SilentlyContinue)) {
    throw 'Write-mdiReportFile was not defined by the canonical script'
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('mdi-encoding-{0}' -f ([guid]::NewGuid().ToString('N')))
[void] (New-Item -ItemType Directory -Path $root -Force)

function Get-LeadingBytes {
    param([string] $Path, [int] $Count = 3)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $take = [Math]::Min($Count, $bytes.Length)
    if ($take -le 0) { return '' }
    (($bytes[0..($take - 1)]) | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
}
function Test-HasUtf8Bom {
    param([string] $Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
}

# Non-ASCII on purpose: the umlaut is the character the mark exists to protect.
$jsonBody = '{"Forest":"contoso.com","Server":"dc-m' + [char]0x00FC + 'nchen.contoso.com"}'
$ps1Body  = "# remediation for dc-m" + [char]0x00FC + "nchen`r`nWrite-Output 'ok'"
$htmlBody = '<html><body>dc-m' + [char]0x00FC + 'nchen</body></html>'

$jsonPath = Join-Path $root 'mdi-report.json'
$ps1Path  = Join-Path $root 'mdi-remediation.ps1'
$htmlPath = Join-Path $root 'mdi-report.html'

Write-mdiReportFile -Content $jsonBody -FilePath $jsonPath
Write-mdiReportFile -Content $ps1Body  -FilePath $ps1Path
Write-mdiReportFile -Content $htmlBody -FilePath $htmlPath

Assert-That 'The .json is written WITHOUT a byte-order mark' (-not (Test-HasUtf8Bom $jsonPath)) ("firstBytes=$(Get-LeadingBytes $jsonPath)")
Assert-That 'The .ps1 is STILL written WITH a byte-order mark'  (Test-HasUtf8Bom $ps1Path)  ("firstBytes=$(Get-LeadingBytes $ps1Path)")
Assert-That 'The .html is STILL written WITH a byte-order mark' (Test-HasUtf8Bom $htmlPath) ("firstBytes=$(Get-LeadingBytes $htmlPath)")

# The first byte of a JSON document must be the document itself.
$jsonBytes = [IO.File]::ReadAllBytes($jsonPath)
Assert-That 'The first byte of the .json is the opening brace' ($jsonBytes[0] -eq 0x7B) ("first=0x{0:X2}" -f $jsonBytes[0])

# Non-ASCII must survive, and the script's own reader must still parse it.
$readBack = [IO.File]::ReadAllText($jsonPath, [Text.Encoding]::UTF8)
$parsed = $readBack | ConvertFrom-Json
Assert-That 'The .json still round-trips non-ASCII through the reader the script uses' ($parsed.Server -eq ('dc-m' + [char]0x00FC + 'nchen.contoso.com')) ("got=$($parsed.Server)")

# Case-insensitive extension: a path ending .JSON is the same artefact.
$upperPath = Join-Path $root 'MDI-REPORT.JSON'
Write-mdiReportFile -Content $jsonBody -FilePath $upperPath
Assert-That 'An uppercase .JSON is treated as JSON too' (-not (Test-HasUtf8Bom $upperPath)) ("firstBytes=$(Get-LeadingBytes $upperPath)")

# Compatibility: a baseline written by an EARLIER build, WITH a mark, must still be readable, or
# every operator's existing history breaks the moment they upgrade.
$legacyPath = Join-Path $root 'legacy-baseline.json'
[IO.File]::WriteAllText($legacyPath, $jsonBody, (New-Object Text.UTF8Encoding $true))
$legacyRead = [IO.File]::ReadAllText($legacyPath, [Text.Encoding]::UTF8)
$legacyOk = $false
try { $null = $legacyRead | ConvertFrom-Json; $legacyOk = $true } catch { $legacyOk = $false }
Assert-That 'An existing BOM-marked baseline is still readable after the change' $legacyOk

# Ground truth: a real third-party parser, if one is present. Skipped rather than faked when absent.
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    $pyCode = 'import json,sys' + "`n" + 'json.load(open(sys.argv[1], encoding="utf-8"))' + "`n" + 'print("parsed")'
    $pyFile = Join-Path $root 'parse.py'
    [IO.File]::WriteAllText($pyFile, $pyCode, (New-Object Text.UTF8Encoding $false))
    # A FAILING parse is the exact condition under test, and python reports it on stderr. Under
    # ErrorActionPreference=Stop that native stderr raises a terminating NativeCommandError and
    # kills the whole test file, so the run produces no summary line at all - the defect being
    # present would look like the harness being broken instead of a clean FAIL. Relaxed for the
    # child call only.
    $pyOut = ''
    $prevEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $pyOut = & $python.Source $pyFile $jsonPath 2>&1 | Out-String
    } catch {
        $pyOut = "$pyOut $($_.Exception.Message)"
    } finally {
        $ErrorActionPreference = $prevEap
    }
    Assert-That 'python json.load parses the written .json' ($pyOut -match 'parsed') ("out=$(($pyOut -replace '\s+',' ').Trim())")
} else {
    "  SKIP  python not present, third-party parse not measured"
}

try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue } catch { }

""
"  $($script:pass) passed, $($script:fail) failed"
if ($script:fail -gt 0) { exit 1 }
