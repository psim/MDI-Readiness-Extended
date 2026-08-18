<#
    The machine-readable report must publish the same coverage and readiness facts as the console
    and HTML. The check denominator includes unread checks. Readiness is tri-state: a measured
    failure is false, while a run with no measured failure and unread evidence is 'N/A'.

    This test executes the shipped Main report/output block in Windows PowerShell child processes,
    lets the real report writer emit JSON and HTML, captures the real console stream, and compares
    the three rendered surfaces. It does not inspect source for the fields under test.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$canonical = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path -LiteralPath $target)) { $target = $canonical }
if (-not (Test-Path -LiteralPath $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$target = (Resolve-Path -LiteralPath $target).ProviderPath
# Run-Suite.ps1 copies every test into a FLAT isolated directory, whose PARENT is $env:TEMP and holds
# no product script. Resolving the canonical path unconditionally threw there and killed the file
# before a single assertion ran - the suite then reported it as "no assertions", which reads as a
# quiet test rather than a dead one. The canonical copy is now optional context, not a precondition.
$canonicalHash = $null
if (Test-Path -LiteralPath $canonical) {
    $canonical = (Resolve-Path -LiteralPath $canonical).ProviderPath
    $canonicalHash = (Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash
} else {
    $canonical = '(not present beside this copy)'
}

$loadedHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
"LOADED_PATH=$target"
"LOADED_SHA256=$loadedHash"
"CANONICAL_PATH=$canonical"
"CANONICAL_SHA256=$canonicalHash"
"HASH_MATCH=$($null -ne $canonicalHash -and $loadedHash -eq $canonicalHash)"
if ($null -ne $canonicalHash -and $loadedHash -ne $canonicalHash) {
    "NOTE=loaded copy differs from the canonical file (expected inside an isolated suite copy)"
}

$script:pass = 0
$script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:pass++
        "  PASS  $Name"
    } else {
        $script:fail++
        "  FAIL  $Name $Detail"
    }
}

# The guard that matters is that the file loaded IS the product script - not that it is byte-current
# with a copy one directory up, which an isolated snapshot legitimately is not.
Assert-That 'the script actually loaded is the Test-MdiReadiness product script' `
    ((Get-Content -LiteralPath $target -Raw) -match '(?m)^function Get-mdiReportStatistics') "(loaded=$target)"

$childText = @'
param(
    [Parameter(Mandatory = $true)] [ValidateSet('Mixed', 'Unread')] [string] $Case,
    [Parameter(Mandatory = $true)] [ValidateSet('Console', 'Json')] [string] $Mode,
    [Parameter(Mandatory = $true)] [string] $Target,
    [Parameter(Mandatory = $true)] [string] $OutputPath
)
$ErrorActionPreference = 'Stop'
$raw = [IO.File]::ReadAllText($Target)
$mainIndex = $raw.IndexOf('#region Main', [StringComparison]::Ordinal)
if ($mainIndex -lt 0) { throw 'Main region was not found' }
$definitions = $raw.Substring(0, $mainIndex)
$definitions = [regex]::Replace($definitions, '(?im)^\s*#requires[^\r\n]*(?:\r?\n)?', '')
$definitions = [regex]::Replace($definitions, '(?im)^\s*\[CmdletBinding\([^\r\n]*\)\]\s*(?:\r?\n)?', '')
Invoke-Expression $definitions

$main = $raw.Substring($mainIndex)
$startMarker = '    # Compute each headline fact once, through the same functions used by the console and HTML, and'
$endMarker = '    # A scan that enumerated nothing exits non-zero even without -FailOnIssues.'
$start = $main.IndexOf($startMarker, [StringComparison]::Ordinal)
$end = $main.IndexOf($endMarker, $start, [StringComparison]::Ordinal)
if ($start -lt 0 -or $end -lt 0) { throw "Main report block not found (start=$start end=$end)" }
$mainBlock = $main.Substring($start, $end - $start)

$server = [PSCustomObject][ordered]@{
    FQDN = 'dc1.probe.invalid'
    Domain = 'probe.invalid'
    Unreachable = $false
    PartialFailure = $false
    Details = [PSCustomObject]@{}
}
if ($Case -eq 'Mixed') {
    $server | Add-Member -NotePropertyName OSVersion -NotePropertyValue $true
    $server | Add-Member -NotePropertyName AdvancedAuditing -NotePropertyValue $false
    $server | Add-Member -NotePropertyName RootCertificates -NotePropertyValue 'N/A'
} else {
    $server | Add-Member -NotePropertyName OSVersion -NotePropertyValue 'N/A'
    $server | Add-Member -NotePropertyName AdvancedAuditing -NotePropertyValue 'N/A'
    $server | Add-Member -NotePropertyName RootCertificates -NotePropertyValue 'N/A'
}

$report = @{
    ScriptVersion = 'json-verdict-test'
    Domain = 'probe.invalid'
    Forest = 'probe.invalid'
    ForestDiscovery = [PSCustomObject]@{ Name = 'probe.invalid'; Domains = @('probe.invalid'); Complete = $true }
    DomainsInScope = @('probe.invalid')
    DomainControllers = @($server)
    CAServers = @()
    EntraConnectServers = @()
    DomainAuditing = @()
    DomainAdfsAuditing = $null
    DomainObjectAuditing = $null
    DomainExchangeAuditing = $null
    DomainDeletedObjects = $null
    DomainSchemaVersion = [PSCustomObject]@{ schemaVersion = 0; details = 'not measured' }
    LdapPlanGapDomains = @()
    AddresslessDomainControllers = @()
    NnrUnresolvedTargets = @()
    NnrTargetComputer = @()
    MaxNnrTargets = 5
    SkippedAreas = @('Network ports', 'Certification authority servers', 'Entra Connect servers', 'Sensor v3.x readiness')
}

if ([IO.Directory]::Exists($OutputPath)) { [IO.Directory]::Delete($OutputPath, $true) }
[void] [IO.Directory]::CreateDirectory($OutputPath)
$Path = $OutputPath
$BaselinePath = $null
$SkipTrend = $true
$SkipRemediationScript = $true
$SkipNetworkPorts = $true
$SkipCA = $true
$SkipEntraConnect = $true
$SkipSensorV3Readiness = $true
$OpenHtmlReport = $false
$PassThru = $false
$FailOnIssues = $false
$AsJson = $Mode -eq 'Json'
$script:mdiJsonMode = $AsJson

Invoke-Expression $mainBlock
'@

$work = Join-Path $here ('.json-coverage-{0}' -f [guid]::NewGuid().ToString('N'))
[void] [IO.Directory]::CreateDirectory($work)
$childPath = Join-Path $work 'invoke-main.ps1'
[IO.File]::WriteAllBytes($childPath, (New-Object Text.UTF8Encoding($true)).GetBytes($childText))
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Quote-ProcessArgument {
    param([string] $Value)
    '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-MainCase {
    param([string] $Case, [string] $Mode, [string] $OutputPath)

    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $childPath,
        '-Case', $Case, '-Mode', $Mode, '-Target', $target, '-OutputPath', $OutputPath
    )
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $ps51
    $psi.Arguments = ($arguments | ForEach-Object { Quote-ProcessArgument ([string] $_) }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($psi)
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $stdout = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()
    [PSCustomObject]@{
        ExitCode = $process.ExitCode
        StdOut = $stdout
        StdErr = $stderrTask.Result
    }
}

function Get-TypeName {
    param([AllowNull()] $Value)
    if ($null -eq $Value) { '<null>' } else { $Value.GetType().FullName }
}

function Get-ConsoleVerdict {
    param([string] $Text)
    if ($Text -match 'READINESS N/A') { return 'N/A' }
    if ($Text -match '(?m)^\s*READY\s+') { return $true }
    if ($Text -match 'issue\(s\) found') { return $false }
    '<missing>'
}

function Get-HtmlVerdict {
    param([string] $Text)
    if ($Text -match 'Readiness N/A') { return 'N/A' }
    if ($Text -match 'All prerequisites met') { return $true }
    if ($Text -match 'Action required') { return $false }
    '<missing>'
}

function Test-SameTriState {
    param([AllowNull()] $Left, [AllowNull()] $Right)
    (Get-TypeName $Left) -eq (Get-TypeName $Right) -and [string] $Left -ceq [string] $Right
}

try {
    foreach ($case in @(
            [PSCustomObject]@{ Name = 'Mixed'; Passed = 1; Measured = 2; Unread = 1; Denominator = 3; Readiness = $false }
            [PSCustomObject]@{ Name = 'Unread'; Passed = 0; Measured = 0; Unread = 3; Denominator = 3; Readiness = 'N/A' }
        )) {
        $consolePath = Join-Path $work ($case.Name + '-console')
        $jsonPath = Join-Path $work ($case.Name + '-json')
        $consoleRun = Invoke-MainCase -Case $case.Name -Mode Console -OutputPath $consolePath
        $jsonRun = Invoke-MainCase -Case $case.Name -Mode Json -OutputPath $jsonPath

        $stdoutReport = $null
        $stdoutParses = $false
        try {
            $stdoutReport = $jsonRun.StdOut | ConvertFrom-Json
            $stdoutParses = $true
        } catch {
            $stdoutParses = $false
        }
        $diskJsonFile = Join-Path $jsonPath 'mdi-probe.invalid.json'
        $htmlFile = Join-Path $jsonPath 'mdi-probe.invalid.html'
        $diskReport = if (Test-Path -LiteralPath $diskJsonFile) {
            [IO.File]::ReadAllText($diskJsonFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
        } else { $null }
        $html = if (Test-Path -LiteralPath $htmlFile) { [IO.File]::ReadAllText($htmlFile) } else { '' }

        $consoleFractionMatch = [regex]::Match($consoleRun.StdOut, '(\d+)/(\d+) checks passed')
        $htmlFractionMatch = [regex]::Match($html, '(\d+) of (\d+) checks passed')
        $consoleFraction = '{0}/{1}' -f $consoleFractionMatch.Groups[1].Value, $consoleFractionMatch.Groups[2].Value
        $htmlFraction = '{0}/{1}' -f $htmlFractionMatch.Groups[1].Value, $htmlFractionMatch.Groups[2].Value
        $jsonDenominator = [int] $stdoutReport.ChecksTotal + [int] $stdoutReport.ChecksUnread
        $jsonFraction = '{0}/{1}' -f [int] $stdoutReport.ChecksPassed, $jsonDenominator
        $consoleVerdict = Get-ConsoleVerdict $consoleRun.StdOut
        $htmlVerdict = Get-HtmlVerdict $html

        "--- CASE=$($case.Name) ---"
        "CONSOLE_RAW=$(($consoleRun.StdOut.Trim() -replace '\r?\n', '<NL>'))"
        "CONSOLE_FRACTION=$consoleFraction"
        "HTML_FRACTION=$htmlFraction"
        "JSON_FRACTION=$jsonFraction"
        "JSON_COUNTS=Passed:$($stdoutReport.ChecksPassed),Measured:$($stdoutReport.ChecksTotal),Unread:$($stdoutReport.ChecksUnread),Denominator:$jsonDenominator"
        "JSON_COUNT_TYPES=Passed:$(Get-TypeName $stdoutReport.ChecksPassed),Measured:$(Get-TypeName $stdoutReport.ChecksTotal),Unread:$(Get-TypeName $stdoutReport.ChecksUnread)"
        "CONSOLE_VERDICT=$consoleVerdict TYPE=$(Get-TypeName $consoleVerdict)"
        "HTML_VERDICT=$htmlVerdict TYPE=$(Get-TypeName $htmlVerdict)"
        "JSON_READINESS=$($stdoutReport.Readiness) TYPE=$(Get-TypeName $stdoutReport.Readiness)"

        Assert-That "$($case.Name): console child completed" ($consoleRun.ExitCode -eq 0) `
            "(exit=$($consoleRun.ExitCode) stderr='$($consoleRun.StdErr.Trim())')"
        Assert-That "$($case.Name): JSON child completed" ($jsonRun.ExitCode -eq 0) `
            "(exit=$($jsonRun.ExitCode) stderr='$($jsonRun.StdErr.Trim())')"
        Assert-That "$($case.Name): -AsJson stdout is one valid JSON document" $stdoutParses `
            "(stdout='$($jsonRun.StdOut.Trim())')"
        Assert-That "$($case.Name): the persisted JSON was emitted" ($null -ne $diskReport)
        Assert-That "$($case.Name): the HTML was rendered" (-not [string]::IsNullOrWhiteSpace($html))

        Assert-That "$($case.Name): JSON publishes ChecksPassed as an integer" `
            ($stdoutReport.ChecksPassed -is [int] -and $stdoutReport.ChecksPassed -eq $case.Passed) `
            "(value=$($stdoutReport.ChecksPassed) type=$(Get-TypeName $stdoutReport.ChecksPassed))"
        Assert-That "$($case.Name): JSON publishes measured ChecksTotal as an integer" `
            ($stdoutReport.ChecksTotal -is [int] -and $stdoutReport.ChecksTotal -eq $case.Measured) `
            "(value=$($stdoutReport.ChecksTotal) type=$(Get-TypeName $stdoutReport.ChecksTotal))"
        Assert-That "$($case.Name): JSON publishes ChecksUnread as an integer" `
            ($stdoutReport.ChecksUnread -is [int] -and $stdoutReport.ChecksUnread -eq $case.Unread) `
            "(value=$($stdoutReport.ChecksUnread) type=$(Get-TypeName $stdoutReport.ChecksUnread))"
        Assert-That "$($case.Name): persisted and stdout JSON carry the same counts" `
            ($diskReport.ChecksPassed -eq $stdoutReport.ChecksPassed -and
                $diskReport.ChecksTotal -eq $stdoutReport.ChecksTotal -and
                $diskReport.ChecksUnread -eq $stdoutReport.ChecksUnread)

        $expectedFraction = '{0}/{1}' -f $case.Passed, $case.Denominator
        Assert-That "$($case.Name): console publishes the expected fraction" `
            ($consoleFraction -eq $expectedFraction) "(got=$consoleFraction)"
        Assert-That "$($case.Name): HTML publishes the same fraction" `
            ($htmlFraction -eq $expectedFraction) "(got=$htmlFraction)"
        Assert-That "$($case.Name): JSON publishes the same fraction" `
            ($jsonFraction -eq $expectedFraction) "(got=$jsonFraction)"

        Assert-That "$($case.Name): JSON readiness has the expected value and type" `
            (Test-SameTriState $stdoutReport.Readiness $case.Readiness) `
            "(value=$($stdoutReport.Readiness) type=$(Get-TypeName $stdoutReport.Readiness))"
        Assert-That "$($case.Name): console and JSON publish the same readiness verdict" `
            (Test-SameTriState $consoleVerdict $stdoutReport.Readiness) `
            "(console=$consoleVerdict/$(Get-TypeName $consoleVerdict) json=$($stdoutReport.Readiness)/$(Get-TypeName $stdoutReport.Readiness))"
        Assert-That "$($case.Name): HTML and JSON publish the same readiness verdict" `
            (Test-SameTriState $htmlVerdict $stdoutReport.Readiness) `
            "(html=$htmlVerdict/$(Get-TypeName $htmlVerdict) json=$($stdoutReport.Readiness)/$(Get-TypeName $stdoutReport.Readiness))"
        Assert-That "$($case.Name): persisted and stdout JSON carry the same readiness" `
            (Test-SameTriState $diskReport.Readiness $stdoutReport.Readiness)

        Assert-That "$($case.Name): the pre-existing server detail remains in JSON" `
            (@($stdoutReport.DomainControllers).Count -eq 1 -and
                [string] $stdoutReport.DomainControllers[0].FQDN -eq 'dc1.probe.invalid')
        if ($case.Name -eq 'Mixed') {
            Assert-That 'Mixed: the raw measured pass remains a boolean' `
                ($stdoutReport.DomainControllers[0].OSVersion -is [bool] -and $stdoutReport.DomainControllers[0].OSVersion)
        } else {
            Assert-That "Unread: the raw unknown remains the string 'N/A'" `
                ($stdoutReport.DomainControllers[0].OSVersion -is [string] -and
                    $stdoutReport.DomainControllers[0].OSVersion -ceq 'N/A')
        }
    }
} finally {
    if ([IO.Directory]::Exists($work)) { [IO.Directory]::Delete($work, $true) }
}

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
