<#
    Behavioural regression tests for the generated REMEDIATION script.

    This script is written to change audit policy, registry values and firewall rules on production
    domain controllers, so two properties matter more than anything else it does:

      * nothing from the scanned environment may become executable code in it
      * a finding the report shows the operator must not silently vanish from it

    Every assertion below runs the generator and inspects the RESULT - the parsed AST, or the emitted
    text. None of them matches the generator's source. The generated script is never executed.
#>

param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }

$text = [IO.File]::ReadAllText($scriptPath)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main'); if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:passed++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray }
    else { $script:failed++; Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red }
}

Write-Host 'RemediationScriptSafety.Tests.ps1' -ForegroundColor Cyan

$outDir = Join-Path $env:TEMP ('mdi-remed-tests-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
[void] (New-Item -ItemType Directory -Force -Path $outDir)

function Get-GeneratedScript {
    param([object] $ReportData)
    $path = Join-Path $outDir ('remed-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void] (New-mdiRemediationScript -ReportData $ReportData -FilePath $path)
    if (-not (Test-Path $path)) { return $null }
    [IO.File]::ReadAllText($path)
}

function Get-CommandNameList {
    param([string] $ScriptText)
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($ScriptText, [ref] $null, [ref] $errors)
    [PSCustomObject]@{
        ParseErrors = @($errors).Count
        Commands    = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.Extent.Text })
    }
}

# ---------------------------------------------------------------------------------------------
# A value from the environment must never become a command, whichever quote character it carries.
#
# Windows PowerShell accepts U+2018, U+2019, U+201A and U+201B as single-quote delimiters as well as
# ASCII U+0027. Escaping only U+0027 let a value close its literal early - and U+2019 is the ordinary
# apostrophe in French, so localised Windows error text reaches this with no attacker involved.
# ---------------------------------------------------------------------------------------------
$quoteChars = @{
    'ASCII U+0027' = [char]0x0027
    'U+2018'       = [char]0x2018
    'U+2019'       = [char]0x2019
    'U+201A'       = [char]0x201A
    'U+201B'       = [char]0x201B
}

foreach ($label in ($quoteChars.Keys | Sort-Object)) {
    $q = $quoteChars[$label]
    # The classic break-out: close the literal, run something, reopen so the rest still parses.
    $hostile = 'dc{0}; Write-Host INJECTEDMARKER; {0}x.contoso.com' -f $q
    $report = [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @(
            [PSCustomObject]@{
                FQDN = $hostile; Domain = 'contoso.com'; Unreachable = $false
                OperatingSystem = 'Windows Server 2022'
                AdvancedAuditing = $false; NtlmAuditing = $false; PowerSettings = $false
                Details = [ordered]@{}
            })
        CAServers = @(); EntraConnectServers = @()
    }
    $generated = Get-GeneratedScript -ReportData $report
    Assert-True ("a server name carrying {0} still produces a script" -f $label) ($null -ne $generated)
    if ($null -ne $generated) {
        $parsed = Get-CommandNameList -ScriptText $generated
        Assert-True ("  {0}: the generated script parses" -f $label) ($parsed.ParseErrors -eq 0) ("{0} parse error(s)" -f $parsed.ParseErrors)
        Assert-True ("  {0}: the injected payload is not a command" -f $label) `
            (@($parsed.Commands | Where-Object { $_ -match '^\s*Write-Host\s+INJECTEDMARKER' }).Count -eq 0) `
            (($parsed.Commands | Where-Object { $_ -match 'INJECTEDMARKER' } | Select-Object -First 2) -join ' || ')
        # And it must still be REPORTED - neutralising by deleting the value would hide the server.
        Assert-True ("  {0}: the value survives as inert text" -f $label) ($generated -match 'INJECTEDMARKER')
    }
}

# ---------------------------------------------------------------------------------------------
# Sensor v3.x blockers: an ABSENT classification is not an empty one.
# ---------------------------------------------------------------------------------------------
function New-V3Report {
    param([object] $Details)
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @(
            [PSCustomObject]@{
                FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
                OperatingSystem = 'Windows Server 2022'; SensorV3Ready = $false
                Details = [ordered]@{ SensorV3ReadyDetails = $Details }
            })
        CAServers = @(); EntraConnectServers = @()
    }
}
$blockerText = 'Defender for Endpoint is onboarded: the server is not onboarded to Defender for Endpoint'

# 1. The property is ABSENT - an older report, or another tool's JSON. Nothing classified it, so
#    nothing may be deleted on the strength of that classification.
$absent = [PSCustomObject]@{
    SensorState = 'v2.x sensor running'; SensorV2Version = '2.0'; MigrationEligible = $false
    Blockers = @($blockerText); Checks = @()
}
$absentScript = Get-GeneratedScript -ReportData (New-V3Report -Details $absent)
Assert-True 'a v3 blocker survives when ActionableBlockers is absent' `
    ($absentScript -match 'not onboarded to Defender for Endpoint') `
    ('regions: ' + (([regex]::Matches($absentScript, '#region (.+)') | ForEach-Object { $_.Groups[1].Value }) -join ' | '))
Assert-True 'and the v3 section itself is emitted' ($absentScript -match '#region Sensor v3\.x prerequisites')

# 2. The property is PRESENT and EMPTY - a real classification meaning "this server can never run
#    v3.x, so none of its blockers are work". That deletion is deliberate and must be preserved.
$emptyClassification = [PSCustomObject]@{
    SensorState = 'No sensor installed and not eligible for v3.x (use v2.x)'; SensorV2Version = $null
    MigrationEligible = $false; Blockers = @($blockerText); ActionableBlockers = @(); Checks = @()
}
$emptyScript = Get-GeneratedScript -ReportData (New-V3Report -Details $emptyClassification)
Assert-True 'an explicitly empty ActionableBlockers still suppresses the v3 section' `
    ($emptyScript -notmatch '#region Sensor v3\.x prerequisites') `
    ('regions: ' + (([regex]::Matches($emptyScript, '#region (.+)') | ForEach-Object { $_.Groups[1].Value }) -join ' | '))

# 3. The property is PRESENT and POPULATED - the ordinary case.
$populated = [PSCustomObject]@{
    SensorState = 'v2.x sensor running'; SensorV2Version = '2.0'; MigrationEligible = $false
    Blockers = @($blockerText); ActionableBlockers = @($blockerText); Checks = @()
}
$populatedScript = Get-GeneratedScript -ReportData (New-V3Report -Details $populated)
Assert-True 'a populated ActionableBlockers emits the v3 section' `
    ($populatedScript -match '#region Sensor v3\.x prerequisites' -and $populatedScript -match 'not onboarded')

# 4. The same three cases through the resolver directly, including the dictionary shape another
#    tool's JSON handling produces.
Assert-True 'resolver: absent property falls back to every blocker' `
    (@(Get-mdiV3ActionableBlocker -Detail $absent).Count -eq 1)
Assert-True 'resolver: an explicitly empty classification stays empty' `
    (@(Get-mdiV3ActionableBlocker -Detail $emptyClassification).Count -eq 0)
Assert-True 'resolver: a populated classification is returned as-is' `
    (@(Get-mdiV3ActionableBlocker -Detail $populated).Count -eq 1)
Assert-True 'resolver: a null detail yields nothing' (@(Get-mdiV3ActionableBlocker -Detail $null).Count -eq 0)
$dictEmpty = [ordered]@{ Blockers = @($blockerText); ActionableBlockers = @() }
$dictAbsent = [ordered]@{ Blockers = @($blockerText) }
Assert-True 'resolver: a dictionary with an empty classification stays empty' `
    (@(Get-mdiV3ActionableBlocker -Detail $dictEmpty).Count -eq 0)
Assert-True 'resolver: a dictionary with no classification falls back to every blocker' `
    (@(Get-mdiV3ActionableBlocker -Detail $dictAbsent).Count -eq 1)

# 5. The advisory must not swallow a genuine finding that no scripted section covers. This is the
#    other half of the same filter: it exists to DELETE things, so something has to prove it still
#    lets real work through.
$advisoryReport = [PSCustomObject]@{
    Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers = @(
        [PSCustomObject]@{
            FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
            OperatingSystem = 'Windows Server 2022'; AdvancedAuditing = $true; SensorV3Ready = $false
            # An explicitly empty classification, so the unactionable filter genuinely RUNS. Without
            # one of these the whole filter is skipped and a mutation inside it changes nothing.
            Details = [ordered]@{ SensorV3ReadyDetails = [PSCustomObject]@{
                    SensorState = 'No sensor installed and not eligible for v3.x (use v2.x)'
                    SensorV2Version = $null; MigrationEligible = $false
                    Blockers = @('Server is a domain controller: Not a domain controller')
                    ActionableBlockers = @(); Checks = @() } }
        })
    CAServers = @(
        [PSCustomObject]@{
            FQDN = 'ca1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false
            OperatingSystem = 'Windows Server 2022'; CAAuditing = $false
            Details = [ordered]@{}
        })
    EntraConnectServers = @()
}
$advisoryScript = Get-GeneratedScript -ReportData $advisoryReport
Assert-True 'a finding with no scripted section still reaches the manual-attention advisory' `
    ($advisoryScript -match '#region Findings that need manual attention' -and $advisoryScript -match 'ca1\.contoso\.com') `
    ('regions: ' + (([regex]::Matches([string] $advisoryScript, '#region (.+)') | ForEach-Object { $_.Groups[1].Value }) -join ' | '))
Assert-True 'and the unactionable v3 blocker beside it is still filtered out' `
    ($advisoryScript -notmatch 'Not a domain controller') `
    ('regions: ' + (([regex]::Matches([string] $advisoryScript, '#region (.+)') | ForEach-Object { $_.Groups[1].Value }) -join ' | '))

Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
