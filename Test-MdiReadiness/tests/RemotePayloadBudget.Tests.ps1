# The remote probe script is embedded in a Win32_Process.Create command line, which has a hard length
# limit. Two defects lived here:
#
# 1. Three parser helpers were added and the shipped-function list very nearly was not updated. One
#    that WAS missed - Get-mdiPtrHostEntry, called by Test-mdiReverseDns - would have made every
#    REMOTE reverse-DNS probe die with "The term ... is not recognized", which the caller reads as a
#    server it could not measure rather than as a defect.
# 2. The plan shipped a Notes sentence and a SensorVersion list per probe that the sensor server never
#    reads. Base64 does not compress, so that documentation cost about 8,000 characters of command
#    line and pushed an ordinary single-domain-controller scan over the limit - it threw outright.
#
# These tests pin both: the script must always be self-contained, and a realistic plan must fit with
# room to spare.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}
function New-RealPlan {
    param([int] $Dcs, [int] $Nnr, [string] $Workspace = '')
    $dcList = @(if ($Dcs -gt 0) { 1..$Dcs | ForEach-Object { [PSCustomObject]@{ Name = ('dc{0:D2}.contoso.com' -f $_); IP = ('10.0.{0}.{1}' -f [int]($_ / 250), ($_ % 250)) } } })
    $nnrList = @(if ($Nnr -gt 0) { 1..$Nnr | ForEach-Object { [PSCustomObject]@{ Name = ('wks{0:D3}.contoso.com' -f $_); IP = ('10.1.{0}.{1}' -f [int]($_ / 250), ($_ % 250)) } } })
    $params = @{ Domain = 'contoso.com'; DomainController = $dcList; NnrTarget = $nnrList; TimeoutMs = 1500 }
    if ($Workspace) { $params['WorkspaceName'] = $Workspace }
    New-mdiPortProbePlan @params
}

'[shipping] the generated script is self-contained'
# Built from the AST, so a name appearing in a comment or a string is not mistaken for a call.
foreach ($case in @(@{ D = 1; N = 1; W = '' }, @{ D = 2; N = 5; W = 'contoso-corp' }, @{ D = 5; N = 5; W = '' })) {
    $plan = New-RealPlan -Dcs $case.D -Nnr $case.N -Workspace $case.W
    $script = Get-mdiPortProbeScriptText -Plan $plan -OutputFile 'C:\Windows\Temp\m.json'
    $missing = Get-mdiMissingShippedFunction -ScriptText $script
    Assert-That "every mdi function called is also defined (DCs=$($case.D), workspace='$($case.W)')" (
        $missing.Count -eq 0) "(missing: $($missing -join ', '))"
    $perr = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$null, [ref]$perr)
    Assert-That "  ...and the script parses" (@($perr).Count -eq 0)
}
# The check must actually be able to fail, or it guards nothing.
Assert-That 'the completeness check detects a missing helper' (
    @(Get-mdiMissingShippedFunction -ScriptText 'function Test-mdiThing { Get-mdiNotShipped }').Count -eq 1)
Assert-That 'and does not flag a name that only appears in a string' (
    @(Get-mdiMissingShippedFunction -ScriptText 'function Test-mdiThing { $x = ''Get-mdiNotShipped'' }').Count -eq 0)
Assert-That 'nor one that is defined alongside it' (
    @(Get-mdiMissingShippedFunction -ScriptText 'function Get-mdiHelper { 1 } function Test-mdiThing { Get-mdiHelper }').Count -eq 0)

'[budget] a realistic plan fits the command line with room to spare'
# 32000 is the hard throw. A plan that only just fits is one string literal away from breaking, and
# the symptom is a scan that cannot run at all rather than a wrong number, so a margin is required.
foreach ($case in @(
        @{ D = 1; N = 1 }, @{ D = 2; N = 5 }, @{ D = 5; N = 5 }, @{ D = 10; N = 5 }, @{ D = 19; N = 5 }, @{ D = 25; N = 10 }
    )) {
    foreach ($ws in @('', 'contoso-corp')) {
        $plan = New-RealPlan -Dcs $case.D -Nnr $case.N -Workspace $ws
        $length = -1
        try { $length = (Get-mdiPortProbeCommandLine -Plan $plan -OutputFile 'C:\Windows\Temp\m.json').Length }
        catch { if ($_.Exception.Message -match '\((\d+) characters\)') { $length = [int] $Matches[1] } }
        Assert-That ("a $($case.D)-DC/$($case.N)-target plan$(if($ws){' with a workspace'}) fits with 1000 chars to spare") (
            $length -gt 0 -and $length -lt 31000) "($length chars)"
    }
}

'[budget] the plan ships what the remote code reads, and not the documentation'
$plan = New-RealPlan -Dcs 2 -Nnr 5 -Workspace 'contoso-corp'
$slim = Get-mdiSlimProbePlan -Plan $plan
Assert-That 'the slim plan keeps every probe' (@($slim.Probes).Count -eq @($plan.Probes).Count) "($(@($slim.Probes).Count) of $(@($plan.Probes).Count))"
foreach ($field in 'Id', 'Name', 'Protocol', 'Port', 'Scope', 'Group', 'Requirement') {
    Assert-That "  the slim plan keeps $field" ($null -ne @($slim.Probes)[0].PSObject.Properties[$field])
}
foreach ($field in 'Notes', 'SensorVersion') {
    Assert-That "  the slim plan drops $field" ($null -eq @($slim.Probes)[0].PSObject.Properties[$field])
}
Assert-That 'the slim plan keeps the targets' (
    @($slim.DomainControllers).Count -eq @($plan.DomainControllers).Count -and
    @($slim.NnrTargets).Count -eq @($plan.NnrTargets).Count)
Assert-That 'the slim plan keeps the sensor API url' ([string] $slim.SensorApiUrl -eq [string] $plan.SensorApiUrl)
# The caller's plan is reused for the local run and written into the report, so it must not be pruned.
Assert-That 'the original plan is not modified' ($null -ne @($plan.Probes)[0].PSObject.Properties['Notes'])

'[budget] the shipped plan survives the round trip the remote script performs'
$scriptText = Get-mdiPortProbeScriptText -Plan $plan -OutputFile 'C:\Windows\Temp\m.json'
$b64 = [regex]::Match($scriptText, "FromBase64String\('([A-Za-z0-9+/=]+)'\)").Groups[1].Value
$roundTripped = [text.encoding]::UTF8.GetString([convert]::FromBase64String($b64)) | ConvertFrom-Json
Assert-That 'the shipped plan round-trips' (@($roundTripped.Probes).Count -eq @($plan.Probes).Count)
Assert-That 'a probe keeps its scope after the round trip' (
    -not [string]::IsNullOrWhiteSpace([string] @($roundTripped.Probes)[0].Scope))
Assert-That 'a target keeps its address after the round trip' (
    [string] @($roundTripped.DomainControllers)[0].IP -eq [string] @($plan.DomainControllers)[0].IP)

'[compression] stripping indentation must not alter string content'
# Leading whitespace inside a string that spans lines is CONTENT. Trimming it would silently reword a
# message the operator reads.
$withHereString = @'
function Test-mdiSample {
    $message = @"
    indented content line
        more indented
"@
        return $message
}
'@
$compressed = Compress-mdiScriptText -ScriptText $withHereString
Assert-That 'code indentation is removed' ($compressed -match '(?m)^function Test-mdiSample')
Assert-That 'string content indentation is preserved' ($compressed -match '(?m)^    indented content line')
Assert-That '  ...including deeper lines' ($compressed -match '(?m)^        more indented')
$cerr = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($compressed, [ref]$null, [ref]$cerr)
Assert-That 'the compressed text still parses' (@($cerr).Count -eq 0)
# And the compression must actually do something, or it is guarding nothing.
$indented = "function Test-mdiX {`n        `$a = 1`n            `$b = 2`n}"
Assert-That 'compression really removes indentation' ((Compress-mdiScriptText -ScriptText $indented).Length -lt $indented.Length)

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
