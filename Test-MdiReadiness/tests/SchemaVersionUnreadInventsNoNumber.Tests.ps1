# [x210] A schema version that was NEVER READ must not be printed with a version number.
#
# Get-DomainSchemaVersion returns schemaVersion = 0 beside the sentence 'Not tested - the schema
# version could not be read' whenever the directory did not answer - which across a forest trust is
# the ordinary outcome for the second forest, and is the case that function's own comment records
# having measured against fabrikam.local. The per-domain runner's catch writes the string 'N/A' into
# the same field.
#
# The report headline formatted both exactly like a successful read:
#
#     Schema Not tested - the schema version could not be read (version 0)
#
# A sentence stating that nothing was measured, carrying a number that reads as a measurement. There
# is no schema version 0 - 13, Windows 2000, is the lowest Active Directory has ever had - so the
# number was invented by the renderer rather than read from any directory. The headline is the only
# place the schema appears, so nothing else would have contradicted it.
#
# The same line also dumped a PowerShell object stringification into the headline. The per-domain
# runner's catch wraps details in a [PSCustomObject]@{ Detail = ... } for every sibling of this item;
# a PSCustomObject is truthy, so the old guard passed it to [string] and the headline read
# '@{Detail=Could not be read: ...} (version N/A)'.
#
# Proven against the REAL renderer: Set-MdiReadinessReport is called and the HTML it writes to disk
# is read back. See MDI-AB\live\xforest-210-schemaversionunreadshape.ps1 for the probe that found it
# and MDI-AB\live\xforest-210b-schemacatchreachability.ps1 for the reachability measurement.

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
        FQDN        = $Fqdn; Domain = $Domain
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        Details     = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
    }
}

# The headline fragment the renderer writes: <span>Schema <b>@@SCHEMA@@</b></span>
function Get-SchemaHeadline {
    param($SchemaNode)
    $report = [PSCustomObject]@{
        ScriptVersion       = 'test'; Domain = 'fabrikam.local'; Forest = 'fabrikam.local'
        DomainsInScope      = @('mdilab.local', 'fabrikam.local')
        LdapPlanGapDomains  = @()
        DomainSchemaVersion = $SchemaNode
        DomainControllers   = @((New-Srv -Fqdn 'dcfab01.fabrikam.local' -Domain 'fabrikam.local'))
        CAServers           = @(); EntraConnectServers = @()
        DomainAuditing      = @()
        ForestDiscovery     = [PSCustomObject]@{ Name = 'fabrikam.local'; Complete = $true }
        SkippedAreas        = @()
    }
    $outDir = Join-Path $env:TEMP ('mdischema-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void](New-Item -ItemType Directory -Path $outDir -Force)
    try {
        Set-MdiReadinessReport -Domain 'fabrikam.local' -Path $outDir -ReportData $report -SkipTrend 3>$null 4>$null 6>$null | Out-Null
        $file = @(Get-ChildItem $outDir -Filter '*.html' -File)
        if ($file.Count -eq 0) { return $null }
        $html = [IO.File]::ReadAllText($file[0].FullName)
        $m = [regex]::Match($html, '(?s)<span>Schema\s*<b>(.*?)</b></span>')
        if (-not $m.Success) { return $null }
        $m.Groups[1].Value
    } finally { Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue }
}

'[x210] the shape Get-DomainSchemaVersion returns when the directory did not answer'
# This is verbatim what the shipped function returns for a domain it could not read - measured in
# probe 210b against fabrikam.local, FABCORP and four other unreachable names: schemaVersion 0, and
# details of type String.
$unread = Get-SchemaHeadline -SchemaNode @{ schemaVersion = 0; details = 'Not tested - the schema version could not be read' }
Assert-That 'the renderer wrote a schema headline' ($null -ne $unread) "(got '$unread')"
Assert-That 'the unread schema still says it was not tested' `
    ($unread -like '*Not tested*') "(got '$unread')"
Assert-That 'THE DEFECT: no version number is invented for a schema that was never read' `
    ($unread -notmatch '\(version') "(got '$unread')"
Assert-That '  and specifically not "version 0"' `
    ($unread -notmatch 'version\s*0') "(got '$unread')"

'[x210] the shape the per-domain runner catch builds'
$caught = Get-SchemaHeadline -SchemaNode ([PSCustomObject]@{
        details       = [PSCustomObject]@{ Detail = 'Could not be read: the directory did not answer' }
        schemaVersion = 'N/A'
    })
Assert-That 'no PowerShell object stringification reaches the headline' `
    ($caught -notmatch '@\{') "(got '$caught')"
Assert-That 'the reason the operator can act on is what is shown' `
    ($caught -like '*Could not be read*') "(got '$caught')"
Assert-That 'no version number is invented for the catch shape either' `
    ($caught -notmatch '\(version') "(got '$caught')"

'[x210] a version that WAS read is still reported in full - the control'
# Without this the defect could be "fixed" by deleting the version number altogether.
$read = Get-SchemaHeadline -SchemaNode @{ schemaVersion = 88; details = 'Windows Server 2019 / 2022' }
Assert-That 'a measured schema still names the Windows version' `
    ($read -like '*Windows Server 2019 / 2022*') "(got '$read')"
Assert-That 'a measured schema still carries its version number' `
    ($read -match '\(version\s*88\)') "(got '$read')"

$read90 = Get-SchemaHeadline -SchemaNode @{ schemaVersion = 90; details = 'Windows Server 2025' }
Assert-That 'a 2025 schema still carries version 90' `
    ($read90 -match '\(version\s*90\)') "(got '$read90')"

# A version the directory ANSWERED with but this script has no name for is still a MEASUREMENT, and
# must keep its number - that is the whole point of the 'Unrecognised schema version' branch.
$unnamed = Get-SchemaHeadline -SchemaNode @{ schemaVersion = 137; details = 'Unrecognised schema version - this script has no name for it' }
Assert-That 'an unrecognised but MEASURED version keeps its number' `
    ($unnamed -match '\(version\s*137\)') "(got '$unnamed')"

'[x210] the unreadable shapes - nothing invents a measurement'
foreach ($case in @(
        @{ Label = 'details $null      '; Node = @{ schemaVersion = 0; details = $null } }
        @{ Label = "details ''         "; Node = @{ schemaVersion = 0; details = '' } }
        @{ Label = 'details whitespace '; Node = @{ schemaVersion = 0; details = '   ' } }
        @{ Label = 'whole node $null   '; Node = $null }
        @{ Label = 'details a hashtable'; Node = @{ schemaVersion = 'N/A'; details = @{ Detail = 'Could not be read' } } }
        @{ Label = 'details an array   '; Node = @{ schemaVersion = 88; details = @('a', 'b') } }
        @{ Label = 'version a bool     '; Node = @{ schemaVersion = $true; details = 'Not tested - the schema version could not be read' } }
        @{ Label = 'version non-numeric'; Node = @{ schemaVersion = 'eighty-eight'; details = 'Not tested - the schema version could not be read' } }
        @{ Label = 'version negative   '; Node = @{ schemaVersion = -1; details = 'Not tested - the schema version could not be read' } }
    )) {
    $got = Get-SchemaHeadline -SchemaNode $case.Node
    Assert-That ("  {0} renders without an object dump" -f $case.Label) `
    ($got -notmatch '@\{' -and $got -notmatch 'System\.Collections' -and $got -notmatch 'System\.Object\[\]') "(got '$got')"
}

# The three above that carry no readable version must not print one. 'version a bool' is the sharpest:
# [int]$true is 1, and 1 is not a schema version any directory has ever reported.
foreach ($case in @(
        @{ Label = 'version a bool     '; Node = @{ schemaVersion = $true; details = 'Not tested - the schema version could not be read' } }
        @{ Label = 'version non-numeric'; Node = @{ schemaVersion = 'eighty-eight'; details = 'Not tested - the schema version could not be read' } }
        @{ Label = 'version negative   '; Node = @{ schemaVersion = -1; details = 'Not tested - the schema version could not be read' } }
    )) {
    $got = Get-SchemaHeadline -SchemaNode $case.Node
    Assert-That ("  {0} invents no version number" -f $case.Label) ($got -notmatch '\(version') "(got '$got')"
}

'[x210] an absent schema node still renders the n/a placeholder'
$none = Get-SchemaHeadline -SchemaNode $null
Assert-That 'a report with no schema reading renders "n/a"' ($none -eq 'n/a') "(got '$none')"

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
