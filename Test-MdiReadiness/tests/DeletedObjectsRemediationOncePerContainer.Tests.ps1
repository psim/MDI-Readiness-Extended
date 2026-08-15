<#
    The one section of the generated remediation script that runs a DESTRUCTIVE native command must
    run once per CONTAINER, not once per domain row.

    New-mdiRemediationScript emits the Deleted Objects block inside
    "foreach ($domainRow in $auditedDomains)". Two rows can legitimately describe the same container:
    domains are de-duplicated upstream only by a CASE-SENSITIVE Select-Object -Unique, so
    'contoso.com' and 'CONTOSO.COM' both survive; and unlike servers, which are reconciled by
    Merge-mdiServerByFqdn, domain rows have no merge step at all.

    With no de-duplication the generated file contained the whole block TWICE for one container:

        dsacls /takeownership   x2      <- takes ownership of a production system container, twice
        dsacls /G               x2
        Read-Host for the DSA   x2      <- the operator is asked for the same account twice

    Measured on the shipped generator: takeown=2 grant=2 prompts=2 against ONE distinct container.

    Two prompts is not merely untidy. This block is the only part of the generated script that runs
    a native tool locally against a production directory, and an operator who answers the first
    prompt and is then asked again has no way to tell whether the first attempt failed.

    THE CONTROL THAT MUST NOT BE BROKEN: two REAL domains with two DIFFERENT containers must still
    emit both blocks. A fix that de-duplicates on domain name, or that simply emits the section once,
    would silently drop a child domain's remediation - a far worse defect than the one being fixed.
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
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
# Write-mdiReportFile is the only thing New-mdiRemediationScript does with the emitted text, so
# stubbing it captures the generated script without writing anything to disk.
$script:emitted = ''
Set-Item -Path function:script:Write-mdiReportFile -Value {
    param($Content, $FilePath)
    $script:emitted = [string] $Content
}

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

function New-DomainRow {
    param([string] $Domain, [string] $Container)
    [PSCustomObject]@{
        Domain                 = $Domain
        ObjectAuditing         = [PSCustomObject]@{ isObjectAuditingOk = $true }
        ObjectAuditingMeasured = $true
        ExchangeAuditing       = [PSCustomObject]@{ isExchangeAuditingOk = $true }
        ExchangeAuditingMeasured = $true
        AdfsAuditing           = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        AdfsAuditingMeasured   = $true
        DeletedObjects         = [PSCustomObject]@{
            isDeletedObjectsPermissionOk = $false
            details = [PSCustomObject]@{ Container = $Container; Detail = 'The DSA has no read access' }
        }
        DeletedObjectsMeasured = $true
    }
}

function Get-Generated {
    param([object[]] $DomainRows)
    $report = [PSCustomObject]@{
        Domain              = 'contoso.com'
        DomainsInScope      = @('contoso.com')
        DomainControllers   = @()
        CAServers           = @()
        EntraConnectServers = @()
        ForestDiscovery     = [PSCustomObject]@{ Complete = $true }
        DomainAuditing      = @($DomainRows)
    }
    # A real path is required because the generator ends with Resolve-Path on it. Nothing is written
    # there: the Write-mdiReportFile stub above captures the content instead.
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('mdi-delobj-{0}.ps1' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    [IO.File]::WriteAllText($scratch, '')
    $script:emitted = ''
    try {
        $null = New-mdiRemediationScript -ReportData $report -FilePath $scratch 3>$null 4>$null
    } finally {
        Remove-Item $scratch -Force -ErrorAction SilentlyContinue
    }
    $s = [string] $script:emitted
    [PSCustomObject]@{
        Script     = $s
        TakeOwn    = ([regex]::Matches($s, 'dsacls\.exe \$container /takeownership')).Count
        Grant      = ([regex]::Matches($s, 'dsacls\.exe \$container /G ')).Count
        Prompts    = ([regex]::Matches($s, "Read-Host\s+'Enter the Directory Service Account")).Count
        Sections   = ([regex]::Matches($s, '#region Deleted Objects container permissions')).Count
        Containers = @([regex]::Matches($s, '\$container\s*=\s*''([^'']+)''') | ForEach-Object { $_.Groups[1].Value })
    }
}

Write-Host 'The destructive Deleted Objects block runs once per container, not once per domain row' -ForegroundColor Cyan

$container = 'CN=Deleted Objects,DC=contoso,DC=com'
$childContainer = 'CN=Deleted Objects,DC=child,DC=contoso,DC=com'

# CONTROL A: a single domain row. The ordinary case, and it must be untouched.
$single = Get-Generated @( (New-DomainRow 'contoso.com' $container) )
# CONTROL B: two REAL domains with two DIFFERENT containers. BOTH must still be remediated.
$twoReal = Get-Generated @(
    (New-DomainRow 'contoso.com' $container),
    (New-DomainRow 'child.contoso.com' $childContainer)
)
# DEFECT 1: one domain spelled two ways - what the case-sensitive upstream de-dupe lets through.
$twoSpellings = Get-Generated @(
    (New-DomainRow 'contoso.com' $container),
    (New-DomainRow 'CONTOSO.COM' $container)
)
# DEFECT 2: the identical row twice.
$repeated = Get-Generated @(
    (New-DomainRow 'contoso.com' $container),
    (New-DomainRow 'contoso.com' $container)
)

# --- The defect -----------------------------------------------------------------------------------
Assert-That 'one container takes ownership exactly once (two spellings)' (
    $twoSpellings.TakeOwn -eq 1
) ("takeownership=$($twoSpellings.TakeOwn)")
Assert-That 'one container is granted exactly once (two spellings)' (
    $twoSpellings.Grant -eq 1
) ("grants=$($twoSpellings.Grant)")
Assert-That 'the operator is prompted for the DSA exactly once (two spellings)' (
    $twoSpellings.Prompts -eq 1
) ("prompts=$($twoSpellings.Prompts)")
Assert-That 'the container appears once in the generated script (two spellings)' (
    @($twoSpellings.Containers | Sort-Object -Unique).Count -eq @($twoSpellings.Containers).Count
) ("containers=$($twoSpellings.Containers -join ', ')")

Assert-That 'an exactly repeated row does not duplicate takeownership' (
    $repeated.TakeOwn -eq 1
) ("takeownership=$($repeated.TakeOwn)")
Assert-That 'an exactly repeated row does not duplicate the prompt' (
    $repeated.Prompts -eq 1
) ("prompts=$($repeated.Prompts)")

# --- The controls that must NOT be broken -----------------------------------------------------------
# This is the assertion that stops the lazy fix. Two real domains have two real containers and BOTH
# need remediating; de-duplicating on anything other than the container DN would drop one.
Assert-That 'two DIFFERENT containers are both still remediated' (
    $twoReal.TakeOwn -eq 2 -and $twoReal.Grant -eq 2
) ("takeownership=$($twoReal.TakeOwn) grants=$($twoReal.Grant)")
Assert-That 'two DIFFERENT containers both appear in the script' (
    @($twoReal.Containers | Sort-Object -Unique).Count -eq 2
) ("containers=$($twoReal.Containers -join ', ')")
Assert-That 'the child container is not the one that was dropped' (
    $twoReal.Script -match [regex]::Escape($childContainer)
) 'the child domain container is missing from the generated script'

Assert-That 'a single domain row still takes ownership once' ($single.TakeOwn -eq 1) (
    "takeownership=$($single.TakeOwn)")
Assert-That 'a single domain row still prompts once' ($single.Prompts -eq 1) (
    "prompts=$($single.Prompts)")
Assert-That 'a single domain row emits the section' ($single.Sections -ge 1) (
    "sections=$($single.Sections)")

# A measured-good container must never be remediated at all - the guard above it still holds.
$good = New-DomainRow 'contoso.com' $container
$good.DeletedObjects.isDeletedObjectsPermissionOk = $true
$passing = Get-Generated @($good)
Assert-That 'a passing container is never touched' (
    $passing.TakeOwn -eq 0 -and $passing.Prompts -eq 0
) ("takeownership=$($passing.TakeOwn) prompts=$($passing.Prompts)")

# An explicitly UNMEASURED container must never be touched either: this block is destructive and may
# only run on a positive measured failure.
$unmeasured = New-DomainRow 'contoso.com' $container
$unmeasured.DeletedObjectsMeasured = $false
$unmeasuredOut = Get-Generated @($unmeasured)
Assert-That 'an unmeasured container is never touched' (
    $unmeasuredOut.TakeOwn -eq 0 -and $unmeasuredOut.Prompts -eq 0
) ("takeownership=$($unmeasuredOut.TakeOwn) prompts=$($unmeasuredOut.Prompts)")

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
