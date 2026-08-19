<#
    A MEASUREMENT A ROW EXPLICITLY RECORDED IS NOT DISCARDED BECAUSE OF THE ROW'S SHAPE.

    THE DEFECT THIS PINS. Two readers asked whether a property was present with

        $row.PSObject.Properties['<name>']

    and treated $null as "this row never recorded that measurement", falling back to a POSITIVE
    default. On an IDictionary that question cannot be answered: PSObject.Properties over a hashtable
    or an [ordered] hashtable enumerates the dictionary's own .NET members - Count, Keys, Values,
    IsReadOnly - and NEVER its entries. So a row that had EXPLICITLY recorded $false was read as
    having recorded nothing, and the positive default was applied over the top of a real measurement.

    This script states the fact itself, in Copy-mdiDetails:

        "PSObject.Properties on an IDictionary enumerates the .NET members (Count, Keys, Values,
         IsReadOnly...), NOT the entries."

    and ships Test-mdiDetailEntry / Get-mdiDetailValue for exactly this.

    WHY IT IS A DEFECT AND NOT A DOCUMENTED LIMITATION. In both places the SAME function reads the
    row's OTHER fields by direct member access, which a dictionary answers correctly, and both
    properties have SIBLING readers elsewhere in this script that use direct access and therefore
    already work on a dictionary row:

        Merge-mdiDomainControllerEndpoint  reads .Name, .IP, .Addresses directly, then reads
                                           AddressResolutionComplete through PSObject.Properties
        Set-MdiReadinessReport             reads .DeletedObjects directly, then reads
                                           DeletedObjectsMeasured through PSObject.Properties
                                           - while the same field is read as
                                           $domainRow.DeletedObjectsMeasured -ne $false and as
                                           $Domain.DeletedObjectsMeasured by its two siblings

    So the row was legible; one reader in each pair simply asked the wrong way, and the two readers
    of one field disagreed about the same row.

    WHAT EACH ONE COSTS.

    AddressResolutionComplete is not decoration. Its own comment calls it "a MEASUREMENT, not a
    constant", and Get-mdiDomainControllerInventory reads exactly this flag to decide whether to
    trust the stored addresses or fall back to Get-mdiComputerAddress. A source saying $false means
    "these addresses are NOT the resolved set, go and resolve them". Turned into $true, that DNS
    FALLBACK BECOMES UNREACHABLE, and a domain controller whose addresses could not be resolved is
    reported "cannot be probed" without the second attempt the code was written to give it. Measured
    on the shipped function, one source row carrying AddressResolutionComplete=$false:

        PSCustomObject row   ->  AddressResolutionComplete=False   (carried, correct)
        Hashtable row        ->  AddressResolutionComplete=True    (fabricated)
        [ordered] row        ->  AddressResolutionComplete=True    (fabricated)

    DeletedObjectsMeasured decides how an 'N/A' Deleted Objects result is PRESENTED. Measured $true
    renders "Not applicable" - a domain where the check genuinely does not apply. Measured $false
    renders "Not tested" with the detail "The Deleted Objects permission could not be read on this
    domain". So on a dictionary row the honest "we could not read this" was displayed as "nothing to
    fix here", which is the false green this codebase exists to prevent.

    THE ABSENT DEFAULT ITSELF IS UNCHANGED AND STILL POSITIVE. A row that genuinely does not carry
    the property - a legacy report predating it, an inventory row from a producer that never set it -
    must keep reading as $true, exactly as before. This fixes only the case where the property is
    PRESENT and its value was thrown away because of the row's shape.

    SCOPE, stated no more strongly than it was measured: today's producers emit PSCustomObject rows,
    and an -AsJson round trip returns PSCustomObject, so neither of these was a live false green in
    the shipped pipeline. Each is one reader of a row disagreeing with the rest of the script about
    how a row is read - the same class of defect, and the same argument for fixing it at the reader,
    that the address and domain guards in Resolve-mdiLdapTarget were fixed under.
#>

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$script:target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $script:target)) {
    $script:target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
}
if (-not (Test-Path $script:target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$script:pass = 0
$script:fail = 0
function Assert-True {
    param([string] $What, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:pass++
        Write-Host ("  PASS  {0}" -f $What) -ForegroundColor Green
    } else {
        $script:fail++
        Write-Host ("  FAIL  {0} {1}" -f $What, $Detail) -ForegroundColor Red
    }
}

$text = Get-Content -LiteralPath $script:target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main')
if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body

function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

Write-Host 'A recorded measurement is not discarded because of the row shape'

function New-Row {
    param([string] $Shape, [hashtable] $Fields)
    switch ($Shape) {
        'PSCustomObject' { [PSCustomObject] $Fields }
        'Hashtable' { $h = @{}; foreach ($k in $Fields.Keys) { $h[$k] = $Fields[$k] }; $h }
        'Ordered' { $o = [ordered] @{}; foreach ($k in $Fields.Keys) { $o[$k] = $Fields[$k] }; $o }
        default { throw "unknown shape $Shape" }
    }
}
$shapes = @('PSCustomObject', 'Hashtable', 'Ordered')

# =================================================================================================
# 1. Merge-mdiDomainControllerEndpoint carries an explicitly recorded AddressResolutionComplete.
# =================================================================================================
foreach ($shape in $shapes) {
    $row = New-Row $shape @{
        Name                      = 'dcfab01'
        IP                        = '10.10.1.50'
        Addresses                 = @('10.10.1.50')
        AddressResolutionComplete = $false
    }
    $merged = @(Merge-mdiDomainControllerEndpoint -Server @($row) -Domain 'fabrikam.local')

    Assert-True ("{0}: the merge returns the row" -f $shape) `
    (@($merged).Count -eq 1) `
    ("returned {0} row(s)" -f @($merged).Count)

    Assert-True ("{0}: an explicit AddressResolutionComplete=`$false is carried, not overwritten" -f $shape) `
    ($merged[0].AddressResolutionComplete -eq $false) `
    ("the row recorded `$false and the merge returned [{0}] - the DNS fallback in Get-mdiDomainControllerInventory is gated on this flag" -f `
        [string] $merged[0].AddressResolutionComplete)
}

# The pessimistic carry across copies of one host must still hold in every shape: if ANY copy was
# incompletely resolved, the merged host is incompletely resolved.
foreach ($shape in $shapes) {
    $complete = New-Row $shape @{ Name = 'dcfab01'; IP = '10.10.1.50'; Addresses = @('10.10.1.50'); AddressResolutionComplete = $true }
    $partial = New-Row $shape @{ Name = 'dcfab01'; IP = '10.10.1.51'; Addresses = @('10.10.1.51'); AddressResolutionComplete = $false }
    $merged = @(Merge-mdiDomainControllerEndpoint -Server @($complete, $partial) -Domain 'fabrikam.local')

    Assert-True ("{0}: the carry stays pessimistic across two copies of one host" -f $shape) `
    (@($merged).Count -eq 1 -and $merged[0].AddressResolutionComplete -eq $false) `
    ("merged {0} row(s), AddressResolutionComplete=[{1}]" -f @($merged).Count, [string] $merged[0].AddressResolutionComplete)
}

# A row that genuinely does not carry the property must still read as complete - the absent default
# is deliberate and is NOT what this change touches.
foreach ($shape in $shapes) {
    $row = New-Row $shape @{ Name = 'dcfab01'; IP = '10.10.1.50'; Addresses = @('10.10.1.50') }
    $merged = @(Merge-mdiDomainControllerEndpoint -Server @($row) -Domain 'fabrikam.local')
    Assert-True ("{0}: a row that never recorded the flag still reads as complete" -f $shape) `
    ($merged[0].AddressResolutionComplete -eq $true) `
    ("AddressResolutionComplete=[{0}]" -f [string] $merged[0].AddressResolutionComplete)
}

# The value must be a REAL boolean. The STRING 'True' and the INTEGER 1 are what a boolean becomes
# through an -AsJson round trip, and neither is a completed measurement.
foreach ($notABoolean in @{ Label = "the string 'True'"; Value = 'True' }, @{ Label = 'the integer 1'; Value = 1 }) {
    foreach ($shape in $shapes) {
        $row = New-Row $shape @{
            Name = 'dcfab01'; IP = '10.10.1.50'; Addresses = @('10.10.1.50')
            AddressResolutionComplete = $notABoolean.Value
        }
        $merged = @(Merge-mdiDomainControllerEndpoint -Server @($row) -Domain 'fabrikam.local')
        Assert-True ("{0}: {1} is not a completed measurement" -f $shape, $notABoolean.Label) `
        ($merged[0].AddressResolutionComplete -eq $false) `
        ("AddressResolutionComplete=[{0}]" -f [string] $merged[0].AddressResolutionComplete)
    }
}

# =================================================================================================
# 2. The DeletedObjectsMeasured reader, exercised THROUGH THE REAL REPORT.
#
#    The reader is inline in Set-MdiReadinessReport, so the only honest way to pin it is to render a
#    report from a row whose DeletedObjectsMeasured is a dictionary entry and read the cell that
#    comes out. Asserting against a reimplementation of the predicate here would pin this test file,
#    not the product, and would stay green when the defect returned.
#
#    An 'N/A' Deleted Objects result renders as the neutral "Not applicable" pill when the check was
#    measured, and as the "Not tested" warning pill when it was not. The row below records
#    DeletedObjectsMeasured = $false: the permission could NOT be read, so the honest cell is
#    "Not tested".
# =================================================================================================
function New-DomainAuditingRow {
    param([string] $Shape, $Measured)
    $fields = [ordered] @{
        Domain                   = 'fabrikam.local'
        ObjectAuditing           = [PSCustomObject]@{ isObjectAuditingOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
        ObjectAuditingMeasured   = $true
        ExchangeAuditing         = [PSCustomObject]@{ isExchangeAuditingOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
        ExchangeAuditingMeasured = $true
        AdfsAuditing             = [PSCustomObject]@{ isAdfsAuditingOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
        AdfsAuditingMeasured     = $true
        DeletedObjects           = [PSCustomObject]@{
            isDeletedObjectsPermissionOk = 'N/A'
            details                      = [PSCustomObject]@{ Detail = '' }
        }
    }
    if ($null -ne $Measured) { $fields['DeletedObjectsMeasured'] = $Measured }
    New-Row $Shape $fields
}

function Get-DeletedObjectsCell {
    param($Row)
    $report = [PSCustomObject]@{
        Domain              = 'fabrikam.local'
        Forest              = 'fabrikam.local'
        DomainsInScope      = @('fabrikam.local')
        DomainControllers   = @([PSCustomObject]@{
                FQDN = 'dcfab01.fabrikam.local'; OperatingSystem = 'Windows Server 2022'
                AdvancedAuditing = $true; NtlmAuditing = $true; Unreachable = $false
            })
        CAServers           = @()
        EntraConnectServers = @()
        DomainAuditing      = @($Row)
    }
    $outDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi-rowshape-' + [Guid]::NewGuid().ToString('N'))
    [void] (New-Item -ItemType Directory -Force -Path $outDir)
    try {
        [void] (Set-MdiReadinessReport -Domain 'fabrikam.local' -Path $outDir -ReportData @($report) -SkipTrend 3> $null 4> $null 6> $null)
        $htmlFile = @(Get-ChildItem -LiteralPath $outDir -Filter '*.html' -File)[0]
        $html = [IO.File]::ReadAllText($htmlFile.FullName)
        $m = [regex]::Match($html, '<tr><td class="mono">fabrikam\.local</td><td>(<span class="pill[^<]*</span>)</td><td>([^<]*)</td></tr>')
        if (-not $m.Success) { return '<cell not rendered>' }
        $m.Groups[1].Value
    } finally {
        Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

foreach ($shape in $shapes) {
    $cell = Get-DeletedObjectsCell (New-DomainAuditingRow $shape $false)

    Assert-True ("{0}: an explicit DeletedObjectsMeasured=`$false renders as 'Not tested'" -f $shape) `
    ($cell -like '*Not tested*' -and $cell -like '*pill warn*') `
    ("the row recorded that the permission could NOT be read; the cell rendered [{0}] - 'Not applicable' says there is nothing to fix" -f $cell)
}

foreach ($shape in $shapes) {
    # A legacy row that never carried the property at all must keep reading as measured, which is the
    # deliberate positive default and is NOT what this change touches.
    $cell = Get-DeletedObjectsCell (New-DomainAuditingRow $shape $null)

    Assert-True ("{0}: a legacy row without the property still renders as 'Not applicable'" -f $shape) `
    ($cell -like '*Not applicable*' -and $cell -like '*pill na*') `
    ("the deliberate positive default for a row predating the property was lost; cell rendered [{0}]" -f $cell)
}

foreach ($shape in $shapes) {
    # And an explicit $true must still render as measured.
    $cell = Get-DeletedObjectsCell (New-DomainAuditingRow $shape $true)

    Assert-True ("{0}: an explicit DeletedObjectsMeasured=`$true still renders as 'Not applicable'" -f $shape) `
    ($cell -like '*Not applicable*' -and $cell -like '*pill na*') `
    ("cell rendered [{0}]" -f $cell)
}

# =================================================================================================
# 3. The three shapes must AGREE. That agreement is the invariant the defect broke.
# =================================================================================================
$pso = (@(Merge-mdiDomainControllerEndpoint -Server @(New-Row 'PSCustomObject' @{ Name = 'd'; IP = '10.10.1.50'; Addresses = @('10.10.1.50'); AddressResolutionComplete = $false }) -Domain 'fabrikam.local'))[0].AddressResolutionComplete
$hash = (@(Merge-mdiDomainControllerEndpoint -Server @(New-Row 'Hashtable' @{ Name = 'd'; IP = '10.10.1.50'; Addresses = @('10.10.1.50'); AddressResolutionComplete = $false }) -Domain 'fabrikam.local'))[0].AddressResolutionComplete
$ord = (@(Merge-mdiDomainControllerEndpoint -Server @(New-Row 'Ordered' @{ Name = 'd'; IP = '10.10.1.50'; Addresses = @('10.10.1.50'); AddressResolutionComplete = $false }) -Domain 'fabrikam.local'))[0].AddressResolutionComplete

Assert-True 'a hashtable row merges identically to the same row as a PSCustomObject' `
($hash -eq $pso) `
("PSCustomObject=[{0}] Hashtable=[{1}]" -f [string] $pso, [string] $hash)

Assert-True 'an ordered-hashtable row merges identically to the same row as a PSCustomObject' `
($ord -eq $pso) `
("PSCustomObject=[{0}] Ordered=[{1}]" -f [string] $pso, [string] $ord)

# =================================================================================================
# 4. What must NOT have changed - the merge's other behaviour on the ordinary shape.
# =================================================================================================
$multi = @(
    [PSCustomObject]@{ Name = 'dcfab01'; IP = '10.10.1.50'; Addresses = @('10.10.1.50') }
    [PSCustomObject]@{ Name = 'dcfab01'; IP = '10.10.1.51'; Addresses = @('10.10.1.51') }
    [PSCustomObject]@{ Name = 'dcfab02'; IP = '10.10.1.52'; Addresses = @('10.10.1.52') }
)
$mergedMulti = @(Merge-mdiDomainControllerEndpoint -Server $multi -Domain 'fabrikam.local')
Assert-True 'two records of one host still merge to one row carrying both addresses' `
(@($mergedMulti).Count -eq 2 -and
    @($mergedMulti | Where-Object { $_.Name -eq 'dcfab01.fabrikam.local' }).Addresses.Count -eq 2) `
("merged to {0} row(s)" -f @($mergedMulti).Count)

Assert-True 'a nameless source row is still skipped' `
(@(Merge-mdiDomainControllerEndpoint -Server @([PSCustomObject]@{ Name = ''; IP = '10.10.1.50'; Addresses = @('10.10.1.50') }) -Domain 'fabrikam.local').Count -eq 0) `
    'a nameless row was merged'

# An empty collection is still accepted and yields nothing. (A NULL ELEMENT is not tested here: the
# parameter is Mandatory [object[]], and PowerShell's binder refuses an array containing $null before
# the function body runs, so the loop's own null guard cannot be reached through this parameter.
# Measured on the shipped function - @($null), @($null,$good) and @($good,$null) all throw
# "Cannot bind argument to parameter 'Server' because it is null".)
Assert-True 'an empty collection still merges to nothing' `
(@(Merge-mdiDomainControllerEndpoint -Server @() -Domain 'fabrikam.local').Count -eq 0) `
    'an empty collection did not merge to nothing'

Write-Host ''
Write-Host ("PASS={0} FAIL={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
