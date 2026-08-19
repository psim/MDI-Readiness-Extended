<#
    THE REPORT ITSELF MAY BE A DICTIONARY, NOT ONLY THE RECORDS INSIDE IT.

    Test-mdiForestEnumerationIncomplete is THE definition of "forest discovery says it did not
    finish", shared by the three surfaces that would otherwise decide it independently: the score
    (Get-mdiReportStatistics), the findings table (Get-mdiIssueList) and the verdict
    (Test-mdiReadinessResult). All three used to ask
    $ReportData.ForestDiscovery.PSObject.Properties['Complete'], and PSObject.Properties over an
    IDictionary enumerates the DICTIONARY'S OWN .NET MEMBERS - Count, Keys, Values, IsReadOnly -
    never its entries. So on a dictionary-shaped ForestDiscovery the presence test answered $null,
    the guard was skipped, the verdict kept its DEFAULT of complete, and a run that could not
    enumerate the forest - and said so in its own Error field - was certified as having enumerated
    it. Get-mdiForestDiscoveryRecord was extracted to normalise the record through
    ConvertTo-mdiRecordObject, and IncompleteForestIsRefusedWhateverTheRecordShape.Tests.ps1 pins
    that fix.

    WHAT THIS TEST ADDS, AND WHY IT IS A DIFFERENT QUESTION. That test varies ONE axis: it rebuilds
    the ForestDiscovery RECORD as Hashtable, OrderedDictionary and Generic.Dictionary while leaving
    $ReportData ITSELF a PSCustomObject on every run. Nothing had ever asked what happens when the
    REPORT is the dictionary - and Get-mdiForestDiscoveryRecord reaches the record by DIRECT MEMBER
    ACCESS, $ReportData.ForestDiscovery, exactly as Get-mdiReportStatistics reaches
    .DomainControllers, .CAServers and .EntraConnectServers. One reader of a structure disagreeing
    with the rest of the script about how that structure is read is the family this codebase keeps
    finding; Get-mdiProbeTargetKey's header records the same thing one level down, for a row rather
    than for the report.

    A dictionary-shaped REPORT is the same arrival vector ConvertTo-mdiRecordObject exists for and
    which that sibling test's own header names: another tool's JSON, a hand-edited report, an older
    version. A cross-forest report is the one most likely to be round-tripped or merged between
    tools, because -MultiForest is what reaches a second forest at all.

    Measured on the shipped functions, one healthy two-forest estate - mdilab.local and
    fabrikam.local, every check on every server passing - with ForestDiscovery.Complete = $false and
    nothing differing but the shape of the REPORT:

        report shape          record read   incomplete   forest finding   verdict
        PSCustomObject        yes           True         1                NOT READY
        Hashtable             yes           True         1                NOT READY
        OrderedDictionary     yes           True         1                NOT READY
        Generic.Dictionary    yes           True         1                NOT READY

    All four agree today. This test exists so they cannot stop agreeing: the behaviour is correct
    and completely unpinned, which is the state a refactor silently breaks. It is also what closes
    the last function in the product that no test named - Get-mdiForestDiscoveryRecord, measured as
    the only one of 186.

    WHAT MUST NOT REGRESS, pinned below alongside:
      * ABSENCE IS NOT INCOMPLETENESS. A report written before the property existed carries no
        Complete at all, and charging it would invent a gap on every historical baseline - on every
        report shape, not just the object one.
      * NO FALSE RED. The same estate with Complete = $true must stay READY on every report shape.
      * A ForestDiscovery that is not a record at all - $null, '', '   ', 'Unknown', 0, 1, 12345,
        $true, @(), @('a','b') - must leave the run unaffected and must never throw. One unreadable
        field must not kill the report, which is the failure Format-mdiWholeNumber and
        Get-mdiAddresslessDomainController were both hardened against.
      * Get-mdiForestDiscoveryRecord itself: $null in, $null out; a record in, its ENTRIES readable
        out, whatever dictionary it arrived in.
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
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Write-Host 'The report itself may be a dictionary, not only the records inside it' -ForegroundColor Cyan

function ConvertTo-Shape ($Shape, $Ordered) {
    switch ($Shape) {
        'PSCustomObject' { [PSCustomObject] $Ordered }
        'Hashtable' { $h = @{}; foreach ($k in $Ordered.Keys) { $h[$k] = $Ordered[$k] }; $h }
        'OrderedDictionary' { $Ordered }
        'Generic.Dictionary' {
            $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'
            foreach ($k in $Ordered.Keys) { $d[[string] $k] = $Ordered[$k] }
            $d
        }
    }
}

# A healthy CROSS-FOREST estate whose every check passes. The only thing wrong is that forest
# enumeration states it did not finish, so anything but NOT READY is a forest nobody enumerated
# coming back certified.
function New-Report ($ReportShape, $Complete, [switch] $NoForestDiscovery, $RawDiscovery, [switch] $UseRaw) {
    $fd = [ordered]@{
        Name     = 'mdilab.local'
        Domains  = @('mdilab.local', 'fabrikam.local')
        Method   = 'ADWS'
        Complete = $Complete
        Error    = 'the forest root domain fabrikam.local is absent from the returned domain list'
    }
    $report = [ordered]@{
        Domain              = 'mdilab.local'
        DomainsInScope      = @('mdilab.local', 'fabrikam.local')
        DomainControllers   = @(
            [PSCustomObject]@{ FQDN = 'dc2022.mdilab.local'; Domain = 'mdilab.local'; isAdvancedAuditingOk = $true; isPowerSchemeOk = $true }
            [PSCustomObject]@{ FQDN = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; isAdvancedAuditingOk = $true; isPowerSchemeOk = $true }
        )
        CAServers           = @()
        EntraConnectServers = @()
        DomainAuditing      = @()
    }
    if (-not $NoForestDiscovery) {
        $report['ForestDiscovery'] = if ($UseRaw) { $RawDiscovery } else { [PSCustomObject] $fd }
    }
    ConvertTo-Shape $ReportShape $report
}

$shapes = @('PSCustomObject', 'Hashtable', 'OrderedDictionary', 'Generic.Dictionary')

# ---------------------------------------------------------------------------------------------------
# Get-mdiForestDiscoveryRecord itself - the function no test named.
# ---------------------------------------------------------------------------------------------------
Assert-That 'a null report yields no discovery record' `
($null -eq (Get-mdiForestDiscoveryRecord -ReportData $null))

foreach ($s in $shapes) {
    $rec = Get-mdiForestDiscoveryRecord -ReportData (New-Report $s $false)
    Assert-That ("the discovery record is read from a {0} report" -f $s) ($null -ne $rec)
    Assert-That ("its ENTRIES are readable from a {0} report" -f $s) `
    ($null -ne $rec -and $null -ne $rec.PSObject.Properties['Complete'] -and
        ([string] $rec.Name) -eq 'mdilab.local') `
    ("got properties: {0}" -f $(if ($rec) { ($rec.PSObject.Properties.Name -join ',') } else { '<null>' }))
}

# A report that carries no ForestDiscovery at all yields no record, on every shape.
foreach ($s in $shapes) {
    Assert-That ("a {0} report with no ForestDiscovery yields no record" -f $s) `
    ($null -eq (Get-mdiForestDiscoveryRecord -ReportData (New-Report $s $true -NoForestDiscovery)))
}

# ---------------------------------------------------------------------------------------------------
# THE DEFINITION, through every report shape. Complete = $false must be REFUSED.
# ---------------------------------------------------------------------------------------------------
foreach ($s in $shapes) {
    $r = New-Report $s $false
    Assert-That ("Complete=False is refused when the report is a {0}" -f $s) `
    ([bool] (Test-mdiForestEnumerationIncomplete -ReportData $r))
}

# ---------------------------------------------------------------------------------------------------
# THE THREE SURFACES. The verdict must refuse READY and the findings table must SAY WHY - a banner
# reading NOT READY over an issue list that names nothing is this codebase's own stated failure.
# ---------------------------------------------------------------------------------------------------
foreach ($s in $shapes) {
    $r = New-Report $s $false
    $stats = Get-mdiReportStatistics -ReportData $r
    $issues = @(Get-mdiIssueList -Statistics $stats -ReportData $r)
    $forest = @($issues | Where-Object { ([string] $_.Area + [string] $_.Issue) -match 'forest' })
    Assert-That ("a {0} report still counts both servers" -f $s) (([string] $stats.TotalServers) -eq '2') `
    ("got {0}" -f $stats.TotalServers)
    Assert-That ("a {0} report raises a forest finding" -f $s) ($forest.Count -ge 1) `
    ("issues: {0}" -f (($issues | ForEach-Object { '{0}/{1}' -f $_.Area, $_.Severity }) -join ' | '))
    Assert-That ("a {0} report refuses READY" -f $s) (-not (Test-mdiReadinessResult -ReportData $r))
}

# ---------------------------------------------------------------------------------------------------
# NO FALSE RED. The same estate, complete, must stay READY on every shape.
# ---------------------------------------------------------------------------------------------------
foreach ($s in $shapes) {
    $r = New-Report $s $true
    Assert-That ("a complete {0} report is not called incomplete" -f $s) `
    (-not (Test-mdiForestEnumerationIncomplete -ReportData $r))
    Assert-That ("a complete {0} report stays READY" -f $s) ([bool] (Test-mdiReadinessResult -ReportData $r))
}

# ABSENCE IS NOT INCOMPLETENESS - a historical baseline must not be charged a gap it never had.
foreach ($s in $shapes) {
    $r = New-Report $s $true -NoForestDiscovery
    Assert-That ("a {0} report with no ForestDiscovery is not incomplete" -f $s) `
    (-not (Test-mdiForestEnumerationIncomplete -ReportData $r))
}

# ---------------------------------------------------------------------------------------------------
# A ForestDiscovery THAT IS NOT A RECORD AT ALL. Complete is present in none of these, so absence
# rules: not incomplete, and above all NOTHING MAY THROW - one unreadable field must not cost the
# whole report.
# ---------------------------------------------------------------------------------------------------
$raws = [ordered]@{
    'null'              = $null
    'empty string'      = ''
    'whitespace'        = '   '
    'Unknown'           = 'Unknown'
    'zero'              = 0
    'one'               = 1
    'number 12345'      = 12345
    'boolean true'      = $true
    'empty array'       = @()
    'two-element array' = @('a', 'b')
}
foreach ($s in 'Hashtable', 'Generic.Dictionary', 'PSCustomObject') {
    foreach ($k in $raws.Keys) {
        $r = New-Report $s $true -UseRaw -RawDiscovery $raws[$k]
        $threw = $false
        $inc = $null
        try {
            $inc = [bool] (Test-mdiForestEnumerationIncomplete -ReportData $r)
            [void] (Test-mdiReadinessResult -ReportData $r)
        } catch { $threw = $true }
        Assert-That ("a {0} report with ForestDiscovery = {1} does not throw" -f $s, $k) (-not $threw)
        Assert-That ("a {0} report with ForestDiscovery = {1} is not charged incomplete" -f $s, $k) `
        ((-not $threw) -and ($inc -eq $false)) ("incomplete={0}" -f $inc)
    }
}

Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 }
