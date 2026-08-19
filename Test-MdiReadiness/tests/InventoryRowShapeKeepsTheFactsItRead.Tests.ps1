<#
    A server inventory row written as a dictionary must not lose the facts that WERE read - starting
    with the host's own name.

    THE DEFECT THIS PINS. The server table in Set-MdiReadinessReport fills every cell that is not a
    readiness check straight off the row:

        $value = $srv.PSObject.Properties[$p]
        if ($null -eq $value) { $null } else { $value.Value }

    PSObject.Properties over an IDictionary enumerates the DICTIONARY'S OWN .NET MEMBERS - Count,
    Keys, Values, SyncRoot, IsReadOnly, IsFixedSize, IsSynchronized - and never its entries. The CHECK
    columns survive on their own, because Get-mdiEffectiveCheckProperty and Get-mdiUnreadCheckName
    both normalise; the DESCRIPTIVE ones (FQDN, SensorVersion, CapturingComponent, MachineType,
    Comment) had nothing between them and the raw row.

    Measured end to end on the shipped function - Set-MdiReadinessReport called for real and the
    generated HTML read back - with one cross-forest domain controller written both ways and nothing
    else differing, counting how often each fact reaches the report:

        row shape            FQDN   SensorVersion   CapturingComponent   MachineType
        PSCustomObject         3          1                 2                  1
        Hashtable              2          0                 1                  0
        OrderedDictionary      2          0                 1                  0
        Generic.Dictionary     2          0                 1                  0

    So the inventory row lost the host's NAME, its sensor version, its capture driver and its
    platform. This is the same straightforward data loss the function's own comment already names -
    "an estate where every check failed to read lost the facts that had been read successfully" -
    arriving through the row's SHAPE rather than through the branch that was fixed for it.

    A cross-forest estate is where the shape stops being hypothetical: -MultiForest assembles a second
    forest's results, and a report round-tripped through -AsJson or produced by another tool hands the
    rows back as dictionaries.

    THE FIX. The rows are normalised through ConvertTo-mdiRecordObject as they enter the table
    builder, which is the normaliser this script already applies to the port records, the merged
    server rows, the forest discovery record, the domain check results and the sensor v3.x check rows
    for the identical reason. Normalising at the entry point also makes the column discovery, the sort
    and the cells all read the same object.

    Pinned here, END TO END through the real report writer:

    1. On every IDictionary shape the row keeps its FQDN, SensorVersion, CapturingComponent and
       MachineType, exactly as the object shape does.
    2. The readiness checks on the row keep their verdicts on every shape - a measured failure is
       still present - so the fix cannot have bought the columns back by flattening the checks.
    3. An 'N/A' descriptive value still renders as "Not tested" and is NOT turned into a positive
       claim, on every shape: a value nobody could read must not come back looking like a measurement.
    4. Object-shaped rows are unchanged.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Set-MdiReadinessReport') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
$text = $text -replace '(?m)^\s*#Requires.*$', ''
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

$shapes = @('PSCustomObject', 'Hashtable', 'OrderedDictionary', 'Generic.Dictionary')

function New-ServerRow {
    param([string] $Shape, [string] $SensorVersion = '2.250.0.0')
    $f = [ordered]@{
        FQDN               = 'dcfab01.fabrikam.local'
        Domain             = 'fabrikam.local'
        IP                 = '10.10.1.50'
        Addresses          = @('10.10.1.50')
        MachineType        = 'Physical'
        OS                 = 'Windows Server 2025'
        SensorVersion      = $SensorVersion
        CapturingComponent = 'Npcap'
        Comment            = ''
        AdvancedAuditing   = $false
        PowerSettings      = $true
    }
    switch ($Shape) {
        'PSCustomObject' { return [PSCustomObject] $f }
        'Hashtable' { $h = @{}; foreach ($k in $f.Keys) { $h[$k] = $f[$k] }; return $h }
        'OrderedDictionary' { return $f }
        'Generic.Dictionary' {
            $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'
            foreach ($k in $f.Keys) { $d[[string] $k] = $f[$k] }
            return $d
        }
    }
    throw "unknown shape $Shape"
}

# The real report writer, on a cross-forest domain, with the HTML read back off disk.
function Get-ReportHtml {
    param($Row)
    $out = Join-Path ([IO.Path]::GetTempPath()) ("mdi-invrow-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    try {
        $data = [PSCustomObject]@{
            Domain              = 'fabrikam.local'
            Domains             = @('fabrikam.local')
            DomainsInScope      = @('fabrikam.local')
            DomainControllers   = @($Row)
            CAServers           = @()
            EntraConnectServers = @()
            DomainAuditing      = @()
        }
        Set-MdiReadinessReport -Domain 'fabrikam.local' -Path $out -ReportData @($data) -SkipTrend | Out-Null
        $file = Get-ChildItem $out -Filter '*.html' | Select-Object -First 1
        if (-not $file) { return '' }
        return (Get-Content -LiteralPath $file.FullName -Raw)
    } finally {
        Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Measure-Fact {
    param([string] $Html, [string] $Pattern)
    @(($Html -split "`r?`n") | Where-Object { $_ -match $Pattern }).Count
}

''
'--- 1  the facts that WERE read survive on every row shape ---'
$baseline = $null
foreach ($shape in $shapes) {
    $html = Get-ReportHtml (New-ServerRow -Shape $shape)
    $counts = [PSCustomObject]@{
        Name    = Measure-Fact -Html $html -Pattern 'dcfab01\.fabrikam\.local'
        Sensor  = Measure-Fact -Html $html -Pattern '2\.250\.0\.0'
        Capture = Measure-Fact -Html $html -Pattern 'Npcap'
        Machine = Measure-Fact -Html $html -Pattern 'Physical'
    }
    if ($shape -eq 'PSCustomObject') { $baseline = $counts }

    Assert-That "$shape : the host still has a NAME in the report" ($counts.Name -ge 1) "got $($counts.Name)"
    Assert-That "$shape : the sensor version survives" ($counts.Sensor -ge 1) "got $($counts.Sensor)"
    Assert-That "$shape : the capture driver survives" ($counts.Capture -ge 1) "got $($counts.Capture)"
    Assert-That "$shape : the machine type survives" ($counts.Machine -ge 1) "got $($counts.Machine)"
    Assert-That "$shape : every descriptive fact reaches the report as often as on an object row" `
    ($counts.Name -eq $baseline.Name -and $counts.Sensor -eq $baseline.Sensor -and
        $counts.Capture -eq $baseline.Capture -and $counts.Machine -eq $baseline.Machine) `
        "object=[$($baseline.Name),$($baseline.Sensor),$($baseline.Capture),$($baseline.Machine)] this=[$($counts.Name),$($counts.Sensor),$($counts.Capture),$($counts.Machine)]"

    Assert-That "$shape : the row's measured FAILURE is still on the page" `
    ([bool] ($html -match 'Advanced Auditing')) 'the failing check vanished from the table'
}

''
'--- 2  an unread descriptive value is not turned into a positive claim, on any shape ---'
foreach ($shape in $shapes) {
    $html = Get-ReportHtml (New-ServerRow -Shape $shape -SensorVersion 'N/A')
    Assert-That "$shape : SensorVersion = 'N/A' is rendered as Not tested" `
    ([bool] ($html -match 'Not tested')) 'an unread value lost its "could not be read" rendering'
    Assert-That "$shape : SensorVersion = 'N/A' does not become 'Not installed'" `
    (-not ($html -match 'Not installed')) 'an unread value became a positive claim'
}

''
"RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
