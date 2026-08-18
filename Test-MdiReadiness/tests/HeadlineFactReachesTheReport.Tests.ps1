<#
    The four machine-readable headline facts must actually reach the report, on every shape the
    report is held in.

    Set-mdiReportValue is the single publishing point for ChecksPassed, ChecksTotal, ChecksUnread and
    Readiness (Main, immediately before either JSON writer sees the report). Readiness is the field a
    pipeline gates a build on: it reads $true as "ready", $false as "prerequisites failed" and the
    string 'N/A' as "inconclusive, nothing proven wrong".

    The function exists because the report is not one shape. Main builds it as a HASHTABLE, where
    `$report.Name = value` quietly adds the key, while several tests execute a SLICE of the real Main
    block against a report they built as a [PSCustomObject], where that same statement throws
    "The property 'ChecksPassed' cannot be found on this object" - killing the file before a single
    assertion, so the suite recorded it as "no assertions" rather than as a failure. Assigning through
    this function is what makes the publishing step independent of which shape the caller holds.

    That contract had NO test of any kind: a coverage sweep over the product on 18 Aug found 177
    functions against 259 test files with exactly one function uncovered, and this was it. A silent
    regression here does not look like a crash - it looks like a report whose Readiness field is
    absent or stale, which a consumer cannot distinguish from a run that never got that far.

    Pinned here: a fact published onto a hashtable, a PSCustomObject and an ordered dictionary is
    readable back off that same object; republishing REPLACES a previously published value rather
    than leaving the earlier run's verdict in place; the tri-state string 'N/A' survives intact and is
    not coerced to a boolean; and an unreadable value ($null, '', a non-numeric string, a wrong type)
    is stored as given without throwing, so a value that was never measured cannot end the run and
    cannot come back looking like a measurement.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = [IO.Path]::GetFullPath($target)
$text = [IO.File]::ReadAllText($target)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main')
if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body

$script:passed = 0
$script:failed = 0
$script:warnings = New-Object System.Collections.ArrayList
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:passed++
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray
    } else {
        $script:failed++
        Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red
    }
}
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value {
    param($Message)
    [void] $script:warnings.Add([string] $Message)
}

# Read a published fact the way a JSON writer does: off the object the caller is holding. A key that
# was never written and a key written as $null are reported differently, because "absent" and
# "published as nothing" are different failures.
function Get-PublishedValue {
    param($Report, [string] $Name)
    if ($null -eq $Report) { return '<null-report>' }
    if ($Report -is [System.Collections.IDictionary]) {
        if ($Report.Contains($Name)) { return $Report[$Name] }
        return '<absent>'
    }
    $property = $Report.PSObject.Properties[$Name]
    if ($null -eq $property) { return '<absent>' }
    $property.Value
}
function Test-IsPublished {
    param($Report, [string] $Name)
    $value = Get-PublishedValue -Report $Report -Name $Name
    return ([string] $value -ne '<absent>')
}

# The published names are the real ones, so a rename in Main cannot leave this test pinning a field
# nobody writes any more.
$script:headlineFacts = @('ChecksPassed', 'ChecksTotal', 'ChecksUnread', 'Readiness')

Write-Host '--- every headline fact reaches a HASHTABLE report (the shape Main builds) ---'
$hashReport = @{ Domain = 'mdilab.local' }
foreach ($fact in $script:headlineFacts) {
    Set-mdiReportValue -Report $hashReport -Name $fact -Value 7
}
foreach ($fact in $script:headlineFacts) {
    Assert-True ("hashtable: {0} is published" -f $fact) (
        (Get-PublishedValue -Report $hashReport -Name $fact) -eq 7
    ) ("got={0}" -f (Get-PublishedValue -Report $hashReport -Name $fact))
}
Assert-True 'hashtable: publishing does not disturb an unrelated existing key' (
    $hashReport['Domain'] -eq 'mdilab.local'
) ("Domain={0}" -f $hashReport['Domain'])

Write-Host '--- every headline fact reaches a PSCustomObject report (the slice-of-Main shape) ---'
$objectReport = [PSCustomObject]@{ Domain = 'mdilab.local' }
foreach ($fact in $script:headlineFacts) {
    Set-mdiReportValue -Report $objectReport -Name $fact -Value 7
}
foreach ($fact in $script:headlineFacts) {
    Assert-True ("PSCustomObject: {0} is published" -f $fact) (
        (Get-PublishedValue -Report $objectReport -Name $fact) -eq 7
    ) ("got={0}" -f (Get-PublishedValue -Report $objectReport -Name $fact))
}
Assert-True 'PSCustomObject: publishing does not disturb an unrelated existing property' (
    $objectReport.Domain -eq 'mdilab.local'
) ("Domain={0}" -f $objectReport.Domain)

Write-Host '--- publishing onto a PSCustomObject does not throw (the failure this function exists for) ---'
$threw = $null
try {
    $sliceReport = [PSCustomObject]@{ Domain = 'mdilab.local' }
    Set-mdiReportValue -Report $sliceReport -Name 'ChecksPassed' -Value 3
} catch {
    $threw = $_.Exception.Message
}
Assert-True 'a PSCustomObject report is published without an exception' ($null -eq $threw) ("threw={0}" -f $threw)

Write-Host '--- an ordered dictionary is a dictionary, not an object ---'
$orderedReport = [ordered]@{ Domain = 'mdilab.local' }
Set-mdiReportValue -Report $orderedReport -Name 'Readiness' -Value 'N/A'
Assert-True 'ordered dictionary: the fact is published' (
    [string] (Get-PublishedValue -Report $orderedReport -Name 'Readiness') -eq 'N/A'
) ("got={0}" -f (Get-PublishedValue -Report $orderedReport -Name 'Readiness'))

Write-Host '--- republishing REPLACES: a stale verdict must not survive a recomputation ---'
$staleHash = @{ Readiness = $true; ChecksPassed = 99 }
Set-mdiReportValue -Report $staleHash -Name 'Readiness' -Value 'N/A'
Set-mdiReportValue -Report $staleHash -Name 'ChecksPassed' -Value 0
Assert-True 'hashtable: a previously published Readiness is replaced' (
    [string] (Get-PublishedValue -Report $staleHash -Name 'Readiness') -eq 'N/A'
) ("got={0}" -f (Get-PublishedValue -Report $staleHash -Name 'Readiness'))
Assert-True 'hashtable: a previously published count is replaced, including by zero' (
    (Get-PublishedValue -Report $staleHash -Name 'ChecksPassed') -eq 0
) ("got={0}" -f (Get-PublishedValue -Report $staleHash -Name 'ChecksPassed'))

$staleObject = [PSCustomObject]@{ Readiness = $true; ChecksPassed = 99 }
Set-mdiReportValue -Report $staleObject -Name 'Readiness' -Value 'N/A'
Set-mdiReportValue -Report $staleObject -Name 'ChecksPassed' -Value 0
Assert-True 'PSCustomObject: a previously published Readiness is replaced' (
    [string] (Get-PublishedValue -Report $staleObject -Name 'Readiness') -eq 'N/A'
) ("got={0}" -f (Get-PublishedValue -Report $staleObject -Name 'Readiness'))
Assert-True 'PSCustomObject: a previously published count is replaced, including by zero' (
    (Get-PublishedValue -Report $staleObject -Name 'ChecksPassed') -eq 0
) ("got={0}" -f (Get-PublishedValue -Report $staleObject -Name 'ChecksPassed'))

Write-Host '--- the tri-state survives: N/A stays the string N/A and is not coerced to a boolean ---'
foreach ($shape in @(
        @{ Label = 'hashtable'; Report = @{} },
        @{ Label = 'PSCustomObject'; Report = [PSCustomObject]@{} }
    )) {
    Set-mdiReportValue -Report $shape.Report -Name 'Readiness' -Value 'N/A'
    $published = Get-PublishedValue -Report $shape.Report -Name 'Readiness'
    Assert-True ("{0}: 'N/A' is published as the string 'N/A'" -f $shape.Label) (
        $published -is [string] -and $published -eq 'N/A'
    ) ("type={0} value={1}" -f $published.GetType().Name, $published)
}

Write-Host '--- a real boolean verdict stays a boolean ---'
foreach ($verdict in @($true, $false)) {
    $boolReport = @{}
    Set-mdiReportValue -Report $boolReport -Name 'Readiness' -Value $verdict
    $published = Get-PublishedValue -Report $boolReport -Name 'Readiness'
    Assert-True ("a {0} verdict is published as a boolean" -f $verdict) (
        $published -is [bool] -and $published -eq $verdict
    ) ("type={0} value={1}" -f $published.GetType().Name, $published)
}

Write-Host '--- an unreadable value is stored as given, never thrown and never invented ---'
foreach ($case in @(
        @{ Label = '$null'; Value = $null },
        @{ Label = 'empty string'; Value = '' },
        @{ Label = 'a non-numeric string'; Value = 'not-a-number' },
        @{ Label = 'a wrong type (array)'; Value = @(1, 2, 3) }
    )) {
    foreach ($shape in @(
            @{ Label = 'hashtable'; Report = @{} },
            @{ Label = 'PSCustomObject'; Report = [PSCustomObject]@{} }
        )) {
        $publishError = $null
        try {
            Set-mdiReportValue -Report $shape.Report -Name 'ChecksTotal' -Value $case.Value
        } catch {
            $publishError = $_.Exception.Message
        }
        Assert-True ("{0}: {1} does not end the run" -f $shape.Label, $case.Label) ($null -eq $publishError) ("threw={0}" -f $publishError)
        # The key must EXIST. A publishing step that silently skipped an unreadable value would leave
        # the field absent, which a consumer reads as "this run never got that far" rather than as
        # "this run could not measure it".
        Assert-True ("{0}: {1} is still published rather than skipped" -f $shape.Label, $case.Label) (
            Test-IsPublished -Report $shape.Report -Name 'ChecksTotal'
        ) 'the key was absent'
    }
}

Write-Host '--- an unreadable value is not silently promoted into a number ---'
$junkReport = @{}
Set-mdiReportValue -Report $junkReport -Name 'ChecksTotal' -Value 'not-a-number'
$junk = Get-PublishedValue -Report $junkReport -Name 'ChecksTotal'
Assert-True 'a non-numeric count is published unchanged, not coerced to 0' (
    $junk -is [string] -and $junk -eq 'not-a-number'
) ("type={0} value={1}" -f $junk.GetType().Name, $junk)

$nullReport = @{}
Set-mdiReportValue -Report $nullReport -Name 'ChecksTotal' -Value $null
Assert-True 'a $null count is published as $null, not as 0' (
    $null -eq (Get-PublishedValue -Report $nullReport -Name 'ChecksTotal')
) ("got={0}" -f (Get-PublishedValue -Report $nullReport -Name 'ChecksTotal'))

Write-Host '--- control: publishing raises no operator-facing warning ---'
Assert-True 'control: no warning was written while publishing' ($script:warnings.Count -eq 0) (
    "Warnings={0}" -f ($script:warnings -join ' | ')
)

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
