<#
    A JSON collection field must be a JSON array whatever it contains.

    -AsJson exists so a pipeline can consume this report. A field whose SHAPE changes with its item
    count cannot be consumed: the operator's choice of -Skip switches decided whether SkippedAreas
    arrived as an empty object, a bare string, or an array.

        no -Skip switches   ->  "SkippedAreas": {}                    (the zero-output sentinel)
        one -Skip switch    ->  "SkippedAreas": "Network ports"       (a bare string)
        two or more         ->  "SkippedAreas": ["...","..."]         (an array)

    The cause is a pipeline written OUTSIDE the array subexpression, so @() captured the assignment
    rather than the filtered result. JavaScript .forEach throws on the first two, and no schema can
    describe the field as the collection its name promises.

    These tests assert the SERIALISED shape produced by the real ConvertTo-Json, because that is what
    a consumer sees. They do not inspect the script's source text, so restoring the misplaced pipeline
    turns them red.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# The SkippedAreas expression is lifted verbatim out of the shipped script and evaluated with the
# switches set, which is the only way to exercise every cardinality without running a whole scan.
# Extracting it by text would be a source-shape test; instead the expression is located by its
# assignment and executed, so it is the real code path that runs.
$startMarker = 'SkippedAreas           = '
$start = $text.IndexOf($startMarker)
if ($start -lt 0) { throw 'Could not locate the SkippedAreas assignment in the target script' }
$tail = $text.Substring($start + $startMarker.Length)
# Balance parentheses from the first one to find the whole expression.
$depth = 0
$end = -1
for ($i = 0; $i -lt $tail.Length; $i++) {
    $c = $tail[$i]
    if ($c -eq '(') { $depth++ }
    elseif ($c -eq ')') { $depth--; if ($depth -eq 0) { $end = $i; break } }
}
if ($end -lt 0) { throw 'Could not balance the SkippedAreas expression' }
# Continue past the closing parenthesis to the end of the logical line. The DEFECT lives in a trailing
# `| Where-Object { $_ }` that sits OUTSIDE the array subexpression, so stopping at the balanced paren
# would silently drop the very thing under test and the mutation would appear to change nothing.
$rest = $tail.Substring($end + 1)
$lineEnd = $rest.IndexOf("`n")
if ($lineEnd -lt 0) { $lineEnd = $rest.Length }
$expression = $tail.Substring(0, $end + 1) + $rest.Substring(0, $lineEnd)
$expression = $expression.TrimEnd()

function Get-SkippedJson {
    param([bool] $Ports, [bool] $CA, [bool] $Entra, [bool] $V3)
    $sb = [scriptblock]::Create(@"
param([bool] `$SkipNetworkPorts, [bool] `$SkipCA, [bool] `$SkipEntraConnect, [bool] `$SkipSensorV3Readiness)
[PSCustomObject]@{ SkippedAreas = $expression }
"@)
    $obj = & $sb $Ports $CA $Entra $V3
    # Depth 7 is what the shipped -AsJson path uses.
    $json = $obj | ConvertTo-Json -Depth 7
    ($json | ConvertFrom-Json).SkippedAreas
    # Also hand back the raw text so the shape can be asserted directly.
    , $json
}

Write-Host 'SkippedAreas is a JSON array at every cardinality' -ForegroundColor Cyan
$cases = @(
    @{ Name = 'no areas skipped'; P = $false; C = $false; E = $false; V = $false; Expect = 0 }
    @{ Name = 'exactly one area skipped'; P = $true; C = $false; E = $false; V = $false; Expect = 1 }
    @{ Name = 'two areas skipped'; P = $true; C = $true; E = $false; V = $false; Expect = 2 }
    @{ Name = 'every area skipped'; P = $true; C = $true; E = $true; V = $true; Expect = 4 }
)
foreach ($c in $cases) {
    $sb = [scriptblock]::Create(@"
param([bool] `$SkipNetworkPorts, [bool] `$SkipCA, [bool] `$SkipEntraConnect, [bool] `$SkipSensorV3Readiness)
[PSCustomObject]@{ SkippedAreas = $expression }
"@)
    $obj = & $sb $c.P $c.C $c.E $c.V
    $json = $obj | ConvertTo-Json -Depth 7
    $revived = ($json | ConvertFrom-Json).SkippedAreas

    # The serialised text must open with '[' - an object '{}' or a bare string both fail here.
    $serialised = ($json -replace '\s+', ' ')
    Assert-That "$($c.Name): serialises as a JSON array" ($serialised -match '"SkippedAreas"\s*:\s*\[') "got: $serialised"

    # And the revived value must behave like a collection for a consumer.
    $isCollection = $revived -is [System.Collections.IEnumerable] -and $revived -isnot [string]
    Assert-That "  ...and revives as a collection, not a string or an object" $isCollection `
        "got type $(if ($null -eq $revived) { '<null>' } else { $revived.GetType().FullName })"
    Assert-That "  ...with $($c.Expect) item(s)" (@($revived).Count -eq $c.Expect) "got $(@($revived).Count)"
}

Write-Host 'The contents are still correct, not merely well-shaped' -ForegroundColor Cyan
$sbOne = [scriptblock]::Create(@"
param([bool] `$SkipNetworkPorts, [bool] `$SkipCA, [bool] `$SkipEntraConnect, [bool] `$SkipSensorV3Readiness)
$expression
"@)
$one = @(& $sbOne $true $false $false $false)
Assert-That 'a single skip names the right area' ($one[0] -eq 'Network ports') "got '$($one[0])'"
$all = @(& $sbOne $true $true $true $true)
Assert-That 'every skip is listed' ($all.Count -eq 4) "got $($all.Count)"
Assert-That '  ...and none is blank' (@($all | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) "got: $($all -join ', ')"
$none = @(& $sbOne $false $false $false $false)
Assert-That 'no skips produces an empty list, not a list containing nothing' ($none.Count -eq 0) "got $($none.Count): $($none -join ', ')"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
