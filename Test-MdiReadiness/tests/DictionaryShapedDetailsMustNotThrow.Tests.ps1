<#
    THE DEFECT THIS TEST PINS

    A Details container shaped as a Generic.Dictionary made the shape-agnostic accessors THROW.

    Test-mdiDetailEntry and Get-mdiDetailValue exist for one reason: to answer "does this row carry
    this entry, and what is it" WHATEVER SHAPE the row has. Both proved the object was a dictionary
    with `-is [Collections.IDictionary]` and then called the bare `$Details.Contains($Name)`.

    PowerShell resolves that method against the object's OWN type, not against the interface the line
    above just proved it implements. Hashtable and OrderedDictionary publish the non-generic
    Contains(object), so they answered. Dictionary[string,object] publishes
    Contains(KeyValuePair[string,object]) and provides IDictionary.Contains(object) only as an
    EXPLICIT interface implementation, which method resolution does not see - so a [string] argument
    bound to no overload and the call threw:

        Cannot find an overload for "Contains" and the argument count: "1".

    Measured on the shipped accessors, the SAME entry present in every shape:

        shape                              Test-mdiDetailEntry   Get-mdiDetailValue
        Hashtable                          True                  x
        OrderedDictionary                  True                  x
        PSCustomObject                     True                  x
        Generic.Dictionary[string,object]  THREW                 THREW
        SortedDictionary[string,object]    THREW                 THREW

    The two shapes anybody would think to test are the two that work, which is why it survived. Its
    own siblings did not have it - Get-mdiDetailEntry, Set-mdiDetailEntry, Copy-mdiDetails and
    ConvertTo-mdiRecordObject all handled every dictionary shape - and three separate docstrings in
    the product assert in their measurement tables that Generic.Dictionary behaves "the same as
    Hashtable". ConvertTo-mdiRecordObject states the contract these accessors exist to keep: "the
    shape that reaches here comes from whatever produced the report, not from this script."

    WHY IT MATTERS MORE THAN A WRONG ANSWER. It is an EXCEPTION, not a bad value, and these
    accessors are called inside Where-Object filters and inside the per-server merge, where a throw
    does not produce a bad row - it aborts the pass. Get-mdiUnexaminedDomain asks Test-mdiDetailEntry
    of every server row to decide whether that row can speak about a domain at all, so on a
    dictionary-shaped inventory the throw lands in the COVERAGE comparison, which is the one place
    this tool must never stop measuring.

    Get-mdiV3ActionableBlocker took the same external shape and made the same bare call, so it is
    pinned here too.

    THE FIX is the cast to [Collections.IDictionary], which reaches the explicit implementation and
    answers on every IDictionary. The SortedDictionary, ListDictionary and HybridDictionary cases are
    included so a future "simplification" back to the bare call cannot pass by handling only the one
    shape this defect was found on.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$text = Get-Content -LiteralPath $target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main')
if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert ($Condition, $Message, $Got) {
    if ($Condition) { $script:pass++; Write-Host ("  PASS  {0}" -f $Message) }
    else { $script:fail++; Write-Host ("  FAIL  {0} got {1}" -f $Message, $Got) }
}

function New-Shape {
    param([string] $Kind, [string] $Key, $Value)
    switch ($Kind) {
        'Hashtable' { $d = @{}; $d[$Key] = $Value; return $d }
        'OrderedDictionary' { $d = [ordered]@{}; $d[$Key] = $Value; return $d }
        'Generic.Dictionary' { $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'; $d[$Key] = $Value; return $d }
        'SortedDictionary' { $d = New-Object 'System.Collections.Generic.SortedDictionary[string,object]'; $d[$Key] = $Value; return $d }
        'ListDictionary' { $d = New-Object System.Collections.Specialized.ListDictionary; $d[$Key] = $Value; return $d }
        'HybridDictionary' { $d = New-Object System.Collections.Specialized.HybridDictionary; $d[$Key] = $Value; return $d }
        'PSCustomObject' { return [PSCustomObject]@{ $Key = $Value } }
    }
    throw "unknown shape $Kind"
}

$shapes = @('Hashtable', 'OrderedDictionary', 'Generic.Dictionary', 'SortedDictionary',
    'ListDictionary', 'HybridDictionary', 'PSCustomObject')

Write-Host 'Every dictionary shape answers, and none of them throws'
foreach ($s in $shapes) {
    $d = New-Shape -Kind $s -Key 'RequiredPortsDetails' -Value 'measured'

    $threw = $false; $got = $null
    try { $got = Test-mdiDetailEntry -Details $d -Name 'RequiredPortsDetails' } catch { $threw = $true; $got = $_.Exception.Message }
    Assert (-not $threw) ("$s : Test-mdiDetailEntry does not throw for a present entry") $got
    Assert ($got -eq $true) ("$s : Test-mdiDetailEntry finds the present entry") $got

    $threw = $false; $got = $null
    try { $got = Test-mdiDetailEntry -Details $d -Name 'NotThere' } catch { $threw = $true; $got = $_.Exception.Message }
    Assert (-not $threw) ("$s : Test-mdiDetailEntry does not throw for an absent entry") $got
    Assert ($got -eq $false) ("$s : an absent entry is absent") $got

    $threw = $false; $got = $null
    try { $got = Get-mdiDetailValue -Details $d -Name 'RequiredPortsDetails' } catch { $threw = $true; $got = $_.Exception.Message }
    Assert (-not $threw) ("$s : Get-mdiDetailValue does not throw") $got
    Assert ($got -eq 'measured') ("$s : Get-mdiDetailValue returns the value") $got

    $threw = $false; $got = $null
    try { $got = Get-mdiDetailValue -Details $d -Name 'NotThere' } catch { $threw = $true; $got = $_.Exception.Message }
    Assert (-not $threw) ("$s : Get-mdiDetailValue does not throw for an absent entry") $got
    Assert ($null -eq $got) ("$s : an absent entry reads back as `$null") $got
}

Write-Host ''
Write-Host 'A dictionary-shaped server row does not abort the coverage comparison'
foreach ($s in @('Generic.Dictionary', 'SortedDictionary')) {
    # The row shape Get-mdiUnexaminedDomain asks Test-mdiDetailEntry about for every server.
    $row = New-Shape -Kind $s -Key 'Domain' -Value 'fabrikam.local'
    $threw = $false; $got = $null
    try {
        $got = @(Get-mdiUnexaminedDomain -ScopedDomain @('fabrikam.local') -Server @($row) -DomainControllerServer @($row))
    } catch { $threw = $true; $got = $_.Exception.Message }
    Assert (-not $threw) ("$s : a dictionary-shaped row does not throw the coverage comparison") $got
    Assert ((-not $threw) -and (@($got).Count -eq 0)) ("$s : a scanned domain is not charged as unexamined") (@($got) -join ',')
}

Write-Host ''
Write-Host 'Get-mdiV3ActionableBlocker took the same external shape and made the same bare call'
foreach ($s in $shapes) {
    $d = New-Shape -Kind $s -Key 'ActionableBlockers' -Value @('a blocker')
    $threw = $false; $got = $null
    try { $got = @(Get-mdiV3ActionableBlocker -Detail $d) } catch { $threw = $true; $got = $_.Exception.Message }
    Assert (-not $threw) ("$s : Get-mdiV3ActionableBlocker does not throw") $got
    Assert ((-not $threw) -and (@($got).Count -eq 1)) ("$s : the actionable blocker survives") (@($got) -join ',')
}

Write-Host ''
Write-Host 'A present-but-EMPTY entry is still told apart from an absent one on every shape'
foreach ($s in $shapes) {
    $d = New-Shape -Kind $s -Key 'ActionableBlockers' -Value @()
    $threw = $false; $got = $null
    try { $got = @(Get-mdiV3ActionableBlocker -Detail $d) } catch { $threw = $true; $got = $_.Exception.Message }
    Assert (-not $threw) ("$s : an empty ActionableBlockers does not throw") $got
    Assert ((-not $threw) -and (@($got).Count -eq 0)) ("$s : present-and-empty does not fall back to Blockers") (@($got) -join ',')
}

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
