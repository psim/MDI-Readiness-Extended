<#
    [w217] A record entry was silently dropped, and the WRONG value kept under the surviving name.

    ConvertTo-mdiRecordObject copies any IDictionary into `$bag = [ordered]@{}`. That bag is
    CASE-INSENSITIVE in PowerShell. The source need not be: a Generic.Dictionary[string,object] built
    with an ORDINAL comparer legitimately holds 'Requirement' and 'requirement' as two entries.
    Copying both into a case-insensitive bag collapses them, the LAST one enumerated wins, and the
    surviving property keeps the FIRST key's spelling with the SECOND key's value.

    MEASURED on the shipped function, source holding Requirement='Required' and requirement='Optional':

        source entries        4
        converted properties  3            <- one entry gone
        surviving VALUE       Optional     <- the wrong one
        warnings raised       0            <- nothing for a caller to notice

    Property access in PowerShell is case-insensitive, so a consumer reading .Requirement gets
    'Optional'. A REQUIRED port measured as refused therefore reads as OPTIONAL, which is word for
    word what this function's own header warns about: "A required port measured as refused then
    arrives with no Requirement, so it is not counted as a required failure and the server stays in
    the ready count." A false green, the class this project rates worst.

    REACHABILITY, stated honestly: nothing in this script produces the trigger. Its own hashtables
    are case-insensitive and cannot hold both spellings, and ConvertFrom-Json yields a PSCustomObject
    which never enters the dictionary branch at all. It needs a third-party producer that used an
    ordinal-comparer dictionary AND two case-differing spellings of one field. The function's header
    explicitly contemplates foreign input - "the shape that reaches here comes from whatever produced
    the report, not from this script" - which is why it is worth closing rather than dismissing.

    THE FIX FOLLOWS THIS FUNCTION'S OWN PRECEDENT, and deliberately not the obvious alternative.
    The function already handles "a name that cannot be represented as a property" by carrying it
    under a prefixed name rather than dropping it:

        if ($name -in @('PSObject','PSBase',...)) { $bag['_' + $name] = $entry.Value; continue }

    A colliding key is carried the same way. GIVING THE BAG AN ORDINAL COMPARER WOULD NOT WORK: it
    preserves both entries but produces a PSCustomObject with two properties differing only in case,
    and since property access is case-insensitive the consumer would still get an arbitrary one. The
    loss would move, not go away. That is asserted below so the wrong fix cannot be substituted.

    Run under Windows PowerShell 5.1.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path -LiteralPath $target)) {
    $parent = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
    if (Test-Path -LiteralPath $parent) { $target = $parent }
}
if (-not (Test-Path -LiteralPath $target)) {
    $staged = Join-Path (Split-Path (Split-Path $here -Parent) -Parent) 'MDI-Repo\Test-MdiReadiness\Test-MdiReadiness.ps1'
    if (Test-Path -LiteralPath $staged) { $target = $staged }
}
if (-not (Test-Path -LiteralPath $target)) { Write-Host 'FAIL  the product script could not be located'; exit 1 }

$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-OrdinalRecord {
    # The shape the defect needs, and it is a legitimate one: an ordinal comparer really does keep
    # both spellings as separate entries.
    $d = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $d.Add('Port', 389)
    $d.Add('Requirement', 'Required')
    $d.Add('requirement', 'Optional')
    $d.Add('Success', $false)
    $d
}

"`n[0] PRECONDITION - the source really does hold both spellings"
$src = New-OrdinalRecord
Assert-That 'the ordinal dictionary holds 4 entries including both spellings' ($src.Count -eq 4) "(count=$($src.Count))"

"`n[1] THE DEFECT - no entry may be lost, and the surviving name must keep its OWN value"
$o = ConvertTo-mdiRecordObject -Value $src
$props = @($o.PSObject.Properties | ForEach-Object { $_.Name })
Assert-That 'every source entry survives the conversion' ($props.Count -eq 4) "(props=$($props -join ', '))"
# The first spelling keeps its own value. Which of two case-variants is "right" is unknowable, so
# the rule is the one that cannot silently mislead: the name and the value must belong together.
Assert-That "the value under .Requirement is the one that was recorded as 'Requirement'" `
($o.Requirement -eq 'Required') "(got '$($o.Requirement)')"
Assert-That 'the colliding entry is carried, not discarded' `
(($props | Where-Object { $_ -like '*requirement*' -and $_ -ne 'Requirement' }).Count -ge 1) "(props=$($props -join ', '))"
$carried = @($props | Where-Object { $_ -like '_*' })
if ($carried.Count -ge 1) {
    Assert-That "  ...and carries the OTHER value ('Optional')" `
    (@($carried | Where-Object { $o.$_ -eq 'Optional' }).Count -ge 1) "(carried=$($carried -join ', '))"
}

"`n[2] THE WRONG FIX IS EXCLUDED - two properties differing only in case would not help"
# If the bag were merely given an ordinal comparer, both entries would survive but the object would
# carry 'Requirement' and 'requirement' as two properties. Property access is case-insensitive, so
# the consumer would still get an arbitrary one and the loss would simply move.
$caseOnlyPairs = @($props | Where-Object { $p = $_; @($props | Where-Object { $_ -ne $p -and $_.ToLowerInvariant() -eq $p.ToLowerInvariant() }).Count -gt 0 })
Assert-That 'no two properties differ only in case' ($caseOnlyPairs.Count -eq 0) "(offenders=$($caseOnlyPairs -join ', '))"

"`n[3] CONTROLS - the job this function already did must be untouched"
$plain = @{ Port = 389; Requirement = 'Required'; Success = $false; Detail = 'Open' }
$po = ConvertTo-mdiRecordObject -Value $plain
Assert-That 'an ordinary hashtable keeps all four entries' (@($po.PSObject.Properties).Count -eq 4)
Assert-That '  ...with the right values' ($po.Requirement -eq 'Required' -and $po.Port -eq 389)
$gd = New-Object 'System.Collections.Generic.Dictionary[string,object]'
$gd.Add('Port', 636); $gd.Add('Requirement', 'Required'); $gd.Add('Success', $true); $gd.Add('Detail', 'Open')
$go = ConvertTo-mdiRecordObject -Value $gd
Assert-That 'the Generic.Dictionary this function exists for is still unwrapped' `
($go.Port -eq 636 -and $go.Requirement -eq 'Required' -and $go.Detail -eq 'Open') "(props=$(@($go.PSObject.Properties | ForEach-Object { $_.Name }) -join ', '))"
Assert-That 'a non-dictionary is returned unchanged' ((ConvertTo-mdiRecordObject -Value 'plain string') -eq 'plain string')
Assert-That 'null stays null' ($null -eq (ConvertTo-mdiRecordObject -Value $null))

"`n[4] THE RESERVED-NAME PRECEDENT this fix is modelled on still works"
$reserved = @{ PSObject = 'x'; Port = 389 }
$ro = ConvertTo-mdiRecordObject -Value $reserved
Assert-That 'a reserved name is still carried under a prefix rather than throwing' `
(@($ro.PSObject.Properties | ForEach-Object { $_.Name }) -contains '_PSObject') `
"(props=$(@($ro.PSObject.Properties | ForEach-Object { $_.Name }) -join ', '))"

"`n[5] NOTHING MAY THROW - one odd record must not cost the whole report"
foreach ($odd in @(
        @{ '' = 'empty key'; Port = 1 },
        @{ '   ' = 'whitespace key'; Port = 2 }
    )) {
    $threw = $false
    try { [void] (ConvertTo-mdiRecordObject -Value $odd) } catch { $threw = $true }
    Assert-That 'an odd key shape does not throw' (-not $threw)
}

""
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
