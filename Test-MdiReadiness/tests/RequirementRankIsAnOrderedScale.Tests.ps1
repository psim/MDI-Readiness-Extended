<#
    Requirement strength is a RANK, not a string comparison, and an unrecognised value must lose.

    Get-mdiRequirementRank exists so that two roles describing the same probe differently merge to
    the STRONGER obligation instead of to whichever was read first. Merge-mdiPortRecord consults it
    at two tie-breaks: when two records carry equal evidence it keeps the one whose Requirement
    ranks higher, and only when the ranks are equal too does it fall back to an ordinal comparison
    of the Detail text. If this function ranked wrongly, a probe that one role calls 'Required' and
    another calls 'Optional' would settle on whichever the discovery order happened to present
    first - and a REQUIRED port failure that must block the verdict would silently become optional.

    No defect was found in this function. It is pinned because nothing named it before, and because
    the scale it implements is load-bearing for the merge above it.

    Pinned here:

    1. The documented scale: Required and All are both 3, AtLeastOne is 2, Recommended is 1,
       Optional is 0. Required and All must be EQUAL - they are two spellings of "every one must
       pass" - and AtLeastOne must sit strictly between Recommended and Required, which is what
       makes the NNR group's "one of these must succeed" weaker than a hard requirement but
       stronger than advice.
    2. Matching is case-insensitive, which is what `switch` on a string does by default. A role
       spelling it 'required' must not be demoted to 0. Replacing the switch with a case-sensitive
       comparison turns this red.
    3. An unreadable or unrecognised value ranks 0 - BELOW every real one, so it can never win a
       tie by accident. $null, the empty string and an unknown word are all 0. This is the
       function's own stated contract: "an unrecognised value must sort BELOW a real one rather
       than winning by accident".
    4. The ordering itself is asserted as a chain rather than only as fixed numbers, so a future
       rescale that keeps the ordering stays green while one that inverts it goes red.

    Deliberately NOT pinned: whitespace-padded spellings such as ' Required' rank 0, which would be
    a demotion if it could happen. It cannot. Every Requirement value in this script is a hard-coded
    object literal (Requirement = 'Required') in the port definition table, not text parsed out of a
    CSV or read from the directory, so no padded value can reach here. Asserting the padded case
    either way would freeze behaviour that has no caller and invite a "fix" for a defect that does
    not exist.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiRequirementRank') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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
function Rank { param($Value) Get-mdiRequirementRank -Requirement $Value }

'1. The documented scale'
Assert-That "'Required' ranks 3"    ((Rank 'Required') -eq 3)    "got $(Rank 'Required')"
Assert-That "'All' ranks 3"         ((Rank 'All') -eq 3)         "got $(Rank 'All')"
Assert-That "'AtLeastOne' ranks 2"  ((Rank 'AtLeastOne') -eq 2)  "got $(Rank 'AtLeastOne')"
Assert-That "'Recommended' ranks 1" ((Rank 'Recommended') -eq 1) "got $(Rank 'Recommended')"
Assert-That "'Optional' ranks 0"    ((Rank 'Optional') -eq 0)    "got $(Rank 'Optional')"
Assert-That "'Required' and 'All' are the SAME strength" ((Rank 'Required') -eq (Rank 'All'))

'2. Matching is case-insensitive'
foreach ($v in 'required', 'REQUIRED', 'ReQuIrEd') {
    Assert-That "'$v' still ranks 3" ((Rank $v) -eq 3) "got $(Rank $v)"
}
Assert-That "'atleastone' still ranks 2" ((Rank 'atleastone') -eq 2) "got $(Rank 'atleastone')"
Assert-That "'RECOMMENDED' still ranks 1" ((Rank 'RECOMMENDED') -eq 1)

'3. Unreadable or unrecognised ranks 0, below every real value'
Assert-That 'a null Requirement ranks 0'  ((Rank $null) -eq 0)  "got $(Rank $null)"
Assert-That 'an empty string ranks 0'     ((Rank '') -eq 0)     "got $(Rank '')"
Assert-That 'whitespace ranks 0'          ((Rank '   ') -eq 0)
Assert-That 'an unknown word ranks 0'     ((Rank 'Nonsense') -eq 0)
Assert-That 'a bare number ranks 0'       ((Rank '3') -eq 0) "a numeric string must not be read as a rank"
Assert-That 'unrecognised never outranks Recommended, the weakest REAL obligation' `
    ((Rank 'Nonsense') -lt (Rank 'Recommended'))
Assert-That 'unrecognised never outranks Required' ((Rank $null) -lt (Rank 'Required'))

'4. The ordering is a strict chain'
Assert-That 'Required > AtLeastOne'    ((Rank 'Required') -gt (Rank 'AtLeastOne'))
Assert-That 'AtLeastOne > Recommended' ((Rank 'AtLeastOne') -gt (Rank 'Recommended'))
Assert-That 'Recommended > Optional'   ((Rank 'Recommended') -gt (Rank 'Optional'))
Assert-That 'Recommended > unrecognised' ((Rank 'Recommended') -gt (Rank 'Nonsense'))
Assert-That 'the rank is an integer, not a string' ((Rank 'Required') -is [int])

''
"PASS: $script:pass  FAIL: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
