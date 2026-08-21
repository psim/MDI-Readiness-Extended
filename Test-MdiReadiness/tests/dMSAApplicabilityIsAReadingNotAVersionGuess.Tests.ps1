# DEFECT PINNED: a schema-version number was allowed to OVERRULE a reading, not merely to stand in
# for a missing one.
#
# Get-mdiObjectAuditing decides whether the delegated Managed Service Account audit entry applies by
# looking for the ms-DS-Delegated-Managed-Service-Account CLASS in the schema, and keeps the answer
# as a deliberate TRI-STATE: $true = the class is there, $false = it is not, $null = the question
# could not be asked. The file says so in its own words - "$null means 'applicability could not be
# determined', which is NOT the same as 'the class is absent'".
#
# The domain schema version is documented one comment further down as a FALLBACK, existing only
# "for the case where the schema itself could not be read, so behaviour never becomes worse than it
# was". A fallback is consulted when the primary reading is ABSENT. The shipped condition was
#
#     if ($dmsaPresent -ne $true -and $DomainSchemaVersion -ge 90) { $dmsaPresent = $true }
#
# and `-ne $true` is satisfied by $false exactly as much as by $null. So a directory that was asked,
# and answered that the class is NOT present, had that answer discarded and replaced with $true the
# moment the forest reported schema version 90 or 91. The very next branch asks the question the
# right way round - `$null -eq $dmsaPresent` - which is what made the first one visibly a slip
# rather than a decision.
#
# Measured on the shipped text before the fix, running those lines verbatim out of the product file:
#
#     dmsaPresent   DomainSchemaVersion   resolved to
#     ----------------------------------------------
#     $null          0                    unknown -> N/A          correct
#     $null          88                   class ABSENT            correct (fallback)
#     $null          90 / 91              class PRESENT           correct (fallback - the case it exists for)
#     $false         0 / 88               class ABSENT            correct
#     $false         90 / 91              class PRESENT           WRONG - the reading was overruled
#
# What the false verdict costs: $expectedAuditing only DROPS the dMSA ACE while $dmsaPresent is
# falsy. Forced to $true, the requirement stays in the expected set, so a domain that genuinely does
# not carry the class is charged with failing an auditing requirement it cannot satisfy - the file
# names that exact harm two comments earlier, "guessing wrong in the permissive direction tells an
# administrator to add an audit entry for an object class their directory does not have, which
# cannot be applied". It is a false RED no administrator can clear.
#
# Why it survived to now: it needs a directory that reports schema 90/91 AND answers "no such
# object" for the class. A single-forest run, where one account reads both the version and the
# class, does not produce that pair. A CROSS-FOREST bind does: rootDSE and the forest schema version
# are broadly readable over a trust, while ::Exists() against the class object returns a plain
# $false - not an exception - when the bind is refused or the object is not replicated on the
# contacted DC. fabrikam.local, reached over the bidirectional trust from mdilab.local, is precisely
# that shape.
#
# THE FIX: the first branch asks $null -eq $dmsaPresent, like the second. A reading wins; the
# version is consulted only when there is no reading. This test fails if `-ne $true` ever returns.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The decision lives inside a function whose inputs come from an [adsi] cast and a static
# ::Exists() call, neither of which can be shadowed the way a cmdlet can. So the shipped LINES are
# located by content and executed verbatim. Retyping the condition here would test only that this
# file agrees with itself, which is precisely the failure mode a regression test must not have.
$lines = Get-Content -LiteralPath $target
$anchor = -1
for ($n = 0; $n -lt $lines.Count; $n++) {
    if ($lines[$n] -match '\$DomainSchemaVersion\s+-ge\s+90') { $anchor = $n; break }
}
Assert-That 'the dMSA applicability decision is still present in the product' ($anchor -ge 0) '(anchor not found)'
if ($anchor -lt 0) {
    "================ $script:pass passed / $script:fail failed ================"
    exit 1
}

$sliceLines = @(); $depth = 0; $started = $false
for ($n = $anchor; $n -lt [Math]::Min($anchor + 20, $lines.Count); $n++) {
    $sliceLines += $lines[$n]
    $depth += ([regex]::Matches($lines[$n], '\{')).Count - ([regex]::Matches($lines[$n], '\}')).Count
    if (([regex]::Matches($lines[$n], '\{')).Count -gt 0) { $started = $true }
    if ($started -and $depth -le 0 -and (($sliceLines -join "`n") -match 'if \(\$null -eq \$dmsaPresent\)')) { break }
}
$slice = $sliceLines -join "`n"

Assert-That 'the slice carries both branches and the tri-state gate' (
    ($slice -match '\$DomainSchemaVersion\s+-ge\s+90') -and
    ($slice -match '\$DomainSchemaVersion\s+-gt\s+0') -and
    ($slice -match 'if \(\$null -eq \$dmsaPresent\)')) '(extraction drifted)'

$decide = [scriptblock]::Create(@"
param(`$dmsaPresent, [int] `$DomainSchemaVersion)
$slice
[PSCustomObject]@{ Resolved = `$dmsaPresent }
"@)

function Get-Applicability {
    param($Present, [int] $Version)
    $r = @(& $decide $Present $Version)[-1]
    if ($r -is [hashtable]) { return 'unknown' }
    if ($r.Resolved) { return 'present' }
    return 'absent'
}

'[dMSA applicability] a reading is not overruled by a version number'

# THE DEFECT ITSELF. Both 90 and 91 are quoted as the Windows Server 2025 schema version, and the
# product comment records this forest reporting 91, so both are pinned.
Assert-That 'a MEASURED absent class stays absent at schema 90' (
    (Get-Applicability -Present $false -Version 90) -eq 'absent') "(got $(Get-Applicability -Present $false -Version 90))"
Assert-That 'a MEASURED absent class stays absent at schema 91' (
    (Get-Applicability -Present $false -Version 91) -eq 'absent') "(got $(Get-Applicability -Present $false -Version 91))"

# The fallback must still do the job it was added for, or the fix would be a removal.
Assert-That 'an UNREAD class resolves to present at schema 90' (
    (Get-Applicability -Present $null -Version 90) -eq 'present') "(got $(Get-Applicability -Present $null -Version 90))"
Assert-That 'an UNREAD class resolves to present at schema 91' (
    (Get-Applicability -Present $null -Version 91) -eq 'present') "(got $(Get-Applicability -Present $null -Version 91))"
Assert-That 'an UNREAD class resolves to absent at a known pre-2025 schema 88' (
    (Get-Applicability -Present $null -Version 88) -eq 'absent') "(got $(Get-Applicability -Present $null -Version 88))"

# A version that was never read cannot decide anything in either direction. This is the property the
# whole project is built on and it must not regress alongside the fix.
Assert-That 'neither source readable leaves applicability unknown, not guessed' (
    (Get-Applicability -Present $null -Version 0) -eq 'unknown') "(got $(Get-Applicability -Present $null -Version 0))"

# Measurements survive in both directions and at every version.
Assert-That 'a MEASURED present class stays present with no version read' (
    (Get-Applicability -Present $true -Version 0) -eq 'present') "(got $(Get-Applicability -Present $true -Version 0))"
Assert-That 'a MEASURED present class stays present at schema 91' (
    (Get-Applicability -Present $true -Version 91) -eq 'present') "(got $(Get-Applicability -Present $true -Version 91))"
Assert-That 'a MEASURED absent class stays absent with no version read' (
    (Get-Applicability -Present $false -Version 0) -eq 'absent') "(got $(Get-Applicability -Present $false -Version 0))"
Assert-That 'a MEASURED absent class stays absent at schema 88' (
    (Get-Applicability -Present $false -Version 88) -eq 'absent') "(got $(Get-Applicability -Present $false -Version 88))"

# The shape of the fix, stated directly: the version branch must test for a MISSING reading, never
# for "not true". This is what goes red the moment `-ne $true` comes back.
Assert-That 'the version branch tests for an ABSENT reading, not for "not true"' (
    $slice -notmatch '\$dmsaPresent\s+-ne\s+\$true') '(the -ne $true spelling is back in the product)'

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
