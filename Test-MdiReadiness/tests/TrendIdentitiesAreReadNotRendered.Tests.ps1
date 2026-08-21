# THE TREND SUBSYSTEM READ ITS IDENTITIES WITH A BARE CAST, SO VALUES NOBODY READ BECAME NAMES
#
# Two places, one root cause. Both decide what the trend chart is allowed to claim, and both read an
# identity with [string], which tests the RENDERING and not the value. .NET prints a TYPE NAME when
# it has nothing better, so every unreadable value renders NON-BLANK and survives a truthiness test.
# This file had already replaced exactly that pattern twice - Get-mdiServerIdentityKey and
# Get-mdiProbeRecordTargetKey both say "[string] tests the RENDERING, not the value" and both moved
# onto ConvertTo-mdiReadableDomainName, which tests the TYPE.
#
# 1. Get-mdiBaselineHistory, the ServerNames fingerprint:
#
#        ServerNames = @($Statistics.Servers | ForEach-Object { [string] $_.FQDN } |
#                        Where-Object { $_ } | Sort-Object)
#
#    Measured on the shipped function, one row's FQDN replaced one shape at a time. The second
#    column is what THIS FILE'S OWN identity reader makes of the very same row:
#
#        hashtable         -> recorded "System.Collections.Hashtable"   identity reader: unreadable
#        two-element array -> recorded "dcfab01 memfab01"               identity reader: unreadable
#        boolean true      -> recorded "True"                           identity reader: unreadable
#        number 12345      -> recorded "12345"                          identity reader: unreadable
#        PSCustomObject    -> recorded "@{name=memfab01}"               identity reader: unreadable
#        whitespace '   '  -> recorded "   "                            identity reader: unreadable
#
#    So two readers of "which machine is this" disagreed. This is the worse of the two places for
#    that, because the value is PERSISTED: the function's own header says twice that the history "is
#    written permanently and is what gets reported upward", and the baseline JSON on disk really did
#    contain the string System.Collections.Hashtable. It is also ordinary cross-forest rather than
#    contrived - over a forest trust the caller is a foreign principal and dNSHostName is not in the
#    partial attribute set a global catalog replicates, so rows genuinely arrive unnamed.
#
# 2. Test-mdiTrendPointsComparable, the estate identity and the scanner version:
#
#        $estateName      = { param($p) ([string] $p).Trim().TrimEnd('.') }
#        $previousVersion = ([string] $Previous.ScriptVersion).Trim()
#
#    An unreadable identity was treated as a NAME rather than as "not recorded", so it compared
#    UNEQUAL to a real name and REFUSED a comparison the design intends to allow - the guard
#    deliberately falls through when either side recorded nothing, so that a history written before
#    these fields existed still works. The operator-facing sentence was the real cost, verbatim:
#
#        "the baseline is from a different domain (System.Collections.Hashtable then fabrikam.local)"
#
#    and that message exists, by its own comment, to tell the reader the baseline "belongs to
#    somebody else's estate and should be removed from this folder" - so it named a .NET type as a
#    domain and advised deleting a file on that basis.
#
# WHAT THIS TEST DELIBERATELY DOES NOT ASSERT, because it was measured and is NOT a defect:
#   * Two runs whose estate identity is unreadable ON BOTH SIDES are comparable. That is the SAME
#     outcome the design already intends for "both absent", and it is not a false green: the
#     ServerNames fingerprint independently refuses two genuinely different estates. The test below
#     PINS that backstop so a future fix cannot weaken it.
#   * An unreadable FQDN still makes two runs of one estate incomparable (2 names vs 1). That is
#     honest - if a server's name could not be read the tool does not know it measured the same
#     estate. The fabrication was the defect, not the refusal.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
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

function New-Stats {
    param($Servers)
    [PSCustomObject]@{
        CheckTotals    = @{ 'Sensor version' = 1; 'Time sync' = 1 }
        Servers        = @($Servers)
        ServerScores   = @($Servers | ForEach-Object { [PSCustomObject]@{ FQDN = $_.FQDN; Passed = 2; Total = 2; Failed = 0; Unread = 0 } })
        ChecksPassed   = 4; ChecksTotal = 4; ChecksUnread = 0
        TotalServers   = @($Servers).Count
        PortsOpen      = 2; PortsTotal = 2
        NnrResolvable  = 2; NnrTargetCount = 2
        V3Ready        = 2; V3Evaluated = 2; V3Unevaluated = 0
    }
}
function New-Row { param($Fqdn) [PSCustomObject]@{ FQDN = $Fqdn; Domain = 'fabrikam.local' } }

$root = Join-Path ([IO.Path]::GetTempPath()) ('trendid-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $root -Force | Out-Null
$n = 0
function Get-Entry {
    param($Servers)
    $script:n++
    $dir = Join-Path $root ('e' + $script:n)
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $h = Get-mdiBaselineHistory -BaselinePath $dir -Domain 'fabrikam.local' -Forest 'fabrikam.local' -Statistics (New-Stats -Servers $Servers)
    [PSCustomObject]@{ Entry = $h.Current; Path = $h.Path }
}

try {
    ''
    '[the defect, part 1] an unreadable FQDN must not be persisted as a server name'
    $shapes = [ordered]@{
        'hashtable'         = @{}
        'two-element array' = @('dcfab01', 'memfab01')
        'boolean'           = $true
        'number'            = 12345
        'PSCustomObject'    = ([PSCustomObject]@{ name = 'memfab01' })
        'whitespace'        = '   '
    }
    foreach ($k in $shapes.Keys) {
        $r = Get-Entry -Servers @((New-Row 'dcfab01.fabrikam.local'), (New-Row $shapes[$k]))
        $names = @($r.Entry.ServerNames)
        Assert-That "an unreadable FQDN ($k) is not recorded as a server name" `
        ($names.Count -eq 1 -and $names[0] -eq 'dcfab01.fabrikam.local') "recorded: $($names -join ' | ')"
        # PERSISTED is the point - assert it is not on DISK either, not merely absent in memory.
        $raw = Get-Content -LiteralPath $r.Path -Raw
        Assert-That "an unreadable FQDN ($k) reaches the baseline file on disk" `
        (-not ($raw -match 'System\.Collections\.Hashtable') -and -not ($raw -match '@\{name=')) 'a rendered object is in the JSON'
    }
    # The reader must agree with the file's own identity reader about every one of those rows.
    foreach ($k in $shapes.Keys) {
        $key = Get-mdiServerIdentityKey -Server ([PSCustomObject]@{ FQDN = $shapes[$k]; Domain = 'fabrikam.local' })
        Assert-That "the identity reader also calls ($k) unreadable, so the two agree" ([string]::IsNullOrEmpty($key)) "key=$key"
    }

    ''
    '[unchanged] readable names must be recorded exactly as before'
    $ok = Get-Entry -Servers @((New-Row 'dcfab01.fabrikam.local'), (New-Row 'memfab01.fabrikam.local'))
    Assert-That 'both readable names are recorded' (@($ok.Entry.ServerNames).Count -eq 2) "got $(@($ok.Entry.ServerNames) -join ' | ')"
    Assert-That 'readable names keep their exact spelling' ($ok.Entry.ServerNames -contains 'dcfab01.fabrikam.local') "got $(@($ok.Entry.ServerNames) -join ' | ')"
    # A one-element collection is legitimately unwrapped everywhere else in this file, so it must be here too.
    $unwrap = Get-Entry -Servers @((New-Row 'dcfab01.fabrikam.local'), (New-Row @('memfab01.fabrikam.local')))
    Assert-That 'a one-element array FQDN is still unwrapped and recorded' `
    (@($unwrap.Entry.ServerNames).Count -eq 2 -and $unwrap.Entry.ServerNames -contains 'memfab01.fabrikam.local') "got $(@($unwrap.Entry.ServerNames) -join ' | ')"
    # CASE must not be normalised: doing so would rewrite ServerNames for every existing baseline
    # and make every stored history incomparable with the next run.
    $case = Get-Entry -Servers @((New-Row 'DCFAB01.FABRIKAM.LOCAL'))
    Assert-That 'the recorded name is NOT lowercased (existing baselines must stay comparable)' `
    ($case.Entry.ServerNames -contains 'DCFAB01.FABRIKAM.LOCAL') "got $(@($case.Entry.ServerNames) -join ' | ')"

    ''
    '[the defect, part 2] an unreadable estate identity must fall through, not refuse'
    function New-Run {
        param($Domain = 'fabrikam.local', $Forest = 'fabrikam.local', $Version = '1.2.0', $Servers = @('dcfab01.fabrikam.local', 'memfab01.fabrikam.local'))
        [PSCustomObject]@{
            ScriptVersion = $Version; Domain = $Domain; Forest = $Forest
            CheckNames = @('Sensor version', 'Time sync'); ServerNames = @($Servers)
            ChecksPassed = 3; ChecksTotal = 4; ChecksUnread = 0
        }
    }
    foreach ($k in @('hashtable', 'two-element array', 'boolean', 'number', 'PSCustomObject')) {
        $r = Test-mdiTrendPointsComparable -Previous (New-Run -Domain $shapes[$k]) -Current (New-Run)
        Assert-That "an unreadable Domain ($k) falls through instead of refusing" ($r.IsComparable -eq $true) "reason: $($r.Reason)"
        $rf = Test-mdiTrendPointsComparable -Previous (New-Run -Forest $shapes[$k]) -Current (New-Run)
        Assert-That "an unreadable Forest ($k) falls through instead of refusing" ($rf.IsComparable -eq $true) "reason: $($rf.Reason)"
    }
    # THE VERSION AXIS IS DELIBERATELY ASYMMETRIC WITH THE ESTATE AXIS, and this block pins the
    # difference so nobody "tidies" the two into one rule.
    #
    # For the ESTATE, falling through is safe: the ServerNames fingerprint still refuses two
    # different estates (pinned at the end of this file), so nothing can be compared across
    # customers. For the VERSION there is no such backstop - the version guard is the ONLY thing
    # stopping two runs made by different builds being compared, and its own comment says why that
    # matters: "Every fix in this project that corrected a false green moved a check from passing to
    # failing, so the version guard is what stops those corrections from being read as a regression
    # the customer caused." Falling through on an unreadable version therefore means ASSUMING the
    # builds match, which is the loose direction.
    #
    # So only a NON-SCALAR - a value that cannot be a version at all and whose only crime is
    # rendering as a type name in the operator's message - falls through. A scalar that is merely
    # WRONG ('True', '12345') is still refused, because it is a version this run cannot vouch for.
    foreach ($k in @('hashtable', 'two-element array', 'PSCustomObject')) {
        $rv = Test-mdiTrendPointsComparable -Previous (New-Run -Version $shapes[$k]) -Current (New-Run)
        Assert-That "a non-scalar ScriptVersion ($k) falls through instead of naming a type" ($rv.IsComparable -eq $true) "reason: $($rv.Reason)"
    }
    foreach ($k in @('boolean', 'number')) {
        $rv = Test-mdiTrendPointsComparable -Previous (New-Run -Version $shapes[$k]) -Current (New-Run)
        Assert-That "a scalar but nonsense ScriptVersion ($k) is still REFUSED (the safe direction)" ($rv.IsComparable -eq $false) "reason: $($rv.Reason)"
    }
    # No refusal message may ever present a rendered .NET object to the operator as a domain.
    $msg = (Test-mdiTrendPointsComparable -Previous (New-Run -Domain @{}) -Current (New-Run)).Reason
    Assert-That 'no refusal names a .NET type as a domain' `
    (-not ([string] $msg -match 'System\.Collections\.|@\{')) "reason: $msg"

    ''
    '[unchanged] the real comparability rules must all still work'
    Assert-That 'a genuinely identical estate is still comparable' `
    ((Test-mdiTrendPointsComparable -Previous (New-Run) -Current (New-Run)).IsComparable -eq $true) ''
    Assert-That 'a genuinely different domain is still refused' `
    ((Test-mdiTrendPointsComparable -Previous (New-Run -Domain 'mdilab.local') -Current (New-Run)).IsComparable -eq $false) ''
    Assert-That 'a genuinely different forest is still refused' `
    ((Test-mdiTrendPointsComparable -Previous (New-Run -Forest 'mdilab.local') -Current (New-Run)).IsComparable -eq $false) ''
    Assert-That 'a genuine version change is still refused' `
    ((Test-mdiTrendPointsComparable -Previous (New-Run -Version '1.1.5') -Current (New-Run)).IsComparable -eq $false) ''
    Assert-That 'case and a trailing dot are still ONE estate' `
    ((Test-mdiTrendPointsComparable -Previous (New-Run -Domain 'FABRIKAM.LOCAL.' -Forest 'FABRIKAM.LOCAL.') -Current (New-Run)).IsComparable -eq $true) ''
    foreach ($blank in @($null, '', '   ')) {
        Assert-That "a history that recorded no domain still falls through ('$blank')" `
        ((Test-mdiTrendPointsComparable -Previous (New-Run -Domain $blank) -Current (New-Run)).IsComparable -eq $true) ''
    }

    ''
    '[the backstop] the fingerprint must STILL refuse two genuinely different estates'
    # This is what makes the fall-through above safe. If a future change weakens it, an unreadable
    # estate identity really would let a delta be drawn across a stranger's estate.
    foreach ($k in @('hashtable', 'boolean', 'number')) {
        $r = Test-mdiTrendPointsComparable `
            -Previous (New-Run -Domain $shapes[$k] -Servers @('dc1.contoso.com', 'dc2.contoso.com')) `
            -Current (New-Run -Domain $shapes[$k])
        Assert-That "two DIFFERENT estates with an unreadable Domain ($k) are still refused" `
        ($r.IsComparable -eq $false) "reason: $($r.Reason)"
    }

    ''
    "pass=$script:pass  fail=$script:fail"
    if ($script:fail -gt 0) { exit 1 } else { exit 0 }
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
