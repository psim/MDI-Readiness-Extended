<#
    THE DEFECT THIS TEST PINS

    A caller-supplied server list that named NOTHING made the scanner skip discovery and then check
    nothing, in complete silence.

    Three role scanners each decide whether to auto-discover their servers or to trust a list the
    caller passed in:

        Get-mdiDomainControllerReadiness   -DomainController
        Get-mdiCAReadiness                 -CAServer
        Get-mdiEntraConnectReadiness       -EntraConnectServer

    All three asked the same question:

        if ([string]::IsNullOrEmpty($DomainController)) { ...discover... } else { ...trust it... }

    Every one of those parameters is declared [string[]]. [string]::IsNullOrEmpty takes a [string],
    so passing the array forces an ARRAY-TO-STRING coercion, which joins the elements with $OFS - a
    space. The question that actually got asked was therefore not "is the list empty" but "is the
    list, JOINED WITH SPACES, an empty string".

    Two blank entries join to a single space. A space is not empty. So:

        @('','')      -> ' '    IsNullOrEmpty=False   -> discovery SKIPPED
        @($null,$null)-> ' '    IsNullOrEmpty=False   -> discovery SKIPPED
        @(' ',' ')    -> '   '  IsNullOrEmpty=False   -> discovery SKIPPED
        ' '           -> ' '    IsNullOrEmpty=False   -> discovery SKIPPED

    while the one blank shape anybody would think to try by hand behaves correctly, which is why
    this survived:

        @('')         -> ''     IsNullOrEmpty=True    -> discovery ran

    The branch that was skipped is the ONLY one that reports the loss. In
    Get-mdiDomainControllerReadiness it is the sole source of

        'Unable to enumerate the domain controllers of {0} ...'
        'No domain controller was checked. ...'

    and in the other two it is where $caNotMeasured and $entraConnectNotMeasured are set, which are
    what produce the 'AD CS (not enumerated)' and 'Entra Connect (not enumerated)' placeholder rows
    that charge the role as unread instead of rendering it as "nothing here to check".

    One step after the branch, every blank is dropped:

        $DomainController = @($DomainController | ForEach-Object { ConvertTo-mdiCanonicalComputerName ... }
                              | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } ...)

    so the list became empty IMMEDIATELY AFTER the only code that would have said so. The run then
    iterated an empty list and produced a report of nothing - with no warning, no unmeasured
    population, and no placeholder row.

    That is precisely the outcome Get-mdiDomainControllerReadiness's own comment says must be
    impossible: "A discovery failure is fatal to the whole report: every later check runs per server,
    so an empty list silently produces a clean-looking report of nothing. It is raised rather than
    swallowed so the run cannot be mistaken for a completed scan."

    Measured on the shipped functions with -DomainController @('',''): discovered=False,
    namesAfter=0, and neither warning raised. This is the project's recurring family wearing a new
    hat - a value that was never read (no server was ever named) coming back looking like a
    measurement (a completed scan of an estate).

    A list carrying blanks ALONGSIDE a real name was never affected and must not change: @('','dc1')
    names a server, and the caller's list is rightly trusted.

    THE FIX

    Test-mdiNoNameSupplied asks the question the branch actually needs - "did the caller name a
    server?" - per ELEMENT, with IsNullOrWhiteSpace, never on the joined text and never on array
    length. @('') and @($null) are lists that exist and name nothing.

    WHAT MUST NOT REGRESS IN THE OTHER DIRECTION

    A real caller-supplied list must still suppress auto-discovery. If this predicate ever returns
    $true for a list containing a usable name, every explicit -DomainController / -CAServer /
    -EntraConnectServer run would silently ignore the operator and re-discover the estate instead,
    which is the same class of "the tool did something other than what it reported" defect pointed
    the other way.

    KNOWN RESIDUAL, deliberately not claimed as fixed here: @('.') is a non-whitespace string, so the
    caller did name something; it simply canonicalises to nothing. That is the unreadable-name family
    rather than the empty-list one, and it is left for its own fix rather than silently folded in.
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

Write-Host 'A list that names nothing must route to discovery'

# The parameter typing is reproduced exactly, because the coercion IS the defect: a [string[]]
# parameter is what turns @('','') into the single space that defeated IsNullOrEmpty. Asserting
# against a bare array would test a shape the product never sees and would pass with the bug present.
function Invoke-Guard {
    param ([Parameter(Mandatory = $false)] [string[]] $List = $null)
    Test-mdiNoNameSupplied -Name $List
}

$namesNothing = @(
    @{ L = '$null';           V = $null }
    @{ L = '@()';             V = @() }
    @{ L = "@('')";           V = @('') }
    @{ L = "@('','')";        V = @('', '') }
    @{ L = "@(`$null,`$null)"; V = @($null, $null) }
    @{ L = "' ' (one space)"; V = @(' ') }
    @{ L = "@(' ',' ')";      V = @(' ', ' ') }
    @{ L = "@('','','')";     V = @('', '', '') }
    @{ L = "@(`"`t`")";        V = @("`t") }
)
foreach ($c in $namesNothing) {
    Assert-True ("a list that names nothing routes to discovery: {0}" -f $c.L) `
        (Invoke-Guard -List $c.V) `
        'the caller named no server, so the discovery branch - the only one that reports the loss - must run'
}

Write-Host ''
Write-Host 'A list that names a server must suppress discovery'

$namesSomething = @(
    @{ L = "@('dc2022.mdilab.local')";      V = @('dc2022.mdilab.local') }
    @{ L = "@('dc1','dc2')";                V = @('dc1', 'dc2') }
    @{ L = "@('','dc2022.mdilab.local')";   V = @('', 'dc2022.mdilab.local') }
    @{ L = "@('dcfab01.fabrikam.local')";   V = @('dcfab01.fabrikam.local') }
    @{ L = "@(' ','memfab01')";             V = @(' ', 'memfab01') }
)
foreach ($c in $namesSomething) {
    Assert-True ("a list that names a server is trusted: {0}" -f $c.L) `
        (-not (Invoke-Guard -List $c.V)) `
        'the operator named a server and must not be silently overridden by auto-discovery'
}

Write-Host ''
Write-Host 'The coercion that caused it is pinned directly'

# Pinned explicitly so the ROOT CAUSE cannot quietly return by someone "simplifying" the predicate
# back to a test on the joined text. These are facts about PowerShell, not about the product, and
# they are what make IsNullOrEmpty the wrong question for a [string[]].
Assert-True 'two blank entries join to a space, which is NOT IsNullOrEmpty' `
    ((-not [string]::IsNullOrEmpty([string] ([string[]] @('', '')))) -and
        [string]::IsNullOrWhiteSpace([string] ([string[]] @('', '')))) `
    'if this ever fails the coercion changed and the header needs revisiting'

Assert-True 'the predicate does not merely re-test the joined text' `
    (Invoke-Guard -List @('', '')) `
    'joined text is a space and passes IsNullOrEmpty; only a per-element test gets this right'

Write-Host ''
Write-Host ("pass={0}  fail={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
