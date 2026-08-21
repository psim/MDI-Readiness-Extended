<#
    [w142] The domain-scope resolver guarded the RENDERING of the directory's answer, not the answer.

    Resolve-mdiDomainScopeDnsName turns a NetBIOS -Domain into its DNS name. Its own header is strict
    about why the acceptance rule is narrow: "this value becomes the report identity, the output file
    name and the key every later comparison is made against."

    It is narrower than it looks, because BOTH readers stringify before the rule ever runs:

        Read = { ([string] (Get-ADDomain -Server $requested).DNSRoot) }
        Read = { ([string] (...GetDomain($context)).Name) }

    So $isUsable never sees the directory's answer - it sees a STRING RENDERED FROM IT. A format
    string has no opinion about what it was given, and .NET renders a type name when it has nothing
    better, so:

        DNSRoot = @{}      -> 'System.Collections.Hashtable'   letters and dots, matches the DNS
                                                               regex, carries a dot, is not an IP
        DNSRoot = 1.5      -> '1.5'                            digits and a dot, same
        DNSRoot = 12345    -> '12345'                          REFUSED already, by the separate rule
                                                               that a dotless answer must equal the
                                                               request - which is exactly why fixing
                                                               only the dotless case would not fix
                                                               this one

    WHAT THAT COSTS, and it is not confined to a label. The resolved name is assigned straight back
    into the run-wide $Domain, which then feeds the JSON report name, the HTML report name, the
    BASELINE FILE NAME, and every subsequent LDAP:// bind. A run that resolves to a different string
    writes and reads a DIFFERENT baseline file, so the trend silently compares against nothing.

    THE FIX PINNED HERE: require the answer to BE a string, before it is rendered as one. Both
    readers hand back the raw value and $isUsable refuses anything that is not [string]. A refusal is
    cheap and already well-defined - the reader falls through to the next one, and if none answers
    usably the operator's own spelling is kept, which is the documented behaviour whenever the
    directory cannot be asked.

    NO PROVEN ARRIVAL VECTOR, stated plainly rather than dressed up: both shipped readers return
    values AD types as strings, so no live run is known to produce these shapes. This is hardening of
    a value with an outsized blast radius, ruled in deliberately, not a defect with a field report.

    Run under Windows PowerShell 5.1.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path -LiteralPath $target)) {
    $parent = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
    if (Test-Path -LiteralPath $parent) { $target = $parent }
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

# NOSUCHDOM deliberately: the DC-locator fallback must FAIL, so that what this test measures is
# purely whether $isUsable accepted the ADWS answer. A name that resolves in the lab - FABCORP does -
# would let the locator answer correctly and mask the whole question.
$requestedName = 'NOSUCHDOM'
$script:answer = $null
function Get-ADDomain {
    param($Server, $ErrorAction)
    [PSCustomObject]@{ DNSRoot = $script:answer }
}

# Each case: the value the directory hands back, and what the scope must be afterwards.
# 'KEEP' means the operator's own spelling survives - the documented answer when nothing usable came
# back. Anything else is the DNS name that must be adopted.
$cases = @(
    @{ n = 'a real DNS name';                v = 'fabrikam.local';                     want = 'fabrikam.local' }
    @{ n = 'the request itself (1-label)';   v = $requestedName;                       want = $requestedName }
    @{ n = 'a hashtable';                    v = @{};                                  want = 'KEEP' }
    @{ n = 'a double 1.5';                   v = [double] 1.5;                         want = 'KEEP' }
    @{ n = 'an int 12345';                   v = 12345;                                want = 'KEEP' }
    @{ n = 'an array of two names';          v = @('a.b', 'c.d');                      want = 'KEEP' }
    @{ n = 'a PSObject';                     v = ([PSCustomObject]@{ X = 1 });          want = 'KEEP' }
    @{ n = 'a datetime';                     v = ([datetime]'2026-08-21');             want = 'KEEP' }
    @{ n = 'a scriptblock';                  v = { 'evil.local' };                     want = 'KEEP' }
    @{ n = 'null';                           v = $null;                                want = 'KEEP' }
    @{ n = 'an empty string';                v = '';                                   want = 'KEEP' }
    @{ n = 'an IP address string';           v = '10.0.0.1';                           want = 'KEEP' }
)

"`n[1] The directory's answer is accepted only when it IS a name, not when it RENDERS as one"
foreach ($c in $cases) {
    $script:answer = $c.v
    $got = $null; $threw = $null
    try { $got = Resolve-mdiDomainScopeDnsName -DomainName $requestedName } catch { $threw = $_.Exception.Message }
    $expected = if ($c.want -eq 'KEEP') { $requestedName } else { $c.want }
    Assert-That "survives: $($c.n)" ($null -eq $threw) "(threw: $threw)"
    if ($null -ne $threw) { continue }
    Assert-That "  scope is '$expected': $($c.n)" ($got -eq $expected) "(got '$got')"
    Assert-That "  no type name leaked into the scope: $($c.n)" `
        (([string] $got) -notmatch 'System\.|PSCustomObject|ScriptBlock') "(got '$got')"
}

"`n[2] CONTROLS - the paths that must not move"
$script:answer = 'fabrikam.local'
$fqdn = Resolve-mdiDomainScopeDnsName -DomainName 'already.qualified.local'
Assert-That 'an FQDN request is returned untouched, without asking the directory' `
    ($fqdn -eq 'already.qualified.local') "(got '$fqdn')"
$blank = Resolve-mdiDomainScopeDnsName -DomainName ''
Assert-That 'a blank request stays blank' ([string]::IsNullOrWhiteSpace($blank)) "(got '$blank')"

""
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
