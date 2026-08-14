# [w103] The Entra Connect sync-account description parser must not return the NOUN.
#
# The description is matched against a list of patterns, first match wins. The GENERIC catch-alls
# ("running on <token>") were listed BEFORE the specific ones ("on computer <NAME>"), and on
# Microsoft's own canonical English description:
#
#   "Account created by Microsoft Entra Connect with installation identifier <id> running on computer
#    AADC01 configured to synchronize to tenant contoso.onmicrosoft.com."
#
# the generic pattern matched first and captured the literal word "computer". The loop broke, so the
# 'on computer (...)' pattern - written for exactly this string - was never reached. The script then
# asked the directory for a computer named "computer", found nothing, verified ZERO Entra Connect
# servers, and told the operator this "can happen when the account description is in a non-English
# locale" - about an English description on an English directory.
#
# Two guards, because either alone would have prevented it:
#   * the specific patterns run FIRST;
#   * a capture that is one of the nouns the description uses to introduce the name is rejected, so
#     re-ordering the list again cannot bring the defect back.
#
# The English-only policy is deliberate and must survive: a localised description is routed to the
# not-measured path rather than risking a tenant name being mistaken for a server name.
#
# MUTATION NOTE. The two guards are defence in depth, so each one ALONE is an equivalent mutant that
# this file cannot kill, and that is correct rather than a gap:
#   * re-ordering the list back (generic first) while the noun guard stays -> still resolves AADC01,
#     because the guard rejects the noun capture and the loop continues to the specific pattern;
#   * removing the noun guard while the specific patterns stay first -> still resolves AADC01,
#     because 'on computer (...)' matches before any generic pattern is tried.
# Defeating BOTH reproduces the shipped defect and this file goes red on it: verified by putting
# 'running on? ?(...)\s' first and neutering the noun list, which fails four cases here with
# "got 'computer'". Note also that of the two generic patterns only the '\s' one is dangerous - the
# '\s+configured' variant is anchored by the trailing word and captures AADC01 correctly - so a
# mutation that promotes the wrong generic pattern will survive and prove nothing.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$fullText = Get-Content -LiteralPath $target -Raw

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The parser lives inside Get-mdiEntraConnectReadiness, which needs a live directory. The pattern
# list and the noun guard are lifted out of the SHIPPED source and executed here, so this asserts on
# the behaviour of the real list rather than on a copy that could drift. If the shape changes so the
# list can no longer be located, that is a failure, not a silent pass.
$block = [regex]::Match($fullText,
    '(?s)\$descriptionNoun\s*=\s*@\((?<nouns>[^)]*)\).*?foreach \(\$pattern in (?<patterns>.*?)\) \{')
Assert-That 'the shipped pattern list and noun guard were located in the source' ($block.Success) `
    '(the parser shape changed - re-point this test at it rather than deleting the case)'
if (-not $block.Success) { "EntraSyncAccountNameParsing: $script:pass passed, $script:fail failed"; exit 1 }

$nouns = @([regex]::Matches($block.Groups['nouns'].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
$patterns = @([regex]::Matches($block.Groups['patterns'].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
Assert-That 'the pattern list is non-empty' ($patterns.Count -ge 2) "($($patterns.Count) pattern(s))"
Assert-That "the noun guard names 'computer'" ($nouns -contains 'computer') "(nouns: $($nouns -join ', '))"

# Exactly the shipped loop.
function Resolve-Name {
    param([string] $Description)
    foreach ($p in $patterns) {
        $m = [regex]::Match($Description, $p)
        if ($m.Success -and $m.Groups[1].Value -and $m.Groups[1].Value -notin $nouns) { return $m.Groups[1].Value }
    }
    ''
}

'[w103] every English wording Microsoft ships resolves to the SERVER, never to a noun'
$english = @(
    @{ N = 'current Entra Connect build'; D = 'Account created by Microsoft Entra Connect with installation identifier 8f9e0d1c2b3a running on computer AADC01 configured to synchronize to tenant contoso.onmicrosoft.com.' }
    @{ N = 'legacy Azure AD Sync build'; D = 'Account created by the Windows Azure Active Directory Sync tool with installation identifier 8f9e0d1c2b3a running on computer AADC01 configured to synchronize to tenant contoso.onmicrosoft.com.' }
    @{ N = 'no "computer" noun'; D = 'Account created by Microsoft Entra Connect with installation identifier abc running on AADC01 configured to synchronize to tenant contoso.onmicrosoft.com.' }
    @{ N = 'build that drops the n of "on"'; D = 'Account created by Microsoft Entra Connect with installation identifier abc running oAADC01 configured to synchronize to tenant contoso.onmicrosoft.com.' }
    @{ N = 'older "installed on" wording'; D = 'Account created by the Directory Sync tool, installed on AADC01.' }
    @{ N = 'short "on computer" wording'; D = 'Sync account on computer AADC01 for tenant contoso.onmicrosoft.com.' }
)
foreach ($case in $english) {
    $got = Resolve-Name -Description $case.D
    Assert-That "  $($case.N) -> AADC01" ($got -eq 'AADC01') "(got '$got')"
}

'[w103] the noun is never returned as a server name'
foreach ($noun in $nouns) {
    $got = Resolve-Name -Description ("Account created by Microsoft Entra Connect with installation identifier abc running on $noun AADC01 configured to synchronize to tenant contoso.onmicrosoft.com.")
    Assert-That "  '$noun' is rejected as a name" ($got -ne $noun) "(got '$got')"
}

'[w103] a tenant name is never mistaken for a server'
foreach ($case in $english) {
    $got = Resolve-Name -Description $case.D
    Assert-That "  $($case.N) does not return the tenant" ($got -notmatch 'contoso|onmicrosoft') "(got '$got')"
}

'[w103] control: the English-only policy still holds'
# A localised description must NOT parse. Guessing here risks assessing the wrong machine, so the
# not-measured path (a placeholder row, an unread charge and a warning) is the correct outcome.
$german = 'Konto, das von Microsoft Entra Connect mit der Installations-ID abc erstellt wurde und auf Computer AADC01 konfiguriert ist.'
Assert-That 'a German description still does not parse' ((Resolve-Name -Description $german) -eq '') `
    "(got '$(Resolve-Name -Description $german)')"
$french = "Compte cree par Microsoft Entra Connect avec l'identificateur abc execute sur l'ordinateur AADC01."
Assert-That 'a French description still does not parse' ((Resolve-Name -Description $french) -eq '') `
    "(got '$(Resolve-Name -Description $french)')"

'[w103] control: a server genuinely named like a noun is still found'
# The guard is a closed list of introducing nouns, not a heuristic, so a real host whose name merely
# CONTAINS one must still resolve.
Assert-That 'SERVER01 resolves' `
    ((Resolve-Name -Description 'Account created by Microsoft Entra Connect with installation identifier abc running on computer SERVER01 configured to synchronize.') -eq 'SERVER01') `
    "(got '$(Resolve-Name -Description 'Account created by Microsoft Entra Connect with installation identifier abc running on computer SERVER01 configured to synchronize.')')"

''
"EntraSyncAccountNameParsing: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
