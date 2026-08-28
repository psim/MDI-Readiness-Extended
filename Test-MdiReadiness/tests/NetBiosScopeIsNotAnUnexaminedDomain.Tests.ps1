<#
    [w210] A NetBIOS domain name the directory could not resolve was charged as an UNEXAMINED domain
    against an estate that had just been fully scanned.

    -Domain is documented as "Domain Name or FQDN", and the name a Windows dialog shows an
    administrator of a DISJOINT namespace is the NetBIOS one: DNS fabrikam.local, NetBIOS FABCORP.
    Resolve-mdiDomainScopeDnsName converts one to the other when it can, and DELIBERATELY keeps the
    operator's spelling when it cannot - "inventing a domain name nobody read would be a worse
    failure than the false red this removes".

    Both of its readers fail together on an ordinary host: no RSAT, or ADWS 9389 filtered AND the DC
    locator unreachable. That is the machine this tool documents itself as runnable from, before any
    sensor is installed. The scope then stays FABCORP while every scanned row says fabrikam.local.

    MEASURED on the shipped Get-mdiUnexaminedDomain:

        scope fabrikam.local, rows fabrikam.local   -> <none>            correct
        scope mdilab.local,   rows fabrikam.local   -> [mdilab.local]    correct, still charges
        scope FABCORP,        rows fabrikam.local   -> [FABCORP]         FALSE RED

    The third costs readiness on all three surfaces that share this definition - the statistics
    charge a domain-level unread check, the issue list raises a Discovery finding, and the verdict
    refuses READY - over a two-controller estate that was scanned end to end and passed.

    WHY THIS IS NOT "INVENTING A NAME". Nothing is written anywhere and no name is resolved; a
    finding is simply not raised. By the time this function runs the scanned rows already agree on
    exactly ONE readable DNS domain, so the scope is being read against the scan rather than against
    a directory that could not be asked.

    THE NARROWING IS THE SAFETY ARGUMENT, AND IT IS PINNED HERE. A dotless entry sitting BESIDE other
    scope entries says nothing about which domain the rows came from, so the rule fires only when
    there is exactly one scope entry and exactly one examined domain. Section [2] measures the shape
    that must keep charging - without it this fix would convert a false red into a FALSE GREEN, which
    this codebase rates strictly worse.

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

function New-Dc {
    param([string] $Fqdn, $Domain)
    [PSCustomObject]@{ FQDN = $Fqdn; Domain = $Domain; OperatingSystem = 'Windows Server 2022' }
}
function Get-Unexamined {
    param($Scope, $Dcs)
    @(Get-mdiUnexaminedDomain -ScopedDomain $Scope -Server $Dcs -DomainControllerServer $Dcs)
}

$fab = @((New-Dc 'dcfab01.fabrikam.local' 'fabrikam.local'), (New-Dc 'dcfab02.fabrikam.local' 'fabrikam.local'))

"`n[1] THE DEFECT - a single unresolved NetBIOS scope over one fully scanned domain"
$r = Get-Unexamined -Scope @('FABCORP') -Dcs $fab
Assert-That 'a NetBIOS scope over the domain that was scanned charges nothing' ($r.Count -eq 0) "(got: $($r -join ', '))"

"`n[2] THE NARROWING - the shape that must STILL charge, or this becomes a false green"
$r = Get-Unexamined -Scope @('FABCORP', 'mdilab.local') -Dcs $fab
Assert-That 'a dotless entry BESIDE another scope entry is still charged' `
(@($r | Where-Object { $_ -eq 'FABCORP' }).Count -eq 1) "(got: $($r -join ', '))"
Assert-That '  ...and so is the genuinely unscanned mdilab.local' `
(@($r | Where-Object { $_ -eq 'mdilab.local' }).Count -eq 1) "(got: $($r -join ', '))"

$twoDomains = @((New-Dc 'dcfab01.fabrikam.local' 'fabrikam.local'), (New-Dc 'dc1.mdilab.local' 'mdilab.local'))
$r = Get-Unexamined -Scope @('FABCORP') -Dcs $twoDomains
Assert-That 'a dotless scope over rows from TWO domains is still charged' `
(@($r | Where-Object { $_ -eq 'FABCORP' }).Count -eq 1) "(got: $($r -join ', '))"

$blankDomains = @((New-Dc 'dcfab01.fabrikam.local' ''), (New-Dc 'dcfab02.fabrikam.local' ''))
$r = Get-Unexamined -Scope @('FABCORP') -Dcs $blankDomains
Assert-That 'a dotless scope over rows that name NO domain is still charged' `
(@($r | Where-Object { $_ -eq 'FABCORP' }).Count -eq 1) "(got: $($r -join ', '))"

$unreadable = @((New-Dc 'dcfab01.fabrikam.local' @{ DnsRoot = 'fabrikam.local' }))
$r = Get-Unexamined -Scope @('FABCORP') -Dcs $unreadable
Assert-That 'a dotless scope over rows whose domain is UNREADABLE is still charged' `
(@($r | Where-Object { $_ -eq 'FABCORP' }).Count -eq 1) "(got: $($r -join ', '))"

"`n[3] CONTROLS - the answers that must not move"
$r = Get-Unexamined -Scope @('fabrikam.local') -Dcs $fab
Assert-That 'a matching FQDN scope charges nothing' ($r.Count -eq 0) "(got: $($r -join ', '))"
$r = Get-Unexamined -Scope @('mdilab.local') -Dcs $fab
Assert-That 'a DIFFERENT single FQDN scope is still charged - it has a dot, so no inference is made' `
(@($r | Where-Object { $_ -eq 'mdilab.local' }).Count -eq 1) "(got: $($r -join ', '))"
$r = Get-Unexamined -Scope @('fabrikam.local', 'mdilab.local') -Dcs $fab
Assert-That 'a second FQDN domain that was never scanned is still charged' `
(@($r | Where-Object { $_ -eq 'mdilab.local' }).Count -eq 1) "(got: $($r -join ', '))"
$r = Get-Unexamined -Scope @('FABCORP') -Dcs @()
Assert-That 'an empty scan still reports nothing per-domain (the empty-scan escape hatch)' `
($r.Count -eq 0) "(got: $($r -join ', '))"
$r = Get-Unexamined -Scope @('CONTOSO') -Dcs $fab
Assert-That 'ANY single dotless scope over one scanned domain is accepted, not just FABCORP' `
($r.Count -eq 0) "(got: $($r -join ', '))"

"`n[4] The case spellings of one dotless name are still one scope entry"
$r = Get-Unexamined -Scope @('FABCORP') -Dcs @((New-Dc 'dcfab01.fabrikam.local' 'FABRIKAM.LOCAL'))
Assert-That 'the examined domain is matched case-insensitively' ($r.Count -eq 0) "(got: $($r -join ', '))"

""
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
