<#
    An AD FS auditing state that could not be read must not become a verdict.

    Get-mdiAdfsAuditing reports whether the AD FS Program Data container carries the SACL that MDI
    needs, and its answer feeds a domain verdict: Test-mdiDomainCheckPassed reads isAdfsAuditingOk
    and Get-mdiIssueList raises a finding from it. Three outcomes are genuinely different:

        $true   the SACL was read and satisfies every expected ACE
        $false  the SACL was read and does NOT satisfy them - a real, blocking gap
        'N/A'   nothing was read, or the role is absent - no assertion is made at all

    The dangerous confusion is 'N/A' collapsing into a boolean. A read failure rendered as $false
    invents a misconfiguration the operator cannot find; rendered as $true it hides a real one.
    Measured carries the other half: "there is no AD FS in this domain" is an ANSWER and returns
    'N/A' with Measured = $true, whereas a genuine failure to read returns 'N/A' with
    Measured = $false, and scoring treats those two differently.

    No defect was found in this function. It is pinned because nothing named it before.

    SCOPE - what this test reaches, and what it does NOT. Read this before trusting it.

    This file asserts ONE branch: a directory that cannot be contacted at all. That branch is
    exercised for real, end to end, through the shipped function against a domain in the reserved
    .invalid TLD, which cannot resolve.

    The other branches are NOT asserted, and the reason is a measured limitation rather than an
    oversight:

      * The container-existence test is the STATIC call [DirectoryServices.DirectoryEntry]::Exists.
        A static cannot be stubbed. Registering a type accelerator named
        DirectoryServices.DirectoryEntry was TRIED and does not shadow it - the real method still
        ran and threw.
      * Repointing the [adsi] accelerator at a fake rootDSE was also TRIED, and does not work
        either: [adsi]'LDAP://...' still constructed a real DirectoryEntry, which then failed with
        "The server is not operational" while the fake was ignored. An earlier draft of this file
        carried that fake and appeared to drive two different branches; both were in fact the same
        real bind failure, and the scaffolding was removed rather than shipped, because a stub that
        is silently inert makes a test look stronger than it is.

    So the container-absent case and the SACL comparison need a live directory. They are left alone
    deliberately rather than reached by loosening the shipped code, which would mean changing the
    product to suit the test.

    Pinned here:

    1. A domain that cannot be contacted yields isAdfsAuditingOk = 'N/A' with Measured = $false.
    2. That value is the STRING 'N/A' and specifically NOT the boolean $false and NOT $true. This is
       the assertion that matters: it is what stops an unread state being scored as a measured
       verdict in either direction.
    3. details is a non-empty explanation beginning "Not tested", so the report has something
       truthful to show instead of a silent blank.
    4. The SACL comparison is never consulted when nothing could be read - no ACE assertion is made
       on the strength of a failed lookup.
    5. The result carries all three fields the callers read, so a caller cannot fall through to an
       absent property and treat it as false.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiAdfsAuditing') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
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

# If the SACL reader is reached, this branch is not what the test thinks it is. Recorded rather
# than assumed - a stub that is never called must prove it was never called.
$script:saclCalls = 0
Set-Item -Path function:script:Get-mdiDsSacl -Value {
    param($LdapPath, $ExpectedAuditing)
    $script:saclCalls++
    [PSCustomObject]@{ isAuditingOk = $true; details = @($ExpectedAuditing) }
}

# .invalid is reserved by RFC 2606 and cannot resolve, so the directory is genuinely unreachable
# rather than merely absent.
$r = Get-mdiAdfsAuditing -Domain 'adfs-probe.invalid'

'1. An unreachable directory is not a measurement'
Assert-That "isAdfsAuditingOk is 'N/A'" ([string] $r.isAdfsAuditingOk -eq 'N/A') "got [$($r.isAdfsAuditingOk)]"
Assert-That 'Measured is $false - nothing was read' ($r.Measured -eq $false) "got [$($r.Measured)]"

'2. Unread is NOT a boolean verdict in either direction'
Assert-That 'it is not the boolean $false (a measured failure)' `
    (-not ($r.isAdfsAuditingOk -is [bool])) "got [$($r.isAdfsAuditingOk)]"
Assert-That 'it is not $true (a measured pass)' ($r.isAdfsAuditingOk -ne $true) "got [$($r.isAdfsAuditingOk)]"
Assert-That 'it is a string' ($r.isAdfsAuditingOk -is [string]) "got [$($r.isAdfsAuditingOk)]"
# 'N/A' -eq $false is False in PowerShell because the RIGHT operand is converted to the LEFT
# operand's type, so this states the intent explicitly rather than relying on that coincidence.
Assert-That 'a caller testing -eq $true does not see a pass' (-not ($r.isAdfsAuditingOk -eq $true))

'3. It explains itself'
Assert-That 'details is a non-empty explanation' (-not [string]::IsNullOrWhiteSpace([string] $r.details)) `
    "got [$($r.details)]"
Assert-That 'details begins "Not tested"' ([string] $r.details -match '^Not tested') "got [$($r.details)]"

'4. No ACE assertion is made on the strength of a failed lookup'
Assert-That 'the SACL comparison was never consulted' ($script:saclCalls -eq 0) "calls=$script:saclCalls"

'5. Every field the callers read is present'
foreach ($p in 'isAdfsAuditingOk', 'Measured', 'details') {
    Assert-That "the result carries $p" ($r.ContainsKey($p)) "keys=[$($r.Keys -join ',')]"
}

''
"PASS: $script:pass  FAIL: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
