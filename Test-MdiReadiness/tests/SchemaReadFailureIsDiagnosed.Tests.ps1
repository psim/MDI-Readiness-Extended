<#
    A schema version that could not be read must be explained, not relayed as an internal error.

    Get-DomainSchemaVersion binds LDAP lazily. A DirectoryEntry pointed at a domain this machine
    cannot reach does not fail when it is constructed - it fails at the first property read, and
    PowerShell surfaces that as:

        Unable to read the Active Directory schema version of fabrikam.local: Cannot index into a
        null array.

    Measured on the live lab: scanning the trusted forest fabrikam.local from a member of
    mdilab.local printed exactly that, twice, directly beneath a sibling warning that described the
    same underlying condition properly - "Unable to contact the server. This may be because this
    server does not exist, it is currently down, or it does not have the Active Directory Web
    Services running." One cause, two messages, one of them naming an implementation detail of this
    function rather than anything the reader can act on.

    This is not a false green: the version is still reported as unread, and the run still completes.
    It is a diagnosis defect, and the whole point of this tool is that what it could not measure is
    stated in terms the reader can do something about. A message nobody can act on is the same
    failure as a number nobody measured, one layer up.

    The check is on the WORDING, because that is the entire defect - the value was always correct.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The warnings are captured rather than inspected in the script text, so this tests what a reader
# actually sees.
$script:warnings = @()
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) $script:warnings += [string] $Message }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }

Write-Host "`n[1] An unreachable domain is explained, not relayed" -ForegroundColor Yellow
$script:warnings = @()
# A name that cannot resolve reproduces the lazy-bind failure without needing a live directory.
$v = Get-DomainSchemaVersion -Domain 'no-such-domain.invalid'
$w = ($script:warnings -join ' ')

Assert-That 'the version is reported as unread, not invented' ($v.Version -eq 0 -or $null -eq $v.Version -or "$($v.Version)" -eq '0') `
    "(got '$($v.Version)')"
Assert-That 'a warning is raised at all' ($script:warnings.Count -ge 1) "(none raised)"
Assert-That 'the internal array error is NOT shown to the reader' ($w -notmatch 'Cannot index into a null array') `
    "(warning was: $w)"
Assert-That 'the message names the domain that failed' ($w -match 'no-such-domain\.invalid') "(warning was: $w)"
Assert-That 'the message says what could not be done' ($w -match 'schema could not be read|Unable to read') "(warning was: $w)"
Assert-That 'the message offers a cause the reader can act on' `
    ($w -match 'may not exist|unreachable|may not permit|does not exist|currently down') "(warning was: $w)"

Write-Host "`n[2] A genuine, meaningful error is still passed through" -ForegroundColor Yellow
# The substitution must be narrow. Replacing every message would hide real diagnoses - an access
# denial and an unreachable host need different actions from the reader.
$sample = 'Logon failure: unknown user name or bad password.'
$masked = if ($sample -match 'Cannot index into a null array|Object reference not set') {
    'the directory did not answer, so the schema could not be read.'
} else { $sample }
Assert-That 'an unrelated error message is left intact' ($masked -eq $sample) "(became '$masked')"

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
