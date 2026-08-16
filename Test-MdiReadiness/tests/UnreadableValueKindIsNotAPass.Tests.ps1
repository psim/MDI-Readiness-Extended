<#
    An NTLM audit value whose TYPE could not be established must not be a measured PASS.

    These settings are REG_DWORD and LSA only honours them as DWORDs, so Get-mdiNtlmAuditing checks
    the value's KIND as well as its text: a REG_SZ "2" is a measured FAILURE, not a pass.

    But the kind is read by a SECOND call (GetValueKind) that Get-mdiRegistryValueSet deliberately
    lets fail without discarding the value it had already read - the row then carries the value with
    valueKind = $null. The type guard was written as

        ($null -ne $_.value -and $null -ne $_.valueKind -and
            [string] $_.valueKind -notin @('DWord','QWord'))

    so a null kind skipped the guard entirely and the row fell through to the text comparison alone.
    The SAME registry content therefore produced OPPOSITE verdicts:

        REG_SZ "2", kind readable    -> measured False   (correct)
        REG_SZ "2", kind unreadable  -> measured True    (false green)

    An audit control's verdict must not depend on whether an enrichment call happened to succeed, and
    a pass is the one answer that must never be reached that way: it also suppresses the remediation
    section that would have repaired the setting, so the script declines to fix what it misread.

    The honest answer when the type cannot be established is 'N/A'. But the runtime type is still
    evidence - GetValue returns an Int32 for a REG_DWORD and a String only for a REG_SZ - so an
    integral value confirms its own type even with the kind unread, and that answer must be kept.

    Behavioural: every assertion drives the shipped function through a stubbed registry reader and
    reads the verdict it returns.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = [IO.File]::ReadAllText([IO.Path]::GetFullPath($target))
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main'); if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body

Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

$expectedRows = @($settings.NTLMAuditing | ConvertFrom-Csv -Header 'regKey', 'regValue', 'expectedValue')
Assert-That 'the shipped NTLM settings carry at least one expectation' ($expectedRows.Count -ge 1) "(count=$($expectedRows.Count))"

# Each case supplies the TYPE used for every row; each row gets the value ITS OWN expectation
# accepts. The three NTLM settings expect different numbers (2, 1 and 7), so a single shared value
# would fail the other rows and the test would measure the wrong thing entirely.
$script:rowKind = 'DWord'
$script:asText = $false
$script:overrideValue = $null
$script:useOverride = $false
Set-Item -Path function:script:Get-mdiRegistryValueSet -Value {
    param($ComputerName, $ExpectedRegistrySet)
    @($ExpectedRegistrySet | ConvertFrom-Csv -Header 'regKey', 'regValue', 'expectedValue' | ForEach-Object {
            $accepted = ([string] $_.expectedValue -split '\|')[0]
            $v = if ($script:useOverride) { $script:overrideValue }
            elseif ($script:asText) { [string] $accepted }
            else { [int] $accepted }
            [PSCustomObject]@{
                regKey        = ('{0}\{1}' -f $_.regKey, $_.regValue)
                value         = $v
                valueKind     = $script:rowKind
                expectedValue = $_.expectedValue
                Readable      = $true
            }
        })
}

function Get-NtlmVerdict {
    param([switch] $AsText, $Kind, $Override, [switch] $UseOverride)
    $script:asText = [bool] $AsText
    $script:rowKind = $Kind
    $script:overrideValue = $Override
    $script:useOverride = [bool] $UseOverride
    $r = Get-mdiNtlmAuditing -ComputerName 'dc1.contoso.com'
    [PSCustomObject]@{ Status = $r.isNtlmAuditingOk; Detail = $r.details }
}

Write-Host "`n[1] Control: the kind is READABLE" -ForegroundColor Yellow
$r = Get-NtlmVerdict -Kind 'DWord'
Assert-That 'a DWORD holding the expected value is a measured pass' ($r.Status -is [bool] -and $r.Status -eq $true) "(got '$($r.Status)')"
$r = Get-NtlmVerdict -AsText -Kind 'String'
Assert-That 'a REG_SZ holding the same text is a measured FAILURE' ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"

Write-Host "`n[2] The kind could NOT be read - the verdict must not flip to a pass" -ForegroundColor Yellow
$r = Get-NtlmVerdict -AsText -Kind $null
Assert-That 'a REG_SZ with an unreadable kind is NOT a measured pass' ($r.Status -ne $true) "(got '$($r.Status)')"
Assert-That '  it is unmeasured' ([string] $r.Status -eq 'N/A') "(got '$($r.Status)')"
Assert-That '  and says so with the Not tested convention' ([string] $r.Detail -like 'Not tested*') "(detail='$($r.Detail)')"

Write-Host "`n[3] The same content must not reach opposite verdicts" -ForegroundColor Yellow
$known = Get-NtlmVerdict -AsText -Kind 'String'
$unknown = Get-NtlmVerdict -AsText -Kind $null
Assert-That 'a readable-kind REG_SZ never passes' ($known.Status -ne $true) "(got '$($known.Status)')"
Assert-That 'an unreadable-kind REG_SZ never passes either' ($unknown.Status -ne $true) "(got '$($unknown.Status)')"

Write-Host "`n[4] The runtime type is still evidence - knowable answers are kept" -ForegroundColor Yellow
$r = Get-NtlmVerdict -Kind $null
Assert-That 'an integral value with an unreadable kind still passes' ($r.Status -is [bool] -and $r.Status -eq $true) "(got '$($r.Status)')"
$r = Get-NtlmVerdict -Kind 'QWord'
Assert-That 'a QWORD is still accepted' ($r.Status -is [bool] -and $r.Status -eq $true) "(got '$($r.Status)')"

Write-Host "`n[5] A definite disqualifier outranks an unknown type" -ForegroundColor Yellow
$r = Get-NtlmVerdict -Kind $null -Override 'not-a-number' -UseOverride
Assert-That 'a wrong VALUE with an unreadable kind is a measured failure' ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"
$r = Get-NtlmVerdict -Kind $null -Override '' -UseOverride
Assert-That 'an empty value with an unreadable kind is a measured failure' ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"
$r = Get-NtlmVerdict -Kind 'String' -Override 0 -UseOverride
Assert-That 'a zero value is still a measured failure' ($r.Status -is [bool] -and $r.Status -eq $false) "(got '$($r.Status)')"

Write-Host "`n[6] Existing unreadable-registry behaviour is unchanged" -ForegroundColor Yellow
Set-Item -Path function:script:Get-mdiRegistryValueSet -Value {
    param($ComputerName, $ExpectedRegistrySet)
    @($ExpectedRegistrySet | ConvertFrom-Csv -Header 'regKey', 'regValue', 'expectedValue' | ForEach-Object {
            [PSCustomObject]@{
                regKey = ('{0}\{1}' -f $_.regKey, $_.regValue); value = $null
                valueKind = $null; expectedValue = $_.expectedValue; Readable = $false
            }
        })
}
$r = Get-mdiNtlmAuditing -ComputerName 'dc1.contoso.com'
Assert-That 'an unreadable registry is still N/A' ([string] $r.isNtlmAuditingOk -eq 'N/A') "(got '$($r.isNtlmAuditingOk)')"
Assert-That '  and still says it could not be read' ([string] $r.details -match 'could not be read') "(detail='$($r.details)')"

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
