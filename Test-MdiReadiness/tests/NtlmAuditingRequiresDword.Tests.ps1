# [w87] NTLM auditing must require a REG_DWORD, not merely the right text.
#
# The settings are REG_DWORD - the code's own comment said so - but nothing verified it, and
# RegistryKey.GetValue renders a REG_SZ "2" and a REG_DWORD 2 as the same string. LSA reads these
# values as DWORDs, so a string one is not honoured: the estate is NOT auditing NTLM.
#
# Measured with a stubbed registry before the fix: kind=String value="2" returned
# isNtlmAuditingOk = True, and so did value="2" with a trailing newline. GETVALUEKIND_CALLS was 0 -
# the reader never asked. That is a false green on an audit control, which is the worst kind because
# nobody goes looking, and it also SUPPRESSED the remediation, so the script declined to fix the
# setting it had misread.
#
# A wrong TYPE is a MEASURED FAILURE, not an unread check: the value was read successfully, and what
# it says is that the setting is not in effect.
#
# The last group is the important one. Reading the kind is a SECOND call against the same remote
# handle and can fail on its own; letting that failure reach the outer catch marked the row unreadable
# and threw away a value already read successfully, turning a measured CA auditing pass into "not
# measured". That regression was caught by tests\RegistrySpecParsing.Tests.ps1 and is pinned here.
#
# Probe: MDI-AB\live\w87-ntlm-kind.ps1

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
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

# The rows Get-mdiRegistryValueSet would have produced. Get-mdiNtlmAuditing is driven directly, with
# its reader replaced via Set-Item -Path function:script: - a `function global:` would NOT override
# the script's own copy and every case below would silently test the real remote registry.
$script:rows = @()
Set-Item -Path function:script:Get-mdiRegistryValueSet -Value {
    param($ComputerName, $ExpectedRegistrySet)
    $script:rows
}
function New-Row {
    param([string] $Name, $Value, $Kind, [bool] $Readable = $true)
    [PSCustomObject]@{
        regKey = "System\CurrentControlSet\Control\Lsa\MSV1_0\$Name"
        value = $Value; valueKind = $Kind; expectedValue = '2'; Readable = $Readable
    }
}
function Get-Ntlm {
    param($Rows)
    $script:rows = $Rows
    Get-mdiNtlmAuditing -ComputerName 'dc1.contoso.com'
}
# Does the generated remediation write the NTLM registry values for this reading?
function Test-WritesNtlm {
    param($Value)
    $srv = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $false
        NtlmAuditing = $Value
        AdvancedAuditing = $true; PowerSettings = $true; RequiredPorts = $true; TimeSync = $true
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
    }
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainsInScope = @('contoso.com')
        DomainControllers = @($srv); CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); SkippedAreas = @()
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
    }
    $dir = Join-Path $env:TEMP ('mdintlm-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void](New-Item -ItemType Directory -Path $dir -Force)
    try {
        $f = Join-Path $dir 'Fix.ps1'
        New-mdiRemediationScript -ReportData $report -FilePath $f 3>$null 4>$null 6>$null | Out-Null
        if (-not (Test-Path $f)) { return $false }
        ([IO.File]::ReadAllText($f)) -match 'MSV1_0'
    } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
}

'[w87] a REG_SZ holding the right text is NOT a configured REG_DWORD'
$r = Get-Ntlm @((New-Row -Name 'AuditReceivingNTLMTraffic' -Value '2' -Kind 'String'))
Assert-That 'it is a measured failure' ($r.isNtlmAuditingOk -eq $false) "(got '$($r.isNtlmAuditingOk)')"
Assert-That '  ...not a pass' ($r.isNtlmAuditingOk -ne $true) "(got '$($r.isNtlmAuditingOk)')"
Assert-That '  ...and not an unread check either' ([string] $r.isNtlmAuditingOk -ne 'N/A') "(got '$($r.isNtlmAuditingOk)')"
Assert-That '  ...and the remediation now offers to fix it' (Test-WritesNtlm -Value $r.isNtlmAuditingOk)

'[w87] a REG_SZ with trailing whitespace is not rescued by the string compare either'
$rlf = Get-Ntlm @((New-Row -Name 'AuditReceivingNTLMTraffic' -Value "2`n" -Kind 'String'))
Assert-That 'it is a measured failure' ($rlf.isNtlmAuditingOk -eq $false) "(got '$($rlf.isNtlmAuditingOk)')"

'[w87] CONTROL - a real REG_DWORD still passes'
# Without this, failing every row would satisfy everything above.
$ok = Get-Ntlm @((New-Row -Name 'AuditReceivingNTLMTraffic' -Value 2 -Kind 'DWord'))
Assert-That 'a DWORD holding the expected value passes' ($ok.isNtlmAuditingOk -eq $true) "(got '$($ok.isNtlmAuditingOk)')"
Assert-That '  ...and generates no remediation' (-not (Test-WritesNtlm -Value $ok.isNtlmAuditingOk))
$okQ = Get-Ntlm @((New-Row -Name 'AuditReceivingNTLMTraffic' -Value 2 -Kind 'QWord'))
Assert-That 'a QWORD holding the expected value also passes' ($okQ.isNtlmAuditingOk -eq $true) "(got '$($okQ.isNtlmAuditingOk)')"

'[w87] CONTROL - a REG_DWORD holding the WRONG value still fails'
$bad = Get-Ntlm @((New-Row -Name 'AuditReceivingNTLMTraffic' -Value 0 -Kind 'DWord'))
Assert-That 'a DWORD holding 0 is a measured failure' ($bad.isNtlmAuditingOk -eq $false) "(got '$($bad.isNtlmAuditingOk)')"

'[w87] CONTROL - the tri-state is preserved: unread stays unread'
# A value that could not be READ is not a value that is wrong, and must never become one.
$unread = Get-Ntlm @((New-Row -Name 'AuditReceivingNTLMTraffic' -Value $null -Kind $null -Readable $false))
Assert-That 'an unreadable row is not measured' ([string] $unread.isNtlmAuditingOk -eq 'N/A') "(got '$($unread.isNtlmAuditingOk)')"
Assert-That '  ...and generates no remediation' (-not (Test-WritesNtlm -Value $unread.isNtlmAuditingOk))

'[w87] CONTROL - an ABSENT value is still a measured failure, not a type problem'
$absent = Get-Ntlm @((New-Row -Name 'AuditReceivingNTLMTraffic' -Value $null -Kind $null))
Assert-That 'a missing value is a measured failure' ($absent.isNtlmAuditingOk -eq $false) "(got '$($absent.isNtlmAuditingOk)')"

'[w87] CONTROL - an UNKNOWN kind must not invent a failure'
# Reading the kind is a second call against the same remote handle and can fail on its own. When it
# does, the value that WAS read successfully must still be judged on its own merits - otherwise a
# correctly configured estate is failed because a secondary call did not answer.
$unknown = Get-Ntlm @((New-Row -Name 'AuditReceivingNTLMTraffic' -Value 2 -Kind $null))
Assert-That 'a correct value with an unknown kind still passes' ($unknown.isNtlmAuditingOk -eq $true) "(got '$($unknown.isNtlmAuditingOk)')"

'[w87] the reader actually asks the registry for the kind'
# The whole fix depends on it being read at all; before, GETVALUEKIND_CALLS was 0.
$readerSrc = ([regex]::Match($text, '(?s)function Get-mdiRegistryValueSet.*?\r?\n\}')).Value
Assert-That 'Get-mdiRegistryValueSet calls GetValueKind' ($readerSrc -match 'GetValueKind') '(the reader never asks for the kind)'
Assert-That '  ...and emits it on every row' ($readerSrc -match 'valueKind\s*=') '(the kind is never surfaced)'
Assert-That '  ...guarded, so a failed kind read cannot invalidate the value' `
    ($readerSrc -match '(?s)try\s*\{[^}]*GetValueKind[^}]*\}\s*catch') '(a GetValueKind failure would mark the row unreadable)'

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
