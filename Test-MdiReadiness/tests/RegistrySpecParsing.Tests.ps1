<#
    Behavioural regression tests for registry specification parsing.

    A specification is "key path,value name,expected value". Only the key PATH carries data from the
    environment - the certification authority's common name is interpolated into it - and a CN
    legitimately contains a comma. Splitting left to right truncated the path, shifted the value name
    and the expectation by one field, and reported a CORRECTLY configured certification authority as
    a MEASURED failure pointing at a registry path that does not exist.

    The end-to-end cases run the SHIPPED Get-mdiCAAuditing over the SHIPPED Get-mdiRegistryValueSet;
    the only thing replaced is the [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey boundary, which is
    hooked onto an in-memory hive. The parsing under test is the script's own code.
#>

param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }

$text = [IO.File]::ReadAllText($scriptPath)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main'); if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:passed++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray }
    else { $script:failed++; Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red }
}

Write-Host 'RegistrySpecParsing.Tests.ps1' -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------
# The parser itself.
# ---------------------------------------------------------------------------------------------
$plain = Split-mdiRegistrySpec -Spec 'System\CurrentControlSet\Services\CertSvc\Configuration\Contoso Inc CA,AuditFilter,127'
Assert-True 'a three-field spec keeps its path' ($plain.KeyPath -eq 'System\CurrentControlSet\Services\CertSvc\Configuration\Contoso Inc CA') $plain.KeyPath
Assert-True 'a three-field spec reads the value name' ($plain.ValueName -eq 'AuditFilter') $plain.ValueName
Assert-True 'a three-field spec reads the expectation' ($plain.ExpectedValue -eq '127') $plain.ExpectedValue

$comma = Split-mdiRegistrySpec -Spec 'System\CurrentControlSet\Services\CertSvc\Configuration\Contoso, Inc CA,AuditFilter,127'
Assert-True 'a comma in the key path stays in the key path' `
    ($comma.KeyPath -eq 'System\CurrentControlSet\Services\CertSvc\Configuration\Contoso, Inc CA') $comma.KeyPath
Assert-True 'a comma in the key path does not shift the value name' ($comma.ValueName -eq 'AuditFilter') $comma.ValueName
Assert-True 'a comma in the key path does not shift the expectation' ($comma.ExpectedValue -eq '127') $comma.ExpectedValue

$many = Split-mdiRegistrySpec -Spec 'Some\Path\A, B, C, Inc CA,AuditFilter,127'
Assert-True 'several commas in the key path all stay there' ($many.KeyPath -eq 'Some\Path\A, B, C, Inc CA') $many.KeyPath
Assert-True 'several commas still leave the value name intact' ($many.ValueName -eq 'AuditFilter') $many.ValueName

# The two-field form reads a value with no expectation - that is how the CA's own name is read.
$twoField = Split-mdiRegistrySpec -Spec 'System\CurrentControlSet\Services\CertSvc\Configuration,Active'
Assert-True 'a two-field spec keeps its path' ($twoField.KeyPath -eq 'System\CurrentControlSet\Services\CertSvc\Configuration') $twoField.KeyPath
Assert-True 'a two-field spec reads the value name' ($twoField.ValueName -eq 'Active') $twoField.ValueName
Assert-True 'a two-field spec carries no expectation' ($null -eq $twoField.ExpectedValue)

Assert-True 'a one-field spec cannot be interpreted' ($null -eq (Split-mdiRegistrySpec -Spec 'JustAPath'))
Assert-True 'an empty spec cannot be interpreted' ($null -eq (Split-mdiRegistrySpec -Spec ''))

# Every specification the script actually ships must parse.
foreach ($spec in @($settings.NTLMAuditing)) {
    $parsed = Split-mdiRegistrySpec -Spec $spec
    Assert-True ("shipped NTLM spec parses: {0}" -f $spec) ($null -ne $parsed -and -not [string]::IsNullOrWhiteSpace($parsed.ValueName))
}
Assert-True 'the shipped CA active-name spec parses' ($null -ne (Split-mdiRegistrySpec -Spec $settings.CASettings.RegPathActive))
foreach ($spec in @($settings.CASettings.RegistrySet)) {
    Assert-True ("the shipped CA registry spec parses for a comma CA name") (
        (Split-mdiRegistrySpec -Spec ($spec -f 'Contoso, Inc CA')).ValueName -eq 'AuditFilter')
}

# ---------------------------------------------------------------------------------------------
# End to end: the shipped CA reader over the shipped registry reader, against an in-memory hive
# holding a CORRECTLY configured certification authority (AuditFilter = 127).
# ---------------------------------------------------------------------------------------------
$fnMatch = [regex]::Match($text, '(?s)function Get-mdiRegistryValueSet\s*\{.*?\r?\n\}\r?\n')
Assert-True 'the registry reader source can be located' ($fnMatch.Success)
if ($fnMatch.Success) {
    $needle = "[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', `$ComputerName, 'Registry64')"
    Assert-True 'the remote-registry boundary is where the hook expects it' ($fnMatch.Value.IndexOf($needle) -ge 0)

    $hooked = $fnMatch.Value.Replace($needle, '$script:Hook_OpenBaseKey.Invoke($ComputerName)')
    $hooked = $hooked -replace '^function Get-mdiRegistryValueSet', 'function script:Get-mdiRegistryValueSet'
    Invoke-Expression $hooked

    function New-FakeKey {
        param([hashtable] $Values)
        $k = New-Object PSObject
        $k | Add-Member NoteProperty _values $Values
        $k | Add-Member ScriptMethod GetValue { param($n) if ($this._values.ContainsKey($n)) { $this._values[$n] } else { $null } }
        $k | Add-Member ScriptMethod Close { }
        $k
    }
    function Set-Hive {
        param([string] $CaName)
        $script:Hive = @{
            'System\CurrentControlSet\Services\CertSvc\Configuration' = @{ Active = $CaName }
            ('System\CurrentControlSet\Services\CertSvc\Configuration\' + $CaName) = @{ AuditFilter = 127 }
        }
        $base = New-Object PSObject
        $base | Add-Member ScriptMethod OpenSubKey { param($p) if ($script:Hive.ContainsKey($p)) { New-FakeKey $script:Hive[$p] } else { $null } }
        $base | Add-Member ScriptMethod Close { }
        $script:Hook_OpenBaseKey = { param($c) $base }.GetNewClosure()
    }

    Set-Hive -CaName 'Contoso, Inc CA'
    $withComma = Get-mdiCAAuditing -ComputerName 'ca1.contoso.com'
    Assert-True 'a correctly configured CA whose name contains a comma is not reported as failed' `
        ($withComma.isCaAuditingOk -ne $false) ("got [{0}] details [{1}]" -f $withComma.isCaAuditingOk, ($withComma.details | ConvertTo-Json -Compress -Depth 3))
    Assert-True 'and it is reported as an actual measured pass, not merely as unmeasured' `
        ($withComma.isCaAuditingOk -eq $true) ("got [{0}]" -f $withComma.isCaAuditingOk)

    Set-Hive -CaName 'Contoso Inc CA'
    $noComma = Get-mdiCAAuditing -ComputerName 'ca1.contoso.com'
    Assert-True 'control: the same CA without a comma still passes' ($noComma.isCaAuditingOk -eq $true) ("got [{0}]" -f $noComma.isCaAuditingOk)

    # A specification the reader cannot interpret measured nothing, and must be REPORTED as unread
    # rather than dropped. Dropping it would leave the caller counting fewer rows than it asked for
    # and reading the absence as a clean result for an entry nobody looked at - the same
    # unmeasured-treated-as-measured shape that this whole check exists to prevent.
    Set-Hive -CaName 'Contoso Inc CA'
    $unparsable = @(Get-mdiRegistryValueSet -ComputerName 'ca1.contoso.com' -ExpectedRegistrySet @('JustAPathWithNoValue'))
    Assert-True 'an uninterpretable spec still produces a row' ($unparsable.Count -eq 1) ("got {0} row(s)" -f $unparsable.Count)
    Assert-True 'and that row is marked unreadable, never measured' `
        ($unparsable.Count -eq 1 -and $unparsable[0].Readable -eq $false) `
        ("Readable=[{0}]" -f $(if ($unparsable.Count) { $unparsable[0].Readable } else { 'no row' }))

    # A genuinely misconfigured CA must still fail, comma or no comma - the fix must not have turned
    # the check into something that can no longer report a failure.
    $script:Hive = @{
        'System\CurrentControlSet\Services\CertSvc\Configuration' = @{ Active = 'Contoso, Inc CA' }
        'System\CurrentControlSet\Services\CertSvc\Configuration\Contoso, Inc CA' = @{ AuditFilter = 3 }
    }
    $base2 = New-Object PSObject
    $base2 | Add-Member ScriptMethod OpenSubKey { param($p) if ($script:Hive.ContainsKey($p)) { New-FakeKey $script:Hive[$p] } else { $null } }
    $base2 | Add-Member ScriptMethod Close { }
    $script:Hook_OpenBaseKey = { param($c) $base2 }.GetNewClosure()
    $misconfigured = Get-mdiCAAuditing -ComputerName 'ca1.contoso.com'
    Assert-True 'control: a comma CA that really is misconfigured is still reported as failed' `
        ($misconfigured.isCaAuditingOk -eq $false) ("got [{0}]" -f $misconfigured.isCaAuditingOk)
}

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
