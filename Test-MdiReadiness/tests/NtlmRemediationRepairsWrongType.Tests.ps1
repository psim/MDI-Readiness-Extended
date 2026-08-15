# The generated NTLM remediation was type-blind, so it never repaired the wrong-type failure it was
# emitted to repair - and the finding was marked COVERED, so nothing told the operator.
#
# The emitted guard read the current value and skipped the write when it already looked right:
#
#     if ([string] $mdiCurrent -notmatch '^(?:2)$') { New-ItemProperty ... -PropertyType DWord -Force }
#
# [string] on a REG_SZ '2' is '2', so a value stored with the WRONG TYPE matched and the write was
# skipped. But Get-mdiNtlmAuditing requires a REG_DWORD - a string-typed value is not the value the
# OS acts on - so the check went in red and came out red.
#
# Measured against the real Win32 registry APIs: REG_SZ '2' in, section runs, value still REG_SZ '2',
# check still False - while the very same emitted New-ItemProperty line, run directly, converted it to
# REG_DWORD and turned the check True. So the emitter was capable and only the guard was wrong.
#
# The operator-visible half is worse than the failed repair: the section IS emitted, so the finding is
# marked covered and is absent from "Findings that need manual attention", and the script still closes
# "Remediation complete. Re-run Test-MdiReadiness.ps1 to verify." The operator runs it, is told it
# worked, and the re-run fails identically with nothing to explain why.
#
# The guard must NOT simply be removed. It exists to stop a domain controller hardened to
# RestrictSendingNTLMTraffic = 2 ('Deny all') being silently relaxed to 1 ('Audit all') by a script
# generated to fix an unrelated value - a real defect the comment above it records. So the fix keeps
# the guard, adds the TYPE to what "already acceptable" means, and when the type is wrong but the
# value is one the check accepts it rewrites THAT value rather than the default.
#
# These assertions EXECUTE the emitted guard against a scratch key under HKCU (GUID-suffixed, removed
# in a finally) so the registry type is a real registry type, not a fixture.

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

$scratch = 'w141-ntlm-' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$scratchRoot = "HKCU:\Software\$scratch"

try {
    # Generate the real remediation for a server whose NTLM auditing failed.
    $dc = [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
        Unreachable = $false; PartialFailure = $false
        NtlmAuditing = $false
        Details = [PSCustomObject]@{}
    }
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        DomainsInScope = @('contoso.com'); DomainControllers = @($dc)
        CAServers = @(); EntraConnectServers = @(); DomainAuditing = @(); SkippedAreas = @()
    }
    $out = Join-Path $env:TEMP ('mdi-ntlm-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
    New-mdiRemediationScript -ReportData $report -FilePath $out 3>$null | Out-Null
    $generated = [IO.File]::ReadAllText($out)
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue

    Assert-That 'the NTLM section is emitted for a failing server' ($generated -match 'AuditReceivingNTLMTraffic') '(no NTLM section)'

    # Pull the emitted guard for one value and retarget its hive at the scratch key. Only the hive
    # prefix is rewritten - the guard logic under test is the shipped text, byte for byte.
    $lines = $generated -split "`r?`n"
    $block = @()
    for ($k = 0; $k -lt $lines.Count; $k++) {
        if ($lines[$k] -match "GetValue\('AuditReceivingNTLMTraffic'\)|\.'AuditReceivingNTLMTraffic'") {
            $start = $k
            while ($start -gt 0 -and $lines[$start] -notmatch '^\s*\$mdiCurrent = \$null') { $start-- }
            for ($j = $start; $j -lt $lines.Count; $j++) {
                $block += $lines[$j]
                if ($lines[$j] -match 'New-ItemProperty.*AuditReceivingNTLMTraffic') { $block += $lines[$j + 1]; break }
            }
            break
        }
    }
    Assert-That 'the emitted guard for AuditReceivingNTLMTraffic was located' ($block.Count -gt 0) "(got $($block.Count) lines)"

    $guardText = ($block -join [Environment]::NewLine)
    $lsaPath = "$scratchRoot\System\CurrentControlSet\Control\Lsa\MSV1_0"
    $guardText = $guardText -replace [regex]::Escape("HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"), $lsaPath
    $guard = [scriptblock]::Create($guardText)

    function Reset-Value {
        param($Kind, $Value)
        if (Test-Path $lsaPath) { Remove-Item -Path $lsaPath -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path $lsaPath -Force | Out-Null
        if ($null -ne $Kind) {
            New-ItemProperty -Path $lsaPath -Name 'AuditReceivingNTLMTraffic' -Value $Value -PropertyType $Kind -Force | Out-Null
        }
    }
    function Get-Stored {
        $item = Get-Item -Path $lsaPath
        if ($item.GetValueNames() -notcontains 'AuditReceivingNTLMTraffic') { return [PSCustomObject]@{ Kind = 'absent'; Value = $null } }
        [PSCustomObject]@{ Kind = [string] $item.GetValueKind('AuditReceivingNTLMTraffic'); Value = $item.GetValue('AuditReceivingNTLMTraffic') }
    }

    '[ntlm guard] a wrong-TYPE value is repaired, not skipped'
    Reset-Value 'String' '2'
    $before = Get-Stored
    Assert-That 'the scratch value really is a REG_SZ' ($before.Kind -eq 'String') "(got $($before.Kind))"
    & $guard | Out-Null
    $after = Get-Stored
    Assert-That 'the wrong-typed value is converted to DWord' ($after.Kind -eq 'DWord') "(got $($after.Kind))"
    Assert-That '  ...keeping the value the machine already expressed' ([int] $after.Value -eq 2) "(got $($after.Value))"

    ''
    '[ntlm guard] the hardening safeguard is preserved'
    # The guard exists so a DC already at an acceptable value is not rewritten to the default. That
    # must survive the type check, in both the right-typed and wrong-typed cases.
    Reset-Value 'DWord' 2
    & $guard | Out-Null
    $kept = Get-Stored
    Assert-That 'an already-correct DWord is left alone' (($kept.Kind -eq 'DWord') -and ([int] $kept.Value -eq 2)) "(got $($kept.Kind)/$($kept.Value))"

    ''
    '[ntlm guard] an absent value is still repaired'
    Reset-Value $null $null
    $absent = Get-Stored
    Assert-That 'the value really is absent to begin with' ($absent.Kind -eq 'absent') "(got $($absent.Kind))"
    & $guard | Out-Null
    $written = Get-Stored
    Assert-That 'an absent value is written as DWord' ($written.Kind -eq 'DWord') "(got $($written.Kind))"
    Assert-That '  ...with the expected value' ([int] $written.Value -eq 2) "(got $($written.Value))"

    ''
    '[ntlm guard] a wrong VALUE of the right type is still repaired'
    Reset-Value 'DWord' 0
    & $guard | Out-Null
    $repaired = Get-Stored
    Assert-That 'a wrong DWord value is corrected' (($repaired.Kind -eq 'DWord') -and ([int] $repaired.Value -eq 2)) "(got $($repaired.Kind)/$($repaired.Value))"

    ''
    '[ntlm guard] every emitted NTLM guard tests the value KIND'
    # All three values are emitted from one loop, so none may be left type-blind.
    $kindTests = @([regex]::Matches($generated, "GetValueKind\('(?<n>[^']+)'\)")).Count
    Assert-That 'each of the three NTLM values checks its kind' ($kindTests -ge 3) "(found $kindTests GetValueKind calls)"
    Assert-That 'no emitted guard relies on the text alone' (
        $generated -notmatch "if \(\[string\] \`$mdiCurrent -notmatch"
    ) '(a text-only guard is still emitted)'
    # ...and the write must not hard-code the default when the current value is already acceptable.
    Assert-That 'the write preserves an acceptable current value' (
        $generated -match '\$mdiWrite = \[int\] \$mdiCurrent'
    ) '(the default would overwrite a hardened value)'

} finally {
    if (Test-Path $scratchRoot) { Remove-Item -Path $scratchRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
