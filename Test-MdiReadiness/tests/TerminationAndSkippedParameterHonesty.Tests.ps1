<#
    Two ways this script told the operator something that was not true.

    1. A TERMINATION THAT FAILED WAS REPORTED AS A TERMINATION THAT SUCCEEDED.

       Invoke-mdiRemoteCommand starts powershell.exe on the target over WMI and waits. A process that
       outlives the wait is terminated rather than abandoned - the comment beside it explains why:
       an abandoned process keeps running on the domain controller, still probing ports and still
       holding its temp file open, so the cleanup cannot remove the file either.

       The warning was written UNCONDITIONALLY, above the attempt, and said "and was terminated" -
       a completed-action claim made before the action was tried:

           Write-mdiWarning ('... did not finish within {1}s and was terminated.')
           try { [void] $stillRunning.Terminate() } catch {
               Write-Verbose ('Could not terminate process ...')     <- a stream a default run never shows
           }

       So when Terminate() threw - access denied is the ordinary case for a non-admin - the operator
       was told the process HAD been terminated and the real failure was invisible. Worse,
       Win32_Process.Terminate reports failure through its RETURN VALUE rather than by throwing, and
       the return value was discarded with [void], so a non-zero status was not noticed at all.

    2. -SkipNetworkPorts SILENTLY SWALLOWED -WorkspaceName.

       The script already has a guard that names every port-plan parameter rendered meaningless by
       -SkipNetworkPorts, with the stated intent that "the operator must not believe NNR or RADIUS
       was validated when port probing was off". -WorkspaceName reaches the run through exactly one
       call - the probe plan builder - so it is discarded like the rest, but it was missing from
       that list. It is the one most likely to be believed: it names the customer's tenant, so a run
       that accepts it in silence reads as "cloud connectivity to my workspace was checked".

    Both are the same class: the tool makes a claim the run does not support.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

# ===================================================================================================
# PART 1 - the termination claim, exercised against the REAL Invoke-MdiRemote
# ===================================================================================================
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body

$script:warnings = New-Object System.Collections.ArrayList
$script:verbose = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:warnings.Add([string] $Message) }
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) [void] $script:verbose.Add([string] $Message) }
Set-Item -Path function:script:Write-Verbose -Value { param($Message) [void] $script:verbose.Add([string] $Message) }
Set-Item -Path function:script:Start-Sleep -Value { param($Seconds, $Milliseconds) }

# How Terminate() behaves on the stubborn process: 'ok', 'throw', or a non-zero WMI return code.
$script:terminateMode = 'ok'
$script:terminateCalls = 0
# Whether the remote process is still running when the wait expires.
$script:stillRunning = $true

$script:remoteArgs = 'powershell.exe -NoProfile -File C:\Windows\Temp\mdi.ps1'

Set-Item -Path function:script:Get-WmiObject -Value {
    param($Class, $ComputerName, $Namespace, $Filter, $List, $ErrorAction)
    if (-not $script:stillRunning) { return $null }
    $o = New-Object PSObject
    $o | Add-Member -MemberType NoteProperty -Name 'CommandLine' -Value $script:remoteArgs -Force
    $o | Add-Member -MemberType NoteProperty -Name 'ProcessId' -Value 4242 -Force
    $o | Add-Member -MemberType ScriptMethod -Name 'Terminate' -Value {
        $script:terminateCalls++
        switch ($script:terminateMode) {
            'throw' { throw 'access denied terminating process' }
            'ok'    { return [PSCustomObject]@{ ReturnValue = 0 } }
            default { return [PSCustomObject]@{ ReturnValue = [int] $script:terminateMode } }
        }
    } -Force
    $o
}

function Invoke-Timeout {
    param([string] $Mode)
    $script:warnings = New-Object System.Collections.ArrayList
    $script:verbose = New-Object System.Collections.ArrayList
    $script:terminateMode = $Mode
    $script:terminateCalls = 0

    # Drive only the timeout/terminate block, using the shipped source of Invoke-MdiRemote so the
    # branch under test is the real one. The WMI create call is stubbed to report a started process.
    $stillRunning = Get-WmiObject -Class Win32_Process
    $result = [PSCustomObject]@{ ReturnValue = 0; ProcessId = 4242 }
    $ComputerName = 'dc1.contoso.com'
    $TimeoutSeconds = 0

    # This is the shipped block, extracted verbatim from the canonical file between its two anchors,
    # so the test cannot drift from the product without failing to find them.
    $src = $script:invokeSource
    $startAnchor = '                $timedOut = $true'
    $s = $src.IndexOf($startAnchor)
    if ($s -lt 0) { throw 'TEST BUG: termination block start anchor not found in the shipped source' }
    # Walk forward tracking brace depth and stop at the closing brace of the ENCLOSING if, so the
    # fragment is exactly the shipped statements and stands alone. A naive TrimEnd of '}' characters
    # ate the else-branch's own brace and produced an unparsable fragment.
    $depth = 0
    $end = -1
    for ($i = $s; $i -lt $src.Length; $i++) {
        $ch = $src[$i]
        if ($ch -eq '{') { $depth++ }
        elseif ($ch -eq '}') {
            if ($depth -eq 0) { $end = $i; break }
            $depth--
        }
    }
    if ($end -lt 0) { throw 'TEST BUG: could not find the end of the termination block' }
    $block = $src.Substring($s, $end - $s)
    $timedOut = $false
    Invoke-Expression $block

    [PSCustomObject]@{
        Warnings       = @($script:warnings)
        Verbose        = @($script:verbose)
        TerminateCalls = $script:terminateCalls
        SaidTerminated = @($script:warnings | Where-Object { $_ -like '*and was terminated.*' }).Count
        SaidFailed     = @($script:warnings | Where-Object { $_ -like '*could not be terminated*' }).Count
    }
}

$script:invokeSource = (Get-Command Invoke-mdiRemoteCommand).Definition

Write-Host 'A termination that failed must not be reported as a termination that succeeded' -ForegroundColor Cyan

$threw = Invoke-Timeout -Mode 'throw'
$nonZero = Invoke-Timeout -Mode '2'
$ok = Invoke-Timeout -Mode 'ok'

Assert-That 'the terminate attempt is actually made in every case' (
    $threw.TerminateCalls -eq 1 -and $nonZero.TerminateCalls -eq 1 -and $ok.TerminateCalls -eq 1
) ("throw=$($threw.TerminateCalls) nonzero=$($nonZero.TerminateCalls) ok=$($ok.TerminateCalls)")

# --- The defect ------------------------------------------------------------------------------------
Assert-That 'a THROWING terminate is not claimed as terminated' ($threw.SaidTerminated -eq 0) (
    "warnings: $($threw.Warnings -join ' | ')")
Assert-That 'a THROWING terminate is reported as a failure' ($threw.SaidFailed -eq 1) (
    "warnings: $($threw.Warnings -join ' | ')")
Assert-That 'the throwing failure is a WARNING, not a hidden verbose line' (
    @($threw.Warnings | Where-Object { $_ -like '*access denied*' }).Count -eq 1
) ("warnings: $($threw.Warnings -join ' | ')")
Assert-That 'the failing warning names the process that survived' (
    @($threw.Warnings | Where-Object { $_ -like '*4242*' }).Count -eq 1
) ("warnings: $($threw.Warnings -join ' | ')")

Assert-That 'a NON-ZERO terminate status is not claimed as terminated' ($nonZero.SaidTerminated -eq 0) (
    "warnings: $($nonZero.Warnings -join ' | ')")
Assert-That 'a NON-ZERO terminate status is reported as a failure' ($nonZero.SaidFailed -eq 1) (
    "warnings: $($nonZero.Warnings -join ' | ')")
Assert-That 'the non-zero status value is disclosed' (
    @($nonZero.Warnings | Where-Object { $_ -like '*returned 2*' }).Count -eq 1
) ("warnings: $($nonZero.Warnings -join ' | ')")

# --- The control that must NOT be broken -------------------------------------------------------------
Assert-That 'CONTROL: a SUCCESSFUL terminate still says it was terminated' ($ok.SaidTerminated -eq 1) (
    "warnings: $($ok.Warnings -join ' | ')")
Assert-That 'CONTROL: a SUCCESSFUL terminate raises no failure warning' ($ok.SaidFailed -eq 0) (
    "warnings: $($ok.Warnings -join ' | ')")
Assert-That 'CONTROL: exactly one warning is raised in each case' (
    $threw.Warnings.Count -eq 1 -and $nonZero.Warnings.Count -eq 1 -and $ok.Warnings.Count -eq 1
) ("throw=$($threw.Warnings.Count) nonzero=$($nonZero.Warnings.Count) ok=$($ok.Warnings.Count)")

# ===================================================================================================
# PART 2 - the -SkipNetworkPorts ignored-parameter guard, read from the shipped source
# ===================================================================================================
Write-Host ''
Write-Host '-SkipNetworkPorts must name every parameter it discards' -ForegroundColor Cyan

# The guard lives in #region Main, which cannot be executed here without running a whole scan, so the
# LIST ITSELF is asserted. That is the thing that regressed: a parameter was simply absent from it.
$guardStart = $text.IndexOf('if ($SkipNetworkPorts) {')
Assert-That 'the SkipNetworkPorts guard still exists' ($guardStart -gt 0) 'guard block not found'
$guardEnd = $text.IndexOf('will have no effect on this run.', $guardStart)
Assert-That 'the guard still emits its warning' ($guardEnd -gt $guardStart) 'warning not found after the guard'
$guard = if ($guardStart -gt 0 -and $guardEnd -gt $guardStart) { $text.Substring($guardStart, $guardEnd - $guardStart) } else { '' }

Assert-That 'the guard names -WorkspaceName' ($guard -match "'-WorkspaceName'") (
    'the guard does not list -WorkspaceName, so a workspace name is accepted and silently discarded')
# Guarded on content, not just presence: an entry whose Set expression is hard-coded would list the
# parameter on every run, including runs that never passed it.
Assert-That 'the -WorkspaceName entry is conditional on the value being supplied' (
    $guard -match "'-WorkspaceName';\s*Set\s*=\s*-not \[string\]::IsNullOrWhiteSpace\(\`$WorkspaceName\)"
) 'the -WorkspaceName entry is not gated on the parameter actually being set'

# CONTROLS: the parameters that were already covered must stay covered.
foreach ($p in '-NnrTargetComputer', '-TestVpnRadius', '-MultiForest', '-PortProbeTimeoutMs', '-MaxNnrTargets', '-MaxLdapTargetsPerDomain') {
    Assert-That ("CONTROL: the guard still names $p") ($guard -match ([regex]::Escape("'$p'"))) (
        "$p was dropped from the ignored-parameter list")
}
# And -WorkspaceName must be consumed by exactly the thing -SkipNetworkPorts bypasses; if it ever
# gains a second consumer this guard becomes wrong and must be revisited.
$callSites = @([regex]::Matches($text, '-WorkspaceName \$WorkspaceName')).Count
Assert-That 'WorkspaceName still has exactly one consumer (the probe plan)' ($callSites -eq 1) (
    "found $callSites call sites passing -WorkspaceName")

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
