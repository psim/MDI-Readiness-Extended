<#
    A finding the generated script cannot fix must never be silently claimed as fixed.

    The remediation generator emits target lists through $litList, which drops any name that is not a
    usable remoting target. Coverage - the record of which findings a scripted section handles, and
    therefore which findings the closing advisory may omit - was recorded separately and unconditionally.
    The two disagreed, and the disagreement was silent in the worst possible direction:

        a High severity "NTLM Auditing check failed" for a server whose FQDN was empty produced
            #region NTLM auditing
            foreach ($computer in @(
                                          <- nothing, because $litList refused the name
            )) { ... }
        and then, because the finding had been marked covered, no "Findings that need manual attention"
        entry either, and the script closed
            Write-Host 'Remediation complete. Re-run Test-MdiReadiness.ps1 to verify.'

    So the operator ran a script that changed nothing, was told it had completed, and the finding
    appeared nowhere. Coverage is now claimed through one helper that applies the same rule $litList
    applies, so a finding can only be called covered if a target for it was actually emitted.

    These tests assert the CONTENT of the generated script - the region, the emitted target, the
    advisory and the closing banner - not the source text of the generator.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

$outDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi-remed-cover-' + [guid]::NewGuid().ToString('N'))
[void] (New-Item -ItemType Directory -Force -Path $outDir)

function Get-Generated {
    param([string] $Fqdn)
    $data = [PSCustomObject]@{
        Domain              = 'contoso.com'
        DomainControllers   = @([PSCustomObject]@{
                FQDN            = $Fqdn
                OperatingSystem = 'Windows Server 2022'
                NtlmAuditing    = $false
                Details         = [PSCustomObject]@{}
            })
        CAServers           = @()
        EntraConnectServers = @()
        Domains             = @()
    }
    $path = Join-Path $outDir ('r-' + [guid]::NewGuid().ToString('N') + '.ps1')
    $result = New-mdiRemediationScript -ReportData $data -FilePath $path
    [PSCustomObject]@{
        Body     = [IO.File]::ReadAllText($path)
        Sections = $result.SectionCount
    }
}

try {
    Write-Host 'The control: a real server with a real failure is still fixed by the script' -ForegroundColor Cyan
    $ok = Get-Generated -Fqdn 'dc1.contoso.com'
    # If this breaks, the generator has stopped doing its job and nothing below means anything.
    Assert-That 'a scripted NTLM section is emitted' ($ok.Body -match '#region NTLM auditing') 'no NTLM region'
    Assert-That '  ...and the server is in the emitted target list' ($ok.Body -match "'dc1\.contoso\.com'") 'FQDN not emitted'
    Assert-That '  ...and the loop is not empty' ($ok.Body -notmatch "foreach \(\`$computer in @\(\s*\r?\n\s*\r?\n\s*\)\)") 'empty foreach'
    Assert-That '  ...and the finding is NOT repeated as manual attention' ($ok.Body -notmatch 'Findings that need manual attention') 'advisory repeated a fixed finding'
    Assert-That '  ...and the script may close "Remediation complete"' ($ok.Body -match 'Remediation complete\.') 'banner missing'

    Write-Host 'A finding whose server cannot be addressed is surfaced, not silently dropped' -ForegroundColor Cyan
    foreach ($bad in @{ Name = 'an empty FQDN'; Value = '' }, @{ Name = 'a whitespace-only FQDN'; Value = '   ' }) {
        $g = Get-Generated -Fqdn $bad.Value
        # The generated script must still PARSE - it is run by an administrator against production DCs.
        $err = $null; $tok = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($g.Body, [ref]$tok, [ref]$err)
        Assert-That "$($bad.Name): the generated script still parses" (@($err).Count -eq 0) "parse errors: $(@($err).Count)"

        # The name must never be emitted as a live remoting target. Inspect the target list itself
        # rather than the whole file, so an unrelated quoted space elsewhere cannot mask the check.
        $targetBlocks = @([regex]::Matches($g.Body, 'foreach \(\$computer in @\(([\s\S]*?)\)\) \{') | ForEach-Object { $_.Groups[1].Value })
        $emittedBlank = @($targetBlocks | Where-Object { $_ -match "'\s*'" }).Count
        Assert-That "  ...and no blank or whitespace target is emitted" ($emittedBlank -eq 0) "a whitespace literal was emitted in $emittedBlank target list(s): $($targetBlocks -join ' | ')"

        # This is the defect: the finding must appear in the advisory...
        Assert-That "  ...and the finding is listed for manual attention" ($g.Body -match 'Findings that need manual attention') 'the finding vanished from the advisory'
        # ...and the script must NOT claim it finished the job.
        Assert-That "  ...and the script does not claim 'Remediation complete'" ($g.Body -notmatch 'Remediation complete\.') 'claimed complete with an unhandled finding'
        Assert-That "  ...and does not claim no remediation was required" ($g.Body -notmatch 'No remediation is required') 'claimed nothing was required'
    }

    Write-Host 'A healthy estate still reports that nothing needs doing' -ForegroundColor Cyan
    $clean = [PSCustomObject]@{
        Domain              = 'contoso.com'
        DomainControllers   = @([PSCustomObject]@{
                FQDN            = 'dc1.contoso.com'
                OperatingSystem = 'Windows Server 2022'
                NtlmAuditing    = $true
                Details         = [PSCustomObject]@{}
            })
        CAServers           = @()
        EntraConnectServers = @()
        Domains             = @()
    }
    $cleanPath = Join-Path $outDir 'clean.ps1'
    $cleanResult = New-mdiRemediationScript -ReportData $clean -FilePath $cleanPath
    $cleanBody = [IO.File]::ReadAllText($cleanPath)
    Assert-That 'a passing estate generates no sections' ($cleanResult.SectionCount -eq 0) "got $($cleanResult.SectionCount)"
    Assert-That '  ...and says no remediation is required' ($cleanBody -match 'No remediation is required') 'banner missing'
    Assert-That '  ...and raises no manual-attention advisory' ($cleanBody -notmatch 'Findings that need manual attention') 'spurious advisory'
} finally {
    Remove-Item -Path $outDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
