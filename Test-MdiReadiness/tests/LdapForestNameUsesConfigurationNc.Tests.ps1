<#
    The forest identity must be read from configurationNamingContext, not guessed from the domain list.

    When rootDomainNamingContext is absent from the RootDSE, discovery fell back to choosing a name out
    of the domains it had already collected, and the shortest one won. An estate rooted at
    actual-root-domain.example was therefore reported as the forest x.io, because a secondary tree root
    had a shorter name. Nothing about that substitution is disclosed, so every later verdict is filed
    against a forest identity nobody measured, and the run's account of what it examined is not honest.

    Pinned here: configurationNamingContext identifies the forest when rootDomainNamingContext is
    missing, a shorter secondary tree root does not steal the forest identity, and all tree roots and
    child domains stay in scope with no record lost. Controls confirm the explicit
    rootDomainNamingContext path is unchanged.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$target = [IO.Path]::GetFullPath($target)
$text = [IO.File]::ReadAllText($target)
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$cut = $body.IndexOf('#region Main')
if ($cut -gt 0) { $body = $body.Substring(0, $cut) }
Invoke-Expression $body

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:passed++
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGray
    } else {
        $script:failed++
        Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red
    }
}
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

function New-FakeDisposable {
    param($Properties)
    $object = [PSCustomObject]@{ Properties = $Properties }
    $object | Add-Member -MemberType ScriptMethod -Name Dispose -Value {} -Force
    $object
}
function New-FakeCrossRef {
    param([string] $DnsRoot)
    [PSCustomObject]@{ Properties = @{ dnsroot = @($DnsRoot) } }
}

$script:configurationNc = $null
$script:rootDomainNc = $null
$script:crossRefs = @()
$script:directoryEntryCalls = 0
$script:fakeSearcher = $null

Set-Item -Path function:script:New-Object -Value {
    param(
        [Parameter(Position = 0)] $TypeName,
        [Parameter(Position = 1)] $ArgumentList,
        $Type,
        $Property
    )
    if ([string] $TypeName -eq 'System.DirectoryServices.DirectoryEntry') {
        $script:directoryEntryCalls++
        if ($script:directoryEntryCalls -eq 1) {
            return (New-FakeDisposable -Properties @{
                    configurationNamingContext = @($script:configurationNc)
                    rootDomainNamingContext = @($script:rootDomainNc | Where-Object { $_ })
                })
        }
        return (New-FakeDisposable -Properties @{})
    }
    if ([string] $TypeName -eq 'System.DirectoryServices.DirectorySearcher') {
        $searcher = [PSCustomObject]@{
            SearchRoot = $null
            Filter = $null
            PageSize = 0
            PropertiesToLoad = ([Collections.ArrayList]::new())
        }
        $searcher | Add-Member -MemberType ScriptMethod -Name FindAll -Value { $script:crossRefs } -Force
        $searcher | Add-Member -MemberType ScriptMethod -Name Dispose -Value {} -Force
        return $searcher
    }
    throw ('Unexpected New-Object type in test: {0}' -f [string] $TypeName)
}

function Invoke-LdapForest {
    param([AllowNull()] [string] $RootDomainNc)
    $script:configurationNc = 'CN=Configuration,DC=actual-root-domain,DC=example'
    $script:rootDomainNc = $RootDomainNc
    $script:crossRefs = @(
        (New-FakeCrossRef 'actual-root-domain.example')
        (New-FakeCrossRef 'x.io')
        (New-FakeCrossRef 'child.actual-root-domain.example')
    )
    $script:directoryEntryCalls = 0
    $unnamed = -1
    $result = Get-mdiForestDomainFromLdap -Domain 'child.actual-root-domain.example' -UnnamedCount ([ref] $unnamed)
    [PSCustomObject]@{ Result = $result; Unnamed = $unnamed }
}

Write-Host 'LdapForestNameUsesConfigurationNc.Tests.ps1' -ForegroundColor Cyan

$missingRootDseProperty = Invoke-LdapForest -RootDomainNc $null
Write-Host ('  RAW missing-root={0}' -f ($missingRootDseProperty | ConvertTo-Json -Depth 6 -Compress))
Assert-True 'configurationNamingContext identifies the forest when rootDomainNamingContext is absent' (
    $missingRootDseProperty.Result.Name -eq 'actual-root-domain.example'
) ("Name={0}" -f $missingRootDseProperty.Result.Name)
Assert-True 'a shorter secondary tree root does not steal the forest identity' (
    $missingRootDseProperty.Result.Name -ne 'x.io'
) ("Name={0}" -f $missingRootDseProperty.Result.Name)
Assert-True 'all tree roots and child domains remain in scope' (
    (@($missingRootDseProperty.Result.Domains) -join ',') -eq
        'actual-root-domain.example,x.io,child.actual-root-domain.example'
) ("Domains={0}" -f (@($missingRootDseProperty.Result.Domains) -join '|'))
Assert-True 'no domain record was lost in the fixture' ($missingRootDseProperty.Unnamed -eq 0) ("Unnamed={0}" -f $missingRootDseProperty.Unnamed)

$explicitRoot = Invoke-LdapForest -RootDomainNc 'DC=actual-root-domain,DC=example'
Write-Host ('  RAW explicit-root={0}' -f ($explicitRoot | ConvertTo-Json -Depth 6 -Compress))
Assert-True 'control: rootDomainNamingContext still identifies the forest when present' (
    $explicitRoot.Result.Name -eq 'actual-root-domain.example'
) ("Name={0}" -f $explicitRoot.Result.Name)
Assert-True 'control: the complete domain list is unchanged' (
    @($explicitRoot.Result.Domains).Count -eq 3
) ("Count={0}" -f @($explicitRoot.Result.Domains).Count)

Write-Host ("RESULT: {0} passed / {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed -gt 0) { exit 1 }
