<#
    A domain controller the directory could not NAME must not vanish from the inventory.

    Resolve-mdiDomainController counts the records a directory returned but could not name, in
    `Unnamed`. The per-domain readiness pass already emits one placeholder row per unnamed record
    ("Domain controller (not named) N of M"), but the server inventory only ever emitted rows for
    NAMED servers, so the two surfaces disagreed about the size of the same domain in a run where
    nothing failed:

        producer   Servers=2  Unnamed=2      (enumeration SUCCEEDED, Error=$null)
        inventory  2 rows
        readiness  4 rows
        console    "Found 2 domain controller(s) in 1 domain(s)"

    The unresolvable-address branch a few lines above states the rule this violated:

        "A domain controller vanishing from the inventory is the most damaging outcome this tool has,
         because the report still reads as a complete scan of the estate."

    Separately, `Servers.Count -eq 0` was treated as a failed enumeration even when the directory had
    ANSWERED with records that merely had no usable name. That produced the warning "Unable to
    enumerate the domain controllers of contoso.com over Active Directory Web Services or LDAP: "
    with nothing after the colon (there was no error to interpolate), and collapsed the whole domain
    into a single Enumerated=$false row, losing the records entirely.

    What a fix must NOT break, asserted here as controls:
      * a domain whose enumeration genuinely FAILED must still be one Enumerated=$false row carrying
        the real error - it must not be silently converted into "zero unnamed records";
      * a domain with no unnamed records must be completely unchanged;
      * the unnamed rows must carry no address, so the port-probe planner still has nothing to target.
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
$script:warnings = New-Object System.Collections.ArrayList
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) [void] $script:warnings.Add([string] $Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

# The producer is stubbed, but only at Resolve-mdiDomainController - the inventory builder under test
# runs for real. Every address resolves to one usable IP so nothing is dropped for an unrelated reason.
$script:resolveResult = $null
Set-Item -Path function:script:Resolve-mdiDomainController -Value {
    param($Domain)
    $script:resolveResult
}
Set-Item -Path function:script:Get-mdiComputerAddress -Value {
    param($ComputerName, $KnownAddress)
    if ([string]::IsNullOrWhiteSpace([string] $ComputerName)) { return @() }
    @('10.0.0.99')
}

function New-Dc { param([string] $Name) [PSCustomObject]@{ Name = $Name; IP = $null; Addresses = @() } }

function Get-Inventory {
    param($Servers, [int] $Unnamed, $Method = 'LDAP', $ErrorText = $null)
    $script:warnings.Clear()
    $script:resolveResult = [PSCustomObject]@{
        Servers = @($Servers); Method = $Method; Error = $ErrorText; Unnamed = $Unnamed
    }
    @(Get-mdiDomainControllerInventory -Domain @('contoso.com'))
}

# Confirm the function under test exists under the name this file drives.
Assert-That 'the inventory builder is present' ($null -ne (Get-Command Get-mdiDomainControllerInventory -ErrorAction SilentlyContinue))

Write-Host "`n[1] Control: named controllers only - unchanged" -ForegroundColor Yellow
$rows = Get-Inventory -Servers @((New-Dc 'dc1.contoso.com'), (New-Dc 'dc2.contoso.com')) -Unnamed 0
Assert-That 'two named controllers give two rows' (@($rows).Count -eq 2) "(got $(@($rows).Count))"
Assert-That '  both are enumerated' (@($rows | Where-Object { $_.Enumerated -eq $true }).Count -eq 2)
Assert-That '  and none carries an error' (@($rows | Where-Object { $_.Error }).Count -eq 0)

Write-Host "`n[2] Control: a genuinely failed enumeration is still one unenumerated row" -ForegroundColor Yellow
$rows = Get-Inventory -Servers @() -Unnamed 0 -Method 'None' -ErrorText 'the server is not operational'
Assert-That 'a failed enumeration gives exactly one row' (@($rows).Count -eq 1) "(got $(@($rows).Count))"
Assert-That '  it is NOT enumerated' (@($rows)[0].Enumerated -eq $false) "(got '$(@($rows)[0].Enumerated)')"
Assert-That '  it carries the real error' ([string] (@($rows)[0].Error) -eq 'the server is not operational') "(got '$(@($rows)[0].Error)')"

Write-Host "`n[3] Named AND unnamed - every record appears" -ForegroundColor Yellow
$rows = Get-Inventory -Servers @((New-Dc 'dc1.contoso.com'), (New-Dc 'dc2.contoso.com')) -Unnamed 2
Assert-That 'two named + two unnamed give four rows' (@($rows).Count -eq 4) "(got $(@($rows).Count))"
$unnamedRows = @($rows | Where-Object { [string]::IsNullOrWhiteSpace([string] $_.Name) })
Assert-That '  two of them are unnamed' ($unnamedRows.Count -eq 2) "(got $($unnamedRows.Count))"
Assert-That '  the unnamed rows carry NO address' (@($unnamedRows | Where-Object { $_.IP }).Count -eq 0)
Assert-That '  the unnamed rows are marked enumerated (the directory answered)' (@($unnamedRows | Where-Object { $_.Enumerated -eq $true }).Count -eq 2)
Assert-That '  each unnamed row explains itself' (@($unnamedRows | Where-Object { [string] $_.Error -match 'neither a DNS host name nor a name' }).Count -eq 2) `
    "(errors='$(($unnamedRows | ForEach-Object { $_.Error }) -join ' | ')')"
Assert-That '  and they are attributed to the domain' (@($unnamedRows | Where-Object { $_.Domain -eq 'contoso.com' }).Count -eq 2)

Write-Host "`n[4] ALL records unnamed - an answered directory is not a failed enumeration" -ForegroundColor Yellow
$rows = Get-Inventory -Servers @() -Unnamed 3
Assert-That 'three unnamed records give three rows' (@($rows).Count -eq 3) "(got $(@($rows).Count))"
Assert-That '  none is reported as a failed enumeration' (@($rows | Where-Object { $_.Enumerated -eq $false }).Count -eq 0)
Assert-That '  every row explains itself' (@($rows | Where-Object { [string] $_.Error -match 'neither a DNS host name nor a name' }).Count -eq 3)
$blankColon = @($script:warnings | Where-Object { $_ -match 'Web Services or LDAP:\s*$' })
Assert-That '  no warning trails off after the colon' ($blankColon.Count -eq 0) "(warnings='$($script:warnings -join ' | ')')"

Write-Host "`n[5] The inventory size matches what the producer said the estate was" -ForegroundColor Yellow
foreach ($case in @(
        @{ Named = 0; Unnamed = 2 }, @{ Named = 0; Unnamed = 3 },
        @{ Named = 2; Unnamed = 2 }, @{ Named = 1; Unnamed = 1 }, @{ Named = 3; Unnamed = 0 })) {
    # 1..0 counts DOWN in PowerShell and yields @(1,0), which would fabricate a phantom controller
    # for the zero-named cases and make this loop measure the wrong estate entirely.
    $servers = @()
    if ($case.Named -gt 0) { $servers = @(1..$case.Named | ForEach-Object { New-Dc ("dc$_.contoso.com") }) }
    $rows = Get-Inventory -Servers $servers -Unnamed $case.Unnamed
    $expected = $case.Named + $case.Unnamed
    Assert-That ("named={0} unnamed={1} -> {2} rows" -f $case.Named, $case.Unnamed, $expected) `
    (@($rows).Count -eq $expected) "(got $(@($rows).Count))"
}

Write-Host ''
Write-Host ("================ {0} passed / {1} failed ================" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
