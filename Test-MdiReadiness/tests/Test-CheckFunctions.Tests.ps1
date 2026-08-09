<#
    MEASUREMENT-LAYER assertions.

    A mutation audit reintroduced ten historical defects into the script; six survived the whole
    existing suite because no test ever invoked an individual check function with realistic mock data
    and asserted the pass/fail outcome - which is exactly where a false green (READY reported for a
    broken estate) originates. These assertions drive the check functions directly with fixtures, so a
    skipped measurement can never read as a passed one.

    Every assertion here was written against a scratch copy of the script with the specific mutation
    applied, confirmed to FAIL, then confirmed to PASS once the mutation was reverted. A test that has
    not been seen to fail is not a test.
#>
$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors: $($errors -join '; ')" }

$settingsAssignment = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$settings' }, $true)[0]
. ([scriptblock]::Create($settingsAssignment.Extent.Text))
$functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
. ([scriptblock]::Create(($functions | ForEach-Object { $_.Extent.Text }) -join "`n"))
foreach ($constAst in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -like '$script:*' -and
            $null -eq $n.Parent.Parent.Parent }, $false)) {
    . ([scriptblock]::Create($constAst.Extent.Text))
}

$pass = 0; $fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; Write-Host "  PASS  $Name $Detail" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red }
}

function New-Report {
    param([object[]] $Servers, [object[]] $DomainAuditing = @(), [string[]] $Scope = @('contoso.com'))
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = $Scope
        DomainControllers = @($Servers); CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @($DomainAuditing)
        DomainAdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DomainObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
        DomainExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
        DomainDeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
    }
}

# ---------------------------------------------------------------------------------------------------
Write-Host "`n[C1] Get-mdiCAAuditing: an empty registry read is NOT MEASURED, never a pass" -ForegroundColor Yellow
# The '$details.Count -eq 0' guard turns "the registry returned nothing" into 'N/A'. Removing it let an
# empty result flow into '@(... | Where-Object {...}).Count -eq 0', which is TRUE for zero entries - so a
# server whose CA auditing could not be read at all was reported as correctly configured: a false green.
function Get-mdiRegistryValueSet {
    param($ComputerName, $ExpectedRegistrySet)
    if ($ExpectedRegistrySet -eq $settings.CASettings.RegPathActive) {
        return [PSCustomObject]@{ value = 'ContosoIssuingCA' }
    }
    return @()   # the auditing registry key could not be read
}
$caEmpty = Get-mdiCAAuditing -ComputerName 'ca1.contoso.com'
Assert-That 'an empty registry read reports N/A (not measured)' (
    [string] $caEmpty.isCaAuditingOk -eq 'N/A') "(got '$($caEmpty.isCaAuditingOk)')"
Assert-That 'an empty registry read is never reported as a pass' (
    $caEmpty.isCaAuditingOk -ne $true)
Remove-Item Function:\Get-mdiRegistryValueSet

# ---------------------------------------------------------------------------------------------------
Write-Host "`n[C2] Get-mdiReportStatistics: a null scope counts ZERO domains, not one" -ForegroundColor Yellow
# '@($null).Count' is 1, not 0. Replacing the IsNullOrWhiteSpace filter with a bare '@(...).Count' made a
# report whose DomainsInScope is null count as one in-scope domain - inflating coverage and hiding that
# nothing was actually scoped.
$statsNull = Get-mdiReportStatistics -ReportData (New-Report -Servers @() -Scope $null)
Assert-That 'a null DomainsInScope yields DomainCount 0' (
    $statsNull.DomainCount -eq 0) "(got $($statsNull.DomainCount))"
$statsTwo = Get-mdiReportStatistics -ReportData (New-Report -Servers @() -Scope @('a.contoso.com', 'b.contoso.com'))
Assert-That 'two real domains still count as two' (
    $statsTwo.DomainCount -eq 2) "(got $($statsTwo.DomainCount))"

# ---------------------------------------------------------------------------------------------------
Write-Host "`n[C3] mdiPortNotTestedPattern: the ^ anchors keep 'could not' mid-sentence a REAL failure" -ForegroundColor Yellow
# The pattern classifies a detail string as "not tested" (a gap) rather than "measured failure". Removing
# the ^ anchors let any sentence CONTAINING 'could not' / 'not tested' be reclassified as not-tested, so a
# measured "Port 135 could not be tested" (a real block) stopped counting against the verdict.
$pat = $script:mdiPortNotTestedPattern
Assert-That "'Port 135 could not be tested' (mid-sentence) is NOT classed as not-tested" (
    'Port 135 could not be tested' -notmatch $pat)
Assert-That "'Could not connect' (line start) IS classed as not-tested" (
    'Could not connect' -match $pat)
# The ten strings a live scan actually produces at a line start must all still read as not-tested.
$realNotTested = @(
    'Not tested - the registry could not be read on this server',
    'Not tested - the default naming context could not be read from rootDSE',
    'Not tested - the configuration naming context could not be read from rootDSE',
    'Not tested - the advanced auditing settings could not be read remotely',
    'Not tested - the active certification authority name could not be read from the registry',
    'Not tested - the AD FS container exists but its SACL could not be read',
    'Not tested - name resolution failed for dc1.contoso.com: No such host is known',
    'Not tested - nothing is listening on TCP 444, the sensor updater service is not installed or not running. Loopback traffic is allowed unless a custom firewall policy blocks it',
    'Not determined (the server could not be queried)',
    'Unable to acquire an exclusive lock on baseline.json within 15s; another run is writing the baseline history. Skipping the trend update for this run.'
)
Assert-That 'all ten real not-tested detail strings still classify as not-tested' (
    @($realNotTested | Where-Object { $_ -notmatch $pat }).Count -eq 0) `
    "($(@($realNotTested | Where-Object { $_ -notmatch $pat }) -join ' | '))"
# Genuinely measured failures must NOT be excused as not-tested.
$realFailures = @(
    'Blocked - no response within 5000 ms, retried and still silent',
    'Closed - connection refused',
    'The server could not be contacted.'
)
Assert-That 'three measured-failure strings are NOT classified as not-tested' (
    @($realFailures | Where-Object { $_ -match $pat }).Count -eq 0) `
    "($(@($realFailures | Where-Object { $_ -match $pat }) -join ' | '))"

# ---------------------------------------------------------------------------------------------------
Write-Host "`n[C4] Test-mdiReadinessResult: the verdict is decided from detail records, not the summary flag" -ForegroundColor Yellow
# Trusting the per-server RequiredPorts summary flag instead of the detail records let a server whose
# summary said $true but whose detail records held a measured Required-port block be called READY - the
# most expensive false green this tool can produce.
$blockedServer = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
    Unreachable = $false; PartialFailure = $false; AdvancedAuditing = $true; SensorVersion = '2.0'
    RequiredPorts = $true
    Details = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = @(
                [PSCustomObject]@{ Id = 'Ldap'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389; Scope = 'DomainController'
                    Group = 'Ports'; Requirement = 'Required'; Target = 'dc1'; TargetIP = '10.0.0.1'
                    Applicable = $true; Success = $false
                    Detail = 'Blocked - no response within 5000 ms, retried and still silent' }
            ) } }
}
$blockedReport = New-Report -Servers @($blockedServer)
Assert-That 'a measured Required-port block fails the verdict despite RequiredPorts=$true' (
    (Test-mdiReadinessResult -ReportData $blockedReport) -eq $false)
$blockedStats = Get-mdiReportStatistics -ReportData $blockedReport
Assert-That 'and it raises a finding' (
    @(Get-mdiIssueList -Statistics $blockedStats -ReportData $blockedReport).Count -gt 0)

# Companion: an AtLeastOne (NNR) group where one member SUCCEEDS must stay READY and not block.
$nnrServer = [PSCustomObject]@{
    FQDN = 'dc2.contoso.com'; Domain = 'contoso.com'; IP = '10.0.0.2'; Addresses = @('10.0.0.2')
    Unreachable = $false; PartialFailure = $false; AdvancedAuditing = $true; SensorVersion = '2.0'
    RequiredPorts = $true
    Details = [ordered]@{ RequiredPortsDetails = [PSCustomObject]@{ Results = @(
                [PSCustomObject]@{ Id = 'NnrRpc'; Name = 'NNR-RPC'; Protocol = 'TCP'; Port = 135; Scope = 'NetworkDevice'
                    Group = 'NNR'; Requirement = 'AtLeastOne'; Target = 'wks1'; TargetIP = '10.0.0.50'
                    Applicable = $true; Success = $true; Detail = 'Resolved' }
                [PSCustomObject]@{ Id = 'NnrNb'; Name = 'NNR-NetBIOS'; Protocol = 'UDP'; Port = 137; Scope = 'NetworkDevice'
                    Group = 'NNR'; Requirement = 'AtLeastOne'; Target = 'wks1'; TargetIP = '10.0.0.50'
                    Applicable = $true; Success = $false
                    Detail = 'Blocked - no response within 5000 ms, retried and still silent' }
            ) } }
}
Assert-That 'an NNR group with one success keeps the run READY' (
    (Test-mdiReadinessResult -ReportData (New-Report -Servers @($nnrServer))) -eq $true)
$nnrRecords = Get-mdiPortResultRecord -Server @($nnrServer)
Assert-That 'and that NNR group produces no blocking failure' (
    @(Get-mdiBlockingPortFailure -Record $nnrRecords).Count -eq 0) `
    "(got $(@(Get-mdiBlockingPortFailure -Record $nnrRecords).Count))"

# ---------------------------------------------------------------------------------------------------
Write-Host "`n[C5] Get-mdiObjectAuditing: coverage is checked per EXPECTED entry, not by counting applied ACEs" -ForegroundColor Yellow
# Iterating the APPLIED ACEs and comparing counts let N duplicate ACEs that all cover ONE expected entry
# produce a match count of N - satisfying "N expected entries" while N-1 expected entries had no auditing
# at all (a false green), and made two valid ACEs for one entry read as a mismatch (2 -ne 1, a false red
# that could never pass). The fix iterates the expected entries and asserts each is covered by >=1 ACE.

# First, the real Get-mdiDsSacl null-SACL branch: a descriptor whose SACL was stripped (no S: section)
# must report N/A, never a measured pass or fail.
$expectedAuditing = @($settings.ObjectAuditing | ConvertFrom-Csv |
        Select-Object SecurityIdentifier, AccessMask, AuditFlagsValue, InheritedObjectAceType |
        Where-Object { $_.InheritedObjectAceType -ne '0feb936f-47b3-49f2-9386-1dedc2c23765' })
$script:fakeDescriptorBytes = $null
function New-Object {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$TypeName, [Parameter(Position = 1)][object[]]$ArgumentList,
        [object]$Property, [string]$ComObject, [switch]$Strict)
    if ($TypeName -like '*DirectorySearcher*') {
        $s = [PSCustomObject]@{ CacheResults = $false; SearchScope = $null; ReferralChasing = $null
            SecurityMasks = $null; PropertiesToLoad = (Microsoft.PowerShell.Utility\New-Object System.Collections.ArrayList) }
        Add-Member -InputObject $s.PropertiesToLoad -MemberType ScriptMethod -Name AddRange -Value { param($x) } -Force
        Add-Member -InputObject $s -MemberType ScriptMethod -Name FindOne -Value {
            $props = @{}
            if ($null -ne $script:fakeDescriptorBytes) { $props['ntsecuritydescriptor'] = @(, $script:fakeDescriptorBytes) }
            [PSCustomObject]@{ Properties = $props }
        }
        Add-Member -InputObject $s -MemberType ScriptMethod -Name Dispose -Value { }
        return $s
    }
    return Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}
$sdNoSacl = New-Object System.Security.AccessControl.RawSecurityDescriptor('O:BAG:BAD:(A;;FA;;;WD)')
$noSaclBytes = New-Object byte[] $sdNoSacl.BinaryLength
$sdNoSacl.GetBinaryForm($noSaclBytes, 0)
$script:fakeDescriptorBytes = $noSaclBytes
$saclNull = Get-mdiDsSacl -LdapPath 'LDAP://contoso.com' -ExpectedAuditing $expectedAuditing
Assert-That 'a null SystemAcl (stripped SACL) reports N/A, not measured' (
    [string] $saclNull.isAuditingOk -eq 'N/A' -and $saclNull.Measured -eq $false) `
    "(got '$($saclNull.isAuditingOk)', Measured=$($saclNull.Measured))"
Remove-Item Function:\New-Object

# Now the coverage loop itself, via Get-mdiObjectAuditing with Get-mdiDsSacl shadowed to return applied ACEs.
function New-mdiAce {
    param($e)
    [PSCustomObject]@{ SecurityIdentifier = $e.SecurityIdentifier; AccessMask = $e.AccessMask
        AuditFlagsValue = $e.AuditFlagsValue; InheritedObjectAceType = $e.InheritedObjectAceType }
}
$script:fakeApplied = @()
function Get-mdiDsSacl {
    param($LdapPath, $ExpectedAuditing)
    [PSCustomObject]@{ isAuditingOk = $true; Measured = $true; details = $script:fakeApplied }
}
# A complete SACL covering every expected entry yields $true.
$script:fakeApplied = @($expectedAuditing | ForEach-Object { New-mdiAce $_ })
$complete = Get-mdiObjectAuditing -Domain 'nonexistent.invalid.test' -DomainSchemaVersion 0
Assert-That 'a SACL covering every expected entry is a pass' (
    $complete.isObjectAuditingOk -eq $true) "(got '$($complete.isObjectAuditingOk)')"
# N duplicate ACEs (one per expected entry) all covering ONE expected entry, the rest uncovered, is a
# FAIL. Counting applied ACEs makes this N matches for N expected entries - a false green.
$script:fakeApplied = @(1..($expectedAuditing.Count) | ForEach-Object { New-mdiAce $expectedAuditing[0] })
$dupes = Get-mdiObjectAuditing -Domain 'nonexistent.invalid.test' -DomainSchemaVersion 0
Assert-That 'duplicate ACEs for one entry do not fake full coverage' (
    $dupes.isObjectAuditingOk -eq $false) "(got '$($dupes.isObjectAuditingOk)')"
# Full coverage PLUS a second valid ACE for one entry is still a pass (the old false red).
$script:fakeApplied = @(@($expectedAuditing | ForEach-Object { New-mdiAce $_ }) + (New-mdiAce $expectedAuditing[0]))
$twoAce = Get-mdiObjectAuditing -Domain 'nonexistent.invalid.test' -DomainSchemaVersion 0
Assert-That 'two valid ACEs matching one entry still pass' (
    $twoAce.isObjectAuditingOk -eq $true) "(got '$($twoAce.isObjectAuditingOk)')"
# The tri-state from Get-mdiDsSacl is honoured: a not-measured SACL stays N/A.
function Get-mdiDsSacl {
    param($LdapPath, $ExpectedAuditing)
    [PSCustomObject]@{ isAuditingOk = 'N/A'; Measured = $false; details = 'Not tested - the SACL was not returned.' }
}
$objNa = Get-mdiObjectAuditing -Domain 'nonexistent.invalid.test' -DomainSchemaVersion 0
Assert-That 'a not-measured SACL keeps object auditing N/A' (
    [string] $objNa.isObjectAuditingOk -eq 'N/A') "(got '$($objNa.isObjectAuditingOk)')"
Remove-Item Function:\Get-mdiDsSacl
Remove-Item Function:\New-mdiAce

# ---------------------------------------------------------------------------------------------------
Write-Host "`n[C6] New-mdiRemediationScript: report data cannot break out of a generated comment" -ForegroundColor Yellow
# The $cmt helper neutralises '#>' and '<#' so a value on a comment line cannot terminate the block
# comment and drop the remainder into the file as live code. Removing that neutralisation let an
# attacker-controlled field (a domain name, server FQDN, Deleted Objects DN or detail string) inject a
# command into a script the operator has been told to run. The generated script must PARSE CLEANLY and
# contain no command originating from the injected text. The generated script is NEVER executed.
$inj = 'Not tested #> Get-Process'
$injOpen = 'evil <# Get-Process'
$injDc = [PSCustomObject]@{ FQDN = ('dc1.contoso.com ' + $inj); Domain = 'contoso.com'; IP = '10.0.0.1'
    Addresses = @('10.0.0.1'); Unreachable = $false; PartialFailure = $false; AdvancedAuditing = $false
    SensorVersion = '2.0'; RequiredPorts = $true; Details = [ordered]@{} }
$injReport = [PSCustomObject]@{
    Domain = ('contoso.com ' + $inj); Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers = @($injDc); CAServers = @(); EntraConnectServers = @()
    DomainAuditing = @([PSCustomObject]@{
            Domain = ('contoso.com ' + $injOpen)
            DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = 'False'
                details = [PSCustomObject]@{ Detail = $inj; Container = ('CN=Deleted Objects,DC=contoso ' + $injOpen) } }
        })
}
$genPath = Join-Path $PSScriptRoot ('_CheckFunctions_remediation_{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
try {
    New-mdiRemediationScript -ReportData $injReport -FilePath $genPath | Out-Null
    $genTokens = $null; $genErrors = $null
    $genAst = [System.Management.Automation.Language.Parser]::ParseFile($genPath, [ref]$genTokens, [ref]$genErrors)
    Assert-That 'the generated remediation script parses with zero errors' (
        @($genErrors).Count -eq 0) "(got $(@($genErrors).Count))"
    $commandNames = @($genAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() })
    Assert-That 'no injected command escaped into the AST' (
        @($commandNames | Where-Object { $_ -eq 'Get-Process' }).Count -eq 0) `
        "(injected commands found: $(@($commandNames | Where-Object { $_ -eq 'Get-Process' }).Count))"
} finally {
    Remove-Item $genPath -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------------------------------
Write-Host "`n[C7] Get-mdiCertReadiness: an expired root is a FAIL, an unreadable store is NOT MEASURED" -ForegroundColor Yellow
# A required root certificate that has expired is a genuine readiness failure; a store that could not be
# opened is a gap, not a pass. The check must distinguish measured-bad ($false), measured-good ($true)
# and not-measured ('N/A') - never collapse a matched-but-expired root, or an unreadable store, into a pass.
$now = Get-Date
$script:fakeCerts = @()
$script:storeThrows = $false
function New-Object {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$TypeName, [Parameter(Position = 1)][object[]]$ArgumentList,
        [object]$Property, [string]$ComObject, [switch]$Strict)
    if ($TypeName -like '*X509Store*') {
        $store = [PSCustomObject]@{}
        Add-Member -InputObject $store -MemberType NoteProperty -Name Certificates -Value $script:fakeCerts
        Add-Member -InputObject $store -MemberType ScriptMethod -Name Open -Value { if ($script:storeThrows) { throw 'Access is denied.' } }
        Add-Member -InputObject $store -MemberType ScriptMethod -Name Close -Value { }
        return $store
    }
    return Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}
$settings.RootCertificates = @('AAAA_VALID', 'BBBB_EXPIRED')
$script:storeThrows = $false
$script:fakeCerts = @([PSCustomObject]@{ Thumbprint = 'BBBB_EXPIRED'; Subject = 'CN=Old Root'; Issuer = 'CN=Old Root'
        NotBefore = $now.AddDays(-800); NotAfter = $now.AddDays(-1) })
$certExpired = Get-mdiCertReadiness -ComputerName 'dc1.contoso.com'
Assert-That 'an expired required root fails' (
    $certExpired.isRootCertificatesOk -eq $false) "(got '$($certExpired.isRootCertificatesOk)')"
$script:fakeCerts = @([PSCustomObject]@{ Thumbprint = 'AAAA_VALID'; Subject = 'CN=Good Root'; Issuer = 'CN=Good Root'
        NotBefore = $now.AddDays(-100); NotAfter = $now.AddDays(400) })
$certValid = Get-mdiCertReadiness -ComputerName 'dc1.contoso.com'
Assert-That 'a valid required root passes' (
    $certValid.isRootCertificatesOk -eq $true) "(got '$($certValid.isRootCertificatesOk)')"
$script:storeThrows = $true
$certUnread = Get-mdiCertReadiness -ComputerName 'dc1.contoso.com'
Assert-That 'an unreadable certificate store is N/A (not measured)' (
    [string] $certUnread.isRootCertificatesOk -eq 'N/A') "(got '$($certUnread.isRootCertificatesOk)')"
Remove-Item Function:\New-Object

Write-Host "`n================ $pass passed / $fail failed ================" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
