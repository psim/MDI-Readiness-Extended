<#
    "I could not read whether this requirement applies" is not "this requirement does not apply".

    Get-mdiObjectAuditing compares the domain-root SACL against a fixed set of expected audit ACEs.
    One of them - the delegated Managed Service Account entry - only applies where that class exists
    in the schema, so the function first decides APPLICABILITY, by looking for the class and falling
    back to the domain schema version.

    That decision was a BOOLEAN initialised to $false, which made two completely different facts
    indistinguishable:

        the class was looked up and is genuinely absent   ->  five ACEs are required   (correct)
        the schema could not be read at all               ->  five ACEs are required   (a guess)

    So when the schema property was unreadable the sixth requirement was silently DELETED from the
    expected set, the remaining five were compared, and the result was published as a MEASURED pass.
    Measured on the shipped producer with schemaNamingContext unreadable and no schema version
    available:

        status=True  Measured=True  expectedACE=5  11/11 checks  0 unread  score 100%  READY=True

    A domain that is genuinely missing dMSA auditing therefore earned a green measured pass PRECISELY
    BECAUSE a read failed. The requirement disappeared, so the issue disappeared with it.

    Applicability must itself be tri-state. This file pins that:
      * class readable, or schema version known  -> answered, in either direction, exactly as before
      * neither readable                         -> N/A / Measured=$false, NO SACL assertion at all

    The two known-version controls exist so that a future "simplification" back to a boolean cannot
    pass by making everything N/A either.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

# [adsi] is a type accelerator, not a function, so Set-Item function:script: cannot reach it. The
# accelerator is repointed at a fake ROOTDSE for the lifetime of this test and restored in the
# finally block. It answers with a usable defaultNamingContext and an UNREADABLE schemaNamingContext,
# which is the real-world shape: the domain NC is world-readable, the schema property may not be.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Globalization;

public sealed class SchemaTriStateAdsiValue {
    public object Value { get; set; }
    public SchemaTriStateAdsiValue(object value) { Value = value; }
}

[TypeConverter(typeof(SchemaTriStateAdsiConverter))]
public sealed class SchemaTriStateAdsi {
    public SchemaTriStateAdsiValue schemaNamingContext { get; private set; }
    public SchemaTriStateAdsiValue defaultNamingContext { get; private set; }
    public SchemaTriStateAdsi(string path) {
        schemaNamingContext = new SchemaTriStateAdsiValue(null);
        defaultNamingContext = new SchemaTriStateAdsiValue("DC=contoso,DC=com");
    }
    public void Dispose() {}
}

public sealed class SchemaTriStateAdsiConverter : TypeConverter {
    public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
        return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
    }
    public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
        string s = value as string;
        if (s != null) { return new SchemaTriStateAdsi(s); }
        return base.ConvertFrom(context, culture, value);
    }
}
'@ -ErrorAction SilentlyContinue

$accelerators = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
$originalAdsi = $accelerators::Get['adsi']
[void] $accelerators::Remove('adsi')
[void] $accelerators::Add('adsi', [SchemaTriStateAdsi])

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

try {
    $body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
    $idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
    Invoke-Expression $body
    Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
    Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

    # Records how many expected ACEs the SACL comparison was asked for, and whether it was called at
    # all. "Not called" is the whole point of the unknown case: no assertion may be made.
    $script:saclCalls = 0
    $script:saclExpectedCount = -1
    Set-Item -Path function:script:Get-mdiDsSacl -Value {
        param($LdapPath, $ExpectedAuditing)
        $script:saclCalls++
        $script:saclExpectedCount = @($ExpectedAuditing).Count
        # A domain that satisfies every ACE it is ASKED about. With the dMSA entry wrongly dropped
        # this is a false green; with it correctly required it is a true green.
        [PSCustomObject]@{ isAuditingOk = $true; details = @($ExpectedAuditing) }
    }

    function New-PassingDc {
        $o = [PSCustomObject]@{
            FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
            Comment = $null; Details = [ordered]@{}
        }
        foreach ($n in 'NtlmAuditing', 'AdvancedAuditing', 'PowerSettings', 'TimeSync', 'SensorHealth', 'RootCertificates', 'CapacitySufficient') {
            $o | Add-Member -NotePropertyName $n -NotePropertyValue $true -Force
        }
        $o
    }

    function Get-Facts {
        param([int] $SchemaVersion)
        $script:saclCalls = 0
        $script:saclExpectedCount = -1
        $result = Get-mdiObjectAuditing -Domain 'contoso.com' -DomainSchemaVersion $SchemaVersion 3>$null 4>$null
        $report = [PSCustomObject]@{
            DomainControllers    = @(New-PassingDc)
            CAServers            = @()
            EntraConnectServers  = @()
            DomainsInScope       = @('contoso.com')
            ForestDiscovery      = [PSCustomObject]@{ Complete = $true }
            DomainObjectAuditing = $result
        }
        $st = Get-mdiReportStatistics -ReportData $report
        [PSCustomObject]@{
            Status       = $result.isObjectAuditingOk
            Measured     = $result.Measured
            Details      = $result.details
            SaclCalls    = $script:saclCalls
            ExpectedACEs = $script:saclExpectedCount
            Unread       = [int] $st.ChecksUnread
            Passed       = [int] $st.ChecksPassed
            Total        = [int] $st.ChecksTotal
            Verdict      = (Test-mdiReadinessResult -ReportData $report 3>$null)
            Issues       = @(Get-mdiIssueList -Statistics $st -ReportData $report)
        }
    }

    Write-Host 'Unknown dMSA applicability must not delete the requirement and call it a pass' -ForegroundColor Cyan

    # Schema unreadable AND no usable schema version: the question is genuinely unanswered.
    $unknown = Get-Facts -SchemaVersion 0
    # Known pre-dMSA schema: answered NO. Five ACEs, exactly as before.
    $knownOld = Get-Facts -SchemaVersion 88
    # Known dMSA-era schema: answered YES. Six ACEs, exactly as before.
    $knownNew = Get-Facts -SchemaVersion 90

    # --- The defect -------------------------------------------------------------------------------
    Assert-That 'unknown applicability is not reported as a measured pass' (
        "$($unknown.Status)" -ne 'True'
    ) ("status=$($unknown.Status)")
    Assert-That 'unknown applicability reports N/A' (
        [string] $unknown.Status -eq 'N/A'
    ) ("status=$($unknown.Status)")
    Assert-That 'unknown applicability is flagged unmeasured' (
        $unknown.Measured -eq $false
    ) ("Measured=$($unknown.Measured)")
    Assert-That 'unknown applicability makes NO SACL assertion at all' (
        $unknown.SaclCalls -eq 0
    ) ("the SACL was compared $($unknown.SaclCalls) time(s) on an unknown requirement set")
    Assert-That 'unknown applicability is charged as unread' (
        $unknown.Unread -ge 1
    ) ("unread=$($unknown.Unread)")
    Assert-That 'unknown applicability refuses READY' (
        -not $unknown.Verdict
    ) ("verdict=$($unknown.Verdict)")
    Assert-That 'unknown applicability raises a finding' (
        $unknown.Issues.Count -ge 1
    ) ("got $($unknown.Issues.Count)")
    Assert-That 'unknown applicability says WHY it was not tested' (
        [string] $unknown.Details -like '*Not tested*'
    ) ("details='$([string] $unknown.Details)'")

    # --- The controls that must NOT change ---------------------------------------------------------
    # These are what stop a lazy fix that simply returns N/A whenever anything is uncertain.
    Assert-That 'a known pre-dMSA schema still measures five ACEs' (
        $knownOld.ExpectedACEs -eq 5 -and $knownOld.SaclCalls -eq 1
    ) ("expected=$($knownOld.ExpectedACEs) calls=$($knownOld.SaclCalls)")
    Assert-That 'a known pre-dMSA schema still reports a measured pass' (
        $knownOld.Status -eq $true -and $knownOld.Measured -eq $true
    ) ("status=$($knownOld.Status) measured=$($knownOld.Measured)")
    Assert-That 'a known pre-dMSA schema charges nothing unread' (
        $knownOld.Unread -eq 0
    ) ("unread=$($knownOld.Unread)")
    Assert-That 'a known pre-dMSA schema stays READY' ($knownOld.Verdict) "verdict=$($knownOld.Verdict)"
    Assert-That 'a known pre-dMSA schema raises no finding' ($knownOld.Issues.Count -eq 0) ("got $($knownOld.Issues.Count)")

    Assert-That 'a known dMSA-era schema still requires the sixth ACE' (
        $knownNew.ExpectedACEs -eq 6 -and $knownNew.SaclCalls -eq 1
    ) ("expected=$($knownNew.ExpectedACEs) calls=$($knownNew.SaclCalls)")
    Assert-That 'a known dMSA-era schema still reports a measured pass' (
        $knownNew.Status -eq $true -and $knownNew.Measured -eq $true
    ) ("status=$($knownNew.Status) measured=$($knownNew.Measured)")
    Assert-That 'a known dMSA-era schema charges nothing unread' (
        $knownNew.Unread -eq 0
    ) ("unread=$($knownNew.Unread)")
    Assert-That 'a known dMSA-era schema stays READY' ($knownNew.Verdict) "verdict=$($knownNew.Verdict)"
    Assert-That 'a known dMSA-era schema raises no finding' ($knownNew.Issues.Count -eq 0) ("got $($knownNew.Issues.Count)")

    # The two known cases must remain DISTINGUISHABLE from each other - that is the original reason
    # applicability is computed at all.
    Assert-That 'the two known schemas still require different ACE counts' (
        $knownOld.ExpectedACEs -ne $knownNew.ExpectedACEs
    ) ("old=$($knownOld.ExpectedACEs) new=$($knownNew.ExpectedACEs)")
    # And the unknown case must not be silently equal to either of them.
    Assert-That 'the unknown case is not identical to a known pre-dMSA domain' (
        [string] $unknown.Status -ne [string] $knownOld.Status -or $unknown.Unread -ne $knownOld.Unread
    ) ("unknown=$($unknown.Status)/unread$($unknown.Unread) knownOld=$($knownOld.Status)/unread$($knownOld.Unread)")

} finally {
    [void] $accelerators::Remove('adsi')
    [void] $accelerators::Add('adsi', $originalAdsi)
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
