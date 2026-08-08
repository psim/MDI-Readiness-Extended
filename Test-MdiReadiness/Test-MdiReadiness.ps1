<#
    .NOTES
        Copyright (c) Microsoft Corporation.  All rights reserved.
        Use of this sample source code is subject to the terms of the Microsoft
        license agreement under which you licensed this sample source code. If
        you did not accept the terms of the license agreement, you are not
        authorized to use this sample source code. For the terms of the license,
        please see the license agreement between you and Microsoft or, if applicable,
        see the LICENSE.RTF on your install media or the root of your tools installation.
        THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES.

        ----------------------------------------------------------------------------
        IMPORTANT - PERSONAL PROJECT, NOT AN OFFICIAL MICROSOFT PRODUCT

        This is an UNOFFICIAL, modified version of the Test-MdiReadiness.ps1 script
        originally published by Microsoft at
        https://github.com/microsoft/Microsoft-Defender-for-Identity

        NOT AN OFFICIAL MICROSOFT PRODUCT. This is a personal project. It is not an
        official Microsoft product, is not endorsed or approved by Microsoft, and is
        not covered by any Microsoft support agreement or service level agreement.
        Microsoft provides no support for it. Do not raise Microsoft support cases
        about this version. For the official, supported tool use the original script
        from the repository above. Views and code here are the author's own.

        NO WARRANTY AND NO LIABILITY. This script is provided "AS IS" and "WITH ALL
        FAULTS", without warranty of any kind, either express or implied, including
        without limitation any warranties of merchantability, fitness for a
        particular purpose, accuracy, or non-infringement.

        NO RESPONSIBILITY AND NO LIABILITY IS ACCEPTED WHATSOEVER if this script does
        not work, produces incorrect or incomplete results, or causes any problem of
        any kind. This includes, without limitation, service interruption, downtime,
        misconfiguration, loss of data, loss of profits, or any direct, indirect,
        incidental, special, consequential or punitive damages, even if advised of
        the possibility of such damage.

        YOU USE IT ENTIRELY AT YOUR OWN RISK. The entire risk as to the results,
        performance and consequences of using this script rests with you. You are
        solely responsible for validating its behaviour and its output before
        relying on either.

        BEFORE YOU RUN IT. This script reads configuration from domain controllers
        and other servers, and opens network connections to them. Nothing is written
        to your environment. Review the code, and test it in a non-production
        environment first.

        It runs from a domain-joined workstation or member server and needs:
          - the RSAT ActiveDirectory PowerShell module
          - read permissions in the domains being scanned (Enterprise Admin for -Forest)
          - WMI access to each target server: TCP 135 and the RPC dynamic port range
          - ICMP to each target server, since every per-server check is gated behind a
            connectivity test

        There is no cloud dependency: the script uses the ActiveDirectory module, WMI
        over RPC/DCOM, LDAP/ADSI and raw sockets, so it runs the same way against
        on-premises domain controllers as against cloud-hosted ones.

        Across WAN links, raise -PortProbeTimeoutMs above its 1500 ms default so a
        slow link is not reported as a blocked port.

        The optional -RemediationScript switch GENERATES a script that would change
        audit policy, registry values and firewall rules. It is never executed
        automatically. Review the generated script and run it with -WhatIf before
        applying anything.

        Findings are based on Microsoft's published documentation at the time of
        writing and may become outdated. Always verify against the current official
        documentation: https://learn.microsoft.com/defender-for-identity/
        ----------------------------------------------------------------------------
    .SYNOPSIS
        Verifies Microsoft Defender for Identity prerequisites are in place
    .DESCRIPTION
        This script will query your domain and report if the different Microsoft Defender for Identity prerequisites are in place. It creates an html report and a detailed json file with all the collected data.
    .PARAMETER Path
        Path to a folder where the reports are be saved. Defaults to the current folder.
    .PARAMETER Domain
        Domain Name or FQDN to work against. Defaults to the current domain.
    .PARAMETER Forest
        Scan every domain in the Active Directory forest instead of a single domain. Requires an account with read
        permissions in all domains of the forest (typically Enterprise Admin). All domain controllers of every domain
        are enumerated and tested, and a single consolidated report is created for the forest.
    .PARAMETER DomainController
        Specific Domain Controller(s) to work against. If not specified, it will query AD for the list of DCs in the domain.
    .PARAMETER CAServer
        Specific Certificate Authority server(s) to work against. If not specified, it will query AD for the members of the "Cert Publishers" group.
    .PARAMETER SkipCA
        Skip Certificate Authority servers
    .PARAMETER EntraConnectServer
        Specific Entra Connect server(s) to work against. If not specified, it will query AD for the Entra Connect server(s) in the domain.
    .PARAMETER SkipEntraConnect
        Skip Entra Connect servers
    .PARAMETER SkipNetworkPorts
        Skip the Microsoft Defender for Identity required network port tests.
    .PARAMETER SkipSensorV3Readiness
        Skip the Defender for Identity sensor v3.x upgrade readiness tests. By default the script reports, for every
        server, whether it meets the prerequisites for the sensor v3.x (Windows Server 2019 or later with the July 2026
        or later cumulative update, Defender for Endpoint onboarded, domain controller role) and whether it is eligible
        for the in-place migration from the sensor v2.x.
    .PARAMETER CapacityPlanning
        Estimate whether each domain controller has enough resources for a Defender for Identity sensor v2.x, using
        the sizing table published in the capacity planning documentation. The script samples the network packet rate
        of every domain controller and maps the busiest window to the required CPU and RAM.

        This is an approximation of the official TriSizingTool (https://aka.ms/mdi/sizingtool), which samples over
        24 hours. Use -CapacityPlanningDuration to lengthen the sample, and prefer the official tool for a formal
        sizing exercise. The sizing tool only applies to the sensor v2.x: the v3.x sensor relies on Windows events
        and event tracing and does not need one.
    .PARAMETER CapacityPlanningDuration
        Number of seconds to sample the packet rate on each domain controller. Defaults to 120. The documented method
        samples for 24 hours (86400) and takes the busiest 15 minutes.

        A sample shorter than 15 minutes (900) cannot contain a busy window, so the whole sample is averaged and the
        verdict is marked as an estimate in the report. It also makes the spike test inert: that test compares the
        busy rate against the average, and on a short sample they are the same number, so a server with heavy but
        brief bursts is still reported as supported. Check the Peak column when the sample is short.
    .PARAMETER CapacityPlanningInterval
        Seconds between packet rate samples. Defaults to 5, matching the documented collection interval.
    .PARAMETER RemediationScript
        Retained for compatibility. The remediation script is now generated on every run, so this switch has no
        effect and existing command lines keep working.
    .PARAMETER SkipRemediationScript
        Do not generate the remediation script.

        By default a Fix-MdiReadiness-<domain>.ps1 is written next to the reports on every run, containing the
        commands that fix the findings that can be fixed automatically (advanced audit policy, NTLM auditing,
        power scheme, Network Name Resolution firewall rules, stopped sensor services and clock
        resynchronisation). It is only ever written, never executed: it supports -WhatIf and must be reviewed
        before it is run.
    .PARAMETER BaselinePath
        Folder where a compact run history is kept, so the report can chart how readiness evolves between runs.
        Defaults to the report folder, so history is recorded on every run without having to ask for it. Use
        this only when the history should live somewhere other than the reports.
    .PARAMETER SkipTrend
        Do not record this run in the trend history, and do not write anything outside the report itself.
    .PARAMETER DirectoryServiceAccount
        The Directory Service Account(s) configured for the domain, used to assert that they have read access to the
        Deleted Objects container. Without this parameter the check only reports which principals currently have access.
    .PARAMETER MaxClockSkewMinutes
        Maximum tolerated clock difference between this computer and each sensor server. Defaults to 5 minutes, which
        is the value required by the Defender for Identity documentation.
    .PARAMETER AsJson
        Emit the full report object as JSON on the pipeline instead of the human-readable summary, for use in a
        pipeline or a scheduled compliance job.
    .PARAMETER PassThru
        Emit the boolean readiness result on the pipeline. Without it the run ends with a readable summary and
        writes nothing to the pipeline, so an interactive run no longer ends with a bare "False" that reads like
        an error. Use -FailOnIssues instead when the caller only needs an exit code.
    .PARAMETER FailOnIssues
        Exit with a non-zero exit code when any prerequisite fails, so the script can be used as a build or compliance
        gate. The exit code is the number of failed checks, capped at 254.
    .PARAMETER WorkspaceName
        The Defender for Identity workspace name, used to test outbound HTTPS connectivity to the sensor API URL
        (https://<WorkspaceName>sensorapi.atp.azure.com). If not specified, the cloud service connectivity test is
        reported as 'N/A'. The workspace name is shown in the Microsoft Defender portal under
        Settings > Identities > About.
    .PARAMETER NnrTargetComputer
        Additional computer(s) that each sensor server should be able to reach using the Network Name Resolution (NNR)
        protocols. Use this to validate NNR against a representative sample of the endpoints in your environment
        (workstations, member servers), not only against domain controllers.
    .PARAMETER MaxNnrTargets
        Maximum number of peer domain controllers each sensor probes for NNR when -NnrTargetComputer is not supplied.
        Defaults to 5. Use 0 to probe every domain controller found (full mesh, can be slow in large forests).
    .PARAMETER MaxLdapTargetsPerDomain
        Maximum number of domain controllers per domain used as LDAP probe targets. Defaults to 2. Use 0 to probe
        every domain controller found.
    .PARAMETER PortProbeTimeoutMs
        Timeout in milliseconds used for each individual port probe. Defaults to 1500.
    .PARAMETER MultiForest
        Treat the environment as a multi-forest deployment. Adds the LDAPS (636) and LDAPS to Global Catalog (3269)
        ports to the required set instead of reporting them as optional.
    .PARAMETER TestVpnRadius
        Test that the sensor servers accept inbound RADIUS accounting traffic on UDP 1813. Only relevant when the
        Defender for Identity VPN integration is configured, and only supported by sensor v2.x.
    .PARAMETER OpenHtmlReport
        Open the HTML report at the end of the collection process.
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -OpenHtmlReport
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -DomainController 'myDC01', 'myDC02'
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -CAServer 'myCA01', 'myCA02'
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -SkipCA
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -EntraConnectServer 'myEC01', 'myEC02'
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -SkipEntraConnect
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -Verbose
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -Forest -OpenHtmlReport -Verbose

        Scans every domain controller in every domain of the current forest, including the required network ports.
        Run this from a workstation or member server with an Enterprise Admin (or equivalent) account.
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -Forest -WorkspaceName 'contoso-corp' -NnrTargetComputer 'WKS001', 'SRV042' -OpenHtmlReport

        Scans the whole forest, tests outbound HTTPS to https://contoso-corpsensorapi.atp.azure.com and validates the
        Network Name Resolution ports against two representative endpoints in addition to the domain controllers.
        Use this to troubleshoot the 'Low success rate of active name resolution' sensor health alert.
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -Forest -SkipCA -SkipNetworkPorts
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -Forest -OpenHtmlReport

        Scans the forest and writes a Fix-MdiReadiness.ps1 script next to the reports containing the commands that
        remediate the findings. Review it, then run it with -WhatIf before applying.
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -Forest -BaselinePath 'C:\MDI\history' -OpenHtmlReport

        Records the run in a history file and charts the readiness trend across runs in the report.
    .EXAMPLE
        .\Test-MdiReadiness.ps1 -Forest -FailOnIssues -SkipNetworkPorts

        Suitable for a scheduled compliance job: exits with a non-zero exit code when any prerequisite fails.
#>

#Requires -Version 4.0
#requires -Module ActiveDirectory

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false, HelpMessage = 'Path to a folder where the reports are be saved')]
    [string] $Path = '.',
    [Parameter(Mandatory = $false, HelpMessage = 'Domain Name or FQDN to work against. Defaults to current domain')]
    [string] $Domain = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Scan every domain in the Active Directory forest. Requires Enterprise Admin (or equivalent) permissions')]
    [switch] $Forest,
    [Parameter(Mandatory = $false, HelpMessage = 'Specific Domain Controller(s) to work against. If not specified, it will query AD for the list of DCs in the domain')]
    [string[]] [Alias('DC')] $DomainController = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Specific Certificate Authority server(s) to work against. If not specified, it will query AD for the members of the "Cert Publishers" group')]
    [string[]] [Alias('CA')] $CAServer = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Skip Certificate Authority servers')]
    [switch] $SkipCA,
    [Parameter(Mandatory = $false, HelpMessage = 'Specific Entra Connect server(s) to work against. If not specified, it will query AD User for the "*configured to synchronize to tenant*" description')]
    [string[]] [Alias('EC')] $EntraConnectServer = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Skip Entra Connect servers')]
    [switch] $SkipEntraConnect,
    [Parameter(Mandatory = $false, HelpMessage = 'Skip the MDI required network port tests')]
    [switch] $SkipNetworkPorts,
    [Parameter(Mandatory = $false, HelpMessage = 'Skip the Defender for Identity sensor v3.x upgrade readiness tests')]
    [switch] $SkipSensorV3Readiness,
    [Parameter(Mandatory = $false, HelpMessage = 'Estimate whether each domain controller has enough resources for a sensor v2.x')]
    [switch] $CapacityPlanning,
    [Parameter(Mandatory = $false, HelpMessage = 'Seconds to sample the packet rate on each domain controller')]
    [ValidateRange(30, 86400)]
    [int] $CapacityPlanningDuration = 120,
    [Parameter(Mandatory = $false, HelpMessage = 'Seconds between packet rate samples')]
    [ValidateRange(1, 60)]
    [int] $CapacityPlanningInterval = 5,
    [Parameter(Mandatory = $false, HelpMessage = 'Retained for compatibility. The remediation script is generated on every run')]
    [switch] $RemediationScript,
    [Parameter(Mandatory = $false, HelpMessage = 'Do not generate the remediation script')]
    [switch] $SkipRemediationScript,
    [Parameter(Mandatory = $false, HelpMessage = 'Folder where a run history is kept so the report can chart the readiness trend. Defaults to the report folder')]
    [string] $BaselinePath = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Do not record this run in the trend history')]
    [switch] $SkipTrend,
    [Parameter(Mandatory = $false, HelpMessage = 'Directory Service Account(s) that must have read access to the Deleted Objects container')]
    [string[]] [Alias('DSA')] $DirectoryServiceAccount = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Maximum tolerated clock difference, in minutes, between this computer and each sensor server')]
    [ValidateRange(1, 1440)]
    [int] $MaxClockSkewMinutes = 5,
    [Parameter(Mandatory = $false, HelpMessage = 'Emit the full report object as JSON instead of the human-readable summary')]
    [switch] $AsJson,
    [Parameter(Mandatory = $false, HelpMessage = 'Emit the boolean readiness result on the pipeline')]
    [switch] $PassThru,
    [Parameter(Mandatory = $false, HelpMessage = 'Exit with a non-zero exit code when any prerequisite fails')]
    [switch] $FailOnIssues,
    [Parameter(Mandatory = $false, HelpMessage = 'MDI workspace name, used to test connectivity to https://<WorkspaceName>sensorapi.atp.azure.com')]
    [string] $WorkspaceName = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Additional computer(s) each sensor should reach using the Network Name Resolution protocols')]
    [string[]] [Alias('NNRTarget')] $NnrTargetComputer = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Maximum number of peer domain controllers probed for NNR from each sensor. 0 means all of them')]
    [ValidateRange(0, 1000)]
    [int] $MaxNnrTargets = 5,
    [Parameter(Mandatory = $false, HelpMessage = 'Maximum number of domain controllers per domain used as LDAP probe targets. 0 means all of them')]
    [ValidateRange(0, 1000)]
    [int] $MaxLdapTargetsPerDomain = 2,
    [Parameter(Mandatory = $false, HelpMessage = 'Timeout in milliseconds for each individual port probe')]
    [ValidateRange(100, 60000)]
    [int] $PortProbeTimeoutMs = 1500,
    [Parameter(Mandatory = $false, HelpMessage = 'Treat the environment as multi-forest, making LDAPS (636) and LDAPS to GC (3269) required')]
    [switch] $MultiForest,
    [Parameter(Mandatory = $false, HelpMessage = 'Test inbound RADIUS accounting (UDP 1813) used by the MDI VPN integration')]
    [switch] $TestVpnRadius,
    [Parameter(Mandatory = $false, HelpMessage = 'Open the HTML report at the end of the collection process')]
    [switch] $OpenHtmlReport
)



#region General settings

$settings = @{

    # Single source of truth for the version. It is surfaced in the HTML report footer, in the -AsJson
    # output and in the baseline history, so a report or a trend can always be traced back to the build
    # that produced it. A release workflow checks this value against the git tag.
    ScriptVersion                   = '1.1.0'

    AdvancedAuditPolicyDCs          = @'
Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Setting Value
System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Distribution Group Management,{0CCE9238-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Computer Account Management,{0CCE9236-69AE-11D9-BED3-505054503030},Success and Failure,3
System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Directory Service Access,{0CCE923B-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Directory Service Changes,{0CCE923C-69AE-11D9-BED3-505054503030},Success and Failure,3
System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,3
'@

    AdvancedAuditPolicyCAs          = @'
Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Setting Value
System,Audit Certification Services,{0cce9221-69ae-11d9-bed3-505054503030},Success and Failure,3
'@

    AdvancedAuditPolicyEntraConnect = @'
Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Setting Value
System,Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,3
'@

    ObjectAuditing                  = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,InheritedObjectAceType,Description
S-1-1-0,852331,1,bf967aba-0de6-11d0-a285-00aa003049e2,Descendant User Objects
S-1-1-0,852331,1,bf967a9c-0de6-11d0-a285-00aa003049e2,Descendant Group Objects
S-1-1-0,852331,1,bf967a86-0de6-11d0-a285-00aa003049e2,Descendant Computer Objects
S-1-1-0,852331,1,ce206244-5827-4a86-ba1c-1c0c386c1b64,Descendant msDS-ManagedServiceAccount Objects
S-1-1-0,852075,1,7b8b558a-93a5-4af7-adca-c017e67f1057,Descendant msDS-GroupManagedServiceAccount Objects
S-1-1-0,852075,1,0feb936f-47b3-49f2-9386-1dedc2c23765,Descendant msDS-DelegatedManagedServiceAccount Objects
'@

    ExchangeAuditing                = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue
S-1-1-0,32,3,194
'@

    ADFSAuditing                    = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue
S-1-1-0,48,3,194
'@

    NTLMAuditing                    = @(
        'System\CurrentControlSet\Control\Lsa\MSV1_0,AuditReceivingNTLMTraffic,2',
        'System\CurrentControlSet\Control\Lsa\MSV1_0,RestrictSendingNTLMTraffic,1|2',
        'System\CurrentControlSet\Services\Netlogon\Parameters,AuditNTLMInDomain,7'
    )

    RootCertificates                = @(
        'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4' # Commercial, DigiCert Global Root G2
        , 'A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436' # USGov, DigiCert Global Root CA
    )

    CASettings                      = @{
        RegPathActive = 'System\CurrentControlSet\Services\CertSvc\Configuration,Active'
        RegistrySet   = @(
            'System\CurrentControlSet\Services\CertSvc\Configuration\{0},AuditFilter,127'
        )
    }

    # Network ports required by the Defender for Identity sensor.
    # Source: https://learn.microsoft.com/defender-for-identity/deploy/prerequisites-sensor-version-2#required-ports
    #         https://learn.microsoft.com/defender-for-identity/nnr-policy
    # Scope   : which peer the port is tested against
    #             Cloud            - the Defender for Identity cloud service (sensor API URL)
    #             Localhost        - loopback traffic between the sensor service and the sensor updater service
    #             DnsServer        - the DNS servers configured on the sensor server
    #             NetworkDevice    - any device on the network the sensor needs to resolve (NNR)
    #             DomainController - domain controllers queried over LDAP
    #             Inbound          - traffic the sensor server must accept
    # Group   : ports that satisfy a requirement together. 'NNR' ports are "at least one of", per the NNR documentation
    RequiredPorts                   = @(
        [PSCustomObject] @{ Id = 'CloudSsl'; Name = 'SSL to the MDI cloud service (*.atp.azure.com)'; Protocol = 'TCP'; Port = 443; Scope = 'Cloud'; Group = $null; Requirement = 'Required'; SensorVersion = 'v2.x, v3.x'; Notes = 'Outbound HTTPS to https://<workspace>sensorapi.atp.azure.com. Alternatively configure access through a proxy.' }
        [PSCustomObject] @{ Id = 'UpdaterSsl'; Name = 'SSL to the sensor updater service'; Protocol = 'TCP'; Port = 444; Scope = 'Localhost'; Group = $null; Requirement = 'Required'; SensorVersion = 'v2.x'; Notes = 'localhost to localhost. Required for the sensor service updater, blocked only by a custom local firewall policy.' }
        [PSCustomObject] @{ Id = 'DnsTcp'; Name = 'DNS'; Protocol = 'TCP'; Port = 53; Scope = 'DnsServer'; Group = $null; Requirement = 'Required'; SensorVersion = 'v2.x'; Notes = 'Sensor to the DNS servers configured on the server.' }
        [PSCustomObject] @{ Id = 'DnsUdp'; Name = 'DNS'; Protocol = 'UDP'; Port = 53; Scope = 'DnsServer'; Group = $null; Requirement = 'Required'; SensorVersion = 'v2.x'; Notes = 'Sensor to the DNS servers configured on the server.' }
        [PSCustomObject] @{ Id = 'NnrRpc'; Name = 'NNR - NTLM over RPC'; Protocol = 'TCP'; Port = 135; Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'; SensorVersion = 'v2.x'; Notes = 'Primary NNR method. Must be open for inbound communication from the sensors on all computers in the environment.' }
        [PSCustomObject] @{ Id = 'NnrNetBios'; Name = 'NNR - NetBIOS'; Protocol = 'UDP'; Port = 137; Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'; SensorVersion = 'v2.x'; Notes = 'Primary NNR method. Must be open for inbound communication from the sensors on all computers in the environment.' }
        [PSCustomObject] @{ Id = 'NnrRdp'; Name = 'NNR - RDP'; Protocol = 'TCP'; Port = 3389; Scope = 'NetworkDevice'; Group = 'NNR'; Requirement = 'AtLeastOne'; SensorVersion = 'v2.x'; Notes = 'Primary NNR method, only the first packet of Client hello. Customized RDP ports are not supported.' }
        [PSCustomObject] @{ Id = 'NnrReverseDns'; Name = 'NNR - Reverse DNS (PTR)'; Protocol = 'UDP'; Port = 53; Scope = 'NetworkDevice'; Group = $null; Requirement = 'Recommended'; SensorVersion = 'v2.x'; Notes = 'Secondary NNR method. Requires the sensor to reach the DNS server and Reverse Lookup Zones to be enabled and populated.' }
        [PSCustomObject] @{ Id = 'LdapTcp'; Name = 'LDAP'; Protocol = 'TCP'; Port = 389; Scope = 'DomainController'; Group = $null; Requirement = 'Required'; SensorVersion = 'v2.x'; Notes = 'Sensors query the directory using LDAP on port 389 by default.' }
        [PSCustomObject] @{ Id = 'LdapUdp'; Name = 'LDAP'; Protocol = 'UDP'; Port = 389; Scope = 'DomainController'; Group = $null; Requirement = 'Required'; SensorVersion = 'v2.x'; Notes = 'Connectionless LDAP (CLDAP) to domain controllers.' }
        [PSCustomObject] @{ Id = 'LdapGcTcp'; Name = 'LDAP to Global Catalog'; Protocol = 'TCP'; Port = 3268; Scope = 'DomainController'; Group = $null; Requirement = 'Required'; SensorVersion = 'v2.x'; Notes = 'Sensors query the global catalog on port 3268 by default.' }
        [PSCustomObject] @{ Id = 'LdapsTcp'; Name = 'Secure LDAP (LDAPS)'; Protocol = 'TCP'; Port = 636; Scope = 'DomainController'; Group = $null; Requirement = 'Optional'; SensorVersion = 'v2.x'; Notes = 'Required in multi-forest deployments, or when the workspace was switched to LDAPS through a support case.' }
        [PSCustomObject] @{ Id = 'LdapsGcTcp'; Name = 'LDAPS to Global Catalog'; Protocol = 'TCP'; Port = 3269; Scope = 'DomainController'; Group = $null; Requirement = 'Optional'; SensorVersion = 'v2.x'; Notes = 'Required in multi-forest deployments, or when the workspace was switched to LDAPS through a support case.' }
        [PSCustomObject] @{ Id = 'RadiusUdp'; Name = 'RADIUS accounting'; Protocol = 'UDP'; Port = 1813; Scope = 'Inbound'; Group = $null; Requirement = 'Optional'; SensorVersion = 'v2.x'; Notes = 'Inbound from the VPN/RADIUS server to the sensor. Only required when the MDI VPN integration is configured.' }
    )

    # Ports promoted from Optional to Required when -MultiForest is used
    MultiForestPorts                = @('LdapsTcp', 'LdapsGcTcp')

    SensorApiUrlFormat              = '{0}sensorapi.atp.azure.com'

    # Estimated sensor v2.x resource consumption per traffic band.
    # Source: https://learn.microsoft.com/defender-for-identity/deploy/capacity-planning
    # 'CPU and RAM capacity refers to the sensor's own consumption, not the domain controller capacity.'
    # 'CPU capacity doesn't include hyper-threaded cores.'
    CapacityPlanning                = @{
        SizingTable        = @(
            [PSCustomObject]@{ MinPps = 0; MaxPps = 1000; Cpu = 0.25; RamGb = 2.50; Band = '0-1k' }
            [PSCustomObject]@{ MinPps = 1000; MaxPps = 5000; Cpu = 0.75; RamGb = 6.00; Band = '1k-5k' }
            [PSCustomObject]@{ MinPps = 5000; MaxPps = 10000; Cpu = 1.00; RamGb = 6.50; Band = '5k-10k' }
            [PSCustomObject]@{ MinPps = 10000; MaxPps = 20000; Cpu = 2.00; RamGb = 9.00; Band = '10k-20k' }
            [PSCustomObject]@{ MinPps = 20000; MaxPps = 50000; Cpu = 3.50; RamGb = 9.50; Band = '20k-50k' }
            [PSCustomObject]@{ MinPps = 50000; MaxPps = 75000; Cpu = 5.50; RamGb = 11.50; Band = '50k-75k' }
            [PSCustomObject]@{ MinPps = 75000; MaxPps = 100000; Cpu = 7.50; RamGb = 13.50; Band = '75k-100k' }
        )
        # 'the Busy packets/sec may be above 60K' turns a Yes verdict into a Maybe
        MaybeThresholdPps  = 60000
        # Beyond the published table the sensor is not supported
        MaxSupportedPps    = 100000
        # A burst far above the daily average is what the documented 'Maybe' verdict describes
        SpikeRatio         = 3
        # 'the 15 busiest minutes over a 24 hour period'
        BusyWindowMinutes  = 15
        # Servers are sampled concurrently so they share one measurement window. 0 means all of them
        # at once; a cap only matters in very large forests, where each concurrent sample costs a WMI
        # session on the machine running this script.
        MaxParallelSamples = 64
        OfficialToolUrl    = 'https://aka.ms/mdi/sizingtool'
        OfficialRepoUrl    = 'https://github.com/microsoft/Microsoft-Defender-for-Identity-Sizing-Tool'
        DocumentationUrl   = 'https://learn.microsoft.com/defender-for-identity/deploy/capacity-planning'
        # WMI performance classes are used instead of PDH counters because their class and property names are
        # not localized, unlike '\Network Interface(*)\Packets/sec' which differs on every non-English OS.
        # The official TriSizingTool uses Remote WMI and Remote PerfMon over RPC in the same way.
        PerfClass          = 'Win32_PerfFormattedData_Tcpip_NetworkInterface'
        CpuPerfClass       = 'Win32_PerfFormattedData_PerfOS_Processor'
        MemoryPerfClass    = 'Win32_PerfFormattedData_PerfOS_Memory'
        ExcludeAdapterName = 'isatap|Loopback|Teredo|Pseudo-Interface|RAS |WAN Miniport'
    }

    # Defender for Identity sensor v3.x requirements.
    # Source: https://learn.microsoft.com/defender-for-identity/deploy/deploy-sensor-v3
    #         https://learn.microsoft.com/defender-for-identity/deploy/migrate-to-sensor-v3
    SensorV3                        = @{
        # 'Is running Windows Server 2019 or later' - Windows Server 2019 is OS build 17763
        MinOSBuild               = 17763

        # 'Includes the Windows Server July 2026 or later cumulative update'. The Defender for Identity documentation
        # does not name a KB, so the July 2026 'B' release revision of each supported Windows Server build is used.
        # Source: https://learn.microsoft.com/windows/release-health/windows-server-release-info
        JulyCumulativeUpdate     = @{
            17763 = @{ Revision = 9020; KB = 'KB5099538'; OS = 'Windows Server 2019' }
            20348 = @{ Revision = 5386; KB = 'KB5099540'; OS = 'Windows Server 2022' }
            26100 = @{ Revision = 33158; KB = 'KB5099536'; OS = 'Windows Server 2025' }
        }

        # Microsoft Defender for Endpoint onboarding state, written by the SENSE service.
        # Source: https://learn.microsoft.com/defender-endpoint/troubleshoot-onboarding
        MdeStatusRegKey          = 'SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
        MdeOnboardingStateValue  = 'OnboardingState'
        MdeSenseServiceName      = 'Sense'

        # 'Defender for Identity sensor v2.x (version 2.254.19112.470 or later)' is required for in-place migration
        MinV2VersionForMigration = '2.254.19112.470'

        # From sensor 3.0.8 RPC auditing is enabled automatically and no longer needs a portal tag
        MinV3VersionAutoRpcAudit = '3.0.8'

        # Identity roles that make a domain controller ineligible for the in-place migration workflow
        IdentityRoleServices     = @{
            'adfssrv' = 'AD FS'
            'CertSvc' = 'AD CS'
            'ADSync'  = 'Microsoft Entra Connect'
        }

        CurrentVersionRegKey     = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    }
}

#endregion

#region Helper functions

function Get-mdiRemoteTempFolder {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    try {
        $wmiParamsTemp = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_Environment'
            Filter       = "Name='TEMP' AND SystemVariable=TRUE"
            ErrorAction  = 'SilentlyContinue'
        }
        $envTempPath = (Get-WmiObject @wmiParamsTemp).VariableValue

        if ($envTempPath -match '%SystemDrive%|%SystemDirectory%|%WindowsDirectory%') {
            $wmiParamsOS = @{
                ComputerName = $ComputerName
                Namespace    = 'root\cimv2'
                Class        = 'Win32_OperatingSystem'
                ErrorAction  = 'SilentlyContinue'
            }
            $osVars = Get-WmiObject @wmiParamsOS
            $envTempPath = $envTempPath -replace '%SystemDrive%', $osVars.SystemDrive
            $envTempPath = $envTempPath -replace '%SystemDirectory%', $osVars.SystemDirectory
            $envTempPath = $envTempPath -replace '%WindowsDirectory%', $osVars.WindowsDirectory
        }

        if ($envTempPath -match '%SystemRoot%') {
            $HKLM = 2147483650
            $reg = [WMIClass]('\\{0}\ROOT\DEFAULT:StdRegProv' -f $ComputerName)
            $SystemRoot = $reg.GetStringValue($HKLM, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'SystemRoot').sValue
            $envTempPath = $envTempPath -replace '%SystemRoot%', $SystemRoot
        }

    } catch {
        $envTempPath = 'C:\Windows\Temp'
    }

    # Get-WmiObject is called with -ErrorAction SilentlyContinue, so an unreachable or
    # WMI-blocked server yields $null rather than an exception and the catch above never
    # runs. Without this guard the function returns $null and every caller then fails on
    # "Join-Path : Cannot bind argument to parameter 'Path' because it is null".
    if ([string]::IsNullOrWhiteSpace($envTempPath)) {
        $envTempPath = 'C:\Windows\Temp'
    }
    $envTempPath
}

function Invoke-mdiRemoteCommand {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $CommandLine,
        [Parameter(Mandatory = $false)] [string] $LocalFile = $null,
        [Parameter(Mandatory = $false)] [int] $TimeoutSeconds = 30
    )

    try {
        $wmiParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_Process'
            Name         = 'Create'
            ErrorAction  = 'SilentlyContinue'
        }
        # IsNullOrWhiteSpace rather than -eq [string]::Empty: the parameter defaults to $null, not an
        # empty string, so every caller that omitted -LocalFile skipped the redirection, then tried to
        # read $null as a path and silently returned no output. Get-mdiPowerScheme is one such caller,
        # which is why the power scheme check could never see a result on some paths.
        $ownsRemoteFile = [string]::IsNullOrWhiteSpace($LocalFile)
        if ($ownsRemoteFile) {
            $LocalFile = Join-Path -Path (Get-mdiRemoteTempFolder -ComputerName $ComputerName) -ChildPath ('mdi-{0}.tmp' -f , [guid]::NewGuid().GUID)
            # "> file 2>&1", not "2>&1>file". cmd.exe applies redirections left to right, so the latter
            # points stderr at the ORIGINAL stdout before stdout is redirected, and error output is lost -
            # exactly the output needed to explain why a check could not run.
            $wmiParams['ArgumentList'] = '{0} > {1} 2>&1' -f $CommandLine, $LocalFile
        } else {
            $wmiParams['ArgumentList'] = $CommandLine
        }

        $result = Invoke-WmiMethod @wmiParams
        $maxWait = [datetime]::Now.AddSeconds($TimeoutSeconds)

        $waitForProcessParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_Process'
            Filter       = ("ProcessId='{0}'" -f $result.ProcessId)
        }

        if ($result.ReturnValue -eq 0) {
            do { Start-Sleep -Milliseconds 200 }
            while (([datetime]::Now -lt $maxWait) -and (Get-WmiObject @waitForProcessParams).CommandLine -eq $wmiParams.ArgumentList)
        }

        $remoteFile = $LocalFile -replace 'C:', ('\\{0}\C$' -f $ComputerName)
        try {
            # Read the file using SMB
            $return = Get-Content -Path $remoteFile -ErrorAction Stop
        } catch {
            try {
                # Read the remote file using WMI
                $psmClassParams = @{
                    Namespace    = 'root\Microsoft\Windows\Powershellv3'
                    ClassName    = 'PS_ModuleFile'
                    ComputerName = $ComputerName
                }
                $cimParams = @{
                    CimClass   = Get-CimClass @psmClassParams
                    Property   = @{ InstanceID = $LocalFile }
                    ClientOnly = $true
                }
                $fileInstanceParams = @{
                    InputObject  = New-CimInstance @cimParams
                    ComputerName = $ComputerName
                }
                $fileContents = Get-CimInstance @fileInstanceParams -ErrorAction Stop
                $fileLengthBytes = $fileContents.FileData[0..3]
                [array]::Reverse($fileLengthBytes)
                $fileLength = [BitConverter]::ToUInt32($fileLengthBytes, 0)
                $fileBytes = $fileContents.FileData[4..($fileLength - 1)]
                $localTempFile = [System.IO.Path]::GetTempFileName()
                try {
                    Set-Content -Value $fileBytes -Encoding Byte -Path $localTempFile
                    $return = Get-Content -Path $localTempFile
                } finally {
                    Remove-Item -Path $localTempFile -Force -ErrorAction SilentlyContinue
                }
            } catch {
                $return = $null
            }
        } finally {
            # Cleanup used to happen only on the SMB success path, so every server whose C$ is disabled -
            # a common hardening step - accumulated a temp file per check per run. Only files this
            # function created are removed; a caller-supplied path belongs to the caller.
            if ($ownsRemoteFile) {
                try { Remove-Item -Path $remoteFile -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    } catch {
        $return = $_.Exception.Message
    }
    $return
}

#region Network port probing primitives
# These functions are intentionally self-contained (no dependency on $settings or other script scope) so that their
# definitions can be serialized and executed on the remote sensor servers, testing the real sensor -> target direction.

function Test-mdiTcpPort {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [int] $Port,
        [Parameter(Mandatory = $false)] [int] $TimeoutMs = 1500
    )

    $client = New-Object -TypeName System.Net.Sockets.TcpClient
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $async = $null
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            try {
                $client.EndConnect($async)
                $stopwatch.Stop()
                [PSCustomObject]@{ Success = $true; Detail = 'Connected'; LatencyMs = [int] $stopwatch.ElapsedMilliseconds }
            } catch {
                # An immediate RST means the host is reachable but nothing is listening. That is a closed port, not a
                # blocked one, and it is reported separately because the remediation is different.
                $stopwatch.Stop()
                [PSCustomObject]@{ Success = $false
                    Detail = ('Closed - connection refused ({0})' -f $_.Exception.InnerException.Message)
                    LatencyMs = [int] $stopwatch.ElapsedMilliseconds
                }
            }
        } else {
            $stopwatch.Stop()
            [PSCustomObject]@{ Success = $false
                Detail = ('Blocked - no response within {0} ms (filtered by a firewall)' -f $TimeoutMs)
                LatencyMs = $null
            }
        }
    } catch {
        $stopwatch.Stop()
        # A name that cannot be resolved was never probed, so it is reported as not tested rather than
        # as a blocked port. The distinction is the difference between "open your firewall" and "fix
        # your DNS", and the report's own filters key on the wording: without it, a stale DNS record
        # produced a red "blocked" row and sent the operator to open a port that was never shut.
        $message = ($_.Exception.Message -replace '[\r\n]+', ' ')
        $inner = ($_.Exception.InnerException.Message -replace '[\r\n]+', ' ')
        $unresolved = $message -match 'No such host is known|host is unknown|not be resolved|No such host' -or
        $inner -match 'No such host is known|host is unknown|not be resolved|No such host'
        $detail = if ($unresolved) {
            'Not tested - the name {0} could not be resolved: {1}' -f $ComputerName, $message
        } else {
            $message
        }
        [PSCustomObject]@{ Success = $false; Detail = $detail; LatencyMs = $null }
    } finally {
        # Order matters on the timeout path. Closing the client first aborts the pending connect, so the
        # subsequent EndConnect completes the async operation and releases its tracking state instead of
        # leaving it pending. Without this, every timed-out probe leaked an OS event handle and a thread
        # pool entry, and a large forest scan exhausted them.
        try { $client.Close() } catch {}
        if ($async) {
            try { $client.EndConnect($async) } catch {}
            try { $async.AsyncWaitHandle.Close() } catch {}
        }
    }
}

function Test-mdiUdpPort {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [int] $Port,
        [Parameter(Mandatory = $true)] [byte[]] $Payload,
        [Parameter(Mandatory = $false)] [int] $TimeoutMs = 1500,
        # NBSTAT, DNS and CLDAP all carry a caller-chosen identifier that the answer must echo. Passing it
        # in lets a reply be checked against the request rather than accepting any datagram that arrives.
        [Parameter(Mandatory = $false)] [int] $ExpectedTransactionId = -1
    )

    # UDP has no handshake, so a plain 'connect' proves nothing. Each UDP port is probed with a real, protocol-specific
    # request and the reply is what proves the port is open end to end.
    $udp = New-Object -TypeName System.Net.Sockets.UdpClient
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Client.SendTimeout = $TimeoutMs
        # Resolved before connecting so that a slow or dead DNS server cannot block for the operating
        # system's own resolver timeout, which is far longer than $TimeoutMs and would silently blow the
        # time budget for the whole scan. An address literal is passed through untouched.
        $target = $ComputerName
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($ComputerName, [ref] $parsed)) {
            try {
                $addresses = @([System.Net.Dns]::GetHostAddresses($ComputerName) |
                        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
                if ($addresses.Count -eq 0) { throw 'no IPv4 address' }
                $target = [string] $addresses[0]
            } catch {
                $stopwatch.Stop()
                # "Not tested" wording on purpose: the probe never left the machine, so nothing was
                # observed to be blocked. The report's filters key on this phrasing to keep an
                # unresolvable name out of the list of ports to open.
                return [PSCustomObject]@{ Success = $false
                    Detail = ('Not tested - name resolution failed for {0}: {1}' -f $ComputerName, ($_.Exception.Message -replace '[\r\n]+', ' '))
                    Response = $null; LatencyMs = $null
                }
            }
        }
        $udp.Connect($target, $Port)
        [void] $udp.Send($Payload, $Payload.Length)
        $remoteEndpoint = New-Object -TypeName System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Any, 0)
        $response = $udp.Receive([ref] $remoteEndpoint)
        $stopwatch.Stop()
        if ($response.Length -eq 0) {
            return [PSCustomObject]@{ Success = $false; Detail = 'Empty response'; Response = $null; LatencyMs = [int] $stopwatch.ElapsedMilliseconds }
        }

        # Any datagram used to count as success, so a firewall or captive portal sending a byte of noise
        # was reported as an open port. The reply must be long enough to hold the protocol header and,
        # where an identifier was sent, must echo it.
        if ($response.Length -lt 4) {
            return [PSCustomObject]@{ Success = $false
                Detail = ('Invalid reply - {0} byte(s), too short to be a protocol response' -f $response.Length)
                Response = $response; LatencyMs = [int] $stopwatch.ElapsedMilliseconds
            }
        }
        if ($ExpectedTransactionId -ge 0) {
            $replyId = ([int] $response[0] -shl 8) -bor [int] $response[1]
            if ($replyId -ne $ExpectedTransactionId) {
                return [PSCustomObject]@{ Success = $false
                    Detail = ('Invalid reply - identifier {0} does not match the request ({1})' -f $replyId, $ExpectedTransactionId)
                    Response = $response; LatencyMs = [int] $stopwatch.ElapsedMilliseconds
                }
            }
        }

        [PSCustomObject]@{ Success = $true; Detail = ('Replied with {0} bytes' -f $response.Length)
            Response = $response; LatencyMs = [int] $stopwatch.ElapsedMilliseconds
        }
    } catch [System.Net.Sockets.SocketException] {
        $stopwatch.Stop()
        $detail = switch ($_.Exception.SocketErrorCode) {
            'ConnectionReset' { 'Closed - ICMP port unreachable (host reachable, no service listening)' }
            'TimedOut' { 'Blocked - no response within {0} ms (filtered by a firewall or no service listening)' -f $TimeoutMs }
            default { '{0} - {1}' -f $_.Exception.SocketErrorCode, $_.Exception.Message }
        }
        [PSCustomObject]@{ Success = $false; Detail = $detail; Response = $null; LatencyMs = $null }
    } catch {
        $stopwatch.Stop()
        [PSCustomObject]@{ Success = $false; Detail = $_.Exception.Message; Response = $null; LatencyMs = $null }
    } finally {
        try { $udp.Close() } catch {}
    }
}

function New-mdiNetBiosNodeStatusPacket {
    # NetBIOS Node Status Request (NBSTAT) for the wildcard name '*', which is what a sensor sends to resolve a name
    # over UDP 137. See RFC 1002 4.2.17.
    $transactionId = Get-Random -Minimum 1 -Maximum 65535
    $packet = New-Object -TypeName System.Collections.Generic.List[byte]
    $packet.Add([byte] ($transactionId -shr 8))
    $packet.Add([byte] ($transactionId -band 0xFF))
    $packet.AddRange([byte[]] @(0x00, 0x00))             # Flags: standard query
    $packet.AddRange([byte[]] @(0x00, 0x01))             # Questions: 1
    $packet.AddRange([byte[]] @(0x00, 0x00))             # Answer RRs
    $packet.AddRange([byte[]] @(0x00, 0x00))             # Authority RRs
    $packet.AddRange([byte[]] @(0x00, 0x00))             # Additional RRs
    $packet.Add([byte] 0x20)                             # Encoded name length (32)
    # First level encoding of the 16-byte NetBIOS name '*' padded with nulls: every nibble becomes a letter from 'A'
    $netBiosName = [byte[]] @(0x2A) + (New-Object -TypeName byte[] -ArgumentList 15)
    foreach ($b in $netBiosName) {
        $packet.Add([byte] (0x41 + ($b -shr 4)))
        $packet.Add([byte] (0x41 + ($b -band 0x0F)))
    }
    $packet.Add([byte] 0x00)                             # End of name
    $packet.AddRange([byte[]] @(0x00, 0x21))             # Type: NBSTAT
    $packet.AddRange([byte[]] @(0x00, 0x01))             # Class: IN
    , $packet.ToArray()
}

function New-mdiDnsQueryPacket {
    param (
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $false)] [int] $QueryType = 1
    )

    $transactionId = Get-Random -Minimum 1 -Maximum 65535
    $packet = New-Object -TypeName System.Collections.Generic.List[byte]
    $packet.Add([byte] ($transactionId -shr 8))
    $packet.Add([byte] ($transactionId -band 0xFF))
    $packet.AddRange([byte[]] @(0x01, 0x00))             # Flags: standard query, recursion desired
    $packet.AddRange([byte[]] @(0x00, 0x01))             # Questions: 1
    $packet.AddRange([byte[]] @(0x00, 0x00))             # Answer RRs
    $packet.AddRange([byte[]] @(0x00, 0x00))             # Authority RRs
    $packet.AddRange([byte[]] @(0x00, 0x00))             # Additional RRs
    foreach ($label in ($Name -split '\.' | Where-Object { $_ })) {
        $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
        $packet.Add([byte] $labelBytes.Length)
        $packet.AddRange($labelBytes)
    }
    $packet.Add([byte] 0x00)                             # End of QNAME
    $packet.Add([byte] ($QueryType -shr 8))
    $packet.Add([byte] ($QueryType -band 0xFF))
    $packet.AddRange([byte[]] @(0x00, 0x01))             # Class: IN
    , $packet.ToArray()
}

function New-mdiCldapPingPacket {
    # Connectionless LDAP (CLDAP) rootDSE base search, the same shape of request a sensor issues over UDP 389
    $berString = {
        param([byte] $Tag, [string] $Value)
        $valueBytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
        [byte[]] @($Tag, $valueBytes.Length) + $valueBytes
    }
    $attribute = & $berString 0x04 'namingContexts'
    $attributes = [byte[]] @(0x30, $attribute.Length) + $attribute
    $filter = & $berString 0x87 'objectClass'          # present filter [7]
    $body = [byte[]] @(0x04, 0x00) +                    # baseObject: '' (rootDSE)
    [byte[]] @(0x0A, 0x01, 0x00) +                      # scope: baseObject
    [byte[]] @(0x0A, 0x01, 0x00) +                      # derefAliases: neverDerefAliases
    [byte[]] @(0x02, 0x01, 0x00) +                      # sizeLimit: 0
    [byte[]] @(0x02, 0x01, 0x00) +                      # timeLimit: 0
    [byte[]] @(0x01, 0x01, 0x00) +                      # typesOnly: FALSE
    $filter + $attributes
    $searchRequest = [byte[]] @(0x63, $body.Length) + $body
    $messageId = [byte[]] @(0x02, 0x01, 0x01)
    $message = $messageId + $searchRequest
    , ([byte[]] @(0x30, $message.Length) + $message)
}

function Test-mdiNnrNetBios {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $false)] [int] $TimeoutMs = 1500
    )

    # The identifier is the first two bytes of the packet, so it is read back from the payload rather
    # than being returned separately. Passing it to the probe makes a reply from something other than
    # the NetBIOS name service - a firewall, a captive portal, an unrelated datagram - fail validation
    # instead of counting as an open port.
    $payload = New-mdiNetBiosNodeStatusPacket
    $transactionId = ([int] $payload[0] -shl 8) -bor [int] $payload[1]
    $result = Test-mdiUdpPort -ComputerName $ComputerName -Port 137 -Payload $payload -TimeoutMs $TimeoutMs -ExpectedTransactionId $transactionId
    if ($result.Success -and $result.Response -and $result.Response.Length -gt 56) {
        # Answer section starts after the 12-byte header, the 34-byte encoded name, 4 bytes of type/class,
        # 4 bytes TTL and 2 bytes RDLENGTH; the first RDATA byte is the number of names returned
        $nameCount = $result.Response[56]
        $names = @(for ($i = 0; $i -lt $nameCount; $i++) {
                $offset = 57 + ($i * 18)
                if (($offset + 15) -lt $result.Response.Length) {
                    ([System.Text.Encoding]::ASCII.GetString($result.Response, $offset, 15)).Trim()
                }
            }) | Select-Object -Unique
        [PSCustomObject]@{ Success = $true
            Detail = ('Resolved to: {0}' -f (($names | Where-Object { $_ }) -join ', '))
            LatencyMs = $result.LatencyMs
        }
    } else {
        [PSCustomObject]@{ Success = $result.Success; Detail = $result.Detail; LatencyMs = $result.LatencyMs }
    }
}

function Test-mdiReverseDns {
    param (
        [Parameter(Mandatory = $true)] [string] $IPAddress
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $hostEntry = [System.Net.Dns]::GetHostEntry($IPAddress)
        $stopwatch.Stop()
        if ($hostEntry.HostName -and $hostEntry.HostName -ne $IPAddress) {
            [PSCustomObject]@{ Success = $true; Detail = ('Resolved to {0}' -f $hostEntry.HostName); LatencyMs = [int] $stopwatch.ElapsedMilliseconds }
        } else {
            [PSCustomObject]@{ Success = $false; Detail = 'No PTR record - verify the Reverse Lookup Zone exists and is populated'; LatencyMs = [int] $stopwatch.ElapsedMilliseconds }
        }
    } catch {
        $stopwatch.Stop()
        [PSCustomObject]@{ Success = $false; Detail = ('No PTR record - {0}' -f $_.Exception.Message.Trim()); LatencyMs = $null }
    }
}

function Test-mdiCloudConnectivity {
    param (
        [Parameter(Mandatory = $true)] [string] $Url,
        [Parameter(Mandatory = $false)] [int] $TimeoutMs = 10000
    )

    try {
        # TLS 1.2 is required by the Defender for Identity cloud service and is not the default on older platforms
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Method = 'GET'
        $request.Timeout = $TimeoutMs
        $request.UserAgent = 'Test-MdiReadiness'
        $response = $request.GetResponse()
        $statusCode = [int] $response.StatusCode
        $response.Close()
        [PSCustomObject]@{ Success = $true; Detail = ('HTTPS connection established (HTTP {0})' -f $statusCode) }
    } catch [System.Net.WebException] {
        $webException = $_.Exception
        if ($webException.Response) {
            # Any HTTP status answer means the TLS session was established end to end, which is what we are testing.
            # The sensor API legitimately answers 401/403/404 to an unauthenticated GET.
            [PSCustomObject]@{ Success = $true; Detail = ('HTTPS connection established (HTTP {0})' -f [int] $webException.Response.StatusCode) }
        } else {
            $detail = switch ($webException.Status) {
                'TrustFailure' { 'TLS trust failure - SSL inspection is not supported and the required root certificates must be installed' }
                'SecureChannelFailure' { 'TLS handshake failed - SSL inspection is not supported by the sensor' }
                'NameResolutionFailure' { 'DNS resolution failed for the sensor API URL' }
                'Timeout' { 'Timed out - traffic to *.atp.azure.com on TCP 443 appears to be blocked' }
                default { '{0} - {1}' -f $webException.Status, $webException.Message }
            }
            [PSCustomObject]@{ Success = $false; Detail = $detail }
        }
    } catch {
        [PSCustomObject]@{ Success = $false; Detail = $_.Exception.Message }
    }
}

function Test-mdiLocalTcpListener {
    param (
        [Parameter(Mandatory = $true)] [int] $Port
    )

    try {
        $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
        @($listeners | Where-Object { $_.Port -eq $Port })
    } catch {
        @()
    }
}

function Test-mdiLocalUdpListener {
    param (
        [Parameter(Mandatory = $true)] [int] $Port
    )

    try {
        $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveUdpListeners()
        $listening = @($listeners | Where-Object { $_.Port -eq $Port })
        if ($listening.Count -gt 0) {
            [PSCustomObject]@{ Success = $true; Detail = ('Listening on {0}' -f (($listening | ForEach-Object { $_.Address.ToString() }) -join ', ')) }
        } else {
            [PSCustomObject]@{ Success = $false; Detail = ('Nothing is listening on UDP {0}' -f $Port) }
        }
    } catch {
        [PSCustomObject]@{ Success = $false; Detail = $_.Exception.Message }
    }
}

function Get-mdiConfiguredDnsServer {
    try {
        $adapters = Get-WmiObject -Namespace 'root\cimv2' -Class 'Win32_NetworkAdapterConfiguration' `
            -Filter 'IPEnabled=True' -ErrorAction Stop
        @($adapters | ForEach-Object { $_.DNSServerSearchOrder } | Where-Object { $_ } | Select-Object -Unique)
    } catch {
        @()
    }
}

function Invoke-mdiPortProbePlan {
    param (
        [Parameter(Mandatory = $true)] [object] $Plan
    )

    $timeoutMs = [int] $Plan.TimeoutMs
    $dnsServers = @(Get-mdiConfiguredDnsServer)
    # ArrayList rather than Generic.List[object]: converting a Generic.List[object] with @() throws
    # "Argument types do not match" on some Windows PowerShell 5.1 builds (for example 5.1.20348.4294).
    $results = New-Object -TypeName System.Collections.ArrayList

    $addResult = {
        param($Probe, $Target, $TargetIP, $Outcome, $Applicable = $true)
        [void] $results.Add([PSCustomObject]@{
                Id          = $Probe.Id
                Name        = $Probe.Name
                Protocol    = $Probe.Protocol
                Port        = $Probe.Port
                Scope       = $Probe.Scope
                Group       = $Probe.Group
                Requirement = $Probe.Requirement
                Target      = $Target
                TargetIP    = $TargetIP
                Applicable  = $Applicable
                Success     = $(if ($Applicable) { [bool] $Outcome.Success } else { $null })
                LatencyMs   = $Outcome.LatencyMs
                Detail      = $Outcome.Detail
            })
    }

    foreach ($probe in $Plan.Probes) {
        switch ($probe.Scope) {

            'Cloud' {
                if ([string]::IsNullOrEmpty($Plan.SensorApiUrl)) {
                    & $addResult $probe '<workspace>sensorapi.atp.azure.com' $null ([PSCustomObject]@{
                            Detail = 'Not tested - re-run with -WorkspaceName to validate connectivity to the sensor API URL'
                        }) $false
                } else {
                    $outcome = Test-mdiCloudConnectivity -Url $Plan.SensorApiUrl -TimeoutMs ([Math]::Max($timeoutMs, 10000))
                    & $addResult $probe ([uri] $Plan.SensorApiUrl).Host $null $outcome
                }
            }

            'Localhost' {
                # A closed TCP port does not always answer with a RST (loopback RSTs are suppressed on some systems),
                # so a plain connect cannot tell 'blocked by policy' from 'nothing is listening'. Only probe the port
                # when the sensor updater service is actually listening on it.
                $listeners = @(Test-mdiLocalTcpListener -Port $probe.Port)
                if ($listeners.Count -eq 0) {
                    & $addResult $probe 'localhost' '127.0.0.1' ([PSCustomObject]@{
                            Detail = ('Not tested - nothing is listening on TCP {0}, the sensor updater service is not installed or not running. Loopback traffic is allowed unless a custom firewall policy blocks it' -f $probe.Port)
                        }) $false
                } else {
                    $outcome = Test-mdiTcpPort -ComputerName '127.0.0.1' -Port $probe.Port -TimeoutMs $timeoutMs
                    if (-not $outcome.Success) {
                        $outcome = [PSCustomObject]@{
                            Success = $false
                            Detail  = ('{0} - the sensor updater service is listening on TCP {1} but loopback traffic to it is blocked by a local firewall policy' -f $outcome.Detail, $probe.Port)
                        }
                    }
                    & $addResult $probe 'localhost' '127.0.0.1' $outcome
                }
            }

            'DnsServer' {
                if ($dnsServers.Count -eq 0) {
                    & $addResult $probe 'DNS servers' $null ([PSCustomObject]@{ Detail = 'No DNS servers are configured on this server' }) $false
                } else {
                    foreach ($dnsServer in $dnsServers) {
                        $outcome = if ($probe.Protocol -eq 'TCP') {
                            Test-mdiTcpPort -ComputerName $dnsServer -Port $probe.Port -TimeoutMs $timeoutMs
                        } else {
                            $dnsPayload = New-mdiDnsQueryPacket -Name $Plan.DnsProbeName
                            Test-mdiUdpPort -ComputerName $dnsServer -Port $probe.Port -TimeoutMs $timeoutMs `
                                -Payload $dnsPayload -ExpectedTransactionId ((([int] $dnsPayload[0]) -shl 8) -bor [int] $dnsPayload[1])
                        }
                        & $addResult $probe $dnsServer $dnsServer $outcome
                    }
                }
            }

            'NetworkDevice' {
                foreach ($target in $Plan.NnrTargets) {
                    $outcome = switch ($probe.Id) {
                        'NnrNetBios' { Test-mdiNnrNetBios -ComputerName $target.IP -TimeoutMs $timeoutMs }
                        'NnrReverseDns' { Test-mdiReverseDns -IPAddress $target.IP }
                        default { Test-mdiTcpPort -ComputerName $target.IP -Port $probe.Port -TimeoutMs $timeoutMs }
                    }
                    & $addResult $probe $target.Name $target.IP $outcome
                }
            }

            'DomainController' {
                foreach ($target in $Plan.DomainControllers) {
                    $outcome = if ($probe.Protocol -eq 'TCP') {
                        Test-mdiTcpPort -ComputerName $target.IP -Port $probe.Port -TimeoutMs $timeoutMs
                    } else {
                        # CLDAP carries its messageID inside BER rather than in the first two bytes, so
                        # the generic identifier check does not apply. The reply is validated by shape
                        # below instead: it must be a BER SEQUENCE.
                        $outcome = Test-mdiUdpPort -ComputerName $target.IP -Port $probe.Port -TimeoutMs $timeoutMs `
                            -Payload (New-mdiCldapPingPacket)
                        if ($outcome.Success -and @($outcome.Response).Count -gt 0 -and $outcome.Response[0] -ne 0x30) {
                            $outcome = [PSCustomObject]@{ Success = $false
                                Detail = 'Invalid reply - not an LDAP message (the first byte is not a BER SEQUENCE)'
                                Response = $outcome.Response; LatencyMs = $outcome.LatencyMs
                            }
                        }
                        $outcome
                    }
                    & $addResult $probe $target.Name $target.IP $outcome
                }
            }

            'Inbound' {
                if (-not $Plan.TestVpnRadius) {
                    & $addResult $probe 'localhost' $null ([PSCustomObject]@{
                            Detail = 'Not tested - only required when the MDI VPN integration is configured. Re-run with -TestVpnRadius to validate'
                        }) $false
                } else {
                    $outcome = Test-mdiLocalUdpListener -Port $probe.Port
                    & $addResult $probe 'localhost' $null $outcome
                }
            }
        }
    }

    , $results.ToArray()
}

function Compress-mdiScriptText {
    param (
        [Parameter(Mandatory = $true)] [string] $ScriptText
    )

    # Comments are stripped with the tokenizer (not with a regular expression) so that '#' characters inside strings
    # are never touched. This keeps the generated command line comfortably inside the Win32_Process.Create limit.
    $tokens = $null
    $parseErrors = $null
    [void] [System.Management.Automation.Language.Parser]::ParseInput($ScriptText, [ref] $tokens, [ref] $parseErrors)
    if ($parseErrors) { return $ScriptText }

    $builder = New-Object -TypeName System.Text.StringBuilder -ArgumentList $ScriptText
    foreach ($comment in @($tokens | Where-Object { $_.Kind -eq 'Comment' } | Sort-Object { $_.Extent.StartOffset } -Descending)) {
        [void] $builder.Remove($comment.Extent.StartOffset, $comment.Extent.EndOffset - $comment.Extent.StartOffset)
    }

    (($builder.ToString() -split "`r?`n" | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ }) -join "`n")
}

function Get-mdiPortProbeCommandLine {
    param (
        [Parameter(Mandatory = $true)] [object] $Plan,
        [Parameter(Mandatory = $true)] [string] $OutputFile
    )

    # The probe primitives are shipped to the sensor server verbatim, so the remote test uses exactly the same logic
    # as the local one. This tests the true sensor -> target direction, which is what MDI requires.
    $functionNames = @(
        'Test-mdiTcpPort', 'Test-mdiUdpPort', 'New-mdiNetBiosNodeStatusPacket', 'New-mdiDnsQueryPacket',
        'New-mdiCldapPingPacket', 'Test-mdiNnrNetBios', 'Test-mdiReverseDns', 'Test-mdiCloudConnectivity',
        'Test-mdiLocalTcpListener', 'Test-mdiLocalUdpListener', 'Get-mdiConfiguredDnsServer', 'Invoke-mdiPortProbePlan'
    )
    # The Function provider does not support -Raw, so the body is taken from the command definition
    $definitions = ($functionNames | ForEach-Object {
            'function {0} {{{1}}}' -f $_, (Get-Command -Name $_ -CommandType Function).Definition
        }) -join [environment]::NewLine

    $planJson = $Plan | ConvertTo-Json -Depth 6 -Compress
    $planB64 = [convert]::ToBase64String([text.encoding]::UTF8.GetBytes($planJson))

    $scriptText = Compress-mdiScriptText -ScriptText (@'
{0}
$plan = ConvertFrom-Json ([text.encoding]::UTF8.GetString([convert]::FromBase64String('{1}')))
$result = Invoke-mdiPortProbePlan -Plan $plan
$json = $result | ConvertTo-Json -Depth 4 -Compress
[io.file]::WriteAllText('{2}', $json, (New-Object text.utf8encoding $false))
'@ -f $definitions, $planB64, ($OutputFile -replace "'", "''"))

    # gzip + base64 keeps the generated command line well inside the Win32_Process.Create limit
    $memoryStream = New-Object -TypeName System.IO.MemoryStream
    $gzipStream = New-Object -TypeName System.IO.Compression.GzipStream -ArgumentList $memoryStream, ([System.IO.Compression.CompressionMode]::Compress)
    $scriptBytes = [text.encoding]::UTF8.GetBytes($scriptText)
    $gzipStream.Write($scriptBytes, 0, $scriptBytes.Length)
    $gzipStream.Close()
    $compressed = [convert]::ToBase64String($memoryStream.ToArray())
    $memoryStream.Close()

    $stub = @'
$d = [convert]::FromBase64String('{0}')
$m = New-Object io.memorystream (, $d)
$g = New-Object io.compression.gzipstream $m, ([io.compression.compressionmode]::Decompress)
$r = New-Object io.streamreader $g
Invoke-Expression ($r.ReadToEnd())
'@ -f $compressed

    $commandLine = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {0}' -f
    [convert]::ToBase64String([text.encoding]::Unicode.GetBytes($stub))

    # Win32_Process.Create rejects command lines longer than 32767 characters
    if ($commandLine.Length -ge 32000) {
        throw ('The generated port probe command line is too long ({0} characters). Reduce the number of targets with -MaxNnrTargets and -MaxLdapTargetsPerDomain.' -f $commandLine.Length)
    }
    $commandLine
}

function Get-mdiRequiredPorts {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [object] $Plan
    )

    $probeCount = @($Plan.Probes).Count
    $targetCount = [Math]::Max(1, @($Plan.NnrTargets).Count + @($Plan.DomainControllers).Count)
    # Each probe is bounded by its own timeout; allow the whole batch to finish plus room for process start-up
    $timeoutSeconds = [Math]::Min(900, 60 + [int](($probeCount * $targetCount * $Plan.TimeoutMs) / 1000))

    $outputFile = Join-Path -Path (Get-mdiRemoteTempFolder -ComputerName $ComputerName) -ChildPath ('mdi-ports-{0}.json' -f [guid]::NewGuid().GUID)
    $commandLine = Get-mdiPortProbeCommandLine -Plan $Plan -OutputFile $outputFile

    $raw = Invoke-mdiRemoteCommand -ComputerName $ComputerName -CommandLine $commandLine -LocalFile $outputFile -TimeoutSeconds $timeoutSeconds
    $probeSource = 'Sensor server (outbound)'
    $usedFallback = $false

    $details = $null
    if ($raw) {
        try {
            # Assign before wrapping: Windows PowerShell emits a JSON array as a single pipeline object, so
            # @(... | ConvertFrom-Json) would nest every probe result into a one-element array.
            $parsed = ($raw -join '') | ConvertFrom-Json
            $details = @($parsed)
        } catch { $details = $null }
    }

    if ($null -eq $details -or $details.Count -eq 0) {
        # WMI remote execution is not always possible. Fall back to probing the server from the machine running this
        # script, which still detects firewalls blocking the ports, but only in the reverse direction.
        Write-mdiVerbose "Unable to run the port probes on $ComputerName, falling back to probing it remotely"

        # In this direction the probes test what is reachable *inbound* to the server. Ports scoped to
        # DomainController (LDAP and Global Catalog) are only ever served by a domain controller, so probing
        # them against a CA, Entra Connect or member server always fails and would be reported as a blocked
        # required port. They are kept only when the server being tested is itself a domain controller.
        $isDomainController = @($Plan.DomainControllers | Where-Object {
                $_.Name -eq $ComputerName -or $_.IP -eq $ComputerName
            }).Count -gt 0
        $fallbackScopes = if ($isDomainController) { @('NetworkDevice', 'DomainController') } else { @('NetworkDevice') }

        $fallbackPlan = $Plan.PSObject.Copy()
        $fallbackPlan.NnrTargets = @([PSCustomObject]@{ Name = $ComputerName; IP = $ComputerName })
        $fallbackPlan.DomainControllers = @([PSCustomObject]@{ Name = $ComputerName; IP = $ComputerName })
        $fallbackPlan.Probes = @($Plan.Probes | Where-Object { $_.Scope -in $fallbackScopes })
        $details = @(Invoke-mdiPortProbePlan -Plan $fallbackPlan)
        $probeSource = 'This computer (inbound to the server)'
        $usedFallback = $true
    }

    $details = @($details | ForEach-Object {
            $_ | Add-Member -MemberType NoteProperty -Name 'ProbedFrom' -Value $probeSource -Force -PassThru
        })

    $applicable = @($details | Where-Object { $_.Applicable -ne $false })
    $mandatory = @($applicable | Where-Object { $_.Requirement -eq 'Required' })
    $mandatoryFailures = @($mandatory | Where-Object { -not $_.Success })
    # Per the NNR documentation only one of the primary methods is required, but all of them are recommended.
    # The requirement is evaluated per target: a target that no method can resolve is what degrades the sensor's
    # name resolution success rate and raises the 'Low success rate of active name resolution' health alert.
    $nnrProbes = @($applicable | Where-Object { $_.Group -eq 'NNR' })
    # Grouped by address as well as name. A multi-homed target is a separate resolution target per
    # address - the sensor resolves whatever source address it observed - so grouping by name alone let
    # a host with one open NIC and one blocked NIC count as resolved, hiding the very failure that
    # lowers the success rate in the portal.
    $nnrFailedTargets = @($nnrProbes | Group-Object -Property Target, TargetIP |
            Where-Object { @($_.Group | Where-Object { $_.Success }).Count -eq 0 } |
            ForEach-Object {
                $first = @($_.Group)[0]
                if ([string]::IsNullOrWhiteSpace([string] $first.TargetIP)) {
                    [string] $first.Target
                } else {
                    '{0} ({1})' -f [string] $first.Target, [string] $first.TargetIP
                }
            })

    # The verdict is tri-state. When the probes could not be run ON the sensor, what was measured is a
    # different question from the one asked: MDI requires the sensor to reach OUT to each target, and
    # the fallback tests this computer reaching IN to the sensor. A firewall can block one direction
    # and not the other, so a failure here is not evidence that the required path is shut - and
    # reporting it as a failed required-ports check sent operators to open ports that were open, the
    # single most expensive kind of wrong answer this tool can give. The results are still reported,
    # labelled with the direction they were taken in, because a blocked reverse path is worth seeing.
    $isRequiredPortsOk = if ($usedFallback) {
        'N/A'
    } else {
        ($mandatoryFailures.Count -eq 0) -and ($nnrFailedTargets.Count -eq 0)
    }

    [PSCustomObject]@{
        isRequiredPortsOk = $isRequiredPortsOk
        details           = [PSCustomObject]@{
            ProbedFrom       = $probeSource
            # The direction is stated in the finding itself, not only in ProbedFrom, because these
            # strings are what the operator reads in the Issues table and pastes into a change request.
            FailedRequired   = @(foreach ($failure in $mandatoryFailures) {
                    $line = [string] $failure.Protocol + '/' + [string] $failure.Port + ' to ' + [string] $failure.Target + ': ' + [string] $failure.Detail
                    if ($usedFallback) { 'Not tested in the required direction - measured inbound from this computer instead: ' + $line } else { $line }
                })
            NnrFailedTargets = $nnrFailedTargets
            Results          = $details
        }
    }
}

#endregion

function New-mdiPortProbePlan {
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [object[]] $DomainController = @(),
        [Parameter(Mandatory = $false)] [object[]] $NnrTarget = @(),
        [Parameter(Mandatory = $false)] [string] $WorkspaceName = $null,
        [Parameter(Mandatory = $false)] [int] $TimeoutMs = 1500,
        [Parameter(Mandatory = $false)] [switch] $MultiForest,
        [Parameter(Mandatory = $false)] [switch] $TestVpnRadius
    )

    $probes = $settings.RequiredPorts | ForEach-Object {
        $probe = $_.PSObject.Copy()
        if ($MultiForest -and $settings.MultiForestPorts -contains $probe.Id) {
            $probe.Requirement = 'Required'
        }
        $probe
    }

    $sensorApiUrl = if ([string]::IsNullOrWhiteSpace($WorkspaceName)) {
        $null
    } else {
        'https://{0}' -f ($settings.SensorApiUrlFormat -f $WorkspaceName.Trim())
    }

    [PSCustomObject]@{
        TimeoutMs         = $TimeoutMs
        DnsProbeName      = $Domain
        SensorApiUrl      = $sensorApiUrl
        TestVpnRadius     = [bool] $TestVpnRadius
        NnrTargets        = @($NnrTarget)
        DomainControllers = @($DomainController)
        Probes            = @($probes)
    }
}

function Resolve-mdiNnrTarget {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $DomainControllers,
        [Parameter(Mandatory = $false)] [string[]] $NnrTargetComputer = $null,
        [Parameter(Mandatory = $false)] [string] $Domain = $null,
        [Parameter(Mandatory = $false)] [int] $MaxTargets = 5
    )

    # Network Name Resolution must work against every device on the network, not only domain controllers. When the
    # caller supplies representative endpoints we use those, otherwise we fall back to a sample of domain controllers.
    $targets = if ($NnrTargetComputer) {
        @($NnrTargetComputer | ForEach-Object {
                $name = $_
                $knownIp = $null
                try {
                    $adParams = @{ Identity = $name; Properties = 'DNSHostName', 'IPv4Address'; ErrorAction = 'Stop' }
                    if ($Domain) { $adParams['Server'] = $Domain }
                    $computer = Get-ADComputer @adParams
                    $name = if ($computer.DNSHostName) { $computer.DNSHostName } else { $computer.Name }
                    $knownIp = [string] $computer.IPv4Address
                } catch {
                    Write-mdiVerbose "Unable to find '$name' in Active Directory, resolving it with DNS"
                }

                # Every address, not the first one. NNR resolves whatever source address the sensor
                # observed, so a multi-homed host that answers on one NIC and is filtered on another
                # fails resolution for half its traffic - which a single-address probe cannot see.
                $addresses = @(Get-mdiComputerAddress -ComputerName $name -KnownAddress $knownIp)
                if ($addresses.Count -eq 0) {
                    Write-Warning ('Unable to resolve the NNR target computer {0}' -f $name)
                } else {
                    foreach ($address in $addresses) {
                        [PSCustomObject]@{ Name = $name; IP = $address; MultiHomed = ($addresses.Count -gt 1) }
                    }
                }
            })
    } else {
        @($DomainControllers | Where-Object { $_.IP })
    }

    # The cap counts HOSTS, not addresses. Truncating a flat list of addresses would silently drop the
    # second NIC of the last host in the sample - the exact address most likely to be the one failing.
    if ($MaxTargets -gt 0) {
        $byHost = @($targets | Group-Object -Property Name)
        if ($byHost.Count -gt $MaxTargets) {
            $targets = @($byHost | Select-Object -First $MaxTargets | ForEach-Object { $_.Group })
        }
    }
    , $targets
}

function Resolve-mdiLdapTarget {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $DomainControllers,
        [Parameter(Mandatory = $false)] [int] $MaxPerDomain = 2
    )

    # Probing every domain controller from every sensor grows quadratically and is unnecessary: the sensors query the
    # directory of each domain, so a sample of domain controllers per domain proves the LDAP path is open.
    #
    # Unlike NNR, LDAP is reached by NAME - the sensor asks DNS for a domain controller and connects to
    # whatever it gets back - so one address per host is the right unit here, and the inventory's extra
    # rows for a multi-homed DC are collapsed. Without this, MaxPerDomain 2 could spend its whole budget
    # on the two NICs of a single domain controller and never test the second one.
    $candidates = @($DomainControllers | Where-Object { $_.IP } | Group-Object -Property Name | ForEach-Object {
            $_.Group | Select-Object -First 1
        })

    $targets = if ($MaxPerDomain -le 0) {
        $candidates
    } else {
        @($candidates | Group-Object -Property Domain | ForEach-Object {
                $_.Group | Select-Object -First $MaxPerDomain
            })
    }
    , @($targets)
}

function Get-mdiForestDomainFromLdap {
    param (
        [Parameter(Mandatory = $false)] [string] $Domain = $null
    )

    # The LDAP fallback for forest enumeration. Get-ADForest talks to Active Directory Web Services on
    # TCP 9389 - an optional service that can be stopped, firewalled, or refuse a restricted caller - so
    # without this fallback a healthy multi-domain forest collapsed to a single-domain scan and every
    # other domain went unexamined while the report still said "Forest".
    #
    # The Partitions container is the authoritative list of domains in a forest: each domain naming
    # context has a crossRef object carrying its DNS name. systemFlags bit 1 (FLAG_CR_NTDS_DOMAIN, value
    # 2) is what separates a real domain from the schema, configuration and application partitions,
    # which also have crossRef objects and would otherwise be scanned as if they were domains.
    $searcher = $null
    $searchRoot = $null
    $rootDse = $null
    try {
        $path = if ($Domain) { "LDAP://$Domain/RootDSE" } else { 'LDAP://RootDSE' }
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry($path)

        $configNc = $null
        if ($rootDse.Properties['configurationNamingContext'].Count -gt 0) {
            $configNc = [string] $rootDse.Properties['configurationNamingContext'][0]
        }
        $rootNc = $null
        if ($rootDse.Properties['rootDomainNamingContext'].Count -gt 0) {
            $rootNc = [string] $rootDse.Properties['rootDomainNamingContext'][0]
        }
        if ([string]::IsNullOrWhiteSpace($configNc)) { return $null }

        $partitionsPath = if ($Domain) { "LDAP://$Domain/CN=Partitions,$configNc" } else { "LDAP://CN=Partitions,$configNc" }
        $searchRoot = New-Object System.DirectoryServices.DirectoryEntry($partitionsPath)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $searchRoot
        $searcher.Filter = '(&(objectCategory=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))'
        $searcher.PageSize = 200
        [void] $searcher.PropertiesToLoad.Add('dnsroot')

        $domains = @(foreach ($entry in $searcher.FindAll()) {
                if ($entry.Properties['dnsroot'].Count -gt 0) { [string] $entry.Properties['dnsroot'][0] }
            }) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

        if (@($domains).Count -eq 0) { return $null }

        # The forest is named after its root domain, whose DN is turned back into a DNS name. If rootDSE
        # did not carry it, the shortest domain name is the root: every other domain in a forest is a
        # child or tree-root suffixed beneath it.
        $forestName = if (-not [string]::IsNullOrWhiteSpace($rootNc)) {
            (($rootNc -split ',' | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_ -replace '^DC=', '' }) -join '.')
        } else {
            @($domains | Sort-Object { $_.Length })[0]
        }

        [PSCustomObject]@{
            Name    = $forestName
            Domains = @($domains)
        }
    } catch {
        Write-mdiVerbose ('LDAP forest enumeration failed: {0}' -f $_.Exception.Message)
        $null
    } finally {
        if ($searcher) { try { $searcher.Dispose() } catch {} }
        if ($searchRoot) { try { $searchRoot.Dispose() } catch {} }
        if ($rootDse) { try { $rootDse.Dispose() } catch {} }
    }
}

function Get-mdiForestDomain {
    param (
        [Parameter(Mandatory = $false)] [string] $Domain = $null
    )

    # Complete records whether the returned list is the real forest or a guess. A -Forest run that
    # quietly examined one domain out of five and then reported READY is a false green over four
    # domains nobody looked at, so the degraded case is carried forward rather than warned about once
    # and forgotten.
    $reason = $null
    try {
        $forestParams = @{ ErrorAction = 'Stop' }
        if ($Domain) { $forestParams['Server'] = $Domain }
        $adForest = Get-ADForest @forestParams
        if (@($adForest.Domains).Count -gt 0) {
            Write-mdiVerbose ('Found forest {0} with {1} domain(s): {2}' -f $adForest.Name, @($adForest.Domains).Count, ($adForest.Domains -join ', '))
            return [PSCustomObject]@{
                Name     = $adForest.Name
                Domains  = @($adForest.Domains)
                Method   = 'ADWS'
                Complete = $true
                Error    = $null
            }
        }
        $reason = 'the query succeeded but returned no domains'
    } catch {
        $reason = $_.Exception.Message
    }

    Write-mdiVerbose ('Active Directory Web Services could not enumerate the forest ({0}), falling back to LDAP' -f $reason)
    $viaLdap = Get-mdiForestDomainFromLdap -Domain $Domain
    if ($null -ne $viaLdap) {
        Write-mdiVerbose ('Found forest {0} with {1} domain(s) over LDAP: {2}' -f $viaLdap.Name, @($viaLdap.Domains).Count, ($viaLdap.Domains -join ', '))
        return [PSCustomObject]@{
            Name     = $viaLdap.Name
            Domains  = @($viaLdap.Domains)
            Method   = 'LDAP'
            Complete = $true
            Error    = $null
        }
    }

    Write-Warning ('Unable to enumerate the forest domains over Active Directory Web Services or LDAP, falling back to the single domain {0}: {1}. Any other domain in this forest has NOT been examined.' -f $Domain, $reason)
    [PSCustomObject]@{
        Name     = $Domain
        Domains  = @($Domain)
        Method   = 'None'
        Complete = $false
        Error    = $reason
    }
}

function Get-mdiComputerAddress {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $false)] [AllowNull()] [string] $KnownAddress = $null
    )

    <#
        Every IPv4 address a computer answers on, not just the first one.

        A multi-homed domain controller is the case this exists for, and it is not a corner case: DCs
        routinely carry a second NIC for backup, management, cluster heartbeat or a DMZ leg.

        Both of the ways this script previously learned an address return exactly one:
          - Get-ADComputer's IPv4Address property is a single value, and which one it holds depends on
            registration order, not on which interface matters.
          - [System.Net.Dns]::GetHostAddresses(...)[0] takes an arbitrary entry out of several A
            records - and a different one on each call when DNS round-robins, so two runs against an
            unchanged environment disagreed with each other.

        Probing only that one address is the exact blind spot behind the "Low success rate of active
        name resolution" health alert this tool was extended to diagnose. Network Name Resolution
        works on whatever source address the sensor observes in traffic, so a second NIC on a subnet
        where TCP 135/3389 or UDP 137 is filtered - or which has no reverse lookup zone - fails every
        resolution attempt for that host while a single-address probe reports the DC as fully open.
        The report was green and the portal alert stayed lit, with nothing to connect the two.

        Addresses are sorted numerically so that two runs of the same environment produce the same
        report: sorting dotted quads as text puts .10 before .9. Casting to [version] orders them
        correctly because an IPv4 address is four numeric components, and anything that does not look
        like one is pushed to the end rather than throwing inside the sort.
    #>
    $addresses = New-Object -TypeName System.Collections.ArrayList
    if (-not [string]::IsNullOrWhiteSpace($KnownAddress)) { [void] $addresses.Add($KnownAddress.Trim()) }

    try {
        foreach ($address in [System.Net.Dns]::GetHostAddresses($ComputerName)) {
            if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                [void] $addresses.Add($address.IPAddressToString)
            }
        }
    } catch {
        Write-mdiVerbose ('Could not resolve the addresses of {0}: {1}' -f $ComputerName, $_.Exception.Message)
    }

    # APIPA and loopback are never a real service address, and a DC that has one is telling us its DNS
    # registration is stale rather than that it is reachable there.
    $usable = @($addresses | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and
            $_ -notmatch '^169\.254\.' -and $_ -ne '127.0.0.1' -and $_ -ne '0.0.0.0'
        } | Select-Object -Unique)

    @($usable | Sort-Object -Property @{ Expression = {
                if ($_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { [version] $_ } else { [version] '255.255.255.255' }
            }
        }, @{ Expression = { $_ } })
}

function Get-mdiDomainControllerFromLdap {
    param (
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    # The LDAP fallback for domain controller discovery. Get-ADDomainController talks to Active Directory
    # Web Services on TCP 9389, a separate optional service that can be stopped, faulted or firewalled
    # while the directory itself is perfectly healthy, and which fails for a restricted caller with
    # "The operation failed because of a bad parameter". LDAP on 389 has to work or Active Directory does
    # not function at all, so it is the right thing to fall back to.
    $searcher = $null
    $searchRoot = $null
    $rootDse = $null
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain/RootDSE")
        $namingContext = $null
        if ($rootDse.Properties['defaultNamingContext'].Count -gt 0) {
            $namingContext = [string] $rootDse.Properties['defaultNamingContext'][0]
        }
        if ([string]::IsNullOrWhiteSpace($namingContext)) { return @() }

        $searchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain/$namingContext")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $searchRoot
        # SERVER_TRUST_ACCOUNT (8192) identifies a writable domain controller. A read-only one does not
        # carry that bit, it is a workstation trust account flagged PARTIAL_SECRETS_ACCOUNT (67108864),
        # so both are matched or every RODC would be missed.
        $searcher.Filter = '(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))'
        $searcher.PageSize = 200
        [void] $searcher.PropertiesToLoad.Add('dnshostname')
        [void] $searcher.PropertiesToLoad.Add('name')

        @(foreach ($entry in $searcher.FindAll()) {
                $hostName = $null
                if ($entry.Properties['dnshostname'].Count -gt 0) { $hostName = [string] $entry.Properties['dnshostname'][0] }
                if ([string]::IsNullOrWhiteSpace($hostName) -and $entry.Properties['name'].Count -gt 0) {
                    $hostName = '{0}.{1}' -f [string] $entry.Properties['name'][0], $Domain
                }
                if ([string]::IsNullOrWhiteSpace($hostName)) { continue }

                # The addresses are resolved separately because the computer object does not carry one.
                # All of them are kept: a multi-homed domain controller discovered over LDAP must be
                # probed on every interface, and taking [0] picked an arbitrary A record - a different
                # one on each call when DNS round-robins.
                $addresses = @(Get-mdiComputerAddress -ComputerName $hostName)

                [PSCustomObject]@{
                    Name      = $hostName
                    IP        = if ($addresses.Count -gt 0) { $addresses[0] } else { $null }
                    Addresses = $addresses
                }
            })
    } catch {
        @()
    } finally {
        if ($searcher) { try { $searcher.Dispose() } catch {} }
        if ($searchRoot) { try { $searchRoot.Dispose() } catch {} }
        if ($rootDse) { try { $rootDse.Dispose() } catch {} }
    }
}

function Resolve-mdiDomainController {
    param (
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    # Domain controller discovery is the one query the whole report depends on: when it returns nothing
    # every later check has nothing to run against. It is therefore tried over Active Directory Web
    # Services first and over LDAP second, and the method used is reported so that a total failure can be
    # told apart from a domain that genuinely has no matching servers.
    $reason = $null
    try {
        $viaAdws = @(Get-ADDomainController -Server $Domain -Filter * -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Name = [string] $_.HostName
                    IP   = [string] $_.IPv4Address
                }
            })
        if ($viaAdws.Count -gt 0) {
            return [PSCustomObject]@{ Servers = $viaAdws; Method = 'ADWS'; Error = $null }
        }
        $reason = 'the query succeeded but returned no domain controllers'
    } catch {
        $reason = $_.Exception.Message
    }

    Write-mdiVerbose ('Active Directory Web Services could not enumerate the domain controllers of {0} ({1}), falling back to LDAP' -f $Domain, $reason)
    $viaLdap = @(Get-mdiDomainControllerFromLdap -Domain $Domain)
    if ($viaLdap.Count -gt 0) {
        Write-mdiVerbose ('Found {0} domain controller(s) in {1} over LDAP' -f $viaLdap.Count, $Domain)
        return [PSCustomObject]@{ Servers = $viaLdap; Method = 'LDAP'; Error = $null }
    }

    [PSCustomObject]@{ Servers = @(); Method = 'None'; Error = $reason }
}

function Get-mdiDomainControllerInventory {
    param (
        [Parameter(Mandatory = $true)] [string[]] $Domain
    )

    # A consolidated inventory of every domain controller in scope. It is the list of LDAP targets each sensor must be
    # able to reach, and the default set of NNR targets.
    #
    # A domain that cannot be enumerated is recorded rather than merely warned about. Skipping it left a
    # forest scan looking complete while an entire domain had never been examined - and because it
    # contributed no servers, it contributed no failures either, so the run could still be reported
    # READY. The placeholder carries no Name, so it is filtered out of the probe targets while still
    # being visible to the verdict.
    @(foreach ($domainName in $Domain) {
            $resolved = Resolve-mdiDomainController -Domain $domainName
            if ($resolved.Servers.Count -eq 0) {
                Write-Warning ('Unable to enumerate the domain controllers of {0} over Active Directory Web Services or LDAP: {1}' -f $domainName, $resolved.Error)
                [PSCustomObject]@{
                    Name        = $null
                    IP          = $null
                    Addresses   = @()
                    MultiHomed  = $false
                    Domain      = $domainName
                    Enumerated  = $false
                    Error       = $resolved.Error
                }
                continue
            }
            foreach ($dc in $resolved.Servers) {
                # One entry per address. A multi-homed domain controller has to be probed on each one:
                # NNR resolves the address the sensor saw in traffic, and the second NIC is exactly the
                # one likely to sit on a subnet with no reverse lookup zone or a tighter firewall.
                $addresses = @(Get-mdiComputerAddress -ComputerName $dc.Name -KnownAddress $dc.IP)
                if ($addresses.Count -eq 0) { $addresses = @($dc.IP) | Where-Object { $_ } }
                foreach ($address in $addresses) {
                    [PSCustomObject]@{
                        Name       = $dc.Name
                        IP         = $address
                        Addresses  = $addresses
                        MultiHomed = ($addresses.Count -gt 1)
                        Domain     = $domainName
                        Enumerated = $true
                        Error      = $null
                    }
                }
            }
        })
}

#region Sensor v3.x upgrade readiness

function Get-mdiRemoteRegistryResult {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $Key,
        [Parameter(Mandatory = $true)] [string] $Value
    )

    # Returns whether the registry could be read at all, separately from what it contained. A value that
    # is absent and a registry that could not be opened both yield null, but they mean opposite things:
    # the first says the setting is not configured, the second says nothing is known about it.
    $hklm = $null
    try {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, 'Registry64')
    } catch {
        return [PSCustomObject]@{ Readable = $false; Value = $null; Error = ($_.Exception.Message -replace '[\r\n]+', ' ') }
    }

    try {
        $subKey = $hklm.OpenSubKey($Key)
        if ($null -eq $subKey) {
            return [PSCustomObject]@{ Readable = $true; Value = $null; Error = $null }
        }
        try {
            [PSCustomObject]@{ Readable = $true; Value = $subKey.GetValue($Value); Error = $null }
        } finally {
            try { $subKey.Close() } catch {}
        }
    } catch {
        [PSCustomObject]@{ Readable = $false; Value = $null; Error = ($_.Exception.Message -replace '[\r\n]+', ' ') }
    } finally {
        if ($hklm) { try { $hklm.Close() } catch {} }
    }
}

function Get-mdiRemoteRegistryValue {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $Key,
        [Parameter(Mandatory = $true)] [string] $Value
    )

    (Get-mdiRemoteRegistryResult -ComputerName $ComputerName -Key $Key -Value $Value).Value
}

function Get-mdiServiceState {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $ServiceName
    )

    try {
        $serviceParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_Service'
            Property     = 'Name', 'State', 'StartMode', 'PathName'
            Filter       = "Name = '{0}'" -f $ServiceName
            ErrorAction  = 'SilentlyContinue'
        }
        Get-WmiObject @serviceParams
    } catch {
        $null
    }
}

function Get-mdiSensorV3Readiness {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $false)] [string] $SensorVersion = $null
    )

    $checks = New-Object -TypeName System.Collections.ArrayList
    $addCheck = {
        param([string] $Name, [object] $Status, [string] $Detail, [string] $Requirement = 'Required', [bool] $Remediable = $true)
        # ArrayList rather than Generic.List[object]: converting a Generic.List[object] with @() throws
        # "Argument types do not match" on some Windows PowerShell 5.1 builds (for example 5.1.20348.4294).
        # Remediable marks whether a failure is worth acting on. A member server or a Windows Server 2016
        # domain controller can never run the v3.x sensor, so those failures are the expected answer for
        # that server rather than a task, and the remediation script must not raise them.
        # Measured separates the two kinds of N/A. "Not tested" means the server could not be read, so the
        # result is unknown and the overall verdict must not be stated. Any other N/A is informational -
        # a newer build than this script knows about, or a requirement that does not apply here - and
        # leaves the verdict intact. The "Not tested - " prefix is the convention that marks the first.
        [void] $checks.Add([PSCustomObject]@{
                Name        = $Name
                Requirement = $Requirement
                Status      = $Status
                Detail      = $Detail
                Remediable  = $Remediable
                Measured    = -not ($Detail -like 'Not tested*')
            })
    }

    $v3 = $settings.SensorV3

    # --- Server role: v3.x runs on domain controllers only -----------------------------------------------------
    # 'The v3.x sensor supports domain controllers, including domain controllers with these identity roles'
    # 'Use the Defender for Identity sensor v2.x for servers that aren't domain controllers and run AD FS, AD CS,
    #  or Microsoft Entra Connect.'
    $osInfo = $null
    $osError = $null
    try {
        $osInfo = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class 'Win32_OperatingSystem' `
            -Property 'Version', 'Caption', 'ProductType', 'BuildNumber' -ErrorAction Stop
    } catch {
        $osError = $_.Exception.Message -replace '[\r\n]+', ' '
    }

    # Whether the server could be queried at all. Win32_OperatingSystem exists on every running Windows
    # machine, so failing to read it means WMI itself is unavailable rather than the class being absent.
    # Without this distinction every derived check defaulted to false and the report told the customer
    # their domain controllers were not domain controllers.
    $wmiReadable = $null -ne $osInfo
    $unreadable = if ($osError) { 'the server could not be queried over WMI: {0}' -f $osError } else { 'the server could not be queried over WMI' }

    # WMI returns PSObject-wrapped values. They are unwrapped into plain .NET types here because passing a wrapped
    # value to the format operator can break its dynamic binder ("Argument types do not match") in Windows PowerShell.
    $osCaption = if ($osInfo) { [string] $osInfo.Caption } else { 'N/A' }
    $osProductType = if ($osInfo) { [int] $osInfo.ProductType } else { 0 }
    $osBuildText = if ($osInfo) { [string] $osInfo.BuildNumber } else { '' }

    $isDomainController = if (-not $wmiReadable) { 'N/A' } else { $osProductType -eq 2 }
    & $addCheck 'Server is a domain controller' $isDomainController $(
        if (-not $wmiReadable) { 'Not tested - {0}' -f $unreadable }
        elseif ($isDomainController) { 'Domain controller' }
        else { 'Not a domain controller - the v3.x sensor only supports domain controllers, keep using the v2.x sensor on this server' }
    ) 'Required' $false

    # --- Operating system: Windows Server 2019 or later --------------------------------------------------------
    $osBuild = 0
    if ($osBuildText) { [void] [int]::TryParse($osBuildText, [ref] $osBuild) }
    $isOsOk = if (-not $wmiReadable) { 'N/A' } else { $osBuild -ge $v3.MinOSBuild }
    & $addCheck 'Windows Server 2019 or later' $isOsOk $(
        if (-not $wmiReadable) { 'Not tested - {0}' -f $unreadable }
        elseif ($osBuild -eq 0) { 'Unable to determine the operating system version' }
        elseif ($isOsOk -eq $true) { '{0} (build {1})' -f $osCaption, $osBuild }
        else { '{0} (build {1}) - the v3.x sensor requires Windows Server 2019 or later, keep using the v2.x sensor on this server' -f $osCaption, $osBuild }
    ) 'Required' $false

    # --- Cumulative update: July 2026 or later -----------------------------------------------------------------
    $ubrResult = Get-mdiRemoteRegistryResult -ComputerName $ComputerName -Key $v3.CurrentVersionRegKey -Value 'UBR'
    $ubr = if ($null -eq $ubrResult.Value) { $null } else { [int] $ubrResult.Value }
    $expectedUpdate = $v3.JulyCumulativeUpdate[$osBuild]
    # The operating system state is compared as a string: $isOsOk is tri-state, and a bare
    # `$isOsOk -eq 'N/A'` casts the RIGHT operand to the left's type, where [bool]'N/A' is $true, so the
    # comparison is true even when $isOsOk is $true. Casting the left operand to [string] first is the
    # only safe way to test a tri-state value.
    $isCuOk = if ([string] $isOsOk -eq 'N/A') {
        'N/A'
    } elseif ($isOsOk -eq $false) {
        $false
    } elseif ($null -eq $expectedUpdate) {
        # A build newer than the ones known to this script is assumed to be recent enough
        'N/A'
    } elseif (-not $ubrResult.Readable) {
        # The registry could not be read, so the patch level is unknown rather than out of date.
        'N/A'
    } elseif ($null -eq $ubr) {
        $false
    } else {
        $ubr -ge [int] $expectedUpdate.Revision
    }
    & $addCheck 'July 2026 or later cumulative update' $isCuOk $(
        if ([string] $isOsOk -eq 'N/A') { 'Not tested - {0}' -f $unreadable }
        elseif ($isOsOk -eq $false) { 'Not evaluated - the operating system is not supported by the v3.x sensor' }
        elseif ($null -eq $expectedUpdate) { 'OS build {0}.{1} is newer than the builds known to this script, verify the cumulative update level manually' -f $osBuild, $ubr }
        elseif (-not $ubrResult.Readable) { 'Not tested - the registry could not be read on this server: {0}' -f [string] $ubrResult.Error }
        elseif ($null -eq $ubr) { 'Unable to read the update revision from the registry' }
        elseif ($ubr -ge [int] $expectedUpdate.Revision) { '{0} build {1}.{2} meets the July 2026 level ({3}.{4}, {5})' -f [string] $expectedUpdate.OS, $osBuild, $ubr, $osBuild, [int] $expectedUpdate.Revision, [string] $expectedUpdate.KB }
        else { '{0} build {1}.{2} is older than the July 2026 cumulative update ({3}.{4}, {5}) - install it before migrating' -f [string] $expectedUpdate.OS, $osBuild, $ubr, $osBuild, [int] $expectedUpdate.Revision, [string] $expectedUpdate.KB }
    ) 'Required' ($isOsOk -eq $true)

    # --- Defender for Endpoint deployed and onboarded ----------------------------------------------------------
    # 'Defender for Endpoint must be onboarded on the server where the sensor runs; endpoint-only deployment isn't sufficient.'
    $senseService = Get-mdiServiceState -ComputerName $ComputerName -ServiceName $v3.MdeSenseServiceName
    $senseState = if ($senseService) { [string] $senseService.State } else { $null }
    $senseStartMode = if ($senseService) { [string] $senseService.StartMode } else { $null }
    # A null service means "not installed" only when WMI answered. When WMI is unavailable it means
    # nothing was learned, so reporting the service as missing would be an invention.
    $isSenseRunning = if (-not $wmiReadable) { 'N/A' } else { $senseState -eq 'Running' }
    & $addCheck 'Defender for Endpoint (Sense) service is running' $isSenseRunning $(
        if (-not $wmiReadable) { 'Not tested - {0}' -f $unreadable }
        elseif ($null -eq $senseService) { 'The Sense service is not installed - onboard the server to Microsoft Defender for Endpoint' }
        elseif ($isSenseRunning -eq $true) { 'Sense service is running (start mode: {0})' -f $senseStartMode }
        else { 'Sense service is {0} (start mode: {1}) - it must be running' -f $senseState, $senseStartMode }
    )

    $onboardingResult = Get-mdiRemoteRegistryResult -ComputerName $ComputerName -Key $v3.MdeStatusRegKey -Value $v3.MdeOnboardingStateValue
    $onboardingState = $onboardingResult.Value
    # An absent value means not onboarded; an unreadable registry means unknown.
    $isOnboarded = if (-not $onboardingResult.Readable) { 'N/A' } else { $null -ne $onboardingState -and [int] $onboardingState -eq 1 }
    & $addCheck 'Defender for Endpoint is onboarded' $isOnboarded $(
        if (-not $onboardingResult.Readable) { 'Not tested - the registry could not be read on this server: {0}' -f [string] $onboardingResult.Error }
        elseif ($null -eq $onboardingState) { 'OnboardingState is not present under HKLM\{0} - the server is not onboarded to Defender for Endpoint' -f [string] $v3.MdeStatusRegKey }
        elseif ($isOnboarded -eq $true) { 'OnboardingState = 1' }
        else { 'OnboardingState = {0} - the server is not onboarded to Defender for Endpoint' -f [int] $onboardingState }
    )

    # --- Existing v2.x sensor ----------------------------------------------------------------------------------
    # 'Doesn't have a Defender for Identity sensor v2.x already deployed' for a fresh activation. For the in-place
    # migration the v2.x sensor must instead be present and recent enough.
    $v2Service = Get-mdiServiceState -ComputerName $ComputerName -ServiceName 'AATPSensor'
    $hasV2Sensor = $null -ne $v2Service
    $v2ServiceState = if ($v2Service) { [string] $v2Service.State } else { $null }
    $v2Version = if ($SensorVersion -and [string] $SensorVersion -ne 'N/A') { [string] $SensorVersion } else { $null }

    $isV2VersionOk = 'N/A'
    if ($hasV2Sensor -and $v2Version) {
        $parsedVersion = $null
        $isV2VersionOk = if ([version]::TryParse($v2Version, [ref] $parsedVersion)) {
            $parsedVersion -ge [version] $v3.MinV2VersionForMigration
        } else { $false }
    }

    & $addCheck 'Defender for Identity sensor v2.x version supports migration' $isV2VersionOk $(
        if (-not $hasV2Sensor) { 'No v2.x sensor is installed - the server can be activated directly with the v3.x sensor' }
        elseif (-not $v2Version) { 'A v2.x sensor is installed but its version could not be determined' }
        elseif ($isV2VersionOk -eq $true) { 'v2.x sensor {0} meets the minimum version for in-place migration ({1})' -f $v2Version, [string] $v3.MinV2VersionForMigration }
        else { 'v2.x sensor {0} is older than {1} - upgrade the v2.x sensor before migrating' -f $v2Version, [string] $v3.MinV2VersionForMigration }
    ) 'Migration'

    # --- Identity roles block the in-place migration -----------------------------------------------------------
    # 'Domain controllers with identity roles support v3.x for new deployments, but in-place migration isn't
    #  currently supported for these servers.'
    $identityRoles = @(foreach ($service in $v3.IdentityRoleServices.Keys) {
            if ((Get-mdiServiceState -ComputerName $ComputerName -ServiceName $service)) { [string] $v3.IdentityRoleServices[$service] }
        })
    $noIdentityRoles = $identityRoles.Count -eq 0
    & $addCheck 'No additional identity roles (in-place migration)' $noIdentityRoles $(
        if ($noIdentityRoles) { 'No AD FS, AD CS or Microsoft Entra Connect role detected' }
        else { 'Detected: {0}. The v3.x sensor supports these roles on a domain controller for new deployments, but the in-place migration workflow is not available - uninstall the v2.x sensor and activate v3.x instead' -f ($identityRoles -join ', ') }
    ) 'Migration'

    # --- Npcap is no longer needed -----------------------------------------------------------------------------
    $captureComponent = [string] (Get-mdiCaptureComponent -ComputerName $ComputerName)
    $hasCaptureComponent = -not [string]::IsNullOrWhiteSpace($captureComponent) -and [string] $captureComponent -ne 'N/A'
    & $addCheck 'Npcap / WinPcap removed' (-not $hasCaptureComponent) $(
        if ($hasCaptureComponent) { '{0} is installed. It was used by the v2.x sensor and is not required by v3.x - remove it after the migration completes' -f $captureComponent }
        else { 'No packet capture driver installed' }
    ) 'Recommended'

    # A blocker is a check that actually failed. 'N/A' -ne $true is true, so the previous filter counted
    # every unread check as a blocker and a server that could not be queried looked comprehensively
    # ineligible. Unknowns are tracked separately: they are gaps in the evidence, not findings.
    $blockers = @($checks | Where-Object { $_.Requirement -eq 'Required' -and $_.Status -eq $false })
    $unknowns = @($checks | Where-Object { $_.Requirement -eq 'Required' -and -not $_.Measured })
    $migrationWarnings = @($checks | Where-Object { $_.Requirement -eq 'Migration' -and $_.Status -eq $false })

    # The state must not advise activating the v3.x sensor on a server that cannot run it. A Windows
    # Server 2016 domain controller with Defender for Endpoint onboarded satisfies the first branch's
    # conditions, yet it fails the operating system requirement, so the blockers are checked as well.
    $sensorState = if ($unknowns.Count -gt 0 -and $blockers.Count -eq 0) { 'Not determined (the server could not be queried)' }
    elseif (-not $hasV2Sensor -and $isOnboarded -eq $true -and $isSenseRunning -eq $true -and $blockers.Count -eq 0) { 'No v2.x sensor (activate v3.x)' }
    elseif (-not $hasV2Sensor -and $blockers.Count -gt 0) { 'No sensor installed and not eligible for v3.x (use v2.x)' }
    elseif ($hasV2Sensor -and $v2ServiceState -ne 'Running') { 'v2.x sensor installed but not running' }
    elseif ($hasV2Sensor) { 'v2.x sensor running' }
    else { 'No Defender for Identity sensor detected' }

    # Plain concatenation instead of the format operator: the items come from a pipeline over PSObjects, which can
    # trip the Windows PowerShell format-operator binder.
    $blockerMessages = @(foreach ($blocker in $blockers) { [string] $blocker.Name + ': ' + [string] $blocker.Detail })

    # Blockers worth acting on. A server that fails a requirement nobody can act on - a member server,
    # or a domain controller too old for the v3.x sensor - is not eligible at all, so none of its
    # other blockers are work worth doing either and the whole server drops out.
    $architectural = @($blockers | Where-Object { -not $_.Remediable })
    $actionableBlockers = @(
        if ($architectural.Count -eq 0) {
            foreach ($blocker in $blockers) { [string] $blocker.Name + ': ' + [string] $blocker.Detail }
        }
    )

    # Tri-state: a server whose checks could not be read is not ready and is not blocked, it is unknown.
    # Returning false there would report a healthy domain controller as ineligible for the v3.x sensor.
    $v3Ready = if ($blockers.Count -gt 0) { $false }
    elseif ($unknowns.Count -gt 0) { 'N/A' }
    else { $true }

    [PSCustomObject]@{
        isSensorV3Ready = $v3Ready
        details         = [PSCustomObject]@{
            SensorState        = $sensorState
            SensorV2Version    = $v2Version
            MigrationEligible  = ($v3Ready -eq $true) -and ($migrationWarnings.Count -eq 0) -and $hasV2Sensor
            Blockers           = $blockerMessages
            ActionableBlockers = $actionableBlockers
            UnknownChecks      = @(foreach ($u in $unknowns) { [string] $u.Name })
            Checks             = $checks.ToArray()
        }
    }
}

#endregion

function Get-mdiSensorHealth {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    # A sensor that is installed but stopped is invisible to the readiness checks yet reports no data to the cloud
    # service, so its service state is surfaced explicitly.
    #
    # WMI reachability is established first. Get-mdiServiceState returns null both when a service is
    # genuinely absent and when the server could not be queried at all, so without this the function
    # asserted "no sensor is installed" about a machine it never reached.
    $wmiReadable = $false
    try {
        $null = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class 'Win32_OperatingSystem' `
            -Property 'Caption' -ErrorAction Stop
        $wmiReadable = $true
    } catch {
        return [PSCustomObject]@{
            isSensorHealthOk = 'N/A'
            details          = [PSCustomObject]@{
                Installed = 'N/A'
                Detail    = 'Not tested - the server could not be queried over WMI: ' + ($_.Exception.Message -replace '[\r\n]+', ' ')
            }
        }
    }

    $sensor = Get-mdiServiceState -ComputerName $ComputerName -ServiceName 'AATPSensor'
    $updater = Get-mdiServiceState -ComputerName $ComputerName -ServiceName 'AATPSensorUpdater'

    if ($null -eq $sensor -and $null -eq $updater) {
        return [PSCustomObject]@{
            isSensorHealthOk = 'N/A'
            details          = [PSCustomObject]@{
                Installed = $false
                Detail    = 'No Defender for Identity sensor v2.x service is installed on this server'
            }
        }
    }

    $sensorState = if ($sensor) { [string] $sensor.State } else { 'Not installed' }
    $updaterState = if ($updater) { [string] $updater.State } else { 'Not installed' }
    $sensorStartMode = if ($sensor) { [string] $sensor.StartMode } else { 'n/a' }

    $issues = New-Object -TypeName System.Collections.ArrayList
    # A missing service is a finding in its own right. Previously every issue test was guarded by
    # "if ($sensor ...)", so a server with only the updater installed - no AATPSensor service at all -
    # produced no issues and reported "Sensor and updater services are running".
    if ($null -eq $sensor) {
        [void] $issues.Add('The AATPSensor service is not installed, although the updater is present')
    } elseif ($sensorState -ne 'Running') {
        [void] $issues.Add('The AATPSensor service is ' + $sensorState + ' (start mode: ' + $sensorStartMode + ')')
    }
    if ($null -eq $updater) {
        [void] $issues.Add('The AATPSensorUpdater service is not installed; the sensor cannot update itself')
    } elseif ($updaterState -ne 'Running') {
        [void] $issues.Add('The AATPSensorUpdater service is ' + $updaterState)
    }
    if ($sensor -and $sensorStartMode -eq 'Disabled') {
        [void] $issues.Add('The AATPSensor service start mode is Disabled')
    }

    [PSCustomObject]@{
        isSensorHealthOk = $issues.Count -eq 0
        details          = [PSCustomObject]@{
            Installed         = $null -ne $sensor
            SensorService     = $sensorState
            SensorStartMode   = $sensorStartMode
            UpdaterService    = $updaterState
            Issues            = $issues.ToArray()
            Detail            = $(if ($issues.Count -eq 0) { 'Sensor and updater services are running' } else { $issues.ToArray() -join '; ' })
        }
    }
}

function Get-mdiTimeSync {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $false)] [int] $MaxSkewMinutes = 5
    )

    # 'The servers and domain controllers onto which the sensor is installed must have time synchronized to within
    #  five minutes of each other.'
    # Source: https://learn.microsoft.com/defender-for-identity/deploy/prerequisites-sensor-version-2
    try {
        $localBefore = [datetime]::UtcNow
        $os = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class 'Win32_OperatingSystem' `
            -Property 'LocalDateTime' -ErrorAction Stop
        $localAfter = [datetime]::UtcNow

        $remoteTime = [System.Management.ManagementDateTimeConverter]::ToDateTime([string] $os.LocalDateTime).ToUniversalTime()
        # The WMI round trip is bounded by the two local readings, so its midpoint is the fairest local reference
        $reference = $localBefore.AddTicks(($localAfter - $localBefore).Ticks / 2)
        $skew = ($remoteTime - $reference).TotalMinutes
        $absSkew = [math]::Abs($skew)

        [PSCustomObject]@{
            isTimeSyncOk = $absSkew -le $MaxSkewMinutes
            details      = [PSCustomObject]@{
                RemoteUtc    = $remoteTime.ToString('yyyy-MM-dd HH:mm:ss')
                ReferenceUtc = $reference.ToString('yyyy-MM-dd HH:mm:ss')
                SkewSeconds  = [int] [math]::Round($skew * 60)
                Detail       = $(if ($absSkew -le $MaxSkewMinutes) {
                        'Clock is within {0} second(s) of this computer' -f [int] [math]::Round($absSkew * 60)
                    } else {
                        'Clock differs by {0} minute(s) - MDI requires all sensor servers to be within {1} minutes of each other' -f [int] [math]::Round($absSkew), $MaxSkewMinutes
                    })
            }
        }
    } catch {
        # A clock that could not be read is not a clock that has drifted. Returning false produced a
        # High severity time sync issue with no measured skew, and a w32tm resync in the remediation
        # script, for a server whose time may be perfectly correct.
        [PSCustomObject]@{
            isTimeSyncOk = 'N/A'
            details      = [PSCustomObject]@{ Detail = 'Not tested - the remote clock could not be read: ' + ($_.Exception.Message -replace '[\r\n]+', ' ') }
        }
    }
}

function Get-mdiDeletedObjectsPermission {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [string[]] $DirectoryServiceAccount = $null
    )

    # The Directory Service Account must be able to read the Deleted Objects container, otherwise MDI cannot resolve
    # deleted entities. Source: https://aka.ms/mdi/dsa-permissions
    try {
        $rootDse = Get-ADRootDSE -Server $Domain -ErrorAction Stop
        $namingContext = [string] $rootDse.defaultNamingContext
        $deletedObjectsDn = 'CN=Deleted Objects,{0}' -f $namingContext

        # The container is a hidden system object and its security descriptor is awkward to read: binding
        # straight at its distinguished name fails outright, and asking a named server for the descriptor
        # can return an object with no descriptor attached. A domain bind is what works consistently, so
        # that is tried first and the directory module is kept as a fallback.
        $granted = $null
        $readMethod = $null

        try {
            $root = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ('LDAP://{0}/{1}' -f $Domain, $namingContext)
            $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $root
            $searcher.Filter = '(&(objectClass=container)(name=Deleted Objects))'
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
            $searcher.Tombstone = $true
            $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
            [void] $searcher.PropertiesToLoad.Add('ntsecuritydescriptor')
            $found = $searcher.FindOne()
            if ($found -and $found.Properties['ntsecuritydescriptor'].Count -gt 0) {
                $descriptor = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor `
                    -ArgumentList ($found.Properties['ntsecuritydescriptor'][0], 0)
                # LIST_CONTENTS (0x4) and READ_PROPERTY (0x10) are what "read" means on this container, and
                # BOTH are required - the remediation this script generates grants LCRP for exactly that
                # reason. Testing with -band against the combined mask and rejecting only when the result
                # is zero accepted an ACE that granted just one of the two, so a Directory Service Account
                # with a partial grant was reported as having read access it does not have.
                $readMask = 0x4 -bor 0x10
                $granted = @(foreach ($ace in $descriptor.DiscretionaryAcl) {
                        if ($ace.AceType -ne 'AccessAllowed' -and $ace.AceType -ne 'AccessAllowedObject') { continue }
                        if (($ace.AccessMask -band $readMask) -ne $readMask) { continue }
                        # An object ACE whose ObjectType names a single property set grants read of that
                        # set only, not of the container, so it does not satisfy the requirement either.
                        if ($ace.AceType -eq 'AccessAllowedObject' -and $ace.ObjectAceFlags -band 1) { continue }
                        $sid = [string] $ace.SecurityIdentifier
                        try {
                            (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sid).Translate(
                                [System.Security.Principal.NTAccount]).Value
                        } catch { $sid }
                    })
                $readMethod = 'directory search'
            }
        } catch {
            Write-mdiVerbose ('Domain bind could not read the Deleted Objects descriptor: {0}' -f $_.Exception.Message)
        }

        if ($null -eq $granted -or @($granted).Count -eq 0) {
            try {
                $container = Get-ADObject -Identity $deletedObjectsDn -Server $Domain -IncludeDeletedObjects `
                    -Properties nTSecurityDescriptor -ErrorAction Stop
                if ($container.nTSecurityDescriptor) {
                    $granted = @(foreach ($ace in $container.nTSecurityDescriptor.Access) {
                            if ([string] $ace.AccessControlType -ne 'Allow') { continue }
                            $rights = [string] $ace.ActiveDirectoryRights
                            # Both halves of the requirement, matching the mask test above: the right to
                            # list the container's children AND to read properties. GenericRead and
                            # GenericAll each imply both, so either alone is sufficient.
                            $hasList = $rights -match 'ListChildren|ListObject|GenericRead|GenericAll'
                            $hasRead = $rights -match 'ReadProperty|GenericRead|GenericAll'
                            if (-not ($hasList -and $hasRead)) { continue }
                            [string] $ace.IdentityReference
                        })
                    $readMethod = 'directory module'
                }
            } catch {
                Write-mdiVerbose ('Get-ADObject could not read the Deleted Objects descriptor: {0}' -f $_.Exception.Message)
            }
        }

        if ($null -eq $granted -or @($granted).Count -eq 0) {
            return [PSCustomObject]@{
                isDeletedObjectsPermissionOk = 'N/A'
                details                      = [PSCustomObject]@{
                    Container = $deletedObjectsDn
                    Trustees  = @()
                    Detail    = ('The container was found but its security descriptor was not returned. Reading a DACL needs READ_CONTROL, ' +
                        'which the default permissions on this container do not grant to every administrator. Check it manually on a domain ' +
                        'controller with: dsacls "{0}"') -f $deletedObjectsDn
                }
            }
        }

        $granted = @($granted | Where-Object { $_ } | Select-Object -Unique)

        # Without an explicit DSA name the check can only report who has access; it is informational in that case.
        $status = if (-not $DirectoryServiceAccount) {
            'N/A'
        } else {
            @($DirectoryServiceAccount | Where-Object {
                    $account = $_
                    @($granted | Where-Object { $_ -like ('*{0}*' -f $account) }).Count -eq 0
                }).Count -eq 0
        }

        [PSCustomObject]@{
            isDeletedObjectsPermissionOk = $status
            details                      = [PSCustomObject]@{
                Container = $deletedObjectsDn
                Trustees  = $granted
                Detail    = $(if ([string] $status -eq 'N/A') {
                        'Read access is granted to: {0}. Re-run with -DirectoryServiceAccount to assert a specific account' -f ($granted -join ', ')
                    } elseif ($status) {
                        'The Directory Service Account has read access to the Deleted Objects container'
                    } else {
                        'The Directory Service Account does not have read access. Grant it with: dsacls "{0}" /G "<DSA>":LCRP' -f $deletedObjectsDn
                    })
            }
        }
    } catch {
        [PSCustomObject]@{
            isDeletedObjectsPermissionOk = 'N/A'
            details                      = [PSCustomObject]@{ Detail = 'Unable to read the Deleted Objects container: ' + $_.Exception.Message; Trustees = @() }
        }
    }
}

function New-mdiRemediationScript {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param (
        [Parameter(Mandatory = $true)] [object] $ReportData,
        [Parameter(Mandatory = $true)] [string] $FilePath
    )

    # Each collection is wrapped separately: a domain with exactly one server exposes the property as a
    # bare PSObject, and PSObject + PSObject throws "does not contain a method named op_Addition".
    # Only servers that could not be reached at all are excluded. A server that answered and then failed
    # one check still has real results, and dropping it would silently omit fixes the operator needs.
    $servers = @(@($ReportData.DomainControllers) + @($ReportData.CAServers) + @($ReportData.EntraConnectServers) |
            Where-Object { $_ -and -not $_.Unreachable })

    $script = New-Object -TypeName System.Collections.ArrayList
    $add = { param([string] $Line) [void] $script.Add($Line) }

    # Everything below writes PowerShell source from report data - server names, IP addresses, registry
    # paths, certification authority names, account names, error text. Two escapes are needed and both
    # were missing.
    #
    # $lit prepares a value for a single-quoted literal: a single quote must be doubled or it ends the
    # literal early and the rest of the value is parsed as code. Newlines are collapsed because a literal
    # cannot span lines here.
    #
    # $cmt prepares a value for a comment line: a comment ends at the newline, so a value containing one
    # leaves the remainder of the text on its own line as EXECUTABLE SCRIPT. This is the more dangerous
    # of the two, and the reason both exist rather than relying on the values being well behaved.
    $lit = {
        param([object] $Value)
        (([string] $Value) -replace '[\r\n]+', ' ') -replace "'", "''"
    }
    $cmt = {
        param([object] $Value)
        ([string] $Value) -replace '[\r\n]+', ' '
    }
    # Emits a list of values as an indented block of single-quoted literals, each escaped. Used wherever
    # the generator writes an array of server names or addresses into the script.
    $litList = {
        param([object[]] $Values)
        $escaped = @($Values | Where-Object { $_ } | ForEach-Object { (([string] $_) -replace '[\r\n]+', ' ') -replace "'", "''" })
        if ($escaped.Count -eq 0) { return "" }
        "    '" + ($escaped -join ("'," + [environment]::NewLine + "    '")) + "'"
    }

    & $add '<#'
    & $add '    Microsoft Defender for Identity - generated remediation script'
    & $add ('    Source report : mdi-{0}' -f (& $cmt $ReportData.Domain))
    & $add ('    Generated     : {0}' -f [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))
    & $add ''
    & $add '    REVIEW EVERY COMMAND BEFORE RUNNING IT. This script is generated from the findings of'
    & $add '    Test-MdiReadiness.ps1 and changes audit policy, registry values and firewall rules on'
    & $add '    domain controllers. Run it in a maintenance window and test in a lab first.'
    & $add ''
    & $add '    Run with -WhatIf to preview, or without it to apply.'
    & $add ''
    & $add '    TRANSPORT. Each change is applied over PowerShell remoting where it is available, and'
    & $add '    over WMI where it is not, which is the same transport Test-MdiReadiness.ps1 itself uses.'
    & $add '    WinRM is therefore not a requirement. Use -Transport to force one or the other.'
    & $add '#>'
    & $add '[CmdletBinding(SupportsShouldProcess = $true)]'
    & $add 'param('
    & $add '    [ValidateSet(''Auto'', ''WinRM'', ''WMI'')]'
    & $add '    [string] $Transport = ''Auto'','
    & $add '    # Supplied so the script can run unattended: without it the Deleted Objects section has to'
    & $add '    # prompt, and a prompt cannot be answered by a scheduled job.'
    & $add '    [string] $DirectoryServiceAccount'
    & $add ')'
    & $add ''
    & $add '$ErrorActionPreference = ''Stop'''
    & $add ''
    & $add '# Servers whose remediation failed. Each section isolates its own work so that one unreachable'
    & $add '# or misbehaving server does not abort the rollout for every other server, and the run ends with'
    & $add '# an explicit list rather than an optimistic "complete".'
    & $add '$script:mdiFailed = New-Object System.Collections.ArrayList'
    & $add ''
    & $add '# WinRM is disabled in many environments, so remoting is probed once per server and WMI is'
    & $add '# used when it is unavailable. Win32_Process.Create returns no output, so the WMI path reports'
    & $add '# the process exit code rather than the command output.'
    & $add '$script:mdiTransport = @{}'
    & $add ''
    & $add 'function Invoke-MdiRemote {'
    & $add '    param ('
    & $add '        [Parameter(Mandatory = $true)] [string] $ComputerName,'
    & $add '        [Parameter(Mandatory = $true)] [scriptblock] $ScriptBlock,'
    & $add '        [Parameter(Mandatory = $false)] [object[]] $ArgumentList = $null,'
    & $add '        [Parameter(Mandatory = $false)] [int] $TimeoutSeconds = 120'
    & $add '    )'
    & $add ''
    & $add '    if (-not $script:mdiTransport.ContainsKey($ComputerName)) {'
    & $add '        $useWinRm = $false'
    & $add '        if ($Transport -eq ''WinRM'') {'
    & $add '            $useWinRm = $true'
    & $add '        } elseif ($Transport -eq ''Auto'') {'
    & $add '            try {'
    & $add '                Invoke-Command -ComputerName $ComputerName -ScriptBlock { $true } -ErrorAction Stop | Out-Null'
    & $add '                $useWinRm = $true'
    & $add '            } catch {'
    & $add '                Write-Warning ("PowerShell remoting is not available on {0}, using WMI instead" -f $ComputerName)'
    & $add '            }'
    & $add '        }'
    & $add '        $script:mdiTransport[$ComputerName] = $useWinRm'
    & $add '    }'
    & $add ''
    & $add '    if ($script:mdiTransport[$ComputerName]) {'
    & $add '        if ($ArgumentList) {'
    & $add '            Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList'
    & $add '        } else {'
    & $add '            Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock'
    & $add '        }'
    & $add '        return'
    & $add '    }'
    & $add ''
    & $add '    # Rebuild the arguments as literals, since a scriptblock sent through WMI carries no session state'
    & $add '    $invocation = if ($ArgumentList) {'
    & $add '        $literals = foreach ($argument in $ArgumentList) {'
    & $add '            if ($argument -is [System.Array]) {'
    & $add '                ''@('' + ((@($argument) | ForEach-Object { "''" + ([string] $_ -replace "''", "''''") + "''" }) -join '','') + '')'''
    & $add '            } else {'
    & $add '                "''" + ([string] $argument -replace "''", "''''") + "''"'
    & $add '            }'
    & $add '        }'
    & $add '        ''$__mdiArgs = @('' + ($literals -join '','') + '')'' + [environment]::NewLine +'
    & $add '        ''& {'' + $ScriptBlock.ToString() + ''} @__mdiArgs'''
    & $add '    } else {'
    & $add '        ''& {'' + $ScriptBlock.ToString() + ''}'''
    & $add '    }'
    & $add ''
    & $add '    # The remote command writes its outcome to a file, which is read back over the admin share.'
    & $add '    # Win32_Process.Create returns only whether the process STARTED, so without this the helper'
    & $add '    # reported success for a command that failed - and a remediation script that silently does'
    & $add '    # nothing is worse than one that fails loudly.'
    & $add '    $statusName = ''mdi-status-{0}.txt'' -f [guid]::NewGuid().ToString(''N'')'
    & $add '    $statusLocal = Join-Path $env:SystemRoot ("Temp\" + $statusName)'
    & $add '    $statusRemote = ''\\{0}\C$\Windows\Temp\{1}'' -f $ComputerName, $statusName'
    & $add '    $invocation = ''try {'' + [environment]::NewLine +'
    & $add '        ''  $ErrorActionPreference = "Stop"'' + [environment]::NewLine +'
    & $add '        ''  $global:LASTEXITCODE = 0'' + [environment]::NewLine + $invocation + [environment]::NewLine +'
    & $add '        ''  if ($LASTEXITCODE -ne 0) { throw ("the command exited with code " + $LASTEXITCODE) }'' + [environment]::NewLine +'
    & $add '        ''  "OK" | Set-Content -Path "'' + $statusLocal + ''" -Encoding ASCII'' + [environment]::NewLine +'
    & $add '        ''} catch {'' + [environment]::NewLine +'
    & $add '        ''  ("FAIL: " + $_.Exception.Message) | Set-Content -Path "'' + $statusLocal + ''" -Encoding ASCII'' + [environment]::NewLine +'
    & $add '        ''}'''
    & $add ''
    & $add '    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($invocation))'
    & $add '    $commandLine = ''powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand '' + $encoded'
    & $add '    if ($commandLine.Length -ge 32767) { throw ("The command for {0} is too long for WMI" -f $ComputerName) }'
    & $add ''
    & $add '    $process = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $commandLine -ErrorAction Stop'
    & $add '    if ($process.ReturnValue -ne 0) {'
    & $add '        throw ("Unable to start the remediation command on {0}: Win32_Process.Create returned {1}" -f $ComputerName, $process.ReturnValue)'
    & $add '    }'
    & $add ''
    & $add '    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)'
    & $add '    $filter = "ProcessId={0}" -f $process.ProcessId'
    & $add '    $exited = $false'
    & $add '    try {'
    & $add '    while ((Get-Date) -lt $deadline) {'
    & $add '        $running = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Filter $filter -ErrorAction SilentlyContinue'
    & $add '        if (-not $running) { $exited = $true; break }'
    & $add '        Start-Sleep -Seconds 2'
    & $add '    }'
    & $add '    if (-not $exited) {'
    & $add '        # A timeout is a failure, not a note. The change may be half applied.'
    & $add '        throw ("The remediation command on {0} did not finish within {1} seconds" -f $ComputerName, $TimeoutSeconds)'
    & $add '    }'
    & $add ''
    & $add '    $status = $null'
    & $add '    try { $status = (Get-Content -Path $statusRemote -ErrorAction Stop -Raw).Trim() } catch {}'
    & $add '    if ($null -eq $status) {'
    & $add '        Write-Warning ("Could not confirm the result on {0}: the status file could not be read over the admin share. Verify the change manually." -f $ComputerName)'
    & $add '    } elseif ($status -ne ''OK'') {'
    & $add '        throw ("The remediation command failed on {0}: {1}" -f $ComputerName, $status)'
    & $add '    }'
    & $add '    } finally {'
    & $add '        # Cleanup in finally: on the timeout path the throw above skipped it, so every run that'
    & $add '        # timed out left a status file behind on the remote server.'
    & $add '        try { Remove-Item -Path $statusRemote -Force -ErrorAction SilentlyContinue } catch {}'
    & $add '    }'
    & $add '}'
    & $add ''

    $sections = 0

    # --- Advanced audit policy ---------------------------------------------------------------------------------
    $auditFailures = @($servers | Where-Object { $_.PSObject.Properties['AdvancedAuditing'] -and -not $_.AdvancedAuditing })
    if ($auditFailures.Count -gt 0) {
        $sections++
        & $add '#region Advanced audit policy'
        & $add '# https://aka.ms/mdi/advancedauditing'
        & $add ('# Affected: {0}' -f (& $cmt ((@($auditFailures.FQDN)) -join ', ')))
        & $add 'foreach ($computer in @('
        & $add (& $litList @($auditFailures.FQDN))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Configure the MDI advanced audit policy'')) {'
        & $add '        try {'
        & $add '        Invoke-MdiRemote -ComputerName $computer -ScriptBlock {'
        foreach ($row in ($settings.AdvancedAuditPolicyDCs | ConvertFrom-Csv)) {
            & $add ('            auditpol.exe /set /subcategory:"{0}" /success:enable /failure:enable' -f (& $cmt $row.'Subcategory GUID'))
        }
        & $add '        }'
        & $add '        } catch {'
        & $add '            Write-Warning (''{0}: {1}'' -f $computer, $_.Exception.Message)'
        & $add '            [void] $script:mdiFailed.Add($computer)'
        & $add '        }'
        & $add '    }'
        & $add '}'
        & $add '#endregion'
        & $add ''
    }

    # --- NTLM auditing -----------------------------------------------------------------------------------------
    $ntlmFailures = @($servers | Where-Object { $_.PSObject.Properties['NtlmAuditing'] -and -not $_.NtlmAuditing })
    if ($ntlmFailures.Count -gt 0) {
        $sections++
        & $add '#region NTLM auditing'
        & $add '# https://aka.ms/mdi/ntlmauditing'
        & $add ('# Affected: {0}' -f (& $cmt ((@($ntlmFailures.FQDN)) -join ', ')))
        & $add 'foreach ($computer in @('
        & $add (& $litList @($ntlmFailures.FQDN))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Configure NTLM auditing'')) {'
        & $add '        try {'
        & $add '        Invoke-MdiRemote -ComputerName $computer -ScriptBlock {'
        foreach ($entry in $settings.NTLMAuditing) {
            $regPath, $regValue, $expected = $entry -split ','
            # The expected value can be a regular expression alternation, so the first branch is the value to set
            $value = (($expected -split '\|')[0]).Trim()
            & $add ('            New-ItemProperty -Path ''HKLM:\{0}'' -Name ''{1}'' -Value {2} -PropertyType DWord -Force | Out-Null' -f (& $lit $regPath), (& $lit $regValue), ([int] $value))
        }
        & $add '        }'
        & $add '        } catch {'
        & $add '            Write-Warning (''{0}: {1}'' -f $computer, $_.Exception.Message)'
        & $add '            [void] $script:mdiFailed.Add($computer)'
        & $add '        }'
        & $add '    }'
        & $add '}'
        & $add '#endregion'
        & $add ''
    }

    # --- Power scheme ------------------------------------------------------------------------------------------
    $powerFailures = @($servers | Where-Object { $_.PSObject.Properties['PowerSettings'] -and -not $_.PowerSettings })
    if ($powerFailures.Count -gt 0) {
        $sections++
        & $add '#region High performance power scheme'
        & $add '# https://aka.ms/mdi/powersettings'
        & $add 'foreach ($computer in @('
        & $add (& $litList @($powerFailures.FQDN))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Set the High performance power scheme'')) {'
        & $add '        try {'
        & $add '        Invoke-MdiRemote -ComputerName $computer -ScriptBlock {'
        & $add '            powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
        & $add '        }'
        & $add '        } catch {'
        & $add '            Write-Warning (''{0}: {1}'' -f $computer, $_.Exception.Message)'
        & $add '            [void] $script:mdiFailed.Add($computer)'
        & $add '        }'
        & $add '    }'
        & $add '}'
        & $add '#endregion'
        & $add ''
    }

    # --- Blocked NNR ports -------------------------------------------------------------------------------------
    # The rules are created on the *target* devices, because NNR needs inbound access on every device the sensor sees
    $blockedNnr = @(Get-mdiPortResultRecord -Server $servers |
            Where-Object { $_.Applicable -ne $false -and -not $_.Success -and $_.Group -eq 'NNR' })
    $ruleMap = @{
        135  = @{ Name = 'MDI-NNR-RPC-In'; Protocol = 'TCP'; Display = 'MDI Network Name Resolution - NTLM over RPC (TCP 135)' }
        137  = @{ Name = 'MDI-NNR-NetBIOS-In'; Protocol = 'UDP'; Display = 'MDI Network Name Resolution - NetBIOS (UDP 137)' }
        3389 = @{ Name = 'MDI-NNR-RDP-In'; Protocol = 'TCP'; Display = 'MDI Network Name Resolution - RDP (TCP 3389)' }
    }
    $sensorIps = @()
    $blockedTargets = @()
    if ($blockedNnr.Count -gt 0) {
        # Only servers that actually run a sensor. The rules open TCP 135, UDP 137 and TCP 3389 inbound on
        # every target, so the source list must be as narrow as the truth allows: using every server in
        # the report opened those ports to certification authorities, Entra Connect servers and any other
        # scanned machine that will never send an NNR probe. The comment below said "restrict to the
        # sensor servers" while the code used them all.
        # A sensor is present when a version was read, or when the sensor health check found the service.
        $sensorHosts = @($servers | Where-Object {
                (-not [string]::IsNullOrWhiteSpace([string] $_.SensorVersion) -and [string] $_.SensorVersion -ne 'N/A') -or
                $_.Details.SensorHealthDetails.Installed -eq $true
            })
        # If no sensor is deployed yet the domain controllers are where the sensors will go, so they are
        # the correct source list for a pre-deployment run.
        if ($sensorHosts.Count -eq 0) {
            $sensorHosts = @(@($ReportData.DomainControllers) | Where-Object { $_ -and -not $_.Unreachable })
        }
        # Every address of every sensor, not one each. The rules below scope inbound access by source
        # address, and a multi-homed sensor sends its NNR probes from whichever interface routes to the
        # target - so a rule naming only its primary address silently fails to match, the port stays
        # closed to the traffic that matters, and the operator is left believing the fix was applied.
        #
        # The emptiness test filters before counting. @($null).Count is 1, not 0, so testing
        # @($_.Addresses).Count on a server that has no Addresses property at all - a CA server, an
        # Entra Connect server, or any object deserialized from an older baseline - took the "has
        # addresses" branch and yielded $null, dropping that sensor's address entirely.
        $sensorIps = @($sensorHosts | ForEach-Object {
                $hostAddresses = @($_.Addresses | Where-Object { $_ })
                if ($hostAddresses.Count -gt 0) { $hostAddresses } else { [string] $_.IP }
            } | Where-Object { $_ } | Select-Object -Unique | Sort-Object)
        $blockedTargets = @($blockedNnr | Select-Object -ExpandProperty Target -Unique | Sort-Object)
    }

    # Guarded rather than assumed. The generated rules scope inbound access with -RemoteAddress
    # $sensorAddresses; an empty source list emits -RemoteAddress @(), which either errors or - worse,
    # depending on the module version - creates a rule with no source restriction at all, opening
    # TCP 135, UDP 137 and TCP 3389 to the entire network on every target. An empty target list would
    # emit a foreach over nothing and report success having changed nothing. Neither is acceptable in
    # a script an operator runs against production, so the section is skipped and the reason stated.
    if ($blockedNnr.Count -gt 0 -and ($sensorIps.Count -eq 0 -or $blockedTargets.Count -eq 0)) {
        Write-Warning ('Network Name Resolution ports were found blocked, but the remediation section was skipped: {0}.' -f
            $(if ($sensorIps.Count -eq 0) { 'no sensor source address could be determined' } else { 'no target could be determined' }))
    }

    if ($blockedNnr.Count -gt 0 -and $sensorIps.Count -gt 0 -and $blockedTargets.Count -gt 0) {
        $sections++
        & $add '#region Network Name Resolution inbound firewall rules'
        & $add '# https://aka.ms/mdi/nnr/troubleshooting'
        & $add '# These rules must exist on EVERY device the sensors observe, not only on the targets listed here.'
        & $add '# Prefer deploying them through Group Policy; the commands below fix the sampled targets only.'
        & $add ('# Sampled targets that failed: {0}' -f (& $cmt ($blockedTargets -join ', ')))
        & $add ''
        & $add '# Scoped to the sensor servers only, so no port is opened to the whole network.'
        & $add ('# Sources ({0}): {1}' -f $sensorIps.Count, (& $cmt (@($sensorHosts | ForEach-Object { [string] $_.FQDN }) -join ', ')))
        & $add '$sensorAddresses = @('
        & $add (& $litList $sensorIps)
        & $add ')'
        & $add ''
        & $add 'foreach ($computer in @('
        & $add (& $litList $blockedTargets)
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Create the MDI NNR inbound firewall rules'')) {'
        & $add '        try {'
        & $add '        Invoke-MdiRemote -ComputerName $computer -ArgumentList (, $sensorAddresses) -ScriptBlock {'
        & $add '            param($RemoteAddress)'
        foreach ($port in @($blockedNnr | Select-Object -ExpandProperty Port -Unique | Sort-Object)) {
            $rule = $ruleMap[[int] $port]
            if ($null -eq $rule) { continue }
            & $add ('            if (-not (Get-NetFirewallRule -Name ''{0}'' -ErrorAction SilentlyContinue)) {{' -f (& $lit $rule.Name))
            & $add ('                New-NetFirewallRule -Name ''{0}'' -DisplayName ''{1}'' `' -f (& $lit $rule.Name), (& $lit $rule.Display))
            & $add ('                    -Direction Inbound -Action Allow -Protocol {0} -LocalPort {1} `' -f $rule.Protocol, $port)
            & $add '                    -RemoteAddress $RemoteAddress -Profile Domain | Out-Null'
            & $add '            }'
        }
        & $add '        }'
        & $add '        } catch {'
        & $add '            Write-Warning (''{0}: {1}'' -f $computer, $_.Exception.Message)'
        & $add '            [void] $script:mdiFailed.Add($computer)'
        & $add '        }'
        & $add '    }'
        & $add '}'
        & $add '#endregion'
        & $add ''
    }

    # --- Domain wide auditing ----------------------------------------------------------------------------------
    if ($ReportData.DomainObjectAuditing -and $ReportData.DomainObjectAuditing.isObjectAuditingOk -eq $false) {
        $sections++
        & $add '#region Domain object auditing'
        & $add '# https://aka.ms/mdi/objectauditing'
        # The guidance is printed rather than left in comments: a comment is invisible to whoever runs
        # the script, so a warning that points at "the link above" tells them nothing.
        & $add 'Write-Warning ''Domain object auditing is not configured. This one cannot be scripted safely:'''
        & $add 'Write-Host ''    The SACL on the domain root must audit Descendant User, Group, Computer and MSA objects.'' -ForegroundColor Yellow'
        & $add 'Write-Host ''    Easiest: Defender portal > Settings > Identities > Advanced features >'' -ForegroundColor Yellow'
        & $add 'Write-Host ''             Automatic Windows auditing configuration.'' -ForegroundColor Yellow'
        & $add 'Write-Host ''    Manual : https://aka.ms/mdi/objectauditing'' -ForegroundColor Yellow'
        & $add '#endregion'
        & $add ''
    }

    # --- Sensor services ---------------------------------------------------------------------------------------
    $sensorStopped = @($servers | Where-Object { $_.PSObject.Properties['SensorHealth'] -and $_.SensorHealth -eq $false })
    if ($sensorStopped.Count -gt 0) {
        $sections++
        & $add '#region Defender for Identity sensor services'
        & $add ('# Affected: {0}' -f (& $cmt ((@($sensorStopped.FQDN)) -join ', ')))
        & $add 'foreach ($computer in @('
        & $add (& $litList @($sensorStopped.FQDN))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Start the Defender for Identity sensor services'')) {'
        & $add '        try {'
        & $add '        Invoke-MdiRemote -ComputerName $computer -ScriptBlock {'
        & $add '            foreach ($name in ''AATPSensorUpdater'', ''AATPSensor'') {'
        & $add '                $service = Get-Service -Name $name -ErrorAction SilentlyContinue'
        & $add '                if ($service) {'
        & $add '                    if ($service.StartType -eq ''Disabled'') { Set-Service -Name $name -StartupType Automatic }'
        & $add '                    if ($service.Status -ne ''Running'') { Start-Service -Name $name }'
        & $add '                }'
        & $add '            }'
        & $add '        }'
        & $add '        } catch {'
        & $add '            Write-Warning (''{0}: {1}'' -f $computer, $_.Exception.Message)'
        & $add '            [void] $script:mdiFailed.Add($computer)'
        & $add '        }'
        & $add '    }'
        & $add '}'
        & $add '#endregion'
        & $add ''
    }

    # --- Time synchronisation ----------------------------------------------------------------------------------
    $timeFailures = @($servers | Where-Object { $_.PSObject.Properties['TimeSync'] -and $_.TimeSync -eq $false })
    if ($timeFailures.Count -gt 0) {
        $sections++
        & $add '#region Time synchronisation'
        & $add '# MDI requires all sensor servers to be within five minutes of each other.'
        & $add ('# Affected: {0}' -f (& $cmt ((@($timeFailures.FQDN)) -join ', ')))
        & $add 'foreach ($computer in @('
        & $add (& $litList @($timeFailures.FQDN))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Resynchronise the clock'')) {'
        & $add '        try {'
        & $add '        Invoke-MdiRemote -ComputerName $computer -ScriptBlock {'
        & $add '            w32tm.exe /resync /force'
        & $add '            w32tm.exe /query /status'
        & $add '        }'
        & $add '        } catch {'
        & $add '            Write-Warning (''{0}: {1}'' -f $computer, $_.Exception.Message)'
        & $add '            [void] $script:mdiFailed.Add($computer)'
        & $add '        }'
        & $add '    }'
        & $add '}'
        & $add '#endregion'
        & $add ''
    }

    # --- Deleted Objects container -----------------------------------------------------------------------------
    if ($ReportData.DomainDeletedObjects -and $ReportData.DomainDeletedObjects.isDeletedObjectsPermissionOk -eq $false) {
        $sections++
        & $add '#region Deleted Objects container permissions'
        & $add '# https://aka.ms/mdi/dsa-permissions'
        & $add ('# {0}' -f (& $cmt $ReportData.DomainDeletedObjects.details.Detail))
        & $add ('$container = ''{0}''' -f (& $lit $ReportData.DomainDeletedObjects.details.Container))
        # The prompt has to sit INSIDE the ShouldProcess guard. Outside it, -WhatIf still stopped and
        # waited for input, so a preview could never complete unattended and hung any automated run.
        # A parameter is offered as well, so the script can run without a console at all.
        & $add 'if ($PSCmdlet.ShouldProcess($container, ''Grant the Directory Service Account read access'')) {'
        & $add '    $dsaAccount = if ($DirectoryServiceAccount) { $DirectoryServiceAccount }'
        & $add '    else { Read-Host ''Enter the Directory Service Account (DOMAIN\user)'' }'
        & $add '    if ([string]::IsNullOrWhiteSpace($dsaAccount)) {'
        & $add '        Write-Warning ''No Directory Service Account was given, skipping the Deleted Objects permission.'''
        & $add '    } else {'
        & $add '        try {'
        & $add '            dsacls.exe $container /takeownership'
        & $add '            dsacls.exe $container /G "${dsaAccount}:LCRP"'
        & $add '        } catch {'
        & $add '            Write-Warning (''Deleted Objects permission failed: {0}'' -f $_.Exception.Message)'
        & $add '            [void] $script:mdiFailed.Add($container)'
        & $add '        }'
        & $add '    }'
        & $add '}'
        & $add '#endregion'
        & $add ''
    }

    # --- Sensor v3.x blockers ----------------------------------------------------------------------------------
    # Only the blockers somebody can actually act on. @($null).Count is 1, so null entries are filtered
    # out before counting.
    $v3Blocked = @($servers | Where-Object { @($_.Details.SensorV3ReadyDetails.ActionableBlockers | Where-Object { $_ }).Count -gt 0 })
    if ($v3Blocked.Count -gt 0) {
        $sections++
        & $add '#region Sensor v3.x prerequisites (manual)'
        & $add '# https://learn.microsoft.com/defender-for-identity/deploy/deploy-sensor-v3'
        & $add 'Write-Warning ''These servers are eligible for the sensor v3.x but are missing prerequisites:'''
        foreach ($srv in $v3Blocked) {
            # Each blocker is printed with its server, so the person running the script sees exactly
            # what to fix without opening the file
            & $add ('Write-Host ''    {0}'' -ForegroundColor Yellow' -f (& $lit $srv.FQDN))
            foreach ($blocker in @($srv.Details.SensorV3ReadyDetails.ActionableBlockers | Where-Object { $_ })) {
                $text = [string] $blocker -replace '[\r\n]+', ' ' -replace "'", "''"
                & $add ('Write-Host ''      - {0}'' -ForegroundColor Yellow' -f (& $lit $text))
            }
        }
        & $add 'Write-Host '''''
        & $add 'Write-Host ''    Onboard the server to Defender for Endpoint and install the July 2026 or later'' -ForegroundColor Yellow'
        & $add 'Write-Host ''    cumulative update, then re-run Test-MdiReadiness.ps1 to confirm.'' -ForegroundColor Yellow'
        & $add 'Write-Host ''    https://learn.microsoft.com/defender-for-identity/deploy/deploy-sensor-v3'' -ForegroundColor Yellow'
        & $add '#endregion'
        & $add ''
    }

    if ($sections -eq 0) {
        & $add 'Write-Host ''No remediation is required: every automatically fixable check passed.'' -ForegroundColor Green'
    } else {
        & $add ''
    & $add '# The outcome is stated explicitly. "Complete" on its own would read as success even when every'
    & $add '# server failed.'
    & $add 'if ($script:mdiFailed.Count -gt 0) {'
    & $add '    Write-Host ('''' )'
    & $add '    Write-Warning (''Remediation finished with failures on {0} server(s): {1}'' -f $script:mdiFailed.Count, (($script:mdiFailed | Select-Object -Unique) -join '', ''))'
    & $add '    Write-Warning ''Fix the cause and re-run this script, then re-run Test-MdiReadiness.ps1 to verify.'''
    & $add '} else {'
    & $add ('Write-Host ''Remediation complete. Re-run Test-MdiReadiness.ps1 to verify.'' -ForegroundColor Green')
    & $add '}'
    }

    $content = $script.ToArray() -join [environment]::NewLine
    $content | Out-File -FilePath $FilePath -Force -Encoding utf8
    [PSCustomObject]@{
        Path         = (Resolve-Path -Path $FilePath).Path
        SectionCount = $sections
    }
}

function Get-mdiBaselineHistory {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param (
        [Parameter(Mandatory = $true)] [string] $BaselinePath,
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $true)] [object] $Statistics,
        [Parameter(Mandatory = $false)] [int] $KeepRuns = 60
    )

    # A compact, append-only history so the report can show whether the estate is improving between runs.
    $file = Join-Path -Path $BaselinePath -ChildPath ('mdi-baseline-{0}.json' -f $Domain)

    $history = @()
    if (Test-Path -Path $file) {
        try {
            # ConvertFrom-Json emits a JSON array as a single object in Windows PowerShell, so the result must be
            # assigned before being wrapped: @(Get-Content | ConvertFrom-Json) would nest the whole history into a
            # one-element array and every later index would return an array instead of a run.
            $parsed = Get-Content -Path $file -Raw | ConvertFrom-Json
            $history = @($parsed)
        } catch {
            Write-Warning ('Unable to read the baseline history at {0}, starting a new one: {1}' -f $file, $_.Exception.Message)
            $history = @()
        }
    }

    $entry = [PSCustomObject]@{
        Timestamp     = [datetime]::Now.ToString('s')
        # Recorded per run so a trend that spans an upgrade can be read correctly: a different version
        # may check different things, which would otherwise look like a sudden change in the estate.
        ScriptVersion = [string] $settings.ScriptVersion
        # A fingerprint of WHAT was measured, so two runs can be told apart from two measurements of
        # the same thing. The history stores aggregate counts only, so a run that added a check, or one
        # taken after a domain controller was decommissioned, produced a different ratio for reasons
        # that have nothing to do with readiness - and the report drew a confident "up 8 points since
        # the last run" arrow over it. Comparing the fingerprint lets the delta say "not comparable"
        # instead of inventing a trend.
        CheckNames    = @($Statistics.CheckTotals.Keys | Sort-Object)
        ServerNames   = @($Statistics.Servers | ForEach-Object { [string] $_.FQDN } |
                Where-Object { $_ } | Sort-Object)
        ChecksPassed  = [int] $Statistics.ChecksPassed
        ChecksTotal   = [int] $Statistics.ChecksTotal
        ChecksUnread  = [int] $Statistics.ChecksUnread
        ServersTotal  = [int] $Statistics.TotalServers
        # Total -gt 0 as well, matching the Overview KPI. A server whose every check was unreadable has
        # Total 0 and Failed 0, and counting it as ready wrote a wrong figure into the history, where it
        # permanently distorts the trend chart.
        ServersReady  = @($Statistics.ServerScores | Where-Object { $_.Total -gt 0 -and $_.Failed -eq 0 }).Count
        PortsOpen     = [int] $Statistics.PortsOpen
        PortsTotal    = [int] $Statistics.PortsTotal
        NnrResolvable = [int] $Statistics.NnrResolvable
        NnrTargets    = [int] $Statistics.NnrTargetCount
        V3Ready       = [int] $Statistics.V3Ready
        V3Evaluated   = [int] $Statistics.V3Evaluated
    }

    $history = @($history) + $entry
    if ($history.Count -gt $KeepRuns) { $history = @($history | Select-Object -Last $KeepRuns) }

    try {
        if (-not (Test-Path -Path $BaselinePath)) { [void] (New-Item -ItemType Directory -Path $BaselinePath -Force) }
        $history | ConvertTo-Json -Depth 4 | Out-File -FilePath $file -Force -Encoding utf8
    } catch {
        Write-Warning ('Unable to write the baseline history to {0}: {1}' -f $file, $_.Exception.Message)
    }

    [PSCustomObject]@{
        Path    = $file
        History = @($history)
        Current = $entry
    }
}

function New-mdiTrendChart {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $History,
        [Parameter(Mandatory = $false)] [int] $Width = 720,
        [Parameter(Mandatory = $false)] [int] $Height = 190
    )

    # Only well-formed scalar runs can be plotted, so malformed history entries are skipped rather than throwing
    $points = @($History | Where-Object {
            $_ -and @($_.ChecksTotal).Count -eq 1 -and ($_.ChecksTotal -as [int]) -gt 0 -and $null -ne ($_.ChecksPassed -as [int])
        })
    if ($points.Count -lt 2) {
        return '<p class="muted">At least two runs are needed to draw a trend. Re-run the script with the same -BaselinePath to build history.</p>'
    }

    $padLeft = 42; $padRight = 14; $padTop = 14; $padBottom = 26
    $plotWidth = $Width - $padLeft - $padRight
    $plotHeight = $Height - $padTop - $padBottom

    $coords = @(for ($i = 0; $i -lt $points.Count; $i++) {
            $passed = [double] ($points[$i].ChecksPassed -as [int])
            $total = [double] ($points[$i].ChecksTotal -as [int])
            $pct = ($passed / $total) * 100
            $x = $padLeft + ($plotWidth * $i / ($points.Count - 1))
            $y = $padTop + $plotHeight - ($plotHeight * $pct / 100)
            [PSCustomObject]@{ X = $x; Y = $y; Pct = $pct; Point = $points[$i] }
        })

    $parts = New-Object -TypeName System.Collections.ArrayList
    [void] $parts.Add('<svg class="trend" viewBox="0 0 ' + $Width + ' ' + $Height + '" role="img">')
    [void] $parts.Add('<defs><linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0%" stop-color="var(--brand)" stop-opacity="0.30"/>' +
        '<stop offset="100%" stop-color="var(--brand)" stop-opacity="0"/></linearGradient></defs>')

    foreach ($gridPct in 0, 25, 50, 75, 100) {
        $y = $padTop + $plotHeight - ($plotHeight * $gridPct / 100)
        $yText = ConvertTo-mdiSvgNumber $y
        [void] $parts.Add('<line class="grid" x1="' + $padLeft + '" y1="' + $yText + '" x2="' + ($Width - $padRight) + '" y2="' + $yText + '"/>')
        [void] $parts.Add('<text class="axis" x="' + ($padLeft - 8) + '" y="' + (ConvertTo-mdiSvgNumber ($y + 3.5)) + '" text-anchor="end">' + $gridPct + '%</text>')
    }

    $line = ($coords | ForEach-Object { (ConvertTo-mdiSvgNumber $_.X) + ',' + (ConvertTo-mdiSvgNumber $_.Y) }) -join ' '
    $area = (ConvertTo-mdiSvgNumber $coords[0].X) + ',' + (ConvertTo-mdiSvgNumber ($padTop + $plotHeight)) + ' ' + $line + ' ' +
    (ConvertTo-mdiSvgNumber $coords[-1].X) + ',' + (ConvertTo-mdiSvgNumber ($padTop + $plotHeight))
    [void] $parts.Add('<polygon points="' + $area + '" fill="url(#trendFill)"/>')
    [void] $parts.Add('<polyline class="trend-line" points="' + $line + '" fill="none"/>')

    foreach ($c in $coords) {
        [void] $parts.Add('<circle class="trend-dot" cx="' + (ConvertTo-mdiSvgNumber $c.X) + '" cy="' + (ConvertTo-mdiSvgNumber $c.Y) + '" r="3.5">' +
            '<title>' + (ConvertTo-mdiHtmlEncoded ([string] $c.Point.Timestamp)) + ': ' + [int] [math]::Round($c.Pct) + '% (' +
            [int] $c.Point.ChecksPassed + '/' + [int] $c.Point.ChecksTotal + ')</title></circle>')
    }

    [void] $parts.Add('<text class="axis" x="' + $padLeft + '" y="' + ($Height - 8) + '">' +
        (ConvertTo-mdiHtmlEncoded (([string] $points[0].Timestamp) -replace 'T', ' ')) + '</text>')
    [void] $parts.Add('<text class="axis" x="' + ($Width - $padRight) + '" y="' + ($Height - 8) + '" text-anchor="end">' +
        (ConvertTo-mdiHtmlEncoded (([string] $points[-1].Timestamp) -replace 'T', ' ')) + '</text>')
    [void] $parts.Add('</svg>')

    # Delta versus the previous run, but only when the two runs measured the same thing.
    #
    # The history stores aggregate counts, so a change in the check set (a script upgrade that added a
    # check) or in the estate (a domain controller decommissioned, or one that was unreachable this
    # time) moves the ratio for reasons that have nothing to do with readiness. Drawing an arrow over
    # that told the operator their posture had improved or regressed when nothing had changed at all -
    # and a percentage-point figure is exactly the kind of number that ends up in a status report.
    $previous = $points[-2]
    $current = $points[-1]

    $sameChecks = (@($previous.CheckNames) -join '|') -eq (@($current.CheckNames) -join '|')
    $sameServers = (@($previous.ServerNames) -join '|') -eq (@($current.ServerNames) -join '|')
    # A run recorded before the fingerprint existed cannot be compared either, but saying so is honest
    # where inventing a delta is not.
    $hasFingerprint = @($previous.CheckNames).Count -gt 0 -and @($current.CheckNames).Count -gt 0

    $prevTotal = [double] ($previous.ChecksTotal -as [int])
    $currTotal = [double] ($current.ChecksTotal -as [int])

    if (-not $hasFingerprint -or -not $sameChecks -or -not $sameServers -or $prevTotal -le 0 -or $currTotal -le 0) {
        $reason = if (-not $hasFingerprint) {
            'the previous run predates the comparison fingerprint'
        } elseif (-not $sameServers) {
            'the set of servers changed'
        } elseif (-not $sameChecks) {
            'the set of checks changed'
        } else {
            'one of the runs measured nothing'
        }
        $deltaText = 'Not comparable with the previous run - {0} ({1} run(s) recorded)' -f $reason, $points.Count
        return ($parts.ToArray() -join '') + '<p><span class="pill na">' + (ConvertTo-mdiHtmlEncoded $deltaText) + '</span></p>'
    }

    $prevPct = ([double] ($previous.ChecksPassed -as [int]) / $prevTotal) * 100
    $currPct = ([double] ($current.ChecksPassed -as [int]) / $currTotal) * 100
    $delta = $currPct - $prevPct
    $tone = if ($delta -gt 0.5) { 'ok' } elseif ($delta -lt -0.5) { 'bad' } else { 'na' }
    $arrow = if ($delta -gt 0.5) { '&uarr;' } elseif ($delta -lt -0.5) { '&darr;' } else { '&rarr;' }
    $deltaText = '{0} {1} pt vs previous run ({2} run(s) recorded)' -f $arrow, [math]::Round($delta, 1), $points.Count

    ($parts.ToArray() -join '') + '<p><span class="pill ' + $tone + '">' + $deltaText + '</span></p>'
}

#region Console output

<#
    Property names that are not readiness checks.

    A server object carries three kinds of property: boolean checks, descriptive facts, and status
    flags. Only the first kind belongs in a score. The distinction matters twice over: a descriptive
    field legitimately holds 'N/A' - a server with no sensor reports SensorVersion 'N/A' - and a status
    flag is a boolean that would otherwise be counted as a passed or failed check.
#>
$script:mdiInformationalProperty = @('SensorVersion', 'CapturingComponent', 'MachineType', 'OS', 'IP', 'Addresses', 'FQDN', 'Domain', 'Comment', 'Details')
$script:mdiStatusFlag = @('PartialFailure', 'Unreachable')

<#
    How a port probe that never RAN is told apart from one that ran and found the port shut.

    Defined once, because every table and every count has to agree: the KPI, the per-port matrix, the
    NNR matrix and the actionable list all classify on this, and when one of them used a different
    copy the same report showed a red "blocked" port that the list of ports to fix did not mention.
    Red reads as "blocked", so the operator opens a firewall port that was never probed.
#>
$script:mdiPortNotTestedPattern = 'Access is denied|RPC server is unavailable|Not tested|could not be|unable to'

function Get-mdiCheckProperty {
    <#
        The boolean readiness checks on a server object, with the status flags removed.
    #>
    param (
        [Parameter(Mandatory = $true)] [object] $Server
    )
    @($Server.PSObject.Properties | Where-Object {
            $_.Value -is [bool] -and $_.Name -notin $script:mdiStatusFlag
        })
}

function Get-mdiUnreadCheckCount {
    <#
        Checks that could not be measured. Descriptive fields are excluded, because 'N/A' there is an
        answer rather than a gap.
    #>
    param (
        [Parameter(Mandatory = $true)] [object] $Server
    )
    @($Server.PSObject.Properties | Where-Object {
            $_.Name -notin $script:mdiInformationalProperty -and
            $_.Name -notin $script:mdiStatusFlag -and
            $_.Value -is [string] -and $_.Value -eq 'N/A'
        }).Count
}

<#
    Verbose output is one long stream of similar-looking lines, which makes it hard to follow which
    server is being worked on. Colour is added to the parts that vary — server names, counts and
    outcomes — rather than to whole lines.

    Colour is only emitted to an interactive console. $Host.UI.SupportsVirtualTerminal stays true even
    when the output is redirected to a file, so it cannot be used on its own: a run such as
    "Test-MdiReadiness.ps1 -Verbose *> run.log" would fill the log with escape sequences.
#>
$script:mdiUseColour = $false
try {
    $script:mdiUseColour = $Host.UI.SupportsVirtualTerminal -and
    -not [Console]::IsOutputRedirected -and
    $env:NO_COLOR -ne '1' -and $env:TERM -ne 'dumb'
} catch {
    $script:mdiUseColour = $false
}

$script:mdiColour = @{
    Reset  = [char] 27 + '[0m'
    Server = [char] 27 + '[96m'   # bright cyan - the server currently being tested
    Count  = [char] 27 + '[93m'   # bright yellow - how many of something was found
    Good   = [char] 27 + '[92m'
    Bad    = [char] 27 + '[91m'
    Dim    = [char] 27 + '[90m'
}

function Write-mdiVerbose {
    param (
        [Parameter(Mandatory = $true, Position = 0)] [string] $Message
    )

    # The cmdlet is called by its fully qualified name: this function would otherwise resolve to
    # itself and recurse until the call depth is exhausted.
    if (-not $script:mdiUseColour) {
        Microsoft.PowerShell.Utility\Write-Verbose -Message $Message
        return
    }

    $c = $script:mdiColour
    $text = $Message

    # Host names, so the eye can follow which server a block of lines belongs to
    $text = [regex]::Replace($text, '(?<![\w.-])([a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9.-]*[a-z])(?![\w-])',
        { param($m) $c.Server + $m.Groups[1].Value + $c.Reset }, 'IgnoreCase')

    # Counts, which are the numbers worth noticing in a progress stream
    $text = [regex]::Replace($text, '(?<![\w.])(\d+)(?=\s+(?:domain controller|Domain Controller|CA server|Entra Connect server|LDAP target|Network Name Resolution target|section))',
        { param($m) $c.Count + $m.Groups[1].Value + $c.Reset })

    $text = [regex]::Replace($text, '\b(falling back|not available|blocked|failed)\b',
        { param($m) $c.Bad + $m.Groups[1].Value + $c.Reset }, 'IgnoreCase')

    Microsoft.PowerShell.Utility\Write-Verbose -Message $text
}

#endregion

#region Capacity planning

<#
    The sampling loop lives in a standalone script block, with every setting passed in as an
    argument, so that the same code can run either in this session or inside a runspace that
    has no access to the script scope.
#>
$script:mdiTrafficSampleScript = {
    param (
        [string] $ComputerName,
        [int] $DurationSeconds,
        [int] $IntervalSeconds,
        [string] $PerfClass,
        [string] $CpuPerfClass,
        [string] $MemoryPerfClass,
        [string] $ExcludeAdapterName
    )

    $samples = New-Object -TypeName System.Collections.ArrayList
    $deadline = [datetime]::Now.AddSeconds($DurationSeconds)

    do {
        try {
            $adapters = @(Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class $PerfClass `
                    -Property 'Name', 'PacketsPersec' -ErrorAction Stop |
                    Where-Object { $_.Name -notmatch $ExcludeAdapterName })
            if ($adapters.Count -eq 0) { return $null }

            # NIC teaming counts the same packet twice. An LBFO team exposes a Multiplexor Driver
            # interface AND its physical members, and every packet traverses both, so summing all of
            # them inflated the rate by the number of members - which pushes the sizing into a larger
            # band and can turn an adequate server into a false "insufficient capacity".
            #
            # The team is only preferred when it actually carries the traffic. Discarding every
            # non-matching adapter unconditionally was worse than the problem it solved: a domain
            # controller that also runs Hyper-V exposes "vEthernet (Default Switch)" - the always
            # present, near-idle internal NAT switch - so the physical adapter carrying all the real
            # traffic was thrown away and the packet rate collapsed to nearly zero. That under-sizes
            # the sensor and reports a genuinely overloaded server as having sufficient capacity,
            # which is the more dangerous direction of the two errors.
            $teamed = @($adapters | Where-Object { $_.Name -match 'Multiplexor|vEthernet' })
            $physical = @($adapters | Where-Object { $_.Name -notmatch 'Multiplexor|vEthernet' })
            if ($teamed.Count -gt 0) {
                $teamedMax = [double] (@($teamed | ForEach-Object { [double] $_.PacketsPersec } |
                            Measure-Object -Maximum).Maximum)
                $physicalMax = [double] (@($physical | ForEach-Object { [double] $_.PacketsPersec } |
                            Measure-Object -Maximum).Maximum)
                if ($physical.Count -eq 0 -or $teamedMax -ge $physicalMax) { $adapters = $teamed }
            }

            $total = 0
            foreach ($adapter in $adapters) { $total += [double] $adapter.PacketsPersec }

            # The official tool also records compute and memory utilisation alongside the packet rate
            $cpuPercent = $null
            $availableMb = $null
            try {
                $cpu = @(Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class $CpuPerfClass `
                        -Property 'Name', 'PercentProcessorTime' -ErrorAction Stop |
                        Where-Object { $_.Name -eq '_Total' })[0]
                if ($cpu) { $cpuPercent = [double] $cpu.PercentProcessorTime }
                $memory = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class $MemoryPerfClass `
                    -Property 'AvailableMBytes' -ErrorAction Stop
                if ($memory) { $availableMb = [double] $memory.AvailableMBytes }
            } catch {
                # Utilisation is supplementary: a server that does not expose these classes is still sized
            }

            [void] $samples.Add([PSCustomObject]@{
                    Timestamp     = [datetime]::Now
                    PacketsPerSec = $total
                    CpuPercent    = $cpuPercent
                    AvailableMb   = $availableMb
                })
        } catch {
            return $null
        }
        if ([datetime]::Now -lt $deadline) { Start-Sleep -Seconds $IntervalSeconds }
    } while ([datetime]::Now -lt $deadline)

    if ($samples.Count -eq 0) { return $null }
    , $samples.ToArray()
}

function Get-mdiTrafficSampleSet {
    <#
        Samples several servers at the same time, each in its own runspace.

        Sampling sequentially made the total run time grow with the number of domain controllers
        (four DCs at 120 seconds cost eight minutes), and worse, each server was measured over a
        different wall-clock window, so the numbers could not be compared with each other. Running
        the samples together keeps the cost at roughly one sample period for the whole forest and
        measures every server over the same window.
    #>
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [string[]] $ComputerName,
        [Parameter(Mandatory = $true)] [int] $DurationSeconds,
        [Parameter(Mandatory = $true)] [int] $IntervalSeconds,
        [Parameter(Mandatory = $false)] [int] $MaxParallel = 0
    )

    $collected = @{}
    $targets = @($ComputerName | Where-Object { $_ })
    if ($targets.Count -eq 0) { return $collected }

    $capacity = $settings.CapacityPlanning
    # Every server at once by default, so they share one measurement window. The cap exists for very
    # large forests, where hundreds of concurrent WMI sessions would strain the machine running this.
    $throttle = if ($MaxParallel -gt 0) { [Math]::Min($MaxParallel, $targets.Count) } else { $targets.Count }
    if ($throttle -lt $targets.Count) {
        Write-mdiVerbose ('Sampling {0} server(s) {1} at a time; batches are not measured over the same window' -f $targets.Count, $throttle)
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $throttle)
    try {
        # Opened inside the try so a failure to create the pool - resource exhaustion, a constrained
        # language mode host - is reported rather than ending the run, and so the pool is always
        # disposed by the finally below.
        $pool.Open()
    } catch {
        Write-Warning ('Unable to start parallel traffic sampling: {0}. Capacity planning is skipped.' -f $_.Exception.Message)
        $pool.Dispose()
        return $collected
    }

    $pending = New-Object -TypeName System.Collections.ArrayList
    try {
        foreach ($target in $targets) {
            $shell = [powershell]::Create()
            $shell.RunspacePool = $pool
            [void] $shell.AddScript($script:mdiTrafficSampleScript).
                AddArgument($target).
                AddArgument($DurationSeconds).
                AddArgument($IntervalSeconds).
                AddArgument($capacity.PerfClass).
                AddArgument($capacity.CpuPerfClass).
                AddArgument($capacity.MemoryPerfClass).
                AddArgument($capacity.ExcludeAdapterName)
            [void] $pending.Add([PSCustomObject]@{
                    Computer = $target
                    Shell    = $shell
                    Handle   = $shell.BeginInvoke()
                })
        }

        # The wait is bounded. EndInvoke blocks unconditionally, so a domain controller whose WMI hangs -
        # common over an unstable link or with a wedged DCOM - froze the capacity phase forever with no
        # way out. The budget is the sampling duration plus a margin for the WMI round trips.
        $waitMs = ([Math]::Max(1, $DurationSeconds) * 1000) + 120000
        foreach ($job in $pending) {
            try {
                if ($job.Handle.AsyncWaitHandle.WaitOne($waitMs, $false)) {
                    $output = $job.Shell.EndInvoke($job.Handle)
                    $rows = @($output | Where-Object { $_ })
                    $collected[$job.Computer] = if ($rows.Count -gt 0) { $rows } else { $null }
                } else {
                    Write-Warning ('Traffic sampling on {0} did not finish within {1}s and was abandoned' -f $job.Computer, [int] ($waitMs / 1000))
                    try { $job.Shell.Stop() } catch {}
                    $collected[$job.Computer] = $null
                }
            } catch {
                Write-mdiVerbose ('Traffic sampling failed on {0}: {1}' -f $job.Computer, $_.Exception.Message)
                $collected[$job.Computer] = $null
            } finally {
                try { $job.Shell.Dispose() } catch {}
            }
        }
    } finally {
        try { $pool.Close() } catch {}
        try { $pool.Dispose() } catch {}
    }

    $collected
}

function Get-mdiTrafficSample {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [int] $DurationSeconds,
        [Parameter(Mandatory = $true)] [int] $IntervalSeconds
    )

    $capacity = $settings.CapacityPlanning
    $output = & $script:mdiTrafficSampleScript $ComputerName $DurationSeconds $IntervalSeconds `
        $capacity.PerfClass $capacity.CpuPerfClass $capacity.MemoryPerfClass $capacity.ExcludeAdapterName
    $rows = @($output | Where-Object { $_ })
    if ($rows.Count -eq 0) { return $null }
    , $rows
}

function Get-mdiBusyPacketsPerSecond {
    param (
        [Parameter(Mandatory = $true)] [object[]] $Sample,
        [Parameter(Mandatory = $true)] [int] $WindowMinutes
    )

    # 'The sizing tool determines whether your server is supported based on the Busy Packets/Second value,
    #  which is calculated based on the 15 busiest minutes over a 24 hour period.'
    $values = @($Sample | ForEach-Object { [double] $_.PacketsPerSec })
    $average = ($values | Measure-Object -Average).Average
    $peak = ($values | Measure-Object -Maximum).Maximum

    $windowSeconds = $WindowMinutes * 60
    $span = ($Sample[-1].Timestamp - $Sample[0].Timestamp).TotalSeconds

    $busy = if ($span -lt $windowSeconds) {
        # The sample is shorter than the busy window, so the whole sample is the best available estimate
        $average
    } else {
        # Highest average over any rolling window of the requested length. Only windows that are actually
        # full are considered: near the end of the sample the window would otherwise shrink until it held
        # a single reading, and the "average" of one reading is that reading, so one brief spike in the
        # last seconds of sampling was reported as the busiest 15 minutes and pushed the recommendation
        # into a larger sizing band than the traffic justifies.
        $best = 0.0
        $lastTimestamp = $Sample[-1].Timestamp
        for ($i = 0; $i -lt $Sample.Count; $i++) {
            $windowStart = $Sample[$i].Timestamp
            if (($lastTimestamp - $windowStart).TotalSeconds -lt $windowSeconds) { break }
            $windowEnd = $windowStart.AddSeconds($windowSeconds)
            $window = @($Sample | Where-Object { $_.Timestamp -ge $windowStart -and $_.Timestamp -le $windowEnd })
            if ($window.Count -eq 0) { continue }
            $windowAverage = ($window | ForEach-Object { [double] $_.PacketsPerSec } | Measure-Object -Average).Average
            if ($windowAverage -gt $best) { $best = $windowAverage }
        }
        # If no full window existed after all, fall back to the whole-sample average rather than zero.
        if ($best -le 0) { $best = $average }
        $best
    }

    [PSCustomObject]@{
        BusyPacketsPerSec = [int] [math]::Round($busy)
        AveragePacketsPerSec = [int] [math]::Round($average)
        PeakPacketsPerSec = [int] [math]::Round($peak)
        SampleCount = $Sample.Count
        SampleSeconds = [int] [math]::Round($span)
        FullWindow = $span -ge $windowSeconds
    }
}

function Get-mdiCapacityPlanning {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $false)] [int] $DurationSeconds = 120,
        [Parameter(Mandatory = $false)] [int] $IntervalSeconds = 5,
        [Parameter(Mandatory = $false)] [object[]] $TrafficSample = $null
    )

    $capacity = $settings.CapacityPlanning

    $notSized = {
        param([string] $Status, [string] $Detail)
        [PSCustomObject]@{
            isCapacityOk = 'N/A'
            details      = [PSCustomObject]@{ Status = $Status; Detail = $Detail }
        }
    }

    # --- Hardware inventory ------------------------------------------------------------------------------------
    try {
        $processors = @(Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class 'Win32_Processor' `
                -Property 'NumberOfCores', 'NumberOfLogicalProcessors' -ErrorAction Stop)
    } catch { $processors = @() }
    if ($processors.Count -eq 0) { return & $notSized 'Missing core data' 'Unable to read the processor information over WMI' }

    $physicalCores = 0
    $logicalCores = 0
    foreach ($cpu in $processors) {
        $physicalCores += [int] $cpu.NumberOfCores
        $logicalCores += [int] $cpu.NumberOfLogicalProcessors
    }
    # 'We recommend that you don't work with hyper-threaded cores, which can result in health issues'
    $hyperThreaded = $logicalCores -gt $physicalCores

    try {
        $computerSystem = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class 'Win32_ComputerSystem' `
            -Property 'TotalPhysicalMemory' -ErrorAction Stop
        $totalRamGb = [math]::Round(([double] $computerSystem.TotalPhysicalMemory) / 1GB, 2)
    } catch { $totalRamGb = 0 }
    if ($totalRamGb -le 0) { return & $notSized 'Missing RAM data' 'Unable to read the installed memory over WMI' }

    # --- Traffic sample ----------------------------------------------------------------------------------------
    # The caller normally samples every server at once and passes the result in. Sampling here is the
    # fallback for a single server. Note the local name differs from the parameter: PowerShell variable
    # names are case insensitive, so $sample and $Sample would be the same variable.
    if ($TrafficSample) {
        $collected = @($TrafficSample)
    } else {
        Write-mdiVerbose ("Sampling network traffic on {0} for {1}s at {2}s intervals" -f $ComputerName, $DurationSeconds, $IntervalSeconds)
        $collected = Get-mdiTrafficSample -ComputerName $ComputerName -DurationSeconds $DurationSeconds -IntervalSeconds $IntervalSeconds
    }
    if ($null -eq $collected -or @($collected).Count -eq 0) {
        return & $notSized 'Missing traffic data' 'Unable to read the network performance counters over WMI'
    }

    $traffic = Get-mdiBusyPacketsPerSecond -Sample $collected -WindowMinutes $capacity.BusyWindowMinutes
    $busy = $traffic.BusyPacketsPerSec

    $cpuSamples = @($collected | Where-Object { $null -ne $_.CpuPercent } | ForEach-Object { [double] $_.CpuPercent })
    $memSamples = @($collected | Where-Object { $null -ne $_.AvailableMb } | ForEach-Object { [double] $_.AvailableMb })
    $avgCpuPercent = if ($cpuSamples.Count -gt 0) { [int] [math]::Round(($cpuSamples | Measure-Object -Average).Average) } else { $null }
    $maxCpuPercent = if ($cpuSamples.Count -gt 0) { [int] [math]::Round(($cpuSamples | Measure-Object -Maximum).Maximum) } else { $null }
    $minAvailableGb = if ($memSamples.Count -gt 0) { [math]::Round((($memSamples | Measure-Object -Minimum).Minimum) / 1024, 2) } else { $null }

    # --- Required resources ------------------------------------------------------------------------------------
    $band = @($capacity.SizingTable | Where-Object { $busy -ge $_.MinPps -and $busy -lt $_.MaxPps })[0]
    if ($null -eq $band) { $band = $capacity.SizingTable[-1] }

    $requiredCpu = [double] $band.Cpu
    $requiredRamGb = [double] $band.RamGb
    $cpuOk = $physicalCores -ge $requiredCpu
    $ramOk = $totalRamGb -ge $requiredRamGb
    $resourcesOk = $cpuOk -and $ramOk

    $missing = New-Object -TypeName System.Collections.ArrayList
    if (-not $cpuOk) { [void] $missing.Add(('{0} more physical core(s)' -f [math]::Ceiling($requiredCpu - $physicalCores))) }
    if (-not $ramOk) { [void] $missing.Add(('{0} GB more RAM' -f [math]::Round($requiredRamGb - $totalRamGb, 2))) }

    # --- Verdict, following the documented result values ---------------------------------------------------------
    $spiky = ($traffic.AveragePacketsPerSec -gt 0) -and
             ($busy -gt ($traffic.AveragePacketsPerSec * $capacity.SpikeRatio))

    $status = if ($busy -ge $capacity.MaxSupportedPps) {
        'No'
    } elseif ($spiky -or $busy -gt $capacity.MaybeThresholdPps) {
        if ($resourcesOk) { 'Maybe' } else { 'Maybe, but additional resources required' }
    } else {
        if ($resourcesOk) { 'Yes' } else { 'Yes, but additional resources required' }
    }

    $detail = switch -Wildcard ($status) {
        'Yes' { 'The server has enough resources for a sensor v2.x at {0} busy packets/sec' -f $busy }
        'Yes, but*' { 'Supported at {0} busy packets/sec once you add: {1}' -f $busy, ($missing.ToArray() -join ', ') }
        'Maybe' { 'Busy traffic ({0} packets/sec) is well above the average ({1}). Check what runs during the busiest window before deploying' -f $busy, $traffic.AveragePacketsPerSec }
        'Maybe, but*' { 'Busy traffic is {0} packets/sec and the server is missing: {1}' -f $busy, ($missing.ToArray() -join ', ') }
        default { 'A sensor v2.x is not supported at {0} busy packets/sec, which is at or above the {1} packets/sec ceiling of the published sizing table' -f $busy, $capacity.MaxSupportedPps }
    }

    [PSCustomObject]@{
        isCapacityOk = $status -like 'Yes*'
        details      = [PSCustomObject]@{
            Status               = $status
            Detail               = $detail
            Band                 = [string] $band.Band
            BusyPacketsPerSec    = $busy
            AveragePacketsPerSec = $traffic.AveragePacketsPerSec
            PeakPacketsPerSec    = $traffic.PeakPacketsPerSec
            RequiredCpu          = $requiredCpu
            RequiredRamGb        = $requiredRamGb
            PhysicalCores        = $physicalCores
            LogicalCores         = $logicalCores
            HyperThreaded        = $hyperThreaded
            TotalRamGb           = $totalRamGb
            AvgCpuPercent        = $avgCpuPercent
            MaxCpuPercent        = $maxCpuPercent
            MinAvailableRamGb    = $minAvailableGb
            Missing              = $missing.ToArray()
            SampleSeconds        = $traffic.SampleSeconds
            SampleCount          = $traffic.SampleCount
            FullBusyWindow       = $traffic.FullWindow
        }
    }
}

#endregion

function Get-mdiPowerScheme {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $commandLine = 'cmd.exe /c %windir%\system32\powercfg.exe /getactivescheme'
    $details = Invoke-mdiRemoteCommand -ComputerName $ComputerName -CommandLine $commandLine
    if ($details -match ':\s+(?<guid>[a-fA-F0-9]{8}[-]?([a-fA-F0-9]{4}[-]?){3}[a-fA-F0-9]{12})\s+\((?<name>.*)\)') {
        $return = [PSCustomObject]@{
            isPowerSchemeOk = $Matches.guid -eq '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
            details         = $details
        }
    } elseif ($null -eq $details -or [string]::IsNullOrWhiteSpace([string] $details) -or
        [string] $details -match 'Access is denied|RPC server is unavailable|cannot be found|not available') {
        # The scheme was not read, so it is not known to be wrong. Reporting an unread check as a
        # failure sends people to change a power plan that is very likely already correct.
        $return = [PSCustomObject]@{
            isPowerSchemeOk = 'N/A'
            details         = ('Unable to read the active power scheme: {0}' -f
                $(if ([string]::IsNullOrWhiteSpace([string] $details)) { 'no response from the server' } else { ([string] $details).Trim() }))
        }
    } else {
        $return = [PSCustomObject]@{
            isPowerSchemeOk = $false
            details         = $details
        }
    }
    $return
}

function Get-mdiServerRequirements {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    try {
        $csiParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_ComputerSystem'
            Property     = 'NumberOfLogicalProcessors', 'TotalPhysicalMemory'
            ErrorAction  = 'Stop'
        }
        $csi = Get-WmiObject @csiParams

        $osParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_OperatingSystem'
            Property     = 'SystemDrive'
            ErrorAction  = 'Stop'
        }
        $osdiskParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_LogicalDisk'
            Property     = 'FreeSpace', 'DeviceID'
            Filter       = "DeviceID = '{0}'" -f (Get-WmiObject @osParams).SystemDrive
            ErrorAction  = 'Stop'
        }
        $osdisk = Get-WmiObject @osdiskParams

        # With SilentlyContinue these came back null on an access denied, and $null -ge 2 is false, so a
        # server with ample hardware was reported as failing the minimum requirements without any error
        # ever being raised. The query now stops on error and a missing answer is reported as unknown.
        if ($null -eq $csi -or $null -eq $osdisk) {
            throw 'the hardware inventory was not returned'
        }

        $minRequirements = @{
            NumberOfLogicalProcessors = 2
            TotalPhysicalMemory       = 6gb - 1mb
            OsDiskFreeSpace           = 6gb
        }
        $return = [PSCustomObject]@{
            isMinHwRequirementsOk = (
                $csi.NumberOfLogicalProcessors -ge $minRequirements.NumberOfLogicalProcessors -and
                $csi.TotalPhysicalMemory -ge $minRequirements.TotalPhysicalMemory -and
                $osdisk.FreeSpace -ge $minRequirements.OsDiskFreeSpace
            )
            details               = [PSCustomObject]@{
                NumberOfLogicalProcessors = $csi.NumberOfLogicalProcessors
                TotalPhysicalMemory       = $csi.TotalPhysicalMemory
                OsDiskDeviceID            = $osdisk.DeviceID
                OsDiskFreeSpace           = $osdisk.FreeSpace
            }
        }
    } catch {
        # 'N/A' rather than false: the hardware was not found to be insufficient, it could not be read.
        $return = [PSCustomObject]@{
            isMinHwRequirementsOk = 'N/A'
            details               = ('Unable to read the hardware inventory: {0}' -f ($_.Exception.Message -replace '[\r\n]+', ' '))
        }
    }
    $return
}

function Get-mdiRegistryValueSet {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string[]] $ExpectedRegistrySet
    )

    # A remote registry read fails for ordinary reasons: the server is off, the Remote Registry service is
    # stopped, a firewall blocks it, or the caller lacks rights. None of those should end the run, but an
    # unhandled exception here aborted the whole forest scan and left no report at all.
    $hklm = $null
    try {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, 'Registry64')
    } catch {
        Write-Warning ('Unable to read the registry of {0}: {1}' -f $ComputerName, $_.Exception.Message)
        return $null
    }

    try {
        foreach ($reg in $ExpectedRegistrySet) {
            $regKeyPath, $regValue, $expectedValue = $reg -split ','
            $value = $null
            $regKey = $null
            try {
                # OpenSubKey returns null for a key that does not exist rather than throwing, so calling
                # GetValue on the result fails with "You cannot call a method on a null-valued expression".
                # A missing key is a legitimate finding: it means the setting was never configured.
                $regKey = $hklm.OpenSubKey($regKeyPath)
                if ($regKey) { $value = $regKey.GetValue($regValue) }
            } catch {
                Write-Warning ('Unable to read {0}\{1} on {2}: {3}' -f $regKeyPath, $regValue, $ComputerName, $_.Exception.Message)
            } finally {
                if ($regKey) { try { $regKey.Close() } catch {} }
            }

            [PSCustomObject]@{
                regKey        = '{0}\{1}' -f $regKeyPath, $regValue
                value         = $value
                expectedValue = $expectedValue
            }
        }
    } finally {
        # Closed in a finally so the handle is released even when a read throws part way through.
        if ($hklm) { try { $hklm.Close() } catch {} }
    }
}

function Get-mdiNtlmAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    # Get-mdiRegistryValueSet returns null when the registry could not be opened. Piping null into
    # Where-Object runs the body once with $_ = $null, nothing is emitted, the count is 0 and the check
    # reported PASS. A stopped Remote Registry service therefore produced a silent false green on an
    # audit control, which is worse than a false failure: nobody goes looking.
    $details = Get-mdiRegistryValueSet -ComputerName $ComputerName -ExpectedRegistrySet $settings.NTLMAuditing
    if ($null -eq $details) {
        return [PSCustomObject]@{
            isNtlmAuditingOk = 'N/A'
            details          = 'Not tested - the registry could not be read on this server'
        }
    }
    [PSCustomObject]@{
        isNtlmAuditingOk = @($details | Where-Object { $_.value -notmatch $_.expectedValue }).Count -eq 0
        details          = $details | Select-Object regKey, value
    }
}

function Get-mdiCAAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $activeName = Get-mdiRegistryValueSet -ComputerName $ComputerName -ExpectedRegistrySet $settings.CASettings.RegPathActive
    # Without this guard a failed read leaves $activeName null, the format operator produces a path with
    # an empty CA name, OpenSubKey returns null for it, and the missing value is compared against the
    # expected one and reported as misconfigured. A CA that could not be read is not a misconfigured CA.
    $activeValue = if ($activeName) { [string] (@($activeName)[0].value) } else { $null }
    if ([string]::IsNullOrWhiteSpace($activeValue)) {
        return [PSCustomObject]@{
            isCaAuditingOk = 'N/A'
            details        = 'Not tested - the active certification authority name could not be read from the registry'
        }
    }

    $details = @($settings.CASettings.RegistrySet | ForEach-Object {
            Get-mdiRegistryValueSet -ComputerName $ComputerName -ExpectedRegistrySet ($_ -f $activeValue)
        } | Where-Object { $_ })
    if ($details.Count -eq 0) {
        return [PSCustomObject]@{
            isCaAuditingOk = 'N/A'
            details        = 'Not tested - the registry could not be read on this server'
        }
    }
    [PSCustomObject]@{
        isCaAuditingOk = @($details | Where-Object { $_.value -notmatch $_.expectedValue }).Count -eq 0
        details        = $details | Select-Object regKey, value
    }
}

# Get-mdiEntraConnectAuditing was removed here. It was never called - the Entra Connect audit policy is
# read by Get-mdiAdvancedAuditing at the only real call site, which is the correct reader for it - and it
# could not have worked if it had been: it passed $settings.AdvancedAuditPolicyEntraConnect, which is an
# advanced audit policy CSV, to Get-mdiRegistryValueSet, which expects "registry path,value name,expected
# value" triplets. It then used the same CSV as a format string, and the subcategory GUID in it
# ({0cce9215-...}) makes the format operator throw "Format item ends prematurely". It was a copy of
# Get-mdiCAAuditing with the wrong setting substituted. Dead code that looks like a working check is
# worse than no code at all, so it is gone rather than repaired.

function Get-mdiCertReadiness {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    # Opening a remote certificate store fails for the same ordinary reasons as a remote registry read:
    # the server is unreachable, the Remote Registry service is stopped, or the caller lacks rights. This
    # was the only check with no error handling, so an access denied here ended the scan for that server
    # and, before the per-server isolation was added, for the whole forest.
    $store = $null
    $details = $null
    $storeError = $null
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$ComputerName\Root",
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $details = $store.Certificates | Where-Object { $settings.RootCertificates -contains $_.Thumbprint }
    } catch {
        $storeError = $_.Exception.Message -replace '[\r\n]+', ' '
        Write-Warning ('Unable to read the certificate store of {0}: {1}' -f $ComputerName, $storeError)
    } finally {
        if ($store) { try { $store.Close() } catch {} }
    }

    if ($storeError) {
        # 'N/A' rather than false: the certificates were not found to be missing, they could not be read,
        # and reporting an unread check as a failure sends people to fix something that may be fine.
        return [PSCustomObject]@{
            isRootCertificatesOk = 'N/A'
            details              = [PSCustomObject]@{ Error = ('Unable to read the certificate store: {0}' -f $storeError) }
        }
    }

    [PSCustomObject]@{
        isRootCertificatesOk = @($details).Count -ge 1
        details              = $details | Select-Object -Property Thumbprint, Subject, Issuer, NotBefore, NotAfter
    }
}

function Get-mdiCaptureComponent {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    $uninstallRegKey = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    $found = @()
    $anyViewRead = $false

    # Each registry view is handled independently. Previously a single catch wrapped both, so a failure
    # in the 64-bit pass discarded what the 32-bit pass had already found and returned 'N/A' - which the
    # v3 check reads as "no capture driver installed". A server with Npcap installed was reported as
    # having none. The handle is also closed in a finally rather than at the end of the loop body, so a
    # throw part way through no longer leaks a remote registry handle per server per view.
    foreach ($registryView in @('Registry32', 'Registry64')) {
        $hklm = $null
        try {
            $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, $registryView)
            $uninstallRef = $hklm.OpenSubKey($uninstallRegKey)
            if ($null -eq $uninstallRef) { continue }
            $anyViewRead = $true

            try {
                foreach ($app in $uninstallRef.GetSubKeyNames()) {
                    $appDetails = $null
                    try {
                        # A subkey can disappear between enumeration and open if something is uninstalling.
                        $appDetails = $hklm.OpenSubKey($uninstallRegKey + '\' + $app)
                        if ($null -eq $appDetails) { continue }
                        $appDisplayName = $appDetails.GetValue('DisplayName')
                        $appVersion = $appDetails.GetValue('DisplayVersion')
                        if ($appDisplayName -match 'npcap|winpcap') {
                            $found += '{0} ({1})' -f $appDisplayName, $appVersion
                        }
                    } catch {
                        Write-Verbose ('Unable to read {0} on {1}: {2}' -f $app, $ComputerName, $_.Exception.Message)
                    } finally {
                        if ($appDetails) { try { $appDetails.Close() } catch {} }
                    }
                }
            } finally {
                try { $uninstallRef.Close() } catch {}
            }
        } catch {
            Write-Verbose ('Unable to read the {0} uninstall registry of {1}: {2}' -f $registryView, $ComputerName, $_.Exception.Message)
        } finally {
            if ($hklm) { try { $hklm.Close() } catch {} }
        }
    }

    # 'N/A' only when nothing could be read at all. An empty result from a readable registry is a real
    # finding: no capture driver is installed.
    if (-not $anyViewRead) { return 'N/A' }
    ($found -join ', ')
}

function Get-mdiSensorVersion {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    try {
        $serviceParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_Service'
            Property     = 'Name', 'PathName', 'State'
            Filter       = "Name = 'AATPSensor'"
            ErrorAction  = 'SilentlyContinue'
        }
        $service = Get-WmiObject @serviceParams
        if ($service) {
            $versionParams = @{
                ComputerName = $ComputerName
                Namespace    = 'root\cimv2'
                Class        = 'CIM_DataFile'
                Property     = 'Version'
                Filter       = 'Name={0}' -f ($service.PathName -replace '\\', '\\')
                ErrorAction  = 'SilentlyContinue'
            }
            $return = (Get-WmiObject @versionParams).Version
        } else {
            $return = 'N/A'
        }
    } catch {
        # A raw HRESULT in a version field reads as if that string were the sensor version. The field
        # says what is known - nothing - and the reason is written to the verbose stream instead.
        Write-mdiVerbose ('Unable to read the sensor version from {0}: {1}' -f $ComputerName, ($_.Exception.Message -replace '[\r\n]+', ' '))
        $return = 'N/A'
    }
    $return
}

function Get-mdiMachineType {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    try {
        $csiParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_ComputerSystem'
            Property     = 'Model', 'Manufacturer'
            ErrorAction  = 'Stop'
        }
        $csi = Get-WmiObject @csiParams
        # Without this a failed query left $csi null and the switch fell through to 'Physical', so a
        # virtual machine that could not be queried was reported as bare metal.
        if ($null -eq $csi) { throw 'the computer system inventory was not returned' }
        $return = switch ($csi.Model) {
            { $_ -eq 'Virtual Machine' } { 'Hyper-V'; break }
            { $_ -match 'VMware|VirtualBox' } { $_; break }
            default {
                switch ($csi.Manufacturer) {
                    { $_ -match 'Xen|Google' } { $_; break }
                    { $_ -match 'QEMU' } { 'KVM'; break }
                    { $_ -eq 'Microsoft Corporation' } {
                        $azgaParams = @{
                            ComputerName = $ComputerName
                            Namespace    = 'root\cimv2'
                            Class        = 'Win32_Service'
                            Filter       = "Name = 'WindowsAzureGuestAgent'"
                            ErrorAction  = 'SilentlyContinue'
                        }
                        if (Get-WmiObject @azgaParams) { 'Azure' } else { 'Hyper-V' }
                        break
                    }
                    default {
                        $cspParams = @{
                            ComputerName = $ComputerName
                            Namespace    = 'root\cimv2'
                            Class        = 'Win32_ComputerSystemProduct'
                            Property     = 'uuid'
                            ErrorAction  = 'SilentlyContinue'
                        }
                        $uuid = (Get-WmiObject @cspParams).UUID
                        if ($uuid -match '^EC2') { 'AWS' }
                        else { 'Physical' }
                    }
                }
            }
        }
    } catch {
        # A raw HRESULT in a platform field reads as if that string were the platform.
        Write-mdiVerbose ('Unable to read the virtualization platform of {0}: {1}' -f $ComputerName, ($_.Exception.Message -replace '[\r\n]+', ' '))
        $return = 'N/A'
    }
    $return
}

function Get-mdiOSVersion {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )
    try {
        $osParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_OperatingSystem'
            Property     = 'Version', 'Caption'
            ErrorAction  = 'Stop'
        }
        $os = Get-WmiObject @osParams
        # A supported operating system that could not be read is not an unsupported one. Returning false
        # here reported every Windows Server 2022 domain controller as too old whenever WMI was blocked.
        if ($null -eq $os -or [string]::IsNullOrWhiteSpace([string] $os.Version)) {
            throw 'the operating system version was not returned'
        }
        $return = [PSCustomObject]@{
            isOsVerOk = [version]($os.Version) -ge [version]('6.3')
            details   = [PSCustomObject]@{
                Caption = $os.Caption
                Version = $os.Version
            }
        }
    } catch {
        $return = [PSCustomObject]@{
            isOsVerOk = 'N/A'
            details   = [PSCustomObject]@{
                Caption = 'N/A'
                Version = 'N/A'
                Error   = ('Unable to read the operating system version: {0}' -f ($_.Exception.Message -replace '[\r\n]+', ' '))
            }
        }
    }
    $return
}

function Get-mdiAdvancedAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string[]] $ExpectedAuditing
    )
    # Only compare on language-neutral fields: the Subcategory GUID and the raw numeric
    # Setting Value. 'Policy Target' and 'Inclusion Setting' are localized text on
    # non-English OSes and are not needed since the GUID already uniquely identifies
    # the subcategory being audited.
    $properties = 'Subcategory GUID', 'Setting Value'
    $expected = @($ExpectedAuditing | ConvertFrom-Csv)
    $LocalFile = Join-Path -Path (Get-mdiRemoteTempFolder -ComputerName $ComputerName) -ChildPath ('mdi-{0}.csv' -f , [guid]::NewGuid().GUID)
    $commandLine = 'cmd.exe /c auditpol.exe /backup /file:{0}' -f $LocalFile
    $output = Invoke-mdiRemoteCommand -ComputerName $ComputerName -CommandLine $commandLine -LocalFile $LocalFile
    if ($output -and $output.Count -gt 1) {
        # auditpol /backup writes a header row that is localized on non-English OSes (e.g.
        # German), so parsing by header name (e.g. 'Subcategory GUID') can silently match
        # zero rows, leaving $actual as $null and crashing Compare-Object with
        # "argument cannot be bound to parameter 'DifferenceObject' because it is NULL"
        # (see https://github.com/microsoft/Microsoft-Defender-for-Identity/issues/22).
        # The column order is fixed across locales, only the header text is translated, so
        # skip the (possibly localized) header row and re-apply fixed, language-neutral names.
        $knownHeader = 'Machine Name', 'Policy Target', 'Subcategory', 'Subcategory GUID', 'Inclusion Setting', 'Exclusion Setting', 'Setting Value'
        $columnCount = ($output[0] -split ',').Count
        $header = $knownHeader[0..($columnCount - 1)]

        $actual = @($output | Select-Object -Skip 1 | ConvertFrom-Csv -Header $header | Where-Object {
                $_.'Subcategory GUID' -in $expected.'Subcategory GUID'
            } | Select-Object -Property $properties)

        $compareParams = @{
            ReferenceObject  = @($expected | Select-Object -Property $properties)
            DifferenceObject = $actual
            Property         = $properties
        }
        $isAdvancedAuditingOk = $null -eq (Compare-Object @compareParams)
        $return = [PSCustomObject]@{
            isAdvancedAuditingOk = $isAdvancedAuditingOk
            details              = $actual
        }
    } else {
        # The settings were not read, so they are not known to be wrong. Returning false here reported
        # every domain controller as failing the MDI audit policy whenever WMI process creation or the
        # admin share was blocked, and wrote an auditpol reconfiguration into the remediation script for
        # servers that were already correct.
        $return = [PSCustomObject]@{
            isAdvancedAuditingOk = 'N/A'
            details              = 'Not tested - the advanced auditing settings could not be read remotely'
        }
    }
    $return
}

function Get-mdiDsSacl {
    param (
        [Parameter(Mandatory = $true)] [string] $LdapPath,
        [Parameter(Mandatory = $true)] [object[]] $ExpectedAuditing
    )

    # The search root and the searcher are both disposed. Without a finally each call left an unmanaged
    # LDAP connection to be reclaimed non-deterministically by the finalizer, and this runs three times
    # per domain against three different containers.
    $searchRoot = $null
    $searcher = $null
    try {
        $searchRoot = [adsi] $LdapPath
        $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $searchRoot
        $searcher.CacheResults = $false
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
        $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
        $searcher.PropertiesToLoad.AddRange(('ntsecuritydescriptor,distinguishedname,objectsid' -split ','))

        $result = ($searcher.FindOne()).Properties

        # The descriptor is built once and its SACL inspected before anything is compared.
        #
        # A caller without SeSecurityPrivilege ("Manage auditing and security log") does NOT get an
        # error: Active Directory returns the nTSecurityDescriptor attribute with the SACL silently
        # stripped, so the LDAP call succeeds and SystemAcl is null. Piping that null into
        # Select-Object yields one object with every property null, which matches nothing, and the
        # comparison below then concluded that auditing was MISCONFIGURED. Because no exception was
        # thrown the access-denied handling in the catch never ran either.
        #
        # That is the worst answer this tool can give: it sends an administrator to reconfigure
        # auditing that is very probably already correct, and the generated remediation script would
        # rewrite SACLs on the domain naming context on the strength of a read that never happened.
        $descriptorBytes = $null
        if ($null -ne $result -and $result.Contains('ntsecuritydescriptor') -and
            @($result['ntsecuritydescriptor']).Count -gt 0) {
            $descriptorBytes = $result['ntsecuritydescriptor'][0]
        }
        if ($null -eq $descriptorBytes) {
            return [PSCustomObject]@{
                isAuditingOk = 'N/A'
                details      = 'Not tested - the security descriptor of ' + $LdapPath + ' was not returned by the directory'
            }
        }

        $descriptor = New-Object -TypeName Security.AccessControl.RawSecurityDescriptor -ArgumentList ($descriptorBytes, 0)
        if ($null -eq $descriptor.SystemAcl) {
            return [PSCustomObject]@{
                isAuditingOk = 'N/A'
                details      = 'Not tested - the SACL was not returned. The account running this script most likely does not hold SeSecurityPrivilege ("Manage auditing and security log") on the domain controller, in which case the directory strips the SACL instead of reporting an error.'
            }
        }

        $appliedAuditing = @($descriptor.SystemAcl) | Select-Object *,
            @{N = 'AccessMaskDetails'; E = { (([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))).ToString() } },
            @{N = 'AuditFlagsValue'; E = { $_.AuditFlags.value__ } },
            @{N = 'AceFlagsValue'; E = { $_.AceFlags.value__ } }


        $properties = ($expectedAuditing | Get-Member -MemberType NoteProperty).Name
        $compareParams = @{
            ReferenceObject  = $expectedAuditing | Select-Object -Property $properties
            DifferenceObject = $appliedAuditing | Select-Object -Property $properties
            Property         = $properties
        }

        $return = [PSCustomObject]@{
            isAuditingOk = @(Compare-Object @compareParams -ExcludeDifferent -IncludeEqual).Count -eq $expectedAuditing.Count
            details      = $appliedAuditing
        }
    } catch {
        $e = $_
        $message = if ($e.Exception.InnerException.Message) { $e.Exception.InnerException.Message } else { $e.Exception.Message }
        # Reading a SACL needs SeSecurityPrivilege, which a non-administrative account does not hold, and
        # the directory can also be unreachable. Neither means the auditing is wrong, so those are
        # reported as unknown rather than as a misconfiguration. Only a genuine mismatch is a failure.
        $notMeasured = $e.Exception.InnerException.ErrorCode -eq -2147016656 -or
        $message -match 'access is denied|insufficient|privilege|server is not operational|referral|unavailable|credentials'
        $return = [PSCustomObject]@{
            isAuditingOk = if ($notMeasured) { 'N/A' } else { $false }
            details      = $message
        }
    } finally {
        # Cleanup must never throw. A DirectoryEntry binds lazily, so touching any member of one built
        # from a path that does not exist raises "There is no such object on the server" - and an
        # exception raised inside a finally replaces the real error and unwinds the caller.
        try { if ($searcher) { $searcher.Dispose() } } catch {}
        try { if ($searchRoot) { $searchRoot.Dispose() } } catch {}
    }
    $return
}

function Get-mdiObjectAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [int] $DomainSchemaVersion = 0
    )

    Write-mdiVerbose 'Getting MDI related DS Object auditing configuration'
    $expectedAuditing = $settings.ObjectAuditing | ConvertFrom-Csv | Select-Object SecurityIdentifier, AccessMask, AuditFlagsValue, InheritedObjectAceType

    # Remove the msDS-DelegatedManagedServiceAccount entry if the AD schema version is less than 90 (Windows Server 2025)
    if ($DomainSchemaVersion -lt 90) {
        $expectedAuditing = $expectedAuditing | Where-Object { $_.InheritedObjectAceType -ne '0feb936f-47b3-49f2-9386-1dedc2c23765' }
    }

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing

    # The tri-state from Get-mdiDsSacl must be honoured rather than recomputed from its details. When the
    # SACL could not be read - reading one needs SeSecurityPrivilege, which a non-admin does not have -
    # details holds an error string, the comparison below matches nothing, and the domain was reported as
    # having object auditing misconfigured. That fails the whole forest and puts a warning in the
    # Get-mdiExchangeAuditing and Get-mdiAdfsAuditing carry the same guard.
    if ([string] $result.isAuditingOk -eq 'N/A' -or $result.isAuditingOk -eq $false -and $result.details -is [string]) {
        return @{
            isObjectAuditingOk = 'N/A'
            details            = ('Not tested - the security descriptor of the domain root could not be read: {0}' -f [string] $result.details)
        }
    }

    $appliedAuditing = $result.details

    $isAuditingOk = @(foreach ($applied in $appliedAuditing) {
            $expectedAuditing | Where-Object { ($_.SecurityIdentifier -eq $applied.SecurityIdentifier) -and ($_.AuditFlagsValue -eq $applied.AuditFlagsValue) -and
                ($_.InheritedObjectAceType -eq $applied.InheritedObjectAceType) -and
                (([System.DirectoryServices.ActiveDirectoryRights]$applied.AccessMask).HasFlag(([System.DirectoryServices.ActiveDirectoryRights]($_.AccessMask)))) }
        }).Count -eq $expectedAuditing.Count

    $return = @{
        isObjectAuditingOk = $isAuditingOk
        details            = $result.details
    }
    $return
}

function Get-mdiExchangeAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [string] $DSAuditContainer = $null
    )

    Write-mdiVerbose 'Getting MDI related Exchange auditing configuration'

    $expectedAuditing = $settings.ExchangeAuditing | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)

    # The configuration naming context is read from rootDSE rather than assembled from the domain's own
    # naming context. It is forest-wide and lives under the FOREST ROOT, so 'CN=Configuration,' plus a
    # child domain's DN produced a path that does not exist - Exists() returned false and Exchange
    # auditing was silently reported as not applicable in every child domain.
    $configurationNc = [string] $ds.configurationNamingContext.Value
    if ([string]::IsNullOrWhiteSpace($configurationNc)) {
        return @{
            isExchangeAuditingOk = 'N/A'
            details              = 'Not tested - the configuration naming context could not be read from rootDSE'
        }
    }
    $exchangePath = 'LDAP://{0}/CN=Microsoft Exchange,CN=Services,{1}' -f $Domain, $configurationNc
    if ([System.DirectoryServices.DirectoryEntry]::Exists($exchangePath)) {

        $ldapPath = 'LDAP://{0}/{1}' -f $Domain, $configurationNc

        $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing

        # Both unreadable shapes are caught, not just 'N/A'. Get-mdiDsSacl also returns $false with a
        # STRING in details for an error it could not classify as access-denied, and the branch below
        # would then iterate over that error message as though it were a list of ACEs, match nothing,
        # and report Exchange auditing as misconfigured. Note 'N/A' -eq $false is FALSE in PowerShell
        # (the right operand is cast to the left's type, giving 'N/A' -eq 'False'), so the original
        # single test could never have caught it.
        if ([string] $result.isAuditingOk -eq 'N/A' -or
            ($result.isAuditingOk -eq $false -and $result.details -is [string])) {
            return @{
                isExchangeAuditingOk = 'N/A'
                details              = ('Not tested - the security descriptor of the configuration naming context could not be read: {0}' -f [string] $result.details)
            }
        }

        $appliedAuditing = $result.details
        $isAuditingOk = @(foreach ($applied in $appliedAuditing) {
                $expectedAuditing | Where-Object { ($_.SecurityIdentifier -eq $applied.SecurityIdentifier) -and ($_.AuditFlagsValue -eq $applied.AuditFlagsValue) -and
                    ($_.InheritedObjectAceType -eq $applied.InheritedObjectAceType) -and
                    (([System.DirectoryServices.ActiveDirectoryRights]$applied.AccessMask).HasFlag(([System.DirectoryServices.ActiveDirectoryRights]($_.AccessMask)))) }
            }).Count -eq @($expectedAuditing).Count
        $return = @{
            isExchangeAuditingOk = $isAuditingOk
            details              = $result.details
        }
    } else {
        $return = @{
            isExchangeAuditingOk = 'N/A'
            details              = 'Microsoft Exchange Services Configuration container not found'
        }
    }
    $return
}

function Get-mdiAdfsAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain
    )

    Write-mdiVerbose 'Getting MDI related ADFS auditing configuration'

    $expectedAuditing = $settings.ADFSAuditing | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://CN=ADFS,CN=Microsoft,CN=Program Data,{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing

    # Same guard as the other two: 'N/A' OR a $false carrying a string, which is an error message
    # rather than a list of ACEs. Without it an unclassified read failure was compared against the
    # expected auditing, matched nothing, and reported AD FS auditing as misconfigured.
    if ([string] $result.isAuditingOk -eq 'N/A' -or
        ($result.isAuditingOk -eq $false -and $result.details -is [string])) {
        # The reason is carried through rather than replaced. Every 'N/A' used to be reported as
        # "container not found", so an administrator whose account simply could not read the SACL
        # went looking for a container that was there all along.
        $return = @{
            isAdfsAuditingOk = 'N/A'
            details          = if ($result.details -is [string] -and -not [string]::IsNullOrWhiteSpace([string] $result.details)) {
                [string] $result.details
            } else {
                'Microsoft ADFS Program Data container not found'
            }
        }
    } else {
        $appliedAuditing = $result.details
        $isAuditingOk = @(foreach ($applied in $appliedAuditing) {
                $expectedAuditing | Where-Object { ($_.SecurityIdentifier -eq $applied.SecurityIdentifier) -and ($_.AuditFlagsValue -eq $applied.AuditFlagsValue) -and
                    ($_.InheritedObjectAceType -eq $applied.InheritedObjectAceType) -and
                    (([System.DirectoryServices.ActiveDirectoryRights]$applied.AccessMask).HasFlag(([System.DirectoryServices.ActiveDirectoryRights]($_.AccessMask)))) }
            }).Count -eq @($expectedAuditing).Count
        $return = @{
            isAdfsAuditingOk = $isAuditingOk
            details          = $result.details
        }
    }
    $return
}

function Get-DomainSchemaVersion {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain
    )
    $schemaVersions = @{
        13 = 'Windows 2000 Server'
        30 = 'Windows Server 2003'
        31 = 'Windows Server 2003 R2'
        44 = 'Windows Server 2008'
        47 = 'Windows Server 2008 R2'
        56 = 'Windows Server 2012'
        69 = 'Windows Server 2012 R2'
        87 = 'Windows Server 2016'
        88 = 'Windows Server 2019 / 2022'
        91 = 'Windows Server 2025'
    }

    Write-mdiVerbose 'Getting AD Schema Version'
    # Guarded because both callers evaluate this inside the report hashtable, which is built after the
    # whole forest scan, the port probes and the capacity sampling have finished. An LDAP failure here
    # threw out of the hashtable construction, so the report object was never assigned and nothing at
    # all was written - the entire run discarded at its most expensive point.
    # Bound to $Domain rather than the local rootDSE so that -Domain pointing at another forest reports
    # that forest's schema rather than this machine's.
    $rootDse = $null
    $schema = $null
    $schemaVersion = 0
    try {
        $rootDse = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ('LDAP://{0}/rootDSE' -f $Domain)
        $schemaNamingContext = [string] $rootDse.Properties['schemaNamingContext'].Value
        if ([string]::IsNullOrWhiteSpace($schemaNamingContext)) { throw 'the schema naming context was not returned' }

        $schema = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ('LDAP://{0}/{1}' -f $Domain, $schemaNamingContext)
        $value = $schema.Properties['objectVersion'].Value
        if ($null -ne $value) { $schemaVersion = [int] $value }
    } catch {
        Write-Warning ('Unable to read the Active Directory schema version of {0}: {1}' -f $Domain, ($_.Exception.Message -replace '[\r\n]+', ' '))
    } finally {
        # Guarded for the same reason as Get-mdiDsSacl: disposing a lazily bound DirectoryEntry can
        # throw, and a throw inside a finally would discard the whole run at this point.
        try { if ($schema) { $schema.Dispose() } } catch {}
        try { if ($rootDse) { $rootDse.Dispose() } } catch {}
    }

    $return = @{
        schemaVersion = $schemaVersion
        details       = $(if ($schemaVersion -gt 0) { $schemaVersions[$schemaVersion] } else { 'Not tested - the schema version could not be read' })
    }
    $return
}

function Test-mdiServerReachable {
    <#
        Decides whether a server is worth testing.

        ICMP alone is not a safe test: many environments block it by policy, and the script would then
        report every server as unavailable and skip every check, which looks like a healthy silent run
        rather than a failure. What the checks actually need is WMI, so a ping failure falls through to
        a TCP probe of the RPC endpoint mapper and then to a real WMI call. Ping is kept only because
        it is the cheapest positive answer.
    #>
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $false)] [int] $TimeoutMs = 3000
    )

    if (Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction SilentlyContinue) {
        return [PSCustomObject]@{ Reachable = $true; Method = 'ICMP' }
    }

    # TCP 135 is the RPC endpoint mapper, which every WMI call needs anyway
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($ComputerName, 135, $null, $null)
        $connected = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected
        if ($connected) { $client.EndConnect($async) }
        $client.Close()
        if ($connected) {
            return [PSCustomObject]@{ Reachable = $true; Method = 'TCP 135 (RPC), ICMP blocked' }
        }
    } catch {
        Write-mdiVerbose ('TCP 135 probe failed for {0}: {1}' -f $ComputerName, $_.Exception.Message)
    }

    # Last resort: the operation the checks themselves perform. Slower, but authoritative.
    try {
        $wmi = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -Property 'Caption' -ErrorAction Stop
        if ($wmi) {
            return [PSCustomObject]@{ Reachable = $true; Method = 'WMI, ICMP and TCP 135 blocked' }
        }
    } catch {
        Write-mdiVerbose ('WMI probe failed for {0}: {1}' -f $ComputerName, $_.Exception.Message)
    }

    [PSCustomObject]@{ Reachable = $false; Method = 'ICMP, TCP 135 and WMI all failed' }
}

function Get-mdiDomainControllerReadiness {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [string[]] $DomainController = $null,
        [Parameter(Mandatory = $false)] [object] $PortProbePlan = $null,
        [Parameter(Mandatory = $false)] [switch] $TestSensorV3Readiness,
        [Parameter(Mandatory = $false)] [object] $CapacityPlan = $null
    )

    if ([string]::IsNullOrEmpty($DomainController)) {
        Write-mdiVerbose "Searching for Domain Controllers in $Domain"
        $resolved = Resolve-mdiDomainController -Domain $Domain
        if ($resolved.Servers.Count -eq 0) {
            # A discovery failure is fatal to the whole report: every later check runs per server, so an
            # empty list silently produces a clean-looking report of nothing. It is raised rather than
            # swallowed so the run cannot be mistaken for a completed scan.
            Write-Warning ('Unable to enumerate the domain controllers of {0} over Active Directory Web Services or LDAP: {1}' -f $Domain, $resolved.Error)
            Write-Warning 'No domain controller was checked. Verify that this computer can reach a domain controller and that the account running the script is allowed to read the directory.'
            $DomainController = $null
        } else {
            $DomainController = @($resolved.Servers | Select-Object -ExpandProperty Name)
        }
    } else {
        Write-mdiVerbose "Using the provided list of Domain Controller(s)"
    }
    $dcs = @($DomainController | ForEach-Object {
            $dcName = [string] $_
            if ([string]::IsNullOrWhiteSpace($dcName)) { return }
            try {
                # The name is resolved to a directory object only when it is a FQDN. Get-ADObject returns
                # null when nothing matches, and passing null to -Identity is a parameter binding failure
                # that -ErrorAction SilentlyContinue cannot suppress and try/catch does not catch, so the
                # server would be dropped from the report without a word. The name is kept as the fallback
                # identity, and the FQDN is kept even when the directory lookup yields nothing, so a server
                # discovered over LDAP is still tested.
                $identity = $dcName
                if ($dcName -match '\w+\.\w+') {
                    $adObject = Get-ADObject -Filter { DNSHostName -eq $dcName } -Server $Domain -ErrorAction SilentlyContinue
                    if ($adObject) { $identity = $adObject }
                }

                $dcComputer = Get-ADComputer -Identity $identity -Server $Domain `
                    -Properties 'DNSHostName', 'IPv4Address', 'OperatingSystem' -ErrorAction SilentlyContinue

                $fqdn = if ($dcComputer -and $dcComputer.DNSHostName) { [string] $dcComputer.DNSHostName } else { $dcName }
                # IPv4Address holds ONE address even when the domain controller is multi-homed, so every
                # address it answers on is collected. A second NIC is reported rather than hidden: the
                # sensor captures on all interfaces and resolves whatever address it observes, so an
                # interface nobody knew about is an interface nobody firewalled or gave a reverse zone.
                $knownIp = if ($dcComputer) { [string] $dcComputer.IPv4Address } else { $null }
                $addresses = @(Get-mdiComputerAddress -ComputerName $fqdn -KnownAddress $knownIp)
                @{
                    FQDN      = $fqdn
                    IP        = if ($addresses.Count -gt 0) { $addresses[0] } else { $knownIp }
                    Addresses = $addresses
                    OS        = if ($dcComputer) { $dcComputer.OperatingSystem } else { $null }
                }
            } catch {
                Write-Verbose $_.Exception.Message
                # The server is still reported: it was discovered, so dropping it silently would hide it.
                @{ FQDN = $dcName; IP = $null; Addresses = @(); OS = $null }
            }
        })
    Write-mdiVerbose "Found $($dcs.Count) Domain Controller(s)"

    # Capacity sampling happens up front for every reachable domain controller at once. Done inside the
    # loop below it would run one server at a time, so the wall-clock cost grew with the size of the
    # forest and no two servers were measured over the same period.
    $capacitySamples = @{}
    if ($CapacityPlan) {
        $reachable = @($dcs | Where-Object { $_.FQDN -and (Test-mdiServerReachable -ComputerName $_.FQDN).Reachable } |
                ForEach-Object { $_.FQDN })
        if ($reachable.Count -gt 0) {
            Write-mdiVerbose ('Sampling network traffic on {0} domain controller(s) in parallel for {1}s at {2}s intervals' -f
                $reachable.Count, $CapacityPlan.DurationSeconds, $CapacityPlan.IntervalSeconds)
            $capacitySamples = Get-mdiTrafficSampleSet -ComputerName $reachable `
                -DurationSeconds $CapacityPlan.DurationSeconds -IntervalSeconds $CapacityPlan.IntervalSeconds `
                -MaxParallel $settings.CapacityPlanning.MaxParallelSamples
        }
    }

    foreach ($dc in $dcs) {

        # The domain is recorded on every server. In a forest scan the report merged all the domains
        # into one table, so there was no way to tell which domain a server belonged to, and no way for
        # the verdict to notice that a domain in scope had contributed no servers at all - which is what
        # an unreachable or unenumerable domain looks like from here.
        $dc['Domain'] = $Domain

        # Declared before the branch so an unreachable server does not inherit the previous server's
        # details, and reset per server so nothing leaks between iterations.
        $details = [ordered]@{}
        $reach = Test-mdiServerReachable -ComputerName $dc.FQDN
        if ($reach.Reachable) {
            # Every check for one server runs inside a try: a single server that answers reachability and
            # then fails a check - a stopped Remote Registry service, a revoked permission, a reboot part
            # way through - used to abort the whole forest scan and leave no report at all. One bad server
            # must cost its own results, not everyone else's.
            try {
            Write-mdiVerbose "Testing server requirements for $($dc.FQDN)"
            $serverRequirements = Get-mdiServerRequirements -ComputerName $dc.FQDN
            $dc.Add('ServerRequirements', $serverRequirements.isMinHwRequirementsOk)
            $details.Add('ServerRequirementsDetails', $serverRequirements.details)

            Write-mdiVerbose "Testing power settings for $($dc.FQDN)"
            $powerSettings = Get-mdiPowerScheme -ComputerName $dc.FQDN
            $dc.Add('PowerSettings', $powerSettings.isPowerSchemeOk)
            $details.Add('PowerSettingsDetails', $powerSettings.details)

            Write-mdiVerbose "Testing advanced auditing for $($dc.FQDN)"
            $advancedAuditing = Get-mdiAdvancedAuditing -ComputerName $dc.FQDN -ExpectedAuditing $settings.AdvancedAuditPolicyDCs
            $dc.Add('AdvancedAuditing', $advancedAuditing.isAdvancedAuditingOk)
            $details.Add('AdvancedAuditingDetails', $advancedAuditing.details)

            Write-mdiVerbose "Testing NTLM auditing for $($dc.FQDN)"
            $ntlmAuditing = Get-mdiNtlmAuditing -ComputerName $dc.FQDN
            $dc.Add('NtlmAuditing', $ntlmAuditing.isNtlmAuditingOk)
            $details.Add('NtlmAuditingDetails', $ntlmAuditing.details)

            Write-mdiVerbose "Testing certificates readiness for $($dc.FQDN)"
            $certificates = Get-mdiCertReadiness -ComputerName $dc.FQDN
            $dc.Add('RootCertificates', $certificates.isRootCertificatesOk)
            $details.Add('RootCertificatesDetails', $certificates.details)

            Write-mdiVerbose "Testing MDI sensor for $($dc.FQDN)"
            $sensorVersion = Get-mdiSensorVersion -ComputerName $dc.FQDN
            $dc.Add('SensorVersion', $sensorVersion)

            Write-mdiVerbose "Testing capturing component for $($dc.FQDN)"
            $capComponent = Get-mdiCaptureComponent -ComputerName $dc.FQDN
            $dc.Add('CapturingComponent', $capComponent)

            Write-mdiVerbose "Getting virtualization platform for $($dc.FQDN)"
            $machineType = Get-mdiMachineType -ComputerName $dc.FQDN
            $dc.Add('MachineType', $machineType)

            Write-mdiVerbose "Getting Operating System for $($dc.FQDN)"
            $osVer = Get-mdiOSVersion -ComputerName $dc.FQDN
            $dc.Add('OSVersion', $osVer.isOsVerOk)
            $details.Add('OSVersionDetails', $osVer.details)

            if ($PortProbePlan) {
                Write-mdiVerbose "Testing required network ports for $($dc.FQDN)"
                $requiredPorts = Get-mdiRequiredPorts -ComputerName $dc.FQDN -Plan $PortProbePlan
                $dc.Add('RequiredPorts', $requiredPorts.isRequiredPortsOk)
                $details.Add('RequiredPortsDetails', $requiredPorts.details)
            }

            Write-mdiVerbose "Testing sensor health for $($dc.FQDN)"
            $sensorHealth = Get-mdiSensorHealth -ComputerName $dc.FQDN
            # 'N/A' is recorded rather than the property being omitted, but ONLY when the check could
            # not be measured. Omitting it made the gap invisible: it vanished from ChecksTotal and
            # from the unread count, so a server whose sensor health could not be read scored exactly
            # like one with no sensor health problem, and a baseline taken then compared as "unchanged".
            # The two meanings of 'N/A' are told apart by Installed - 'N/A' when WMI could not be
            # queried (a real gap), $false when no sensor is installed (legitimate before deployment,
            # and not something to report as unverified).
            if ([string] $sensorHealth.isSensorHealthOk -ne 'N/A') {
                $dc.Add('SensorHealth', $sensorHealth.isSensorHealthOk)
            } elseif ([string] $sensorHealth.details.Installed -eq 'N/A') {
                $dc.Add('SensorHealth', 'N/A')
            }
            $details.Add('SensorHealthDetails', $sensorHealth.details)

            Write-mdiVerbose "Testing time synchronization for $($dc.FQDN)"
            $timeSync = Get-mdiTimeSync -ComputerName $dc.FQDN -MaxSkewMinutes $MaxClockSkewMinutes
            $dc.Add('TimeSync', $timeSync.isTimeSyncOk)
            $details.Add('TimeSyncDetails', $timeSync.details)

            if ($TestSensorV3Readiness) {
                Write-mdiVerbose "Testing sensor v3.x upgrade readiness for $($dc.FQDN)"
                $sensorV3 = Get-mdiSensorV3Readiness -ComputerName $dc.FQDN -SensorVersion $sensorVersion
                $dc.Add('SensorV3Ready', $sensorV3.isSensorV3Ready)
                $details.Add('SensorV3ReadyDetails', $sensorV3.details)
            }

            # Capacity planning applies to domain controllers only: 'There is no need to run it against servers that
            # are only AD FS, AD CS, or Entra Connect'
            if ($CapacityPlan) {
                Write-mdiVerbose "Estimating sensor capacity for $($dc.FQDN)"
                $capacity = Get-mdiCapacityPlanning -ComputerName $dc.FQDN `
                    -DurationSeconds $CapacityPlan.DurationSeconds -IntervalSeconds $CapacityPlan.IntervalSeconds `
                    -TrafficSample $capacitySamples[[string] $dc.FQDN]
                # Capacity is only evaluated when the caller asked for it, and every 'N/A' it can
                # return means "could not read the hardware or the counters" - never "not applicable".
                # Omitting the property hid that failure from the score entirely, so an unsizeable
                # server counted as sized.
                $dc.Add('CapacitySufficient', $capacity.isCapacityOk)
                $details.Add('CapacityDetails', $capacity.details)
            }

            } catch {
                # The checks completed before the failure are kept, so a partial result is still reported
                # rather than the server vanishing from the output entirely. PartialFailure separates this
                # from "never answered": both leave a Comment, but only one destroys the results.
                if (-not $dc.Contains('Comment')) {
                    $dc.Add('Comment', ('Testing stopped early: {0}' -f $_.Exception.Message))
                }
                $dc['PartialFailure'] = $true
                Write-Warning ('Could not finish testing {0}: {1}' -f $dc.FQDN, $_.Exception.Message)
            }

        } else {
            $dc.Add('Comment', ('Server is not available: {0}' -f $reach.Method))
            $dc['Unreachable'] = $true
            Write-Warning ('{0} is not available ({1}). If ICMP is blocked by policy, the fallbacks over TCP 135 and WMI also failed, so the server genuinely cannot be tested from here.' -f $dc.FQDN, $reach.Method)
        }

        if (-not $dc.Contains('PartialFailure')) { $dc.Add('PartialFailure', $false) }
        if (-not $dc.Contains('Unreachable')) { $dc.Add('Unreachable', $false) }
        $dc.Add('Details', $details)
        [PSCustomObject]$dc
    }
}

function Get-mdiCAReadiness {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [string[]] $CAServer = $null,
        [Parameter(Mandatory = $false)] [object] $PortProbePlan = $null,
        [Parameter(Mandatory = $false)] [switch] $TestSensorV3Readiness
    )

    if ([string]::IsNullOrEmpty($CAServer)) {
        Write-mdiVerbose "Searching for CA servers in $Domain"
        try {
            # -Server $Domain on both calls: Get-mdiCAReadiness runs once per domain in the forest, and
            # without it the SID of the domain running the script was looked up in a different domain,
            # so a child domain's certification authorities were never scanned.
            $CertPublishersSID = $((Get-ADDomain -Server $Domain).DomainSID.Value + "-517")
            $CAServer = Get-ADGroupMember -Server $Domain -Identity $CertPublishersSID -ErrorAction Stop | Where-Object { $_.objectClass -eq 'computer' }
        } catch {
            $CAServer = $null
        }
    } else {
        Write-mdiVerbose "Using the provided list of CA server(s)"
    }
    # Piping $null into ForEach-Object still runs the body once with $_ set to $null, and
    # Get-ADComputer -Identity $null raises a parameter binding error that -ErrorAction cannot
    # suppress and try/catch does not intercept. Empty entries are therefore removed first.
    $cas = @($CAServer | Where-Object { $_ } | ForEach-Object {
            $caName = [string] $_
            try {
                $caComputer = Get-ADComputer -Identity $_ -Server $Domain -Properties DNSHostName, IPv4Address, OperatingSystem -ErrorAction SilentlyContinue
                # The discovered name is kept when the directory lookup returns nothing. A null FQDN was
                # passed to Test-mdiServerReachable, whose -ComputerName is a mandatory [string], and the
                # resulting parameter binding error is terminating, not catchable, and raised outside the
                # try below - so one stale member of Cert Publishers removed every CA from the report.
                $caFqdn = if ($caComputer -and $caComputer.DNSHostName) { [string] $caComputer.DNSHostName } else { $caName }
                # Every address, as for domain controllers: a certification authority can be multi-homed
                # too, and the generated firewall rules scope by source address.
                $caKnownIp = if ($caComputer) { [string] $caComputer.IPv4Address } else { $null }
                $caAddresses = @(Get-mdiComputerAddress -ComputerName $caFqdn -KnownAddress $caKnownIp)
                @{
                    FQDN      = $caFqdn
                    IP        = if ($caAddresses.Count -gt 0) { $caAddresses[0] } else { $caKnownIp }
                    Addresses = $caAddresses
                    OS        = if ($caComputer) { $caComputer.OperatingSystem } else { $null }
                }
            } catch {
                Write-Verbose $_.Exception.Message
                @{ FQDN = $caName; IP = $null; Addresses = @(); OS = $null }
            }
        } | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_.FQDN) })
    Write-mdiVerbose "Found $($cas.Count) CA server(s)"

    foreach ($ca in $cas) {

        $ca['Domain'] = $Domain

        # Declared before the branch so an unreachable server does not inherit the previous server's details.
        $details = [ordered]@{}
        $reach = Test-mdiServerReachable -ComputerName $ca.FQDN
        if ($reach.Reachable) {
            # Wrapped for the same reason as the domain controller loop: one server failing a check part
            # way through must not abort the scan of every other server.
            try {

            Write-mdiVerbose "Testing server requirements for $($ca.FQDN)"
            $serverRequirements = Get-mdiServerRequirements -ComputerName $ca.FQDN
            $ca.Add('ServerRequirements', $serverRequirements.isMinHwRequirementsOk)
            $details.Add('ServerRequirementsDetails', $serverRequirements.details)

            Write-mdiVerbose "Testing power settings for $($ca.FQDN)"
            $powerSettings = Get-mdiPowerScheme -ComputerName $ca.FQDN
            $ca.Add('PowerSettings', $powerSettings.isPowerSchemeOk)
            $details.Add('PowerSettingsDetails', $powerSettings.details)

            Write-mdiVerbose "Testing advanced auditing for $($ca.FQDN)"
            $advancedAuditingCA = Get-mdiAdvancedAuditing -ComputerName $ca.FQDN -ExpectedAuditing $settings.AdvancedAuditPolicyCAs
            $ca.Add('AdvancedAuditingCA', $advancedAuditingCA.isAdvancedAuditingOk)
            $details.Add('AdvancedAuditingCADetails', $advancedAuditingCA.details)

            Write-mdiVerbose "Testing CA auditing for $($ca.FQDN)"
            $caAuditing = Get-mdiCAAuditing -ComputerName $ca.FQDN
            $ca.Add('CAAuditing', $caAuditing.isCaAuditingOk)
            $details.Add('CAAuditingDetails', $caAuditing.details)

            Write-mdiVerbose "Testing certificates readiness for $($ca.FQDN)"
            $certificates = Get-mdiCertReadiness -ComputerName $ca.FQDN
            $ca.Add('RootCertificates', $certificates.isRootCertificatesOk)
            $details.Add('RootCertificatesDetails', $certificates.details)

            Write-mdiVerbose "Testing MDI sensor for $($ca.FQDN)"
            $sensorVersion = Get-mdiSensorVersion -ComputerName $ca.FQDN
            $ca.Add('SensorVersion', $sensorVersion)

            Write-mdiVerbose "Testing capturing component for $($ca.FQDN)"
            $capComponent = Get-mdiCaptureComponent -ComputerName $ca.FQDN
            $ca.Add('CapturingComponent', $capComponent)

            Write-mdiVerbose "Getting virtualization platform for $($ca.FQDN)"
            $machineType = Get-mdiMachineType -ComputerName $ca.FQDN
            $ca.Add('MachineType', $machineType)

            Write-mdiVerbose "Getting Operating System for $($ca.FQDN)"
            $osVer = Get-mdiOSVersion -ComputerName $ca.FQDN
            $ca.Add('OSVersion', $osVer.isOsVerOk)
            $details.Add('OSVersionDetails', $osVer.details)

            if ($PortProbePlan) {
                Write-mdiVerbose "Testing required network ports for $($ca.FQDN)"
                $requiredPorts = Get-mdiRequiredPorts -ComputerName $ca.FQDN -Plan $PortProbePlan
                $ca.Add('RequiredPorts', $requiredPorts.isRequiredPortsOk)
                $details.Add('RequiredPortsDetails', $requiredPorts.details)
            }

            Write-mdiVerbose "Testing sensor health for $($ca.FQDN)"
            $sensorHealth = Get-mdiSensorHealth -ComputerName $ca.FQDN
            if ([string] $sensorHealth.isSensorHealthOk -ne 'N/A') {
                $ca.Add('SensorHealth', $sensorHealth.isSensorHealthOk)
            } elseif ([string] $sensorHealth.details.Installed -eq 'N/A') {
                $ca.Add('SensorHealth', 'N/A')
            }
            $details.Add('SensorHealthDetails', $sensorHealth.details)

            Write-mdiVerbose "Testing time synchronization for $($ca.FQDN)"
            $timeSync = Get-mdiTimeSync -ComputerName $ca.FQDN -MaxSkewMinutes $MaxClockSkewMinutes
            $ca.Add('TimeSync', $timeSync.isTimeSyncOk)
            $details.Add('TimeSyncDetails', $timeSync.details)

            if ($TestSensorV3Readiness) {
                Write-mdiVerbose "Testing sensor v3.x upgrade readiness for $($ca.FQDN)"
                $sensorV3 = Get-mdiSensorV3Readiness -ComputerName $ca.FQDN -SensorVersion $sensorVersion
                $ca.Add('SensorV3Ready', $sensorV3.isSensorV3Ready)
                $details.Add('SensorV3ReadyDetails', $sensorV3.details)
            }

            } catch {
                if (-not $ca.Contains('Comment')) {
                    $ca.Add('Comment', ('Testing stopped early: {0}' -f $_.Exception.Message))
                }
                $ca['PartialFailure'] = $true
                Write-Warning ('Could not finish testing {0}: {1}' -f $ca.FQDN, $_.Exception.Message)
            }

        } else {
            $ca.Add('Comment', ('Server is not available: {0}' -f $reach.Method))
            $ca['Unreachable'] = $true
            Write-Warning ('{0} is not available ({1}). If ICMP is blocked by policy, the fallbacks over TCP 135 and WMI also failed, so the server genuinely cannot be tested from here.' -f $ca.FQDN, $reach.Method)
        }

        if (-not $ca.Contains('PartialFailure')) { $ca.Add('PartialFailure', $false) }
        if (-not $ca.Contains('Unreachable')) { $ca.Add('Unreachable', $false) }
        $ca.Add('Details', $details)
        [PSCustomObject]$ca
    }
}

function Get-mdiEntraConnectReadiness {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [string[]] $EntraConnectServer = $null,
        [Parameter(Mandatory = $false)] [object] $PortProbePlan = $null,
        [Parameter(Mandatory = $false)] [switch] $TestSensorV3Readiness
    )

    if ([string]::IsNullOrEmpty($EntraConnectServer)) {
        Write-mdiVerbose "Searching for Entra Connect servers in $Domain"
        try {
            # -Server $Domain on both queries: this function runs once per domain in the forest, and
            # without it every iteration searched the machine's own domain, so a child domain's Entra
            # Connect servers were never found and the root domain's were reported repeatedly.
            #
            # The server name is extracted by pattern rather than by a fixed character offset. The
            # previous Substring(142, ...) assumed an exact English description string; a different
            # locale, a longer tenant name or any wording change in a future build silently produced no
            # servers at all, which is indistinguishable from "there are none".
            $EntraConnectServer = @(Get-ADUser -LDAPFilter '(description=*configured to synchronize to tenant*)' `
                    -Properties description -Server $Domain -ErrorAction Stop | ForEach-Object {
                    $desc = [string] $_.description
                    # The description names the source server as "on computer <NAME>" in current builds,
                    # and older ones spell it "installed on <NAME>". Both are tried, then a bare NetBIOS
                    # style token as a last resort.
                    $candidate = $null
                    # The wording varies across releases and locales, and at least one Entra Connect build
                    # writes "running o<NAME>" with the "n" of "on" missing - confirmed by reading the raw
                    # attribute in a live directory, where the characters are 'g',' ','o','A','A','D','C'.
                    # That defect is almost certainly why the original code parsed by character offset.
                    # The optional 'n' covers both spellings; the tenant clause is never matched, so a
                    # tenant name cannot be mistaken for a server name.
                    foreach ($pattern in 'running on? ?([A-Za-z0-9\-_]{1,63})\s+configured', 'running on? ?([A-Za-z0-9\-_]{1,63})\s',
                        'on computer ([A-Za-z0-9\-_]{1,63})', 'installed on ([A-Za-z0-9\-_]{1,63})') {
                        $m = [regex]::Match($desc, $pattern)
                        if ($m.Success) { $candidate = $m.Groups[1].Value; break }
                    }
                    if (-not $candidate) {
                        Write-mdiVerbose ('Could not read the Entra Connect server name from the account description: {0}' -f ($desc -replace '[\r\n]+', ' '))
                        return
                    }
                    try { (Get-ADComputer -Identity $candidate -Server $Domain -ErrorAction Stop).distinguishedName } catch {
                        Write-mdiVerbose ('The Entra Connect server {0} named in an account description does not resolve in {1}' -f $candidate, $Domain)
                    }
                })
        } catch {
            $EntraConnectServer = $null
        }
    } else {
        Write-mdiVerbose "Using the provided list of Entra Connect server(s)"
    }
    # Same null guard as the CA discovery above: an empty result must not reach -Identity.
    $ecs = @($EntraConnectServer | Where-Object { $_ } | ForEach-Object {
            $ecName = [string] $_
            try {
                $ecsComputer = Get-ADComputer -Identity $_ -Server $Domain -Properties DNSHostName, IPv4Address, OperatingSystem -ErrorAction SilentlyContinue
                $ecFqdn = if ($ecsComputer -and $ecsComputer.DNSHostName) { [string] $ecsComputer.DNSHostName } else { $ecName }
                $ecKnownIp = if ($ecsComputer) { [string] $ecsComputer.IPv4Address } else { $null }
                $ecAddresses = @(Get-mdiComputerAddress -ComputerName $ecFqdn -KnownAddress $ecKnownIp)
                @{
                    FQDN      = $ecFqdn
                    IP        = if ($ecAddresses.Count -gt 0) { $ecAddresses[0] } else { $ecKnownIp }
                    Addresses = $ecAddresses
                    OS        = if ($ecsComputer) { $ecsComputer.OperatingSystem } else { $null }
                }
            } catch {
                Write-Verbose $_.Exception.Message
                @{ FQDN = $ecName; IP = $null; Addresses = @(); OS = $null }
            }
        } | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_.FQDN) })
    Write-mdiVerbose "Found $($ecs.Count) Entra Connect server(s)"

    foreach ($ec in $ecs) {

        $ec['Domain'] = $Domain

        # Declared before the branch so an unreachable server does not inherit the previous server's details.
        $details = [ordered]@{}
        $reach = Test-mdiServerReachable -ComputerName $ec.FQDN
        if ($reach.Reachable) {
            # Wrapped for the same reason as the domain controller loop: one server failing a check part
            # way through must not abort the scan of every other server.
            try {

            Write-mdiVerbose "Testing server requirements for $($ec.FQDN)"
            $serverRequirements = Get-mdiServerRequirements -ComputerName $ec.FQDN
            $ec.Add('ServerRequirements', $serverRequirements.isMinHwRequirementsOk)
            $details.Add('ServerRequirementsDetails', $serverRequirements.details)

            Write-mdiVerbose "Testing power settings for $($ec.FQDN)"
            $powerSettings = Get-mdiPowerScheme -ComputerName $ec.FQDN
            $ec.Add('PowerSettings', $powerSettings.isPowerSchemeOk)
            $details.Add('PowerSettingsDetails', $powerSettings.details)

            Write-mdiVerbose "Testing advanced auditing for $($ec.FQDN)"
            $AdvancedAuditingEntraConnect = Get-mdiAdvancedAuditing -ComputerName $ec.FQDN -ExpectedAuditing $settings.AdvancedAuditPolicyEntraConnect
            $ec.Add('AdvancedAuditingEntraConnect', $AdvancedAuditingEntraConnect.isAdvancedAuditingOk)
            $details.Add('AdvancedAuditingEntraConnectDetails', $AdvancedAuditingEntraConnect.details)

            Write-mdiVerbose "Testing MDI sensor for $($ec.FQDN)"
            $sensorVersion = Get-mdiSensorVersion -ComputerName $ec.FQDN
            $ec.Add('SensorVersion', $sensorVersion)

            Write-mdiVerbose "Testing capturing component for $($ec.FQDN)"
            $capComponent = Get-mdiCaptureComponent -ComputerName $ec.FQDN
            $ec.Add('CapturingComponent', $capComponent)

            Write-mdiVerbose "Getting virtualization platform for $($ec.FQDN)"
            $machineType = Get-mdiMachineType -ComputerName $ec.FQDN
            $ec.Add('MachineType', $machineType)

            Write-mdiVerbose "Getting Operating System for $($ec.FQDN)"
            $osVer = Get-mdiOSVersion -ComputerName $ec.FQDN
            $ec.Add('OSVersion', $osVer.isOsVerOk)
            $details.Add('OSVersionDetails', $osVer.details)

            if ($PortProbePlan) {
                Write-mdiVerbose "Testing required network ports for $($ec.FQDN)"
                $requiredPorts = Get-mdiRequiredPorts -ComputerName $ec.FQDN -Plan $PortProbePlan
                $ec.Add('RequiredPorts', $requiredPorts.isRequiredPortsOk)
                $details.Add('RequiredPortsDetails', $requiredPorts.details)
            }

            Write-mdiVerbose "Testing sensor health for $($ec.FQDN)"
            $sensorHealth = Get-mdiSensorHealth -ComputerName $ec.FQDN
            if ([string] $sensorHealth.isSensorHealthOk -ne 'N/A') {
                $ec.Add('SensorHealth', $sensorHealth.isSensorHealthOk)
            } elseif ([string] $sensorHealth.details.Installed -eq 'N/A') {
                $ec.Add('SensorHealth', 'N/A')
            }
            $details.Add('SensorHealthDetails', $sensorHealth.details)

            Write-mdiVerbose "Testing time synchronization for $($ec.FQDN)"
            $timeSync = Get-mdiTimeSync -ComputerName $ec.FQDN -MaxSkewMinutes $MaxClockSkewMinutes
            $ec.Add('TimeSync', $timeSync.isTimeSyncOk)
            $details.Add('TimeSyncDetails', $timeSync.details)

            if ($TestSensorV3Readiness) {
                Write-mdiVerbose "Testing sensor v3.x upgrade readiness for $($ec.FQDN)"
                $sensorV3 = Get-mdiSensorV3Readiness -ComputerName $ec.FQDN -SensorVersion $sensorVersion
                $ec.Add('SensorV3Ready', $sensorV3.isSensorV3Ready)
                $details.Add('SensorV3ReadyDetails', $sensorV3.details)
            }

            } catch {
                if (-not $ec.Contains('Comment')) {
                    $ec.Add('Comment', ('Testing stopped early: {0}' -f $_.Exception.Message))
                }
                $ec['PartialFailure'] = $true
                Write-Warning ('Could not finish testing {0}: {1}' -f $ec.FQDN, $_.Exception.Message)
            }

        } else {
            $ec.Add('Comment', ('Server is not available: {0}' -f $reach.Method))
            $ec['Unreachable'] = $true
            Write-Warning ('{0} is not available ({1}). If ICMP is blocked by policy, the fallbacks over TCP 135 and WMI also failed, so the server genuinely cannot be tested from here.' -f $ec.FQDN, $reach.Method)
        }

        if (-not $ec.Contains('PartialFailure')) { $ec.Add('PartialFailure', $false) }
        if (-not $ec.Contains('Unreachable')) { $ec.Add('Unreachable', $false) }
        $ec.Add('Details', $details)
        [PSCustomObject]$ec
    }
}

function ConvertTo-mdiHtmlEncoded {
    param ([Parameter(Mandatory = $false)] [AllowNull()] [string] $Text)
    if ($null -eq $Text) { return '' }
    $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
}

function ConvertTo-mdiFriendlyName {
    param ([Parameter(Mandatory = $false)] [AllowNull()] [string] $Name)
    if ([string]::IsNullOrEmpty($Name)) { return '' }
    # Split camel case without breaking acronyms apart: 'OSVersion' becomes 'OS Version', not 'O S Version'
    $text = [regex]::Replace($Name, '(?<=[a-z0-9])([A-Z])', ' $1')
    $text = [regex]::Replace($text, '(?<=[A-Z])([A-Z][a-z])', ' $1')
    foreach ($acronym in @('NTLM', 'LDAP', 'DNS', 'RPC', 'RDP', 'NNR', 'SAM', 'VPN', 'DSA', 'ADFS', 'ADCS', 'CA', 'OS')) {
        $text = [regex]::Replace($text, '\b' + $acronym + '\b', $acronym, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $text
}

function ConvertTo-mdiSvgNumber {
    param (
        [Parameter(Mandatory = $true)] [double] $Value,
        [Parameter(Mandatory = $false)] [int] $Decimals = 2
    )
    # SVG and CSS require a dot as the decimal separator. Without an invariant culture the report breaks on
    # machines using a comma as the decimal separator (for example it-IT, de-DE or fr-FR).
    $Value.ToString('F' + $Decimals, [System.Globalization.CultureInfo]::InvariantCulture)
}

function New-mdiDonutChart {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Segment,
        [Parameter(Mandatory = $false)] [string] $CenterValue = '',
        [Parameter(Mandatory = $false)] [string] $CenterLabel = '',
        [Parameter(Mandatory = $false)] [int] $Size = 170
    )

    # Segments are drawn as dashed strokes on concentric circles rather than as arc paths: the maths stays trivial
    # and there are no large-arc or sweep-flag edge cases when a single segment covers the whole circle.
    $total = 0
    foreach ($s in $Segment) { $total += [double] $s.Value }

    $strokeWidth = [math]::Round($Size * 0.17)
    $radius = ($Size - $strokeWidth) / 2
    $center = $Size / 2
    $circumference = 2 * [math]::PI * $radius

    $cText = ConvertTo-mdiSvgNumber $center
    $rText = ConvertTo-mdiSvgNumber $radius
    $circText = ConvertTo-mdiSvgNumber $circumference

    $parts = New-Object -TypeName System.Collections.ArrayList
    [void] $parts.Add('<svg class="donut" viewBox="0 0 ' + $Size + ' ' + $Size + '" role="img">')
    [void] $parts.Add('<circle class="donut-track" cx="' + $cText + '" cy="' + $cText + '" r="' + $rText +
        '" fill="none" stroke-width="' + $strokeWidth + '"/>')

    if ($total -gt 0) {
        $offset = 0.0
        foreach ($s in $Segment) {
            $value = [double] $s.Value
            if ($value -le 0) { continue }
            $length = ($value / $total) * $circumference
            $dash = (ConvertTo-mdiSvgNumber $length) + ' ' + (ConvertTo-mdiSvgNumber ($circumference - $length))
            [void] $parts.Add('<circle cx="' + $cText + '" cy="' + $cText + '" r="' + $rText + '" fill="none" stroke="' +
                [string] $s.Color + '" stroke-width="' + $strokeWidth + '" stroke-dasharray="' + $dash +
                '" stroke-dashoffset="' + (ConvertTo-mdiSvgNumber (-$offset)) +
                '" transform="rotate(-90 ' + $cText + ' ' + $cText + ')" stroke-linecap="butt">' +
                '<title>' + (ConvertTo-mdiHtmlEncoded ([string] $s.Label)) + ': ' + $value + '</title></circle>')
            $offset += $length
        }
    }

    if ($CenterValue) {
        [void] $parts.Add('<text class="donut-value" x="' + $cText + '" y="' + (ConvertTo-mdiSvgNumber ($center + 2)) +
            '" text-anchor="middle" dominant-baseline="middle">' + (ConvertTo-mdiHtmlEncoded $CenterValue) + '</text>')
    }
    if ($CenterLabel) {
        [void] $parts.Add('<text class="donut-label" x="' + $cText + '" y="' + (ConvertTo-mdiSvgNumber ($center + $Size * 0.155)) +
            '" text-anchor="middle" dominant-baseline="middle">' + (ConvertTo-mdiHtmlEncoded $CenterLabel) + '</text>')
    }
    [void] $parts.Add('</svg>')

    $legend = New-Object -TypeName System.Collections.ArrayList
    [void] $legend.Add('<ul class="legend">')
    foreach ($s in $Segment) {
        [void] $legend.Add('<li><span class="swatch" style="background:' + [string] $s.Color + '"></span>' +
            (ConvertTo-mdiHtmlEncoded ([string] $s.Label)) + '<b>' + [int] $s.Value + '</b></li>')
    }
    [void] $legend.Add('</ul>')

    '<div class="donut-wrap">' + ($parts.ToArray() -join '') + ($legend.ToArray() -join '') + '</div>'
}

function New-mdiBarChart {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Bar,
        [Parameter(Mandatory = $false)] [string] $EmptyMessage = 'No data'
    )

    if (@($Bar).Count -eq 0) { return '<p class="muted">' + (ConvertTo-mdiHtmlEncoded $EmptyMessage) + '</p>' }

    $rows = New-Object -TypeName System.Collections.ArrayList
    [void] $rows.Add('<div class="barchart">')
    foreach ($b in $Bar) {
        $total = [double] $b.Total
        $value = [double] $b.Value
        $pct = if ($total -gt 0) { ($value / $total) * 100 } else { 0 }
        $tone = if ($pct -ge 100) { 'ok' } elseif ($pct -ge 50) { 'warn' } elseif ($pct -gt 0) { 'warn' } else { 'bad' }
        if ($total -le 0) { $tone = 'na' }
        # The format operator is used instead of concatenation: '[int]$value + "/"' would evaluate left to right and
        # try to convert "/" to an integer.
        $caption = if ($total -gt 0) {
            '{0}/{1} ({2}%)' -f [int] $value, [int] $total, [int] [math]::Round($pct)
        } else { 'n/a' }
        [void] $rows.Add('<div class="bar-row"><div class="bar-label" title="' + (ConvertTo-mdiHtmlEncoded ([string] $b.Hint)) + '">' +
            (ConvertTo-mdiHtmlEncoded ([string] $b.Label)) + '</div>' +
            '<div class="bar-track"><div class="bar-fill ' + $tone + '" style="width:' + (ConvertTo-mdiSvgNumber $pct 1) + '%"></div></div>' +
            '<div class="bar-value">' + $caption + '</div></div>')
    }
    [void] $rows.Add('</div>')
    $rows.ToArray() -join ''
}

function Get-mdiReportStatistics {
    param (
        [Parameter(Mandatory = $true)] [object] $ReportData
    )

    # Each collection is wrapped separately: a domain with exactly one server exposes the property as a
    # bare PSObject, and PSObject + PSObject throws "does not contain a method named op_Addition".
    $allServers = @(@($ReportData.DomainControllers) + @($ReportData.CAServers) + @($ReportData.EntraConnectServers) |
            Where-Object { $_ })
    # Reachability is decided by the explicit flag, not by whether a Comment exists. A server that was
    # reached and then failed one check part way through also carries a Comment, and counting it as
    # unreachable discarded every result it had already produced.
    $reachable = @($allServers | Where-Object { -not $_.Unreachable })
    $unreachable = @($allServers | Where-Object { $_.Unreachable })

    # Every boolean property on a server object is a readiness check, so the score works for domain controllers,
    # CA servers and Entra Connect servers alike without hard-coding the individual check names.
    $serverScores = @(foreach ($srv in $reachable) {
            $bools = Get-mdiCheckProperty -Server $srv
            $passed = @($bools | Where-Object { $_.Value }).Count
            # Checks that returned 'N/A' were not measured. They are counted separately so the report can
            # say how much of the estate it actually managed to look at: a run where almost nothing was
            # readable produced a perfect "5/5 checks passed" headline, which is the most misleading
            # output this tool can produce.
            $unread = Get-mdiUnreadCheckCount -Server $srv
            [PSCustomObject]@{
                FQDN     = [string] $srv.FQDN
                Passed   = $passed
                Total    = $bools.Count
                Failed   = $bools.Count - $passed
                Unread   = $unread
            }
        })

    $checkTotals = @{}
    foreach ($srv in $reachable) {
        foreach ($prop in (Get-mdiCheckProperty -Server $srv)) {
            if (-not $checkTotals.ContainsKey($prop.Name)) { $checkTotals[$prop.Name] = @{ Pass = 0; Total = 0 } }
            $checkTotals[$prop.Name].Total++
            if ($prop.Value) { $checkTotals[$prop.Name].Pass++ }
        }
    }

    $portRecords = @(Get-mdiPortResultRecord -Server $reachable | Where-Object { $_.Applicable -ne $false })
    $nnrRecords = @($portRecords | Where-Object { $_.Group -eq 'NNR' })

    # An NNR target is only resolvable when at least one primary method answers, which is exactly what the
    # 'Low success rate of active name resolution' health alert measures.
    #
    # Grouped by address as well as by name. A multi-homed host is a separate resolution target per
    # address as far as the sensor is concerned - it resolves whatever source address it observed - so
    # counting it once per name let a host with one working NIC and one blocked NIC score as fully
    # resolvable, which is precisely the shape of the alert this tool is meant to explain.
    $nnrTargets = @($nnrRecords | Group-Object -Property Server, Target, TargetIP)
    $nnrResolvable = @($nnrTargets | Where-Object { @($_.Group | Where-Object { $_.Success }).Count -gt 0 })

    $v3Servers = @($reachable | Where-Object { $_.Details.SensorV3ReadyDetails })

    # "Not tested" is not "blocked". The detail table deliberately excludes probes that could not run, so
    # counting them as blocked made the KPI report required ports as blocked while the detail page listed
    # nothing to fix - sending people to open firewall ports that were never actually tested. The same
    # filter is used in both places so the summary and the detail agree.
    $portNotTestedPattern = $script:mdiPortNotTestedPattern
    $portTested = @($portRecords | Where-Object { [string] $_.Detail -notmatch $portNotTestedPattern })

    [PSCustomObject]@{
        TotalServers      = $allServers.Count
        ReachableServers  = $reachable.Count
        UnreachableCount  = $unreachable.Count
        DomainCount       = @($ReportData.DomainsInScope).Count
        ServerScores      = $serverScores
        # Cast to [int] so an empty scan reports 0 rather than nothing at all. Measure-Object -Sum
        # against an empty pipeline returns an object whose .Sum is $null, and $null interpolates as
        # an empty string - so a run that reached no servers printed "issue(s) found: / checks passed"
        # with the numbers simply missing.
        ChecksPassed      = [int] ($serverScores | Measure-Object -Property Passed -Sum).Sum
        ChecksTotal       = [int] ($serverScores | Measure-Object -Property Total -Sum).Sum
        ChecksUnread      = [int] ($serverScores | Measure-Object -Property Unread -Sum).Sum
        CheckTotals       = $checkTotals
        PortsTotal        = $portRecords.Count
        PortsOpen         = @($portTested | Where-Object { $_.Success }).Count
        PortsBlocked      = @($portTested | Where-Object { -not $_.Success }).Count
        PortsRequiredFail = @($portTested | Where-Object { -not $_.Success -and $_.Requirement -eq 'Required' }).Count
        PortsUntested     = @($portRecords | Where-Object { [string] $_.Detail -match $portNotTestedPattern }).Count
        NnrTargetCount    = $nnrTargets.Count
        NnrResolvable     = $nnrResolvable.Count
        NnrRecords        = $nnrRecords
        # 'N/A' is a non-empty string and therefore truthy, so a server whose prerequisites could not be
        # read was counted as ready. That inflated the KPI to a green "12/12" while the sensor v3.x tab
        # showed "Not tested" for the same servers, and the wrong number was written into the baseline
        # history where it permanently distorts the trend. Servers that were not evaluated are excluded
        # from the denominator too, so the ratio compares like with like.
        V3Evaluated       = @($v3Servers | Where-Object { [string] $_.SensorV3Ready -ne 'N/A' }).Count
        V3Ready           = @($v3Servers | Where-Object { $_.SensorV3Ready -eq $true }).Count
        V3MigrationReady  = @($v3Servers | Where-Object { $_.Details.SensorV3ReadyDetails.MigrationEligible }).Count
        Servers           = $allServers
        ReachableList     = $reachable
        UnreachableList   = $unreachable
    }
}

function Get-mdiPortResultRecord {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Server
    )

    @(foreach ($srv in $Server) {
            $portDetails = $srv.Details.RequiredPortsDetails
            if ($null -eq $portDetails) { continue }
            foreach ($result in @($portDetails.Results)) {
                $result | Select-Object -Property *, @{N = 'Server'; E = { $srv.FQDN } }
            }
        })
}

function Get-mdiIssueList {
    <#
        The actionable findings, built once and shared.

        The console summary used to compute its own count as (ChecksTotal - ChecksPassed) + unreachable,
        which counts FAILED CHECKS, while the HTML report lists FINDINGS - and one failed check expands
        into many findings: a RequiredPorts failure becomes one line per blocked port and one per
        unresolvable NNR target. The two numbers therefore disagreed on every real report, and the
        console understated the work by a wide margin. Both now read this list.
    #>
    param (
        [Parameter(Mandatory = $true)] [object] $Statistics,
        [Parameter(Mandatory = $false)] [object] $ReportData = $null
    )

    $issues = New-Object -TypeName System.Collections.ArrayList

    # Domain-level and forest-level findings first. These live on the report, not on any server object,
    # so a list built only from servers could be EMPTY while the verdict was "action required" - the
    # banner said not ready, the issues table said "no issues were found", and the operator had nothing
    # to act on. The conditions below mirror Test-mdiReadinessResult exactly so the two cannot diverge.
    if ($null -ne $ReportData) {
        foreach ($domain in @($ReportData.DomainAuditing | Where-Object { $_ })) {
            $domainName = [string] $domain.Domain
            foreach ($check in @(
                    @{ Name = 'Object auditing'; Value = $domain.ObjectAuditing.isObjectAuditingOk; Measured = $domain.ObjectAuditingMeasured },
                    @{ Name = 'Exchange auditing'; Value = $domain.ExchangeAuditing.isExchangeAuditingOk; Measured = $domain.ExchangeAuditingMeasured },
                    @{ Name = 'AD FS auditing'; Value = $domain.AdfsAuditing.isAdfsAuditingOk; Measured = $domain.AdfsAuditingMeasured }
                )) {
                if ([string] $check.Value -eq 'False') {
                    [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = $domainName; Area = 'Directory auditing'
                            Issue = ('{0} is not configured on this domain' -f $check.Name)
                        })
                } elseif ($check.Measured -eq $false) {
                    [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = $domainName; Area = 'Directory auditing'
                            Issue = ('{0} could not be read on this domain, so it is unverified' -f $check.Name)
                        })
                }
            }
        }

        # A -Forest run that fell back to a single domain examined none of the others.
        if ($null -ne $ReportData.ForestDiscovery -and
            $null -ne $ReportData.ForestDiscovery.PSObject.Properties['Complete'] -and
            [string] $ReportData.ForestDiscovery.Complete -eq 'False') {
            [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $ReportData.Forest; Area = 'Forest discovery'
                    Issue = ('The forest domains could not be enumerated, so only {0} was examined: {1}' -f
                        [string] $ReportData.Domain, [string] $ReportData.ForestDiscovery.Error)
                })
        }

        # A domain in scope that produced no servers was never looked at. When NOTHING was enumerated
        # anywhere, every domain is reported rather than none: the guard below existed to tolerate a
        # report written before servers carried a Domain property, but it also silenced the total
        # failure case, leaving the verdict at "not ready" with an empty issues table and nothing for
        # the operator to act on.
        $scoped = @($ReportData.DomainsInScope | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
        $represented = @(@($Statistics.Servers) | ForEach-Object { [string] $_.Domain } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        if ($represented.Count -gt 0 -or [int] $Statistics.TotalServers -eq 0) {
            foreach ($missing in @($scoped | Where-Object { $_ -notin $represented })) {
                [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $missing; Area = 'Discovery'
                        Issue = 'No server could be enumerated in this domain, so none of it was examined'
                    })
            }
        }
    }

    # A scan that found nothing at all must say so here too, not only in the console banner. Without
    # this the verdict was "not ready" while the report said "no issues were found" - the reader is
    # then told something is wrong and given nothing to look at.
    if ([int] $Statistics.TotalServers -eq 0) {
        [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = '(none)'; Area = 'Discovery'
                Issue = 'No server could be enumerated, so nothing was checked. This is not a readiness result.'
            })
    }

    foreach ($srv in $Statistics.UnreachableList) {
        [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $srv.FQDN; Area = 'Connectivity'
                Issue = 'Server is not available and could not be tested'
            })
    }
    foreach ($srv in $Statistics.ReachableList) {
        $portDetails = $srv.Details.RequiredPortsDetails
        $v3Details = $srv.Details.SensorV3ReadyDetails
        # Specific findings are far more actionable than a generic "<check> failed" line, so the summary row is only
        # emitted when no detailed reason is available for that check. Note @($null).Count is 1, hence the filter.
        $hasPortDetail = @($portDetails.FailedRequired | Where-Object { $_ }).Count -gt 0 -or
        @($portDetails.NnrFailedTargets | Where-Object { $_ }).Count -gt 0
        $hasV3Detail = @($v3Details.Blockers | Where-Object { $_ }).Count -gt 0

        foreach ($prop in @(Get-mdiCheckProperty -Server $srv | Where-Object { -not $_.Value })) {
            if ($prop.Name -eq 'RequiredPorts' -and $hasPortDetail) { continue }
            if ($prop.Name -eq 'SensorV3Ready' -and $hasV3Detail) { continue }
            $area = if ($prop.Name -eq 'RequiredPorts') { 'Network' } elseif ($prop.Name -eq 'SensorV3Ready') { 'Sensor v3.x' } else { 'Configuration' }
            $severity = if ($prop.Name -eq 'SensorV3Ready') { 'Medium' } else { 'High' }
            [void] $issues.Add([PSCustomObject]@{ Severity = $severity; Server = [string] $srv.FQDN; Area = $area
                    Issue = (ConvertTo-mdiFriendlyName ([string] $prop.Name)) + ' check failed'
                })
        }

        # Checks that could not be READ are listed too. The verdict already refuses to call a run ready
        # while any check is unread, but nothing said which ones - so a scan where access was denied
        # produced "not ready" with an issues table that named only the handful of checks that
        # happened to work. An unread check is not a failure to fix; it is a measurement to repeat,
        # and it is labelled that way so nobody reconfigures a setting that was never read.
        foreach ($prop in @($srv.PSObject.Properties | Where-Object {
                    $_.Name -notin $script:mdiInformationalProperty -and
                    $_.Name -notin $script:mdiStatusFlag -and
                    $_.Value -is [string] -and $_.Value -eq 'N/A'
                })) {
            [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $srv.FQDN; Area = 'Not measured'
                    Issue = (ConvertTo-mdiFriendlyName ([string] $prop.Name)) + ' could not be read on this server, so its state is unknown'
                })
        }
        foreach ($blocked in @($portDetails.FailedRequired | Where-Object { $_ })) {
            [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $srv.FQDN; Area = 'Network'; Issue = [string] $blocked })
        }
        foreach ($target in @($portDetails.NnrFailedTargets | Where-Object { $_ })) {
            [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $srv.FQDN; Area = 'Name resolution'
                    Issue = 'No NNR method could resolve ' + [string] $target
                })
        }
        foreach ($blocker in @($v3Details.Blockers | Where-Object { $_ })) {
            [void] $issues.Add([PSCustomObject]@{ Severity = 'Medium'; Server = [string] $srv.FQDN; Area = 'Sensor v3.x'; Issue = [string] $blocker })
        }
        # A sensor that is installed but stopped reports no data while still looking deployed in the portal
        foreach ($sensorIssue in @($srv.Details.SensorHealthDetails.Issues | Where-Object { $_ })) {
            [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $srv.FQDN; Area = 'Sensor health'; Issue = [string] $sensorIssue })
        }
        if ($srv.PSObject.Properties['TimeSync'] -and $srv.TimeSync -eq $false) {
            [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $srv.FQDN; Area = 'Time sync'
                    Issue = [string] $srv.Details.TimeSyncDetails.Detail
                })
        }
    }

    # Returned WITHOUT the comma operator. Using ", @($issues.ToArray())" to stop PowerShell unrolling
    # the array was wrong here: every caller already wraps the call in @(), so the comma produced a
    # single element that WAS the array - the console counted 1 issue regardless of how many there
    # were, and the HTML table rendered one row whose every cell held all the values joined together.
    # Unrolling is what is wanted: @() around an empty result still gives Count 0.
    $issues.ToArray()
}

function Get-mdiOverviewHtml {
    param (
        [Parameter(Mandatory = $true)] [object] $Statistics,
        [Parameter(Mandatory = $true)] [object] $ReportData
    )

    $stats = $Statistics
    $lines = New-Object -TypeName System.Collections.ArrayList

    # Total -gt 0 as well as Failed -eq 0: a reachable server whose every check returned 'N/A' has no
    # boolean properties at all, so Total and Failed are both 0 and it was counted as fully ready and
    # coloured green - while the hero verdict said action required and the Issues table said nothing was
    # measured. Three parts of the same page disagreed about the same server.
    $readyServers = @($stats.ServerScores | Where-Object { $_.Total -gt 0 -and $_.Failed -eq 0 }).Count
    $unmeasuredServers = @($stats.ServerScores | Where-Object { $_.Total -eq 0 }).Count
    $notReady = $stats.ReachableServers - $readyServers
    $scorePct = if ($stats.ChecksTotal -gt 0) { [int] [math]::Round(($stats.ChecksPassed / $stats.ChecksTotal) * 100) } else { 0 }

    $sensorServers = @($stats.ReachableList | Where-Object { $_.Details.SensorHealthDetails })
    $sensorInstalled = @($sensorServers | Where-Object { $_.Details.SensorHealthDetails.Installed })
    $sensorHealthy = @($sensorInstalled | Where-Object { $_.SensorHealth -eq $true })

    # --- KPI cards ---------------------------------------------------------------------------------------------
    $kpis = @(
        @{ Label = 'Servers scanned'; Value = $stats.TotalServers; Sub = ('{0} domain(s) in scope' -f $stats.DomainCount); Tone = 'info' }
        @{ Label = 'Servers fully ready'; Value = ('{0}/{1}' -f $readyServers, $stats.ReachableServers)
            Sub = $(if ($unmeasuredServers -gt 0) { '{0} need attention, {1} not measured' -f ($notReady - $unmeasuredServers), $unmeasuredServers }
                elseif ($notReady -gt 0) { '{0} need attention' -f $notReady }
                else { 'All checks passed' })
            Tone = $(if ($notReady -gt 0) { 'bad' } else { 'ok' })
        }
        @{ Label = 'Required ports open'; Value = ('{0}/{1}' -f $stats.PortsOpen, ($stats.PortsTotal - $stats.PortsUntested))
            Sub = $(if ($stats.PortsRequiredFail -gt 0) { '{0} required port(s) blocked' -f $stats.PortsRequiredFail }
                elseif ($stats.PortsUntested -gt 0) { '{0} probe(s) could not be tested' -f $stats.PortsUntested }
                else { 'No required port blocked' })
            Tone = $(if ($stats.PortsRequiredFail -gt 0) { 'bad' } elseif ($stats.PortsBlocked -gt 0) { 'warn' } else { 'ok' })
        }
        @{ Label = 'NNR resolvable targets'; Value = ('{0}/{1}' -f $stats.NnrResolvable, $stats.NnrTargetCount)
            Sub = $(if ($stats.NnrTargetCount -eq 0) { 'Not evaluated' } elseif ($stats.NnrResolvable -lt $stats.NnrTargetCount) { 'Lowers the name resolution rate' } else { 'Every target resolvable' })
            Tone = $(if ($stats.NnrTargetCount -eq 0) { 'na' } elseif ($stats.NnrResolvable -lt $stats.NnrTargetCount) { 'bad' } else { 'ok' })
        }
        @{ Label = 'Sensors healthy'
            Value = $(if ($sensorInstalled.Count -eq 0) { 'n/a' } else { '{0}/{1}' -f $sensorHealthy.Count, $sensorInstalled.Count })
            Sub = $(if ($sensorInstalled.Count -eq 0) { 'No v2.x sensor installed yet' }
                elseif ($sensorHealthy.Count -lt $sensorInstalled.Count) { '{0} installed but not running' -f ($sensorInstalled.Count - $sensorHealthy.Count) }
                else { 'All sensor services running' })
            Tone = $(if ($sensorInstalled.Count -eq 0) { 'na' } elseif ($sensorHealthy.Count -lt $sensorInstalled.Count) { 'bad' } else { 'ok' })
        }
        @{ Label = 'Sensor v3.x ready'; Value = ('{0}/{1}' -f $stats.V3Ready, $stats.V3Evaluated)
            Sub = $(if ($stats.V3Evaluated -eq 0) { 'Not evaluated' } else { '{0} eligible for in-place migration' -f $stats.V3MigrationReady })
            Tone = $(if ($stats.V3Evaluated -eq 0) { 'na' } elseif ($stats.V3Ready -lt $stats.V3Evaluated) { 'warn' } else { 'ok' })
        }
        @{ Label = 'Overall check score'; Value = ('{0}%' -f $scorePct); Sub = ('{0} of {1} checks passed' -f $stats.ChecksPassed, $stats.ChecksTotal)
            Tone = $(if ($scorePct -eq 100) { 'ok' } elseif ($scorePct -ge 80) { 'warn' } else { 'bad' })
        }
    )

    [void] $lines.Add('<div class="kpi-grid">')
    foreach ($kpi in $kpis) {
        [void] $lines.Add('<div class="kpi ' + $kpi.Tone + '"><span class="kpi-label">' + (ConvertTo-mdiHtmlEncoded $kpi.Label) +
            '</span><span class="kpi-value">' + (ConvertTo-mdiHtmlEncoded ([string] $kpi.Value)) +
            '</span><span class="kpi-sub">' + (ConvertTo-mdiHtmlEncoded ([string] $kpi.Sub)) + '</span></div>')
    }
    [void] $lines.Add('</div>')

    # --- Charts ------------------------------------------------------------------------------------------------
    [void] $lines.Add('<div class="card-grid">')

    $readinessDonut = New-mdiDonutChart -Segment @(
        [PSCustomObject]@{ Label = 'Passed'; Value = $stats.ChecksPassed; Color = 'var(--ok)' }
        [PSCustomObject]@{ Label = 'Failed'; Value = ($stats.ChecksTotal - $stats.ChecksPassed); Color = 'var(--bad)' }
    ) -CenterValue ('{0}%' -f $scorePct) -CenterLabel 'ready'
    [void] $lines.Add('<section class="card chart-card"><h3>Overall readiness</h3>' + $readinessDonut + '</section>')

    if ($stats.PortsTotal -gt 0) {
        $portDonut = New-mdiDonutChart -Segment @(
            [PSCustomObject]@{ Label = 'Open'; Value = $stats.PortsOpen; Color = 'var(--ok)' }
            [PSCustomObject]@{ Label = 'Blocked'; Value = $stats.PortsBlocked; Color = 'var(--bad)' }
        ) -CenterValue ([string] $stats.PortsTotal) -CenterLabel 'probes'
        [void] $lines.Add('<section class="card chart-card"><h3>Network port probes</h3>' + $portDonut + '</section>')
    }

    # NNR success rate per method - the chart to read when troubleshooting the name resolution health alert
    if (@($stats.NnrRecords).Count -gt 0) {
        $nnrBars = @(foreach ($grp in ($stats.NnrRecords | Group-Object -Property Name | Sort-Object Name)) {
                [PSCustomObject]@{
                    Label = ([string] $grp.Name) -replace '^NNR - ', ''
                    Value = @($grp.Group | Where-Object { $_.Success }).Count
                    Total = @($grp.Group).Count
                    Hint  = 'Successful probes across all sensors and targets'
                }
            })
        [void] $lines.Add('<section class="card wide chart-card"><h3>Name resolution success rate by method</h3>' +
            '<p class="muted">Only one primary method has to answer per target, but Microsoft recommends enabling all of them. A low rate here is what raises the <em>Low success rate of active name resolution</em> health alert.</p>' +
            (New-mdiBarChart -Bar $nnrBars) + '</section>')
    }

    # Per-check pass rate across the estate
    if ($stats.CheckTotals.Count -gt 0) {
        $checkBars = @(foreach ($key in ($stats.CheckTotals.Keys | Sort-Object)) {
                [PSCustomObject]@{
                    Label = ConvertTo-mdiFriendlyName ([string] $key)
                    Value = $stats.CheckTotals[$key].Pass
                    Total = $stats.CheckTotals[$key].Total
                    Hint  = 'Servers passing this check'
                }
            })
        [void] $lines.Add('<section class="card wide chart-card"><h3>Pass rate by prerequisite</h3>' +
            (New-mdiBarChart -Bar $checkBars) + '</section>')
    }

    # Per-server score
    if (@($stats.ServerScores).Count -gt 0) {
        $serverBars = @(foreach ($score in ($stats.ServerScores | Sort-Object Passed, FQDN)) {
                [PSCustomObject]@{ Label = $score.FQDN; Value = $score.Passed; Total = $score.Total; Hint = 'Checks passed on this server' }
            })
        [void] $lines.Add('<section class="card wide chart-card"><h3>Readiness by server</h3>' +
            (New-mdiBarChart -Bar $serverBars) + '</section>')
    }

    [void] $lines.Add('</div>')

    # --- Top issues --------------------------------------------------------------------------------------------
    $issues = New-Object -TypeName System.Collections.ArrayList
    [void] $issues.AddRange(@(Get-mdiIssueList -Statistics $stats -ReportData $ReportData))

    [void] $lines.Add('<section class="card wide"><h3>Issues found</h3>')
    if ($issues.Count -eq 0) {
        # A server whose checks could not be read has no failing booleans, so it produces no issues and
        # would otherwise render as a clean pass. The distinction between "nothing is wrong" and "nothing
        # was measured" is the whole point of this table.
        $unmeasured = @($stats.ReachableList | Where-Object {
                @(Get-mdiCheckProperty -Server $_).Count -eq 0
            })
        if ($unmeasured.Count -gt 0) {
            [void] $lines.Add('<p class="empty-state">No failing check was found, but ' + $unmeasured.Count +
                ' server(s) returned no readable results at all, so this is not a clean result. ' +
                'Check that the account running this script can query those servers over WMI and the remote registry.</p>')
        } else {
            [void] $lines.Add('<p class="empty-state">No issues were found. Every evaluated prerequisite passed on every server.</p>')
        }
    } else {
        [void] $lines.Add('<div class="table-scroll"><table class="data"><thead><tr><th class="nowrap">Severity</th><th class="left nowrap">Server</th><th class="nowrap">Area</th><th class="left">Finding</th></tr></thead><tbody>')
        # Issue is the final tie-breaker. Sort-Object in Windows PowerShell is an unstable sort, so two
        # findings with the same severity, server and area - two blocked ports on one DC, say - swapped
        # places between runs of an unchanged environment, which makes report diffs useless.
        foreach ($issue in ($issues.ToArray() | Sort-Object @{E = { if ($_.Severity -eq 'High') { 0 } else { 1 } } }, Server, Area, Issue)) {
            $sev = if ($issue.Severity -eq 'High') { 'bad' } else { 'warn' }
            [void] $lines.Add('<tr><td><span class="pill ' + $sev + '">' + (ConvertTo-mdiHtmlEncoded $issue.Severity) + '</span></td><td class="mono">' +
                (ConvertTo-mdiHtmlEncoded $issue.Server) + '</td><td class="nowrap">' + (ConvertTo-mdiHtmlEncoded $issue.Area) + '</td><td class="left">' +
                (ConvertTo-mdiHtmlEncoded $issue.Issue) + '</td></tr>')
        }
        [void] $lines.Add('</tbody></table></div>')
    }
    [void] $lines.Add('</section>')

    $lines.ToArray() -join [environment]::NewLine
}

function Get-mdiSensorHealthHtml {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Server
    )

    $servers = @($Server | Where-Object { $_.Details.SensorHealthDetails })
    if ($servers.Count -eq 0) {
        return '<p class="muted">Sensor health was not evaluated.</p>'
    }

    $lines = New-Object -TypeName System.Collections.ArrayList
    [void] $lines.Add('<div class="table-scroll"><table>')
    [void] $lines.Add('<tr><th class="left">Server</th><th>Sensor installed</th><th>Sensor service</th><th>Start mode</th><th>Updater service</th><th>Version</th><th class="left">Detail</th></tr>')
    foreach ($srv in ($servers | Sort-Object FQDN)) {
        $health = $srv.Details.SensorHealthDetails
        $installed = [bool] $health.Installed

        if (-not $installed) {
            # A server without a sensor is not a failure: it may simply not be onboarded yet
            [void] $lines.Add(('<tr><td class="mono">{0}</td><td class="grey">No</td><td class="grey">n/a</td><td class="grey">n/a</td><td class="grey">n/a</td><td class="grey">n/a</td><td class="left">{1}</td></tr>' -f
                    (ConvertTo-mdiHtmlEncoded ([string] $srv.FQDN)), (ConvertTo-mdiHtmlEncoded ([string] $health.Detail))))
            continue
        }

        $sensorClass = if ([string] $health.SensorService -eq 'Running') { 'green' } elseif ([string] $health.SensorService -eq 'Not installed') { 'grey' } else { 'red' }
        $updaterClass = if ([string] $health.UpdaterService -eq 'Running') { 'green' } elseif ([string] $health.UpdaterService -eq 'Not installed') { 'grey' } else { 'red' }
        $startClass = if ([string] $health.SensorStartMode -eq 'Disabled') { 'red' } else { 'green' }
        $detailClass = if ($srv.SensorHealth -eq $false) { 'red' } else { 'green' }

        [void] $lines.Add(('<tr><td class="mono">{0}</td><td class="green">Yes</td><td class="{1}">{2}</td><td class="{3}">{4}</td><td class="{5}">{6}</td><td class="mono">{7}</td><td class="left {8}">{9}</td></tr>' -f
                (ConvertTo-mdiHtmlEncoded ([string] $srv.FQDN)),
                $sensorClass, (ConvertTo-mdiHtmlEncoded ([string] $health.SensorService)),
                $startClass, (ConvertTo-mdiHtmlEncoded ([string] $health.SensorStartMode)),
                $updaterClass, (ConvertTo-mdiHtmlEncoded ([string] $health.UpdaterService)),
                (ConvertTo-mdiHtmlEncoded ([string] $srv.SensorVersion)),
                $detailClass, (ConvertTo-mdiHtmlEncoded ([string] $health.Detail))))
    }
    [void] $lines.Add('</table></div>')

    $notInstalled = @($servers | Where-Object { -not $_.Details.SensorHealthDetails.Installed })
    if ($notInstalled.Count -eq $servers.Count) {
        [void] $lines.Add('<p class="muted">No Defender for Identity sensor v2.x is installed on any of the scanned servers, so there is nothing to report yet. This check flags sensors that are installed but stopped or disabled, which report no data to the cloud service while still appearing deployed in the portal.</p>')
    }

    $lines.ToArray() -join [environment]::NewLine
}

function Get-mdiTimeSyncHtml {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Server
    )

    $servers = @($Server | Where-Object { $_.Details.TimeSyncDetails })
    if ($servers.Count -eq 0) {
        return '<p class="muted">Time synchronization was not evaluated.</p>'
    }

    $lines = New-Object -TypeName System.Collections.ArrayList
    [void] $lines.Add('<div class="table-scroll"><table>')
    [void] $lines.Add('<tr><th class="left">Server</th><th>Within tolerance</th><th>Skew</th><th>Remote clock (UTC)</th><th class="left">Detail</th></tr>')
    foreach ($srv in ($servers | Sort-Object FQDN)) {
        $sync = $srv.Details.TimeSyncDetails
        $ok = $srv.TimeSync -eq $true
        # A clock that could not be read is not a clock that has drifted. Rendering it red with "No"
        # contradicted the tri-state and sent people to resynchronise a server whose time may be correct.
        $notTested = [string] $srv.TimeSync -eq 'N/A' -or $null -eq $srv.TimeSync
        $skew = if ($null -ne $sync.SkewSeconds) { [string] ([int] $sync.SkewSeconds) + ' s' } else { 'n/a' }
        $cellClass = if ($ok) { 'green' } elseif ($notTested) { 'muted-cell' } else { 'red' }
        $cellLabel = if ($ok) { 'Yes' } elseif ($notTested) { 'Not tested' } else { 'No' }
        [void] $lines.Add(('<tr><td class="mono">{0}</td><td class="{1}">{2}</td><td class="{1}">{3}</td><td class="mono">{4}</td><td class="left">{5}</td></tr>' -f
                (ConvertTo-mdiHtmlEncoded ([string] $srv.FQDN)),
                $cellClass, $cellLabel,
                (ConvertTo-mdiHtmlEncoded $skew),
                (ConvertTo-mdiHtmlEncoded ([string] $sync.RemoteUtc)),
                (ConvertTo-mdiHtmlEncoded ([string] $sync.Detail))))
    }
    [void] $lines.Add('</table></div>')
    $lines.ToArray() -join [environment]::NewLine
}

function Get-mdiCapacityHtml {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Server
    )

    $capacity = $settings.CapacityPlanning
    $servers = @($Server | Where-Object { $_.Details.CapacityDetails })
    if ($servers.Count -eq 0) {
        return '<p class="muted">Capacity planning was not run. Re-run with <code>-CapacityPlanning</code> to sample the packet rate of each domain controller and estimate whether it has enough resources for a sensor v2.x.</p>' +
        '<p class="muted">For a formal sizing exercise use the official <a href="' + $capacity.OfficialRepoUrl + '">Microsoft Defender for Identity Sizing Tool</a> (<code>TriSizingTool.exe</code>, <a href="' +
        $capacity.OfficialToolUrl + '">download</a>), which samples over 24 hours and produces an Excel workbook.</p>'
    }

    $lines = New-Object -TypeName System.Collections.ArrayList

    # The short-sample caveat governs how every number below must be read, so it goes first and
    # is styled as a warning. Left at the bottom as a grey footnote it was routinely missed.
    $partial = @($servers | Where-Object { $_.Details.CapacityDetails.FullBusyWindow -eq $false })
    if ($partial.Count -gt 0) {
        $seconds = [int] (@($servers.Details.CapacityDetails.SampleSeconds) | Measure-Object -Maximum).Maximum
        # The whole concatenation is parenthesised before -f: the format operator binds tighter than +,
        # so without the parentheses only the last fragment would be formatted and every placeholder in
        # the earlier fragments would render literally as {0}, {1} and so on.
        [void] $lines.Add((('<div class="callout warn"><span class="ico">&#9888;</span><div class="body">' +
                    '<b>Estimate only &mdash; this is not a formal sizing.</b>' +
                    '<p>Microsoft sizes a sensor on the <b>15 busiest minutes of a 24 hour period</b>. This run sampled ' +
                    'only <b>{0} second(s)</b> per server, so there is no busy window to pick from and the whole sample ' +
                    'was averaged instead. Treat the verdict as a quick check for an obviously undersized server, not as ' +
                    'a sizing decision.</p>' +
                    '<p>Because the busy figure equals the average on a sample this short, the <b>spike test cannot ' +
                    'trigger</b>: a server with heavy but brief bursts will still be reported as supported. Compare the ' +
                    '<b>Peak</b> column against the average to judge that yourself.</p>' +
                    '<p>Sample for longer with <code>-CapacityPlanningDuration {1}</code> (at least {2} minutes) during ' +
                    'a representative busy period, or run the official <a href="{3}">TriSizingTool</a>, which samples ' +
                    'over 24 hours.</p></div></div>') -f
                $seconds, ([int] $capacity.BusyWindowMinutes * 60), [int] $capacity.BusyWindowMinutes, $capacity.OfficialToolUrl))
    } else {
        [void] $lines.Add((('<div class="callout info"><span class="ico">&#8505;</span><div class="body">' +
                    '<b>Sampled over a full busy window.</b>' +
                    '<p>The sample was long enough to take the highest rolling {0}-minute average, which is the figure ' +
                    'Microsoft''s method uses. It still covers only the sampled period rather than a full day, so for a ' +
                    'formal exercise use the official <a href="{1}">TriSizingTool</a>.</p></div></div>') -f
                [int] $capacity.BusyWindowMinutes, $capacity.OfficialToolUrl))
    }

    [void] $lines.Add('<div class="table-scroll"><table>')
    [void] $lines.Add('<tr><th class="left">Server</th><th>Sensor supported</th><th>Sample</th><th>Busy packets/sec</th><th>Average</th><th>Peak</th><th>Traffic band</th><th>Sensor needs</th><th>Server has</th><th>CPU used</th><th>RAM free</th><th class="left">Detail</th></tr>')

    foreach ($srv in ($servers | Sort-Object FQDN)) {
        $c = $srv.Details.CapacityDetails
        $status = [string] $c.Status

        if ($null -eq $c.BusyPacketsPerSec) {
            [void] $lines.Add(('<tr><td class="mono">{0}</td><td class="grey">{1}</td><td class="grey" colspan="9">n/a</td><td class="left">{2}</td></tr>' -f
                    (ConvertTo-mdiHtmlEncoded ([string] $srv.FQDN)), (ConvertTo-mdiHtmlEncoded $status),
                    (ConvertTo-mdiHtmlEncoded ([string] $c.Detail))))
            continue
        }

        $class = switch -Wildcard ($status) {
            'Yes' { 'green' }
            'Yes,*' { 'amber' }
            'Maybe*' { 'amber' }
            'No' { 'red' }
            default { 'grey' }
        }
        # A verdict from a sample shorter than the busy window is provisional, so it is never shown
        # in plain green: that would imply more confidence than the measurement supports.
        $sampleText = '{0} s' -f [int] $c.SampleSeconds
        $sampleClass = 'mono'
        if ($c.FullBusyWindow -eq $false) {
            $sampleText = '{0} s, partial' -f [int] $c.SampleSeconds
            $sampleClass = 'mono amber'
            if ($class -eq 'green') { $class = 'amber' }
            $status = $status + ' (estimate)'
        }

        # On a short sample the automatic spike test is inert, so the ratio is surfaced instead.
        $peakClass = 'mono'
        $peakText = [string][int] $c.PeakPacketsPerSec
        if ([int] $c.AveragePacketsPerSec -gt 0) {
            $ratio = [double] $c.PeakPacketsPerSec / [double] $c.AveragePacketsPerSec
            if ($ratio -ge $capacity.SpikeRatio) {
                $peakClass = 'mono amber'
                $peakText = '{0} ({1}x avg)' -f [int] $c.PeakPacketsPerSec, (ConvertTo-mdiSvgNumber ([math]::Round($ratio, 1)))
            }
        }

        $cores = '{0} core(s){1}' -f [int] $c.PhysicalCores, $(if ($c.HyperThreaded) { ' *' } else { '' })
        $cpuUsed = if ($null -ne $c.AvgCpuPercent) { '{0}% avg / {1}% max' -f [int] $c.AvgCpuPercent, [int] $c.MaxCpuPercent } else { 'n/a' }
        $ramFree = if ($null -ne $c.MinAvailableRamGb) { '{0} GB min' -f (ConvertTo-mdiSvgNumber ([double] $c.MinAvailableRamGb)) } else { 'n/a' }
        [void] $lines.Add(('<tr><td class="mono">{0}</td><td class="{1}">{2}</td><td class="{3}">{4}</td><td class="mono">{5}</td><td class="mono">{6}</td><td class="{7}">{8}</td><td class="mono">{9}</td><td class="mono">{10} core / {11} GB</td><td class="mono">{12} / {13} GB</td><td class="mono">{14}</td><td class="mono">{15}</td><td class="left">{16}</td></tr>' -f
                (ConvertTo-mdiHtmlEncoded ([string] $srv.FQDN)), $class, (ConvertTo-mdiHtmlEncoded $status),
                $sampleClass, (ConvertTo-mdiHtmlEncoded $sampleText),
                [int] $c.BusyPacketsPerSec, [int] $c.AveragePacketsPerSec,
                $peakClass, (ConvertTo-mdiHtmlEncoded $peakText),
                (ConvertTo-mdiHtmlEncoded ([string] $c.Band)),
                (ConvertTo-mdiSvgNumber ([double] $c.RequiredCpu)), (ConvertTo-mdiSvgNumber ([double] $c.RequiredRamGb)),
                (ConvertTo-mdiHtmlEncoded $cores), (ConvertTo-mdiSvgNumber ([double] $c.TotalRamGb)),
                (ConvertTo-mdiHtmlEncoded $cpuUsed), (ConvertTo-mdiHtmlEncoded $ramFree),
                (ConvertTo-mdiHtmlEncoded ([string] $c.Detail))))
    }
    [void] $lines.Add('</table></div>')

    if (@($servers | Where-Object { $_.Details.CapacityDetails.HyperThreaded }).Count -gt 0) {
        [void] $lines.Add('<p class="muted">* Hyper-threading is enabled. The published sizing figures exclude hyper-threaded cores, and Microsoft recommends not relying on them because they can cause sensor health issues. Only physical cores are counted above.</p>')
    }

    # The published sizing table, so the verdict above can be checked against the source
    [void] $lines.Add('<h4>Published sizing table</h4>')
    [void] $lines.Add('<p class="muted">Estimated resources consumed by the sensor itself, not by the domain controller. Source: <a href="' +
        $capacity.DocumentationUrl + '">Plan capacity for deployment</a>.</p>')
    [void] $lines.Add('<div class="table-scroll"><table>')
    [void] $lines.Add('<tr><th>Busy packets / second</th><th>CPU (physical cores)</th><th>RAM (GB)</th></tr>')
    foreach ($row in $capacity.SizingTable) {
        $inUse = @($servers | Where-Object { [string] $_.Details.CapacityDetails.Band -eq [string] $row.Band }).Count -gt 0
        $highlight = if ($inUse) { ' class="amber"' } else { '' }
        [void] $lines.Add(('<tr><td{0}>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
                $highlight, (ConvertTo-mdiHtmlEncoded ([string] $row.Band)),
                (ConvertTo-mdiSvgNumber ([double] $row.Cpu)), (ConvertTo-mdiSvgNumber ([double] $row.RamGb))))
    }
    [void] $lines.Add('</table></div>')

    [void] $lines.Add('<h4>Official sizing tool</h4>')
    [void] $lines.Add('<p>For a formal sizing exercise, run the official <a href="' + $capacity.OfficialRepoUrl +
        '">Microsoft Defender for Identity Sizing Tool</a> (<code>TriSizingTool.exe</code>, <a href="' + $capacity.OfficialToolUrl +
        '">download</a>). It samples every domain controller for 24 hours and produces an Excel workbook; read the <b>Sensor Supported</b> column of the <i>Azure ATP Summary</i> sheet.</p>')
    [void] $lines.Add('<ul class="notes">')
    [void] $lines.Add('<li>Run it with domain admin credentials from a domain-joined workstation, before installing any sensor, so the measurements are not skewed.</li>')
    [void] $lines.Add('<li>It needs TCP 135, 389, 445 and the RPC dynamic port range open to every domain controller. This report already validates <b>TCP 135</b> and <b>TCP 389</b> on the Network ports tab.</li>')
    [void] $lines.Add('<li>Do not use an account in the <b>Protected Users</b> group: its Kerberos ticket cannot be renewed past four hours and the tool will fail to authenticate part-way through the run.</li>')
    [void] $lines.Add('<li>The other sheet in the workbook is for Advanced Threat Analytics (ATA) and is not needed for Defender for Identity.</li>')
    [void] $lines.Add('</ul>')

    $lines.ToArray() -join [environment]::NewLine
}

function Get-mdiRequiredPortsHtml {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Server
    )

    $records = @(Get-mdiPortResultRecord -Server $Server)
    if ($records.Count -eq 0) {
        return '<table><tr><td>Network port validation was skipped or produced no results</td></tr></table>'
    }

    $servers = @($records | Select-Object -ExpandProperty Server -Unique | Sort-Object)
    $lines = New-Object -TypeName System.Collections.ArrayList

    # --- Per sensor / per port summary -------------------------------------------------------------------------
    [void] $lines.Add('<div class="table-scroll"><table>')
    $serverHeaders = ($servers | ForEach-Object { '<th>{0}</th>' -f (ConvertTo-mdiHtmlEncoded $_) }) -join ''
    [void] $lines.Add('<tr><th style="text-align:left">Requirement</th><th>Protocol</th><th>Port</th><th>Scope</th>{0}</tr>' -f $serverHeaders)

    foreach ($probeId in @($settings.RequiredPorts.Id)) {
        $probeRecords = @($records | Where-Object { $_.Id -eq $probeId })
        if ($probeRecords.Count -eq 0) { continue }
        $probe = @($settings.RequiredPorts | Where-Object { $_.Id -eq $probeId })[0]

        $cells = foreach ($srv in $servers) {
            $srvRecords = @($probeRecords | Where-Object { $_.Server -eq $srv })
            $applicable = @($srvRecords | Where-Object { $_.Applicable -ne $false })
            # A probe that could not RUN is separated from one that ran and failed. This table was the
            # last place that did not make the distinction: the KPI, the NNR matrix and the actionable
            # list all filter on this pattern, so an unresolvable name or an access-denied probe showed
            # as a red "0/1 open" required port here while every other part of the same report
            # correctly omitted it. Red reads as "blocked", and the operator opens a firewall port that
            # was never probed - the most expensive wrong answer this tool can give.
            $measurable = @($applicable | Where-Object { [string] $_.Detail -notmatch $script:mdiPortNotTestedPattern })
            $notTested = @($applicable | Where-Object { [string] $_.Detail -match $script:mdiPortNotTestedPattern })
            if ($applicable.Count -eq 0) {
                '<td class="grey" title="{0}">N/A</td>' -f (ConvertTo-mdiHtmlEncoded (@($srvRecords.Detail)[0]))
            } elseif ($measurable.Count -eq 0) {
                '<td class="muted-cell" title="{0}">Not tested</td>' -f (ConvertTo-mdiHtmlEncoded (@($notTested.Detail)[0]))
            } else {
                $ok = @($measurable | Where-Object { $_.Success })
                $failed = @($measurable | Where-Object { -not $_.Success })
                if ($failed.Count -eq 0) {
                    # The untested probes are named in the tooltip rather than folded into the ratio,
                    # so an "OK" cell cannot quietly stand for probes that never ran.
                    $suffix = if ($measurable.Count -gt 1) { ' ({0}/{0})' -f $measurable.Count } else { '' }
                    if ($notTested.Count -gt 0) {
                        '<td class="green" title="{0}">OK{1}*</td>' -f
                        (ConvertTo-mdiHtmlEncoded ('{0} probe(s) could not be tested' -f $notTested.Count)), $suffix
                    } else {
                        '<td class="green">OK{0}</td>' -f $suffix
                    }
                } else {
                    # A failed 'at least one of' NNR method is only a warning by itself; the verdict is per target below
                    $class = if ($probeRecords[0].Requirement -eq 'Required') { 'red' } else { 'amber' }
                    $tooltip = (@(foreach ($f in $failed) { [string] $f.Target + ': ' + [string] $f.Detail })) -join ' | '
                    '<td class="{0}" title="{1}">{2}/{3} open</td>' -f $class, (ConvertTo-mdiHtmlEncoded $tooltip), $ok.Count, $measurable.Count
                }
            }
        }

        $requirement = @($probeRecords | Select-Object -ExpandProperty Requirement -Unique)[0]
        [void] $lines.Add(('<tr><td style="text-align:left" title="{0}">{1}<br/><small>{2}</small></td><td>{3}</td><td>{4}</td><td>{5}</td>{6}</tr>' -f
                (ConvertTo-mdiHtmlEncoded $probe.Notes), (ConvertTo-mdiHtmlEncoded $probe.Name), (ConvertTo-mdiHtmlEncoded $requirement),
                $probe.Protocol, $probe.Port, (ConvertTo-mdiHtmlEncoded $probe.Scope), ($cells -join '')))
    }
    [void] $lines.Add('</table></div>')

    # --- Network Name Resolution matrix ------------------------------------------------------------------------
    # This is the table to look at when troubleshooting the 'Low success rate of active name resolution' health alert
    $nnrRecords = @($records | Where-Object { $_.Scope -eq 'NetworkDevice' -and $_.Applicable -ne $false })
    if ($nnrRecords.Count -gt 0) {
        $nnrProbes = @($settings.RequiredPorts | Where-Object { $_.Scope -eq 'NetworkDevice' })
        [void] $lines.Add('<h4>Network Name Resolution (NNR) matrix</h4>')
        [void] $lines.Add('<p>At least one primary method (NTLM over RPC, NetBIOS, RDP) must succeed for every device the sensor observes. Targets where all methods fail are what lower the <a href="https://aka.ms/mdi/nnr/troubleshooting">active name resolution success rate</a>.</p>')
        [void] $lines.Add('<div class="table-scroll"><table>')
        $nnrHeaders = ($nnrProbes | ForEach-Object {
                '<th>{0}<br/><small>{1}/{2}</small></th>' -f (ConvertTo-mdiHtmlEncoded ($_.Name -replace '^NNR - ', '')), $_.Protocol, $_.Port
            }) -join ''
        [void] $lines.Add('<tr><th style="text-align:left">Sensor server</th><th style="text-align:left">Target</th>{0}<th>Resolvable</th></tr>' -f $nnrHeaders)

        foreach ($srv in $servers) {
            $srvNnr = @($nnrRecords | Where-Object { $_.Server -eq $srv })
            # Grouped by target AND address. A multi-homed host is probed once per address, and grouping
            # by name alone merged those rows back into one - which would report a host as resolvable on
            # the strength of the NIC that answered while the other one, the one actually failing in the
            # portal, disappeared from the report entirely.
            # Sorted by name and then NUMERICALLY by address. Group-Object on two properties builds a
            # comma-joined Name, so sorting on it sorted the address as text and put .10 before .9 -
            # two runs of an unchanged environment produced rows in a confusing order.
            foreach ($targetGroup in ($srvNnr | Group-Object -Property Target, TargetIP | Sort-Object `
                    @{ Expression = { [string] $_.Values[0] } },
                    @{ Expression = {
                            $addr = [string] $_.Values[1]
                            if ($addr -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { [version] $addr } else { [version] '255.255.255.255' }
                        }
                    })) {
                $cells = foreach ($probe in $nnrProbes) {
                    $record = @($targetGroup.Group | Where-Object { $_.Id -eq $probe.Id })[0]
                    if ($null -eq $record) {
                        '<td class="grey">N/A</td>'
                    } elseif ($record.Success) {
                        '<td class="green" title="{0}">Open</td>' -f (ConvertTo-mdiHtmlEncoded $record.Detail)
                    } elseif ([string] $record.Detail -match $script:mdiPortNotTestedPattern) {
                        # The probe did not run, so nothing was observed to be blocked. Calling this
                        # "Blocked" sends people to open a firewall port that may already be open.
                        '<td class="muted-cell" title="{0}">Not tested</td>' -f (ConvertTo-mdiHtmlEncoded $record.Detail)
                    } else {
                        '<td class="red" title="{0}">Blocked</td>' -f (ConvertTo-mdiHtmlEncoded $record.Detail)
                    }
                }
                $primaryOk = @($targetGroup.Group | Where-Object { $_.Group -eq 'NNR' -and $_.Success }).Count -gt 0
                $primaryTested = @($targetGroup.Group | Where-Object {
                        $_.Group -eq 'NNR' -and [string] $_.Detail -notmatch $script:mdiPortNotTestedPattern
                    }).Count -gt 0
                $verdict = if ($primaryOk) { '<td class="green">Yes</td>' }
                elseif (-not $primaryTested) { '<td class="muted-cell">Not tested</td>' }
                else { '<td class="red">No</td>' }

                # The address is shown next to the name, because on a multi-homed host the name alone
                # no longer identifies which path was tested.
                $first = @($targetGroup.Group)[0]
                $targetLabel = if ([string]::IsNullOrWhiteSpace([string] $first.TargetIP)) {
                    ConvertTo-mdiHtmlEncoded ([string] $first.Target)
                } else {
                    '{0} <span class="mono muted">{1}</span>' -f
                    (ConvertTo-mdiHtmlEncoded ([string] $first.Target)), (ConvertTo-mdiHtmlEncoded ([string] $first.TargetIP))
                }
                [void] $lines.Add(('<tr><td style="text-align:left">{0}</td><td style="text-align:left">{1}</td>{2}{3}</tr>' -f
                        (ConvertTo-mdiHtmlEncoded $srv), $targetLabel, ($cells -join ''), $verdict))
            }
        }
        [void] $lines.Add('</table></div>')
    }

    # --- Actionable failure list -------------------------------------------------------------------------------
    # A probe that could not run is not a failure to act on: nothing was observed to be blocked. Listing
    # it here sends people to open firewall ports that may already be open.
    $failures = @($records | Where-Object {
            $_.Applicable -ne $false -and -not $_.Success -and
            [string] $_.Detail -notmatch $script:mdiPortNotTestedPattern
        })
    $notTested = @($records | Where-Object {
            $_.Applicable -ne $false -and -not $_.Success -and
            [string] $_.Detail -match $script:mdiPortNotTestedPattern
        })
    if ($failures.Count -gt 0) {
        [void] $lines.Add('<h4>Ports that need attention</h4>')
        [void] $lines.Add('<div class="table-scroll"><table>')
        [void] $lines.Add('<tr><th style="text-align:left">Sensor server</th><th style="text-align:left">Requirement</th><th>Protocol</th><th>Port</th><th style="text-align:left">Target</th><th style="text-align:left">Result</th></tr>')
        foreach ($failure in ($failures | Sort-Object Server, Port, Target)) {
            $class = if ($failure.Requirement -eq 'Required') { 'red' } else { 'amber' }
            [void] $lines.Add(('<tr><td style="text-align:left">{0}</td><td style="text-align:left">{1}</td><td>{2}</td><td class="{3}">{4}</td><td style="text-align:left">{5}</td><td style="text-align:left">{6}</td></tr>' -f
                    (ConvertTo-mdiHtmlEncoded $failure.Server), (ConvertTo-mdiHtmlEncoded $failure.Name), $failure.Protocol,
                    $class, $failure.Port, (ConvertTo-mdiHtmlEncoded $failure.Target), (ConvertTo-mdiHtmlEncoded $failure.Detail)))
        }
        [void] $lines.Add('</table></div>')
    }

    if ($notTested.Count -gt 0) {
        # Kept separate from the failures: these are gaps in the evidence, not findings. Hiding them
        # entirely would let a reader believe the ports were confirmed good.
        [void] $lines.Add('<h4>Ports that could not be tested</h4>')
        [void] $lines.Add('<p class="muted">These probes did not run, so nothing is known about them. They are not reported as blocked. ' +
            'The usual cause is that the account running this script could not reach the server over WMI, or the server was unreachable.</p>')
        [void] $lines.Add('<div class="table-scroll"><table>')
        [void] $lines.Add('<tr><th style="text-align:left">Sensor server</th><th style="text-align:left">Requirement</th><th>Protocol</th><th>Port</th><th style="text-align:left">Target</th><th style="text-align:left">Reason</th></tr>')
        foreach ($row in ($notTested | Sort-Object Server, Port, Target)) {
            [void] $lines.Add(('<tr><td style="text-align:left">{0}</td><td style="text-align:left">{1}</td><td>{2}</td><td class="muted-cell">{3}</td><td style="text-align:left">{4}</td><td style="text-align:left">{5}</td></tr>' -f
                    (ConvertTo-mdiHtmlEncoded $row.Server), (ConvertTo-mdiHtmlEncoded $row.Name), $row.Protocol,
                    $row.Port, (ConvertTo-mdiHtmlEncoded $row.Target), (ConvertTo-mdiHtmlEncoded $row.Detail)))
        }
        [void] $lines.Add('</table></div>')
    }
    # Latency separates "blocked" from "reachable but slow", which matters when a sensor sits across a WAN link
    $timed = @($records | Where-Object { $null -ne $_.LatencyMs -and $_.Success })
    if ($timed.Count -gt 0) {
        $slowest = @($timed | Sort-Object { [int] $_.LatencyMs } -Descending | Select-Object -First 10)
        $average = [int] [math]::Round((($timed | Measure-Object -Property LatencyMs -Average).Average))
        [void] $lines.Add('<h4>Probe latency</h4>')
        [void] $lines.Add('<p class="muted">Round-trip time of each successful probe. Average ' + $average +
            ' ms. Consistently high values point at a slow or saturated link rather than a blocked port.</p>')
        [void] $lines.Add('<div class="table-scroll"><table>')
        [void] $lines.Add('<tr><th style="text-align:left">Sensor server</th><th style="text-align:left">Probe</th><th style="text-align:left">Target</th><th>Latency</th></tr>')
        foreach ($row in $slowest) {
            $latency = [int] $row.LatencyMs
            $cls = if ($latency -ge 1000) { 'red' } elseif ($latency -ge 250) { 'amber' } else { 'green' }
            [void] $lines.Add(('<tr><td style="text-align:left">{0}</td><td style="text-align:left">{1}</td><td style="text-align:left">{2}</td><td class="{3}">{4} ms</td></tr>' -f
                    (ConvertTo-mdiHtmlEncoded $row.Server), (ConvertTo-mdiHtmlEncoded $row.Name),
                    (ConvertTo-mdiHtmlEncoded $row.Target), $cls, $latency))
        }
        [void] $lines.Add('</table></div>')
    }

    $probedFrom = @($Server | ForEach-Object { $_.Details.RequiredPortsDetails.ProbedFrom } | Where-Object { $_ } | Select-Object -Unique)
    [void] $lines.Add('<p><small>Probed from: {0}</small></p>' -f (ConvertTo-mdiHtmlEncoded ($probedFrom -join '; ')))

    $lines.ToArray() -join [environment]::NewLine
}

function Get-mdiSensorV3Html {
    param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Server
    )

    $servers = @($Server | Where-Object { $_.Details.SensorV3ReadyDetails })
    if ($servers.Count -eq 0) {
        return '<table><tr><td>Sensor v3.x readiness validation was skipped or produced no results</td></tr></table>'
    }

    $checkNames = @($servers | ForEach-Object { $_.Details.SensorV3ReadyDetails.Checks } | ForEach-Object { $_.Name } | Select-Object -Unique)
    $lines = New-Object -TypeName System.Collections.ArrayList

    [void] $lines.Add('<div class="table-scroll"><table>')
    $serverHeaders = ($servers | ForEach-Object { '<th>{0}</th>' -f (ConvertTo-mdiHtmlEncoded $_.FQDN) }) -join ''
    [void] $lines.Add('<tr><th style="text-align:left">Prerequisite</th><th>Type</th>{0}</tr>' -f $serverHeaders)

    foreach ($checkName in $checkNames) {
        $requirement = $null
        $cells = foreach ($srv in $servers) {
            $check = @($srv.Details.SensorV3ReadyDetails.Checks | Where-Object { $_.Name -eq $checkName })[0]
            if ($null -eq $check) {
                '<td class="grey">N/A</td>'
            } else {
                if (-not $requirement) { $requirement = $check.Requirement }
                $status = $check.Status
                if ($status -eq $true) {
                    '<td class="green" title="{0}">Pass</td>' -f (ConvertTo-mdiHtmlEncoded $check.Detail)
                } elseif ($check.PSObject.Properties['Measured'] -and -not $check.Measured) {
                    # Distinguished from an informational N/A: this check did not run at all, so calling
                    # it "N/A" understates that the result is missing rather than not applicable.
                    '<td class="muted-cell" title="{0}">Not tested</td>' -f (ConvertTo-mdiHtmlEncoded $check.Detail)
                } elseif ([string] $status -eq 'N/A' -or $null -eq $status) {
                    '<td class="grey" title="{0}">N/A</td>' -f (ConvertTo-mdiHtmlEncoded $check.Detail)
                } else {
                    $class = switch ($check.Requirement) {
                        'Required' { 'red' }
                        'Recommended' { 'amber' }
                        default { 'amber' }
                    }
                    '<td class="{0}" title="{1}">Fail</td>' -f $class, (ConvertTo-mdiHtmlEncoded $check.Detail)
                }
            }
        }
        [void] $lines.Add(('<tr><td style="text-align:left">{0}</td><td><small>{1}</small></td>{2}</tr>' -f
                (ConvertTo-mdiHtmlEncoded $checkName), (ConvertTo-mdiHtmlEncoded $requirement), ($cells -join '')))
    }

    $stateCells = ($servers | ForEach-Object { '<td>{0}</td>' -f (ConvertTo-mdiHtmlEncoded $_.Details.SensorV3ReadyDetails.SensorState) }) -join ''
    [void] $lines.Add('<tr><td style="text-align:left"><b>Current sensor state</b></td><td></td>{0}</tr>' -f $stateCells)

    $migrationCells = ($servers | ForEach-Object {
            if ($_.Details.SensorV3ReadyDetails.MigrationEligible) { '<td class="green">Yes</td>' } else { '<td class="amber">No</td>' }
        }) -join ''
    [void] $lines.Add('<tr><td style="text-align:left"><b>Eligible for in-place migration</b></td><td></td>{0}</tr>' -f $migrationCells)

    $readyCells = ($servers | ForEach-Object {
            # Compared against $true explicitly: 'N/A' is truthy in PowerShell, so a plain if() rendered
            # a server whose checks could not be read as meeting every prerequisite.
            if ($_.SensorV3Ready -eq $true) { '<td class="green">Yes</td>' }
            elseif ([string] $_.SensorV3Ready -eq 'N/A') { '<td class="muted-cell" title="The prerequisites could not be read on this server">Not tested</td>' }
            else { '<td class="red">No</td>' }
        }) -join ''
    [void] $lines.Add('<tr><td style="text-align:left"><b>Meets the v3.x prerequisites</b></td><td></td>{0}</tr>' -f $readyCells)
    [void] $lines.Add('</table></div>')

    $blocked = @($servers | Where-Object { @($_.Details.SensorV3ReadyDetails.Blockers | Where-Object { $_ }).Count -gt 0 })
    if ($blocked.Count -gt 0) {
        [void] $lines.Add('<h4>What blocks the sensor v3.x</h4>')
        [void] $lines.Add('<div class="table-scroll"><table>')
        [void] $lines.Add('<tr><th style="text-align:left">Server</th><th style="text-align:left">Blocker</th></tr>')
        foreach ($srv in $blocked) {
            foreach ($blocker in @($srv.Details.SensorV3ReadyDetails.Blockers)) {
                [void] $lines.Add(('<tr><td style="text-align:left">{0}</td><td style="text-align:left">{1}</td></tr>' -f
                        (ConvertTo-mdiHtmlEncoded $srv.FQDN), (ConvertTo-mdiHtmlEncoded $blocker)))
            }
        }
        [void] $lines.Add('</table></div>')
    }

    $lines.ToArray() -join [environment]::NewLine
}

function Get-mdiReportStyle {
    # Single-quoted here-string: the CSS braces and $ characters must reach the browser untouched, so this block is
    # never passed through the format operator or string interpolation.
    @'
<style>
:root{
  --bg:#f4f6fb; --surface:#ffffff; --surface-2:#f1f4f9; --border:#cbd4e1; --border-strong:#9fadc2;
  --text:#111827; --muted:#5b6577; --heading:#0f172a;
  --brand:#0f6cbd; --brand-2:#6d28d9;
  --ok:#0e7a37; --ok-bg:#d8f0e0; --bad:#b40e1c; --bad-bg:#fadfe1;
  --warn:#8f3a06; --warn-bg:#fbe8d0; --na:#6b7280; --na-bg:#e6e9ee; --brand-bg:#e3effb;
  --shadow:0 1px 2px rgba(16,24,40,.06),0 4px 12px rgba(16,24,40,.05);
  --radius:14px;
  --maxw:1880px;
}
html[data-view="classic"]{
  --bg:#ffffff; --surface:#ffffff; --surface-2:#f2f2f2; --border:#aeb0b5;
  --text:#212121; --muted:#5b616b; --heading:#212121;
  --shadow:none; --radius:0;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);
  font-family:"Segoe UI Variable Text","Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
.wrap{max-width:var(--maxw);margin:0 auto;padding:0 clamp(12px,2.4vw,28px) 96px;width:100%}
a{color:var(--brand);text-decoration:none}
a:hover{text-decoration:underline}
h1,h2,h3,h4{color:var(--heading);margin:0}
.muted{color:var(--muted)}
.mono{font-family:"Cascadia Mono",Consolas,"SF Mono",Menlo,monospace;font-size:12.5px}

/* ---------- hero ---------- */
.hero{background:linear-gradient(120deg,#0b3f78 0%,#0f6cbd 45%,#6d28d9 100%);color:#fff;padding:34px 0 74px;margin-bottom:-46px}
.hero-inner{max-width:var(--maxw);margin:0 auto;padding:0 clamp(12px,2.4vw,28px);display:flex;flex-wrap:wrap;gap:18px;align-items:flex-start;justify-content:space-between}
.hero h1{color:#fff;font-size:26px;font-weight:600;letter-spacing:-.02em}
.hero .sub{color:rgba(255,255,255,.82);margin-top:6px;font-size:13.5px}
.hero .eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:11px;font-weight:700;color:rgba(255,255,255,.72)}
.verdict{display:inline-flex;align-items:center;gap:10px;background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.28);
  border-radius:999px;padding:9px 18px;font-weight:600;backdrop-filter:blur(6px)}
.verdict .dot{width:10px;height:10px;border-radius:50%;box-shadow:0 0 0 4px rgba(255,255,255,.16)}
.verdict.ok .dot{background:#5ee08a}.verdict.bad .dot{background:#ff8a92}
.hero-actions{display:flex;gap:8px;margin-top:12px}
.btn{border:1px solid rgba(255,255,255,.32);background:rgba(255,255,255,.12);color:#fff;border-radius:8px;
  padding:7px 13px;font-size:12.5px;font-weight:600;cursor:pointer;font-family:inherit}
.btn:hover{background:rgba(255,255,255,.22)}

/* ---------- tabs ---------- */
.tabs{position:sticky;top:0;z-index:20;display:flex;gap:4px;overflow-x:auto;background:var(--surface);
  border:1px solid var(--border);border-radius:var(--radius);padding:6px;box-shadow:var(--shadow);margin-bottom:30px}
.tab{appearance:none;border:0;background:transparent;color:var(--muted);font-family:inherit;font-size:13.5px;font-weight:600;
  padding:10px 16px;border-radius:9px;cursor:pointer;white-space:nowrap;display:inline-flex;align-items:center;gap:8px}
.tab:hover{background:var(--surface-2);color:var(--text)}
.tab[aria-selected="true"]{background:linear-gradient(135deg,var(--brand),var(--brand-2));color:#fff}
.tab .count{background:rgba(0,0,0,.10);border-radius:999px;padding:1px 8px;font-size:11px;font-weight:700}
.tab[aria-selected="true"] .count{background:rgba(255,255,255,.26)}
.tab .count.bad{background:var(--bad);color:#fff}
.panel{display:none;animation:fade .22s ease;min-width:0}
.panel.active{display:block}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}

/* ---------- cards ---------- */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:26px 28px;box-shadow:var(--shadow);margin-bottom:34px;min-width:0;overflow-wrap:break-word}
.card h3{font-size:19px;font-weight:700;letter-spacing:-.01em;margin-bottom:20px;padding-bottom:14px;
  border-bottom:1px solid var(--border);display:flex;align-items:center;gap:11px}
.card h3:before{content:"";width:5px;height:20px;border-radius:3px;background:linear-gradient(180deg,var(--brand),var(--brand-2))}
/* Sub-sections inside a card need to read as clear breaks, not as slightly bolder paragraphs */
.card h4{font-size:16px;font-weight:700;color:var(--heading);margin:38px 0 14px;padding-top:22px;
  border-top:2px solid var(--border);letter-spacing:-.01em}
.card h4:first-of-type{margin-top:30px}
.card>p+table,.card>p+.table-scroll{margin-top:14px}
.card-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(340px,100%),1fr));gap:28px;margin-bottom:34px}
/* Grid and flex children default to min-width:auto, which lets a wide table stretch the whole page instead of
   scrolling inside its own container. Resetting it is what makes .table-scroll actually scroll. */
.card-grid>*{min-width:0}
.card-grid .card{margin-bottom:0}
.card.wide{grid-column:1/-1}
.section-intro{color:var(--muted);margin:0 0 20px;max-width:100ch;font-size:13.5px}
.panel>.card:last-child{margin-bottom:12px}

/* ---------- KPI ---------- */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(212px,100%),1fr));gap:18px;margin-bottom:34px}
.kpi-grid>*{min-width:0}
.kpi{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--na);border-radius:var(--radius);
  padding:16px 18px;box-shadow:var(--shadow);display:flex;flex-direction:column;gap:3px;transition:transform .15s}
.kpi:hover{transform:translateY(-2px)}
.kpi.ok{border-left-color:var(--ok)}.kpi.bad{border-left-color:var(--bad)}
.kpi.warn{border-left-color:var(--warn)}.kpi.info{border-left-color:var(--brand)}
.kpi-label{font-size:11.5px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
.kpi-value{font-size:28px;font-weight:700;letter-spacing:-.02em;line-height:1.15}
.kpi-sub{font-size:12px;color:var(--muted)}

/* ---------- charts ---------- */
.donut-wrap{display:flex;align-items:center;gap:22px;flex-wrap:wrap}
.donut{width:170px;height:170px;flex:0 0 auto}
.donut-track{stroke:var(--border)}
.donut-value{font-size:30px;font-weight:700;fill:var(--heading)}
.donut-label{font-size:11px;fill:var(--muted);text-transform:uppercase;letter-spacing:.1em}
.legend{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:8px;min-width:150px}
.legend li{display:flex;align-items:center;gap:9px;font-size:13px;color:var(--muted)}
.legend b{margin-left:auto;color:var(--text);font-variant-numeric:tabular-nums}
.swatch{width:11px;height:11px;border-radius:3px;flex:0 0 auto}
.barchart{display:flex;flex-direction:column;gap:9px}
.bar-row{display:grid;grid-template-columns:minmax(140px,240px) minmax(80px,1fr) 108px;gap:14px;align-items:center}
.bar-label{font-size:12.5px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{background:var(--surface-2);border:1px solid var(--border);border-radius:999px;height:16px;overflow:hidden}
.bar-fill{height:100%;border-radius:999px;transition:width .5s cubic-bezier(.2,.8,.2,1)}
.bar-fill.ok{background:linear-gradient(90deg,var(--ok),#4bc47a)}
.bar-fill.warn{background:linear-gradient(90deg,var(--warn),#e6a15c)}
.bar-fill.bad{background:linear-gradient(90deg,var(--bad),#e85b66)}
.bar-fill.na{background:var(--na)}
.bar-value{font-size:12px;color:var(--muted);text-align:right;font-variant-numeric:tabular-nums}
.trend{width:100%;height:auto;max-height:220px}
.trend .grid{stroke:var(--border);stroke-width:1;stroke-dasharray:3 3}
.trend .axis{font-size:10.5px;fill:var(--muted)}
.trend-line{stroke:var(--brand);stroke-width:2.5;stroke-linejoin:round;stroke-linecap:round}
.trend-dot{fill:var(--surface);stroke:var(--brand);stroke-width:2.5}
code{background:var(--surface-2);border:1px solid var(--border);border-radius:5px;padding:1px 6px;font-size:12px;
  font-family:"Cascadia Mono",Consolas,monospace}
.code-block{background:var(--surface-2);border:1px solid var(--border);border-left:3px solid var(--brand);
  border-radius:8px;padding:14px 16px;font-family:"Cascadia Mono",Consolas,monospace;font-size:12.5px;
  overflow-x:auto;margin:12px 0;white-space:pre;color:var(--text)}
.path-box{background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:11px 14px;
  font-family:"Cascadia Mono",Consolas,monospace;font-size:12.5px;overflow-wrap:break-word;margin:12px 0}

/* ---------- tables ---------- */
table{border-collapse:collapse;width:100%;font-size:13px;background:var(--surface)}
.table-scroll{overflow-x:auto;overflow-y:hidden;-webkit-overflow-scrolling:touch;max-width:100%;
  border:1px solid var(--border-strong);border-radius:10px;background:var(--surface)}
/* Keep the natural column widths so the container scrolls instead of the columns collapsing */
.table-scroll>table{min-width:max-content}
/* The findings table is free text: let it fit the container and wrap the last column instead */
.table-scroll>table.data{min-width:0;width:100%}
.table-scroll::-webkit-scrollbar,.tabs::-webkit-scrollbar{height:10px}
.table-scroll::-webkit-scrollbar-thumb,.tabs::-webkit-scrollbar-thumb{background:var(--border-strong);border-radius:6px}
.table-scroll::-webkit-scrollbar-thumb:hover,.tabs::-webkit-scrollbar-thumb:hover{background:var(--muted)}
/* Full cell borders rather than bottom-only rules: on a white card a single hairline is nearly invisible */
th,td{border:1px solid var(--border);padding:9px 12px;text-align:center;vertical-align:middle}
th{background:var(--surface-2);color:var(--heading);font-size:11.5px;font-weight:700;text-transform:uppercase;
  letter-spacing:.05em;text-align:center;border-color:var(--border-strong)}
/* Headers default to centre so they line up with the centred cell values. Columns whose cells are
   left-aligned (free text, identifiers) mark their header with .left or an inline style. */
th.left,th[style*="left"]{text-align:left}
th a{color:var(--heading)}
td.left,th.left,th[style*="left"]{text-align:left}
tbody tr:nth-child(even) td{background:var(--surface-2)}
tbody tr:hover td{background:#e8eefb}
table small{color:var(--muted);font-size:11px}
caption{caption-side:top;text-align:left;color:var(--muted);padding-bottom:8px}

/* status cells keep their original class names so the fragment builders stay unchanged */
td.green,td.red,td.amber,td.grey{font-weight:700}
/* The zebra-striping rule is more specific, so the status colours must win explicitly */
td.green,tbody tr:nth-child(even) td.green,tbody tr:hover td.green{background:var(--ok-bg);color:var(--ok)}
td.red,tbody tr:nth-child(even) td.red,tbody tr:hover td.red{background:var(--bad-bg);color:var(--bad)}
td.amber,tbody tr:nth-child(even) td.amber,tbody tr:hover td.amber{background:var(--warn-bg);color:var(--warn)}
td.grey,tbody tr:nth-child(even) td.grey,tbody tr:hover td.grey{background:var(--na-bg);color:var(--na)}
/* A check that could not be read is deliberately not coloured like a pass or a failure: it is neither.
   Italic and muted so the eye skips it when scanning for real problems. */
td.muted-cell,tbody tr:nth-child(even) td.muted-cell,tbody tr:hover td.muted-cell{background:var(--na-bg);color:var(--muted);font-style:italic;font-weight:400}
/* A server that never answered is marked once on its row rather than pretending every check failed. */
tr.unreachable td{opacity:.75}
tr.partial td{opacity:.9}
.badge-warn{display:inline-block;margin-left:6px;padding:1px 7px;border-radius:999px;font-size:10.5px;font-weight:700;background:var(--warn-bg);color:var(--warn);border:1px solid currentColor;white-space:nowrap}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11.5px;font-weight:700;letter-spacing:.02em;white-space:nowrap;border:1px solid currentColor}
/* Identifiers and short labels must never be split mid-word; only the free-text column wraps.
   They are left-aligned so the values line up under their left-aligned headers. */
td.mono,td.nowrap,th.nowrap{white-space:nowrap}
td.mono{text-align:left}
td.left{overflow-wrap:break-word}
.pill.ok{background:var(--ok-bg);color:var(--ok)}
.pill.bad{background:var(--bad-bg);color:var(--bad)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}
.pill.na{background:var(--na-bg);color:var(--na)}
.empty-state{background:var(--ok-bg);color:var(--ok);border-radius:10px;padding:16px 18px;font-weight:600;margin:0}

/* ---------- callout ---------- */
/* Used where a caveat changes how the numbers on the page must be read, so it has to be
   impossible to mistake for a footnote. */
.callout{border-radius:10px;padding:15px 18px;margin:0 0 20px;border:1px solid;
  display:flex;gap:13px;align-items:flex-start;line-height:1.55}
.callout .ico{font-size:19px;line-height:1.25;flex:none}
.callout .body{min-width:0}
.callout b{font-weight:700}
.callout p{margin:7px 0 0}
.callout.warn{background:var(--warn-bg);border-color:var(--warn);color:var(--text)}
.callout.warn b{color:var(--warn)}
.callout.info{background:var(--brand-bg,rgba(59,130,246,.09));border-color:var(--brand);color:var(--text)}
.callout.info b{color:var(--brand)}

/* ---------- filter ---------- */
.filter{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
.filter input{flex:1;min-width:220px;max-width:380px;padding:9px 13px;border:1px solid var(--border);border-radius:9px;
  background:var(--surface);color:var(--text);font-family:inherit;font-size:13px}
.filter input:focus{outline:2px solid var(--brand);outline-offset:-1px;border-color:transparent}

/* ---------- misc ---------- */
.notes{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:12px}
.notes li{background:var(--surface-2);border:1px solid var(--border);border-left:3px solid var(--brand);
  border-radius:9px;padding:12px 16px;color:var(--text)}
.footer{margin-top:30px;padding-top:20px;border-top:1px solid var(--border);color:var(--muted);font-size:12.5px;
  display:flex;flex-wrap:wrap;gap:8px 26px}
.footer b{color:var(--text);font-weight:600}
.disclaimer{margin:14px 0 0;padding:12px 15px;border:1px solid var(--warn);border-left:4px solid var(--warn);
  border-radius:8px;background:var(--warn-bg);color:var(--warn);font-size:12px;line-height:1.55}
.disclaimer a{color:var(--warn);text-decoration:underline}

/* ---------- classic view ----------
   Reproduces the original Test-MdiReadiness report: no tabs, every section stacked in one scrolling page,
   Arial, bordered tables and the original status colours. Purely presentational: the markup is identical,
   so switching views never changes the data. */
html[data-view="classic"] body{font-family:Arial,sans-serif,'Open Sans';font-size:14px;background:#fff}
html[data-view="classic"] .hero{background:none;color:#212121;padding:14px 0 0;margin-bottom:0}
html[data-view="classic"] .hero h1{font-size:20px;color:#212121}
html[data-view="classic"] .hero .eyebrow,html[data-view="classic"] .hero .sub{color:#5b616b}
html[data-view="classic"] .verdict{background:none;border:0;padding:0;color:#212121;backdrop-filter:none}
html[data-view="classic"] .btn{background:#e4e2e0;border:1px solid #aeb0b5;color:#212121}
html[data-view="classic"] .btn:hover{background:#d6d7d9}
html[data-view="classic"] .tabs{display:none}
/* Every panel is shown at once, as in the original single-page report */
html[data-view="classic"] .panel{display:block!important;animation:none;margin-bottom:18px}
html[data-view="classic"] .card{border:0;padding:0;margin:0 0 10px;box-shadow:none;background:none}
html[data-view="classic"] .card h3{font-size:19px;font-weight:700;margin:34px 0 10px;padding:0 0 8px;
  border-bottom:2px solid #aeb0b5;display:block}
html[data-view="classic"] .card h3:before{display:none}
html[data-view="classic"] .card h4{font-size:16px;font-weight:700;margin:26px 0 8px;padding:0;border-top:0}
html[data-view="classic"] .card-grid{display:block}
/* The original report had no dashboard, charts or filters.
   The panel rule below uses !important, so hiding a whole panel needs !important too. */
html[data-view="classic"] .kpi-grid,html[data-view="classic"] .chart-card,
html[data-view="classic"] .filter,html[data-view="classic"] .section-intro,
html[data-view="classic"] .trend{display:none}
html[data-view="classic"] #tab-trend{display:none!important}
html[data-view="classic"] .table-scroll{border:0;border-radius:0;background:none;overflow-x:auto}
/* The callout changes how the numbers on the page must be read, so it stays visible in the
   classic view too, just flattened to match that plainer style. */
html[data-view="classic"] .callout{border-radius:0;border-width:1px;padding:10px 14px;margin:0 0 12px}
html[data-view="classic"] table{border-collapse:collapse;width:auto;background:#fff}
html[data-view="classic"] td,html[data-view="classic"] th{border:1px solid #aeb0b5;padding:5px;text-align:center;
  vertical-align:middle;font-size:14px;text-transform:none;letter-spacing:normal}
html[data-view="classic"] tbody tr:nth-child(even) td{background-color:#f2f2f2}
html[data-view="classic"] tbody tr:hover td{background:inherit}
html[data-view="classic"] th{padding:8px;text-align:center;background-color:#e4e2e0;color:#212121;font-weight:700}
/* html[data-view="classic"] th is more specific than th.left, so the left-aligned headers need an explicit rule */
html[data-view="classic"] th.left,html[data-view="classic"] th[style*="left"]{text-align:left}
/* html[data-view="classic"] td is more specific than td.left, so the left-aligned columns need an explicit override */
html[data-view="classic"] td.left,html[data-view="classic"] td.mono{text-align:left}
html[data-view="classic"] td.red,html[data-view="classic"] tbody tr:nth-child(even) td.red{background-color:#cd2026;color:#fff}
html[data-view="classic"] td.green,html[data-view="classic"] tbody tr:nth-child(even) td.green{background-color:#4aa564;color:#212121}
html[data-view="classic"] td.amber,html[data-view="classic"] tbody tr:nth-child(even) td.amber{background-color:#f9c642;color:#212121}
html[data-view="classic"] td.grey,html[data-view="classic"] tbody tr:nth-child(even) td.grey{background-color:#d6d7d9;color:#212121}
html[data-view="classic"] .pill{border-radius:0;padding:1px 6px;border:1px solid currentColor}
html[data-view="classic"] .notes{gap:0}
html[data-view="classic"] .notes li{background:none;border:0;border-radius:0;padding:0 0 0 1.5em;position:relative}
html[data-view="classic"] .notes li:before{content:"\25BA";position:absolute;left:0;color:#cd2026}
html[data-view="classic"] .footer{border-top:1px solid #aeb0b5;display:block;line-height:1.8}
html[data-view="classic"] .empty-state{background:none;color:#212121;padding:0;font-weight:400}

@media (max-width:820px){
  .hero{padding:24px 0 64px}
  .hero h1{font-size:21px}
  .hero-inner{flex-direction:column}
  .bar-row{grid-template-columns:1fr;gap:5px}
  .bar-value{text-align:left}
  .bar-label{white-space:normal}
  .donut-wrap{justify-content:center}
  .legend{min-width:0;width:100%}
  .tab{padding:9px 12px;font-size:12.5px}
  .card{padding:16px 14px}
  .kpi-value{font-size:24px}
}
@media (max-width:520px){
  .donut{width:140px;height:140px}
  .filter input{max-width:none}
  .footer{flex-direction:column;gap:6px}
}

@media print{
  /* Backgrounds and colours are dropped by default when printing, which turns every status cell,
     pill and chart monochrome. Forcing exact colour adjustment on every element keeps the PDF readable. */
  *,*::before,*::after{
    -webkit-print-color-adjust:exact!important;
    print-color-adjust:exact!important;
    color-adjust:exact!important;
  }
  @page{size:A4 landscape;margin:10mm}
  body{background:#fff}
  .tabs,.hero-actions,.filter{display:none!important}
  .callout{page-break-inside:avoid}
  /* Every tab becomes a section of the printed document */
  .panel{display:block!important;page-break-before:always;animation:none}
  .panel:first-of-type{page-break-before:avoid}
  /* Classic view already stacks the panels, so it must not force a page break per section */
  html[data-view="classic"] .panel{page-break-before:auto}
  .wrap{max-width:none;padding:0 6mm 6mm}
  .hero{margin-bottom:8mm;padding:16px 0 20px;
    background:linear-gradient(120deg,#0b3f78 0%,#0f6cbd 45%,#6d28d9 100%)!important}
  .hero-inner{padding:0 6mm}
  .card,.kpi{box-shadow:none;break-inside:avoid;page-break-inside:avoid}
  .card{margin-bottom:12px;padding:0}
  .card h3{font-size:15px;margin-bottom:10px;padding-bottom:6px}
  .card h4{font-size:13px;margin:16px 0 8px;padding-top:10px}
  .card-grid{display:block}
  .card-grid .card{margin-bottom:14px}
  /* Tables must not be clipped by their scroll container on paper */
  .table-scroll{overflow:visible!important;border:1px solid var(--border)}
  .table-scroll>table{min-width:0!important;width:100%!important;font-size:10px}
  th,td{padding:5px 7px}
  tr,img,svg{break-inside:avoid;page-break-inside:avoid}
  a{text-decoration:none}
  a[href^="http"]::after{content:" (" attr(href) ")";font-size:9px;color:#6b7280;word-break:break-all}
  .donut,.trend{max-width:100%}
}
</style>
'@
}

function Get-mdiReportScript {
    @'
<script>
(function () {
  "use strict";
  var tabs = [].slice.call(document.querySelectorAll(".tab"));
  var panels = [].slice.call(document.querySelectorAll(".panel"));

  function activate(id, push) {
    tabs.forEach(function (t) { t.setAttribute("aria-selected", String(t.dataset.target === id)); });
    panels.forEach(function (p) { p.classList.toggle("active", p.id === id); });
    if (push && window.history && window.history.replaceState) {
      window.history.replaceState(null, "", "#" + id);
    }
  }
  function currentTab() {
    var selected = tabs.filter(function (t) { return t.getAttribute("aria-selected") === "true"; })[0];
    return selected ? selected.dataset.target : (panels[0] && panels[0].id);
  }
  tabs.forEach(function (t) {
    t.addEventListener("click", function () { activate(t.dataset.target, true); });
    t.addEventListener("keydown", function (e) {
      var i = tabs.indexOf(t), n = null;
      if (e.key === "ArrowRight") { n = tabs[(i + 1) % tabs.length]; }
      if (e.key === "ArrowLeft") { n = tabs[(i - 1 + tabs.length) % tabs.length]; }
      if (n) { e.preventDefault(); n.focus(); activate(n.dataset.target, true); }
    });
  });
  var initial = (window.location.hash || "").replace("#", "");
  activate(panels.some(function (p) { return p.id === initial; }) ? initial : (panels[0] && panels[0].id), false);

  // Free-text filter over every data row of the tables inside the same panel.
  // Rows containing a <th> are header rows and must never be hidden.
  [].slice.call(document.querySelectorAll(".filter input")).forEach(function (box) {
    box.addEventListener("input", function () {
      var q = box.value.toLowerCase();
      var scope = box.closest(".panel") || document;
      [].slice.call(scope.querySelectorAll("table tr")).forEach(function (row) {
        if (row.getElementsByTagName("th").length) { return; }
        row.style.display = (!q || row.textContent.toLowerCase().indexOf(q) !== -1) ? "" : "none";
      });
    });
  });

  var root = document.documentElement;
  var viewToggle = document.getElementById("viewToggle");

  function applyView(view) {
    root.setAttribute("data-view", view);
    if (viewToggle) {
      viewToggle.textContent = view === "classic" ? "Modern view" : "Classic view";
      viewToggle.setAttribute("aria-pressed", String(view === "classic"));
    }
    // Returning from classic view must restore a single visible panel
    if (view !== "classic") { activate(currentTab(), false); }
  }
  var storedView = null;
  try { storedView = window.localStorage.getItem("mdi-view"); } catch (e) { /* storage can be blocked */ }
  applyView(storedView === "classic" ? "classic" : "modern");
  if (viewToggle) {
    viewToggle.addEventListener("click", function () {
      var next = root.getAttribute("data-view") === "classic" ? "modern" : "classic";
      applyView(next);
      try { window.localStorage.setItem("mdi-view", next); } catch (e) { /* ignore */ }
    });
  }

  var printBtn = document.getElementById("printBtn");
  if (printBtn) { printBtn.addEventListener("click", function () { window.print(); }); }

  // Export every visible table of the active panel as a single CSV.
  // In classic view all panels are visible, so the whole report is exported.
  var csvBtn = document.getElementById("csvBtn");
  if (csvBtn) {
    csvBtn.addEventListener("click", function () {
      var isClassic = root.getAttribute("data-view") === "classic";
      var scope = isClassic ? document : document.querySelector(".panel.active");
      if (!scope) { return; }
      var out = [];
      [].slice.call(scope.querySelectorAll("table")).forEach(function (table, index) {
        if (index) { out.push(""); }
        [].slice.call(table.rows).forEach(function (row) {
          if (row.style.display === "none") { return; }
          var cells = [].slice.call(row.cells).map(function (cell) {
            return '"' + (cell.innerText || "").replace(/\s+/g, " ").trim().replace(/"/g, '""') + '"';
          });
          out.push(cells.join(","));
        });
      });
      if (!out.length) { return; }
      // A BOM keeps Excel happy with UTF-8 accented characters
      var blob = new Blob(["\uFEFF" + out.join("\r\n")], { type: "text/csv;charset=utf-8;" });
      var link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "mdi-" + (isClassic ? "report" : scope.id.replace("tab-", "")) + ".csv";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);
    });
  }
})();
</script>
'@
}

function Set-MdiReadinessReport {
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [object[]] $ReportData,
        [Parameter(Mandatory = $false)] [object] $Remediation = $null,
        [Parameter(Mandatory = $false)] [string] $BaselinePath = $null,
        [Parameter(Mandatory = $false)] [switch] $SkipTrend
    )

    $jsonReportFile = Join-Path -Path $Path -ChildPath "mdi-$Domain.json"
    Write-mdiVerbose "Creating detailed json report: $jsonReportFile"
    # -ErrorAction Stop, because Out-File's write failure is NON-terminating by default: a read-only
    # folder, a path that is a file, or a UNC share without write rights produced no report at all
    # while the script went on to print "READY" and a blank report path. Claiming success for a run
    # that wrote nothing is worse than failing.
    try {
        $ReportData | ConvertTo-Json -Depth 7 | Out-File -FilePath $jsonReportFile -Force -ErrorAction Stop
    } catch {
        throw ('Unable to write the JSON report to {0}: {1}' -f $jsonReportFile, $_.Exception.Message)
    }
    $jsonReportFilePath = (Resolve-Path -Path $jsonReportFile).Path

    $convertServerTable = {
        param($Servers, $SkippedMessage, $EmptyMessage)
        $serverList = @($Servers | Where-Object { $_ })
        if ($serverList.Count -gt 0) {
            # Collected from the objects rather than through Get-Member, which throws on an empty pipeline,
            # and which only saw properties present on the first object.
            $properties = [collections.arraylist] @($serverList | ForEach-Object { Get-mdiCheckProperty -Server $_ } |
                    Select-Object -ExpandProperty Name -Unique)
            $propsToAdd = @('SensorVersion', 'CapturingComponent', 'MachineType', 'Comment')
            if ($properties.Count -gt 0) {
                $properties.Insert(0, 'FQDN')
                [void] $properties.AddRange($propsToAdd)
            } else {
                $properties = [collections.arraylist]@('FQDN', 'Comment')
            }

            # A check that could not be read is not a failed check. It is rendered with the reason so the
            # reader is not sent to fix a setting that was never actually measured. A server that could
            # not be reached at all reports the same way for every one of its checks. A server that was
            # reached and then failed part way through is badged differently: its results are real, and
            # labelling it "not reachable" would tell the reader to ignore findings that are valid.
            $rows = @(foreach ($srv in ($serverList | Sort-Object FQDN)) {
                    $unreachable = [bool] $srv.Unreachable
                    $partial = (-not $unreachable) -and [bool] $srv.PartialFailure
                    $reason = if ($unreachable -or $partial) { [string] $srv.Comment } else { '' }
                    $ordered = [ordered]@{}
                    foreach ($p in $properties) {
                        $value = $srv.PSObject.Properties[$p]
                        $ordered[$p] = if ($null -eq $value) { $null } else { $value.Value }
                    }
                    [PSCustomObject]@{
                        Row         = [PSCustomObject] $ordered
                        Unreachable = $unreachable
                        Partial     = $partial
                        Reason      = $reason
                    }
                })

            $table = ((($rows | ForEach-Object { $_.Row } | ConvertTo-Html -Fragment) `
                        -replace ('<th>(?!FQDN)(?!{0})(\w+)' -f ($propsToAdd -join '|')), '<th><a href="https://aka.ms/mdi/$1">$1</a>') `
                    -replace '<td>True</td>', '<td class="green">True</td>') `
                -replace '<td>False</td>', '<td class="red">False</td>' `
                -join [environment]::NewLine

            $table = $table -replace '<th>FQDN</th>', '<th class="left">FQDN</th>'
            $table = $table -replace '<tr><td>', '<tr><td class="mono">'

            # 'Not tested' rather than 'N/A': the check did not return a neutral answer, it did not run.
            $table = $table -replace '<td>N/A</td>', '<td class="muted-cell" title="This check could not be read on this server, so its state is unknown">Not tested</td>'

            # A row for a server that never answered is marked once, so the reader can tell an unreachable
            # server from one that was tested and failed. A partial failure gets its own badge: those
            # results were measured and are worth acting on.
            foreach ($row in ($rows | Where-Object { $_.Unreachable -or $_.Partial })) {
                $fqdn = [string] $row.Row.FQDN
                $encoded = ConvertTo-mdiHtmlEncoded $fqdn
                $reasonText = ConvertTo-mdiHtmlEncoded $row.Reason
                $rowClass = if ($row.Unreachable) { 'unreachable' } else { 'partial' }
                $badgeText = if ($row.Unreachable) { 'not reachable' } else { 'partial results' }
                # The replacement side of -replace is a regex SUBSTITUTION string, where $&, $_, $1 and
                # ${name} are all meaningful. The reason is an operating system error message and can
                # legitimately contain them - "C:\$Recycle.Bin" or "see $_ for details" - which silently
                # corrupted the row. Escaping every $ as $$ makes the substitution literal. The pattern
                # side is already regex-escaped.
                $replacement = ('<tr class="{0}" title="{1}"><td class="mono">{2} <span class="badge-warn">{3}</span></td>' -f
                    $rowClass, $reasonText, $encoded, $badgeText).Replace('$', '$$')
                $table = $table -replace ('<tr><td class="mono">{0}</td>' -f [regex]::Escape($encoded)), $replacement
            }

            '<div class="table-scroll">' + $table + '</div>'
        } elseif ($SkippedMessage) {
            '<p class="muted">' + $SkippedMessage + '</p>'
        } else {
            '<p class="muted">' + $EmptyMessage + '</p>'
        }
    }

    $htmlDCs = & $convertServerTable $ReportData.DomainControllers $null 'No domain controllers found'
    $htmlCAs = & $convertServerTable $ReportData.CAServers $(if ($SkipCA) { 'CA servers validation skipped' }) 'No CA servers found'
    $htmlEntraConnect = & $convertServerTable $ReportData.EntraConnectServers $(if ($SkipEntraConnect) { 'Entra Connect servers validation skipped' }) 'No Entra Connect servers found'

    # One row per domain. These settings live on each domain's own naming context, so a forest scan that
    # showed a single row was reporting the root domain's configuration under a forest-wide heading.
    # The fallback covers a baseline or report produced before DomainAuditing existed.
    $domainAuditingRows = @($ReportData.DomainAuditing | Where-Object { $_ })
    if ($domainAuditingRows.Count -eq 0) {
        $domainAuditingRows = @([PSCustomObject]@{
                Domain           = $Domain
                ObjectAuditing   = $ReportData.DomainObjectAuditing
                ExchangeAuditing = $ReportData.DomainExchangeAuditing
                AdfsAuditing     = $ReportData.DomainAdfsAuditing
            })
    }
    # Built step by step rather than as one nested expression: the original was five levels of
    # parentheses deep, which is where an off-by-one bracket hides. ConvertTo-Html -Fragment returns an
    # array of lines, so each -replace applies element-wise and the join happens last, exactly as before.
    $dsTable = @($domainAuditingRows | Sort-Object Domain | Select-Object `
        @{N = 'Domain'; E = { $_.Domain } },
        @{N = 'ObjectAuditing'; E = { $_.ObjectAuditing.isObjectAuditingOk } },
        @{N = 'ExchangeAuditing'; E = { $_.ExchangeAuditing.isExchangeAuditingOk } },
        @{N = 'AdfsAuditing'; E = { $_.AdfsAuditing.isAdfsAuditingOk } } | ConvertTo-Html -Fragment)
    $dsTable = $dsTable -replace '<th>(?!Domain)(\w+)', '<th><a href="https://aka.ms/mdi/$1">$1</a>'
    $dsTable = $dsTable -replace '<td>True</td>', '<td class="green">True</td>'
    $dsTable = $dsTable -replace '<td>False</td>', '<td class="red">False</td>'
    $dsTable = $dsTable -replace '<th>Domain</th>', '<th class="left">Domain</th>'
    $dsTable = $dsTable -replace '<tr><td>', '<tr><td class="mono">'
    $htmlDS = '<div class="table-scroll">' + ($dsTable -join [environment]::NewLine) + '</div>'
    # Exchange and AD FS auditing report N/A when the forest has no Exchange or AD FS to audit. That is
    # "does not apply here", which is not the same as a check that failed, so it is not left as a bare
    # cell that reads like a gap in the results.
    $htmlDS = $htmlDS -replace '<td>N/A</td>', '<td class="grey" title="Not applicable: this role was not found in the forest">Not applicable</td>'

    $allServers = @(@($ReportData.DomainControllers) + @($ReportData.CAServers) + @($ReportData.EntraConnectServers) | Where-Object { $_ })

    $htmlPorts = if ($SkipNetworkPorts) {
        '<p class="muted">Network port validation skipped</p>'
    } else {
        Get-mdiRequiredPortsHtml -Server $allServers
    }

    $htmlSensorHealth = Get-mdiSensorHealthHtml -Server $allServers
    $htmlTimeSync = Get-mdiTimeSyncHtml -Server $allServers
    $htmlCapacity = Get-mdiCapacityHtml -Server @($ReportData.DomainControllers | Where-Object { $_ })

    $htmlSensorV3 = if ($SkipSensorV3Readiness) {
        '<p class="muted">Sensor v3.x readiness validation skipped</p>'
    } else {
        Get-mdiSensorV3Html -Server $allServers
    }

    $htmlRemediation = if ($Remediation -and $Remediation.SectionCount -gt 0) {
        $scriptName = Split-Path -Leaf $Remediation.Path
        '<p>A remediation script was generated for the findings that can be fixed automatically. It covers <b>' +
        [int] $Remediation.SectionCount + ' area(s)</b>.</p>' +
        '<p class="path-box">' + (ConvertTo-mdiHtmlEncoded $Remediation.Path) + '</p>' +
        '<p><b>Review every command before running it.</b> The script changes audit policy, registry values and firewall rules on domain controllers. Preview it first with <code>-WhatIf</code>:</p>' +
        '<pre class="code-block">.\' + (ConvertTo-mdiHtmlEncoded $scriptName) + ' -WhatIf   # preview' + [environment]::NewLine +
        '.\' + (ConvertTo-mdiHtmlEncoded $scriptName) + '           # apply</pre>' +
        '<p class="muted">Re-run Test-MdiReadiness.ps1 afterwards to confirm the findings are resolved.</p>'
    } elseif ($Remediation) {
        '<p class="empty-state">Nothing to remediate automatically: every check that this script can fix already passes.</p>'
    } else {
        # -RemediationScript is retained only for compatibility and does nothing; generation is
        # controlled by the ABSENCE of -SkipRemediationScript. Telling the reader to re-run with a
        # no-op switch sent them round the same loop with the same result.
        '<p class="muted">No remediation script was generated because this run used <code>-SkipRemediationScript</code>. Re-run without it to produce a ready-to-run <code>Fix-MdiReadiness-' +
        (ConvertTo-mdiHtmlEncoded $Domain) + '.ps1</code> containing the commands that fix the findings above (advanced audit policy, NTLM auditing, power scheme, Network Name Resolution firewall rules, stopped sensor services and clock resynchronisation).</p>'
    }

    $stats = Get-mdiReportStatistics -ReportData $ReportData
    $htmlOverview = Get-mdiOverviewHtml -Statistics $stats -ReportData $ReportData

    # History is recorded by default, next to the reports, so a second run always has something to
    # compare against. Left opt-in, the trend was almost never populated and the tab stayed empty.
    $trendPath = if ($SkipTrend) { $null } elseif ($BaselinePath) { $BaselinePath } else { $Path }

    $htmlTrend = if ($trendPath) {
        $baseline = Get-mdiBaselineHistory -BaselinePath $trendPath -Domain $Domain -Statistics $stats
        Write-mdiVerbose ('Baseline history: {0} ({1} run(s))' -f $baseline.Path, @($baseline.History).Count)
        New-mdiTrendChart -History $baseline.History
    } else {
        '<p class="muted">Trend tracking was disabled for this run with <code>-SkipTrend</code>. Without it, each run is recorded in the report folder and the chart shows how readiness evolves.</p>'
    }

    $htmlDeletedObjects = if ($ReportData.DomainDeletedObjects) {
        $status = $ReportData.DomainDeletedObjects.isDeletedObjectsPermissionOk
        $cls = if ($status -eq $true) { 'ok' } elseif ([string] $status -eq 'N/A') { 'na' } else { 'bad' }
        $label = if ($status -eq $true) { 'Pass' } elseif ([string] $status -eq 'N/A') { 'Informational' } else { 'Fail' }
        '<p><span class="pill ' + $cls + '">' + $label + '</span> ' +
        (ConvertTo-mdiHtmlEncoded ([string] $ReportData.DomainDeletedObjects.details.Detail)) + '</p>'
    } else {
        '<p class="muted">Not evaluated</p>'
    }

    $isReady = Test-mdiReadinessResult -ReportData $ReportData
    $verdictClass = if ($isReady) { 'ok' } else { 'bad' }
    $verdictText = if ($isReady) { 'All prerequisites met' } else { 'Action required' }
    $issueCount = @(Get-mdiIssueList -Statistics $stats -ReportData $ReportData).Count
    $issueBadge = if ($issueCount -gt 0) { '<span class="count bad">' + $issueCount + '</span>' } else { '' }
    $schemaText = if ($ReportData.DomainSchemaVersion.details) {
        '{0} (version {1})' -f [string] $ReportData.DomainSchemaVersion.details, [string] $ReportData.DomainSchemaVersion.schemaVersion
    } else { 'n/a' }

    $body = @'
<!DOCTYPE html>
<html lang="en" data-view="modern"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230f6cbd'/%3E%3Cpath d='M16 6l8 3.4v6.2c0 5-3.4 9.1-8 10.4-4.6-1.3-8-5.4-8-10.4V9.4L16 6z' fill='%23fff'/%3E%3C/svg%3E"/>
<title>MDI readiness report - @@DOMAIN@@</title>
@@STYLE@@
</head><body>
<header class="hero"><div class="hero-inner">
  <div>
    <div class="eyebrow">Microsoft Defender for Identity</div>
    <h1>Readiness report for @@DOMAIN@@</h1>
    <div class="sub">@@SERVERCOUNT@@ server(s) across @@DOMAINCOUNT@@ domain(s) &middot; generated @@TIMESTAMP@@</div>
    <div class="hero-actions">
      <button class="btn" id="viewToggle" type="button" aria-pressed="false">Classic view</button>
      <button class="btn" id="csvBtn" type="button">Export CSV</button>
      <button class="btn" id="printBtn" type="button">Print / PDF</button>
      <a class="btn" href="https://security.microsoft.com/settings/identities" target="_blank" rel="noopener">Defender portal</a>
    </div>
  </div>
  <div class="verdict @@VERDICTCLASS@@"><span class="dot"></span>@@VERDICTTEXT@@</div>
</div></header>

<div class="wrap">
<nav class="tabs" role="tablist">
  <button class="tab" role="tab" data-target="tab-overview" aria-selected="true">Overview @@ISSUEBADGE@@</button>
  <button class="tab" role="tab" data-target="tab-dcs">Domain controllers <span class="count">@@DCCOUNT@@</span></button>
  <button class="tab" role="tab" data-target="tab-ports">Network ports</button>
  <button class="tab" role="tab" data-target="tab-v3">Sensor v3.x</button>
  <button class="tab" role="tab" data-target="tab-capacity">Capacity</button>
  <button class="tab" role="tab" data-target="tab-trend">Trend</button>
  <button class="tab" role="tab" data-target="tab-services">Domain services</button>
  <button class="tab" role="tab" data-target="tab-notes">Remediation</button>
</nav>

<section class="panel active" id="tab-overview">
@@OVERVIEW@@
</section>

<section class="panel" id="tab-dcs">
  <div class="card wide"><h3>Domain controllers</h3>
  <p class="section-intro">Every domain controller found in scope, with the outcome of each prerequisite check. Column headings link to the matching Microsoft documentation.</p>
  <div class="filter"><input type="search" placeholder="Filter domain controllers&hellip;" aria-label="Filter domain controllers"/></div>
  @@DCS@@
  </div>
  <div class="card wide"><h3>Sensor health</h3>
  <p class="section-intro">State of the Defender for Identity sensor v2.x services. A sensor that is installed but <b>stopped or disabled</b> still appears deployed in the Defender portal while reporting no data, so it is surfaced separately from the prerequisite checks.</p>
  @@SENSORHEALTH@@
  </div>
  <div class="card wide"><h3>Time synchronization</h3>
  <p class="section-intro">Defender for Identity requires every sensor server to have its clock synchronized to within <b>five minutes</b> of the others. The skew below is measured against the computer that ran this script.</p>
  @@TIMESYNC@@
  </div>
</section>

<section class="panel" id="tab-ports">
  <div class="card wide"><h3>Required network ports</h3>
  <p class="section-intro">Probes run <b>on each sensor server</b>, so they test the real sensor&nbsp;&rarr;&nbsp;target direction. UDP ports are validated with a genuine protocol request (NBSTAT on 137, a DNS query on 53, a CLDAP rootDSE search on 389). See the <a href="https://learn.microsoft.com/defender-for-identity/deploy/prerequisites-sensor-version-2#required-ports">required ports</a> documentation.</p>
  <div class="filter"><input type="search" placeholder="Filter ports and targets&hellip;" aria-label="Filter ports"/></div>
  @@PORTS@@
  </div>
</section>

<section class="panel" id="tab-v3">
  <div class="card wide"><h3>Sensor v3.x upgrade readiness</h3>
  <p class="section-intro">The sensor v3.x runs on <b>domain controllers</b> running <b>Windows Server 2019 or later</b> with the <b>July 2026 or later cumulative update</b>, and requires <b>Microsoft Defender for Endpoint to be onboarded</b> on the server. It doesn't use a Directory Service Account or gMSA, doesn't need Npcap, and doesn't support VPN integration or syslog notifications. Servers that aren't domain controllers but run AD FS, AD CS or Microsoft Entra Connect must keep using the <a href="https://learn.microsoft.com/defender-for-identity/deploy/prerequisites-sensor-version-2">sensor v2.x</a>. For the in-place migration, see <a href="https://learn.microsoft.com/defender-for-identity/deploy/migrate-to-sensor-v3">Migrate from sensor v2.x to sensor v3.x</a>.</p>
  @@SENSORV3@@
  </div>
</section>

<section class="panel" id="tab-capacity">
  <div class="card wide"><h3>Capacity planning</h3>
  <p class="section-intro">Estimates whether each domain controller has enough resources for a <b>sensor v2.x</b>, by sampling its network packet rate and mapping the busiest window to the published sizing table. The <b>v3.x sensor does not need a sizing exercise</b> &mdash; it relies on Windows events and event tracing, which greatly reduces its resource requirements. Only domain controllers are sized; standalone AD FS, AD CS and Microsoft Entra Connect servers have negligible sensor impact.</p>
  @@CAPACITY@@
  </div>
</section>

<section class="panel" id="tab-trend">
  <div class="card wide"><h3>Readiness trend</h3>
  <p class="section-intro">Percentage of prerequisite checks passing across the estate on each recorded run. Use the same <code>-BaselinePath</code> on every run to build history &mdash; useful for tracking progress through a remediation or a sensor v3.x migration.</p>
  @@TREND@@
  </div>
</section>

<section class="panel" id="tab-services">
  <div class="card wide"><h3>Domain services readiness</h3>@@DS@@</div>
  <div class="card wide"><h3>Deleted Objects container permissions</h3>
  <p class="section-intro">The Directory Service Account must be able to read the <i>Deleted Objects</i> container so Defender for Identity can resolve deleted entities. See <a href="https://aka.ms/mdi/dsa-permissions">aka.ms/mdi/dsa-permissions</a>.</p>
  @@DELETEDOBJECTS@@
  </div>
  <div class="card wide"><h3>Certificate Authority servers</h3>@@CAS@@</div>
  <div class="card wide"><h3>Microsoft Entra Connect servers</h3>@@ENTRACONNECT@@</div>
</section>

<section class="panel" id="tab-notes">
  <div class="card wide"><h3>Remediation script</h3>
  @@REMEDIATION@@
  </div>
  <div class="card wide"><h3>Checks this script cannot perform</h3>
  <ul class="notes">
    <li>For VMware virtualized machines, verify that the memory is allocated to the virtual machine at all times, and that <i>Large Send Offload (LSO)</i> is disabled.</li>
    <li>The network port tests validate the sensor servers only. Verify that the required ports are also open for inbound communication from the sensor servers on <b>all the other devices</b> in the network. See <a href="https://aka.ms/mdi/NNR">aka.ms/mdi/NNR</a>.</li>
    <li>Verify that the <i>Restrict clients allowed to make remote calls to SAM</i> policy is configured as required. See <a href="https://aka.ms/mdi/SAMR">aka.ms/mdi/SAMR</a>.</li>
    <li>Verify that the Directory Services Account (DSA) configured for the domain has read permissions on the <i>Deleted Objects Container</i>. See <a href="https://aka.ms/mdi/dsa-permissions">aka.ms/mdi/dsa-permissions</a>.</li>
  </ul></div>
</section>

<div class="footer">
  <span>Forest <b>@@FOREST@@</b></span>
  <span>Schema <b>@@SCHEMA@@</b></span>
  <span>Full details <a href="@@JSONPATH@@">@@JSONFILE@@</a></span>
  <span>Generated by <a href="https://aka.ms/mdi/Test-MdiReadiness">Test-MdiReadiness.ps1</a> @@VERSION@@ on @@TIMESTAMP@@</span>
</div>
<p class="disclaimer"><b>Personal project &mdash; not an official Microsoft product.</b> This report was produced by an unofficial, modified version of Test-MdiReadiness.ps1. It is not an official Microsoft product, is not endorsed or approved by Microsoft, and is not covered by any Microsoft support agreement. It is provided "as is", with no warranty and no liability of any kind, and its findings must be verified against the current <a href="https://learn.microsoft.com/defender-for-identity/">official documentation</a> before you act on them. Use at your own risk.</p>
</div>
@@SCRIPT@@
</body></html>
'@

    # Literal token replacement rather than the format operator: the CSS and JavaScript blocks are full of braces,
    # which the format operator would try to interpret as placeholders.
    $htmlContent = $body.
    Replace('@@STYLE@@', (Get-mdiReportStyle)).
    Replace('@@SCRIPT@@', (Get-mdiReportScript)).
    Replace('@@OVERVIEW@@', $htmlOverview).
    Replace('@@DCS@@', $htmlDCs).
    Replace('@@PORTS@@', $htmlPorts).
    Replace('@@SENSORV3@@', $htmlSensorV3).
    Replace('@@DS@@', $htmlDS).
    Replace('@@SENSORHEALTH@@', $htmlSensorHealth).
    Replace('@@CAPACITY@@', $htmlCapacity).
    Replace('@@TIMESYNC@@', $htmlTimeSync).
    Replace('@@REMEDIATION@@', $htmlRemediation).
    Replace('@@TREND@@', $htmlTrend).
    Replace('@@DELETEDOBJECTS@@', $htmlDeletedObjects).
    Replace('@@CAS@@', $htmlCAs).
    Replace('@@ENTRACONNECT@@', $htmlEntraConnect).
    Replace('@@DOMAIN@@', (ConvertTo-mdiHtmlEncoded $Domain)).
    Replace('@@FOREST@@', (ConvertTo-mdiHtmlEncoded ([string] $ReportData.Forest))).
    Replace('@@SCHEMA@@', (ConvertTo-mdiHtmlEncoded $schemaText)).
    Replace('@@SERVERCOUNT@@', [string] $stats.TotalServers).
    Replace('@@DOMAINCOUNT@@', [string] $stats.DomainCount).
    Replace('@@DCCOUNT@@', [string] @($ReportData.DomainControllers).Count).
    Replace('@@ISSUEBADGE@@', $issueBadge).
    Replace('@@VERDICTCLASS@@', $verdictClass).
    Replace('@@VERDICTTEXT@@', $verdictText).
    Replace('@@JSONPATH@@', (ConvertTo-mdiHtmlEncoded $jsonReportFilePath)).
    Replace('@@JSONFILE@@', (ConvertTo-mdiHtmlEncoded (Split-Path -Leaf $jsonReportFilePath))).
    Replace('@@VERSION@@', (ConvertTo-mdiHtmlEncoded ('v' + [string] $settings.ScriptVersion))).
    Replace('@@TIMESTAMP@@', (ConvertTo-mdiHtmlEncoded ([datetime]::Now.ToString('yyyy-MM-dd HH:mm'))))

    $htmlReportFile = Join-Path -Path $Path -ChildPath "mdi-$Domain.html"
    Write-mdiVerbose "Creating html report: $htmlReportFile"
    try {
        $htmlContent | Out-File -FilePath $htmlReportFile -Force -Encoding utf8 -ErrorAction Stop
    } catch {
        throw ('Unable to write the HTML report to {0}: {1}' -f $htmlReportFile, $_.Exception.Message)
    }
    (Resolve-Path -Path $htmlReportFile).Path
}

function Test-mdiReadinessResult {
    param (
        [Parameter(Mandatory = $true)] [object[]] $ReportData
    )

    # Each collection is wrapped separately: when a domain has exactly one server the property is a bare
    # PSObject rather than an array, and PSObject + PSObject throws "does not contain a method named
    # op_Addition". Wrapping first makes every operand an array so the concatenation is always valid.
    $servers = @(@($ReportData.DomainControllers) + @($ReportData.CAServers) + @($ReportData.EntraConnectServers) |
            Where-Object { $_ })

    # Nothing scanned is not a pass. An empty collection makes ($empty -ne $true).Count equal 0, which
    # reads as "no check failed" and returns ready for a run that checked nothing at all. Discovery
    # failing is the very case where a false green is most damaging.
    if ($servers.Count -eq 0) { return $false }

    # Get-Member throws on an empty pipeline, so the boolean check names are collected from the objects
    # themselves. This also picks up checks that only exist on CA or Entra Connect servers, which the
    # previous domain-controller-only projection missed.
    $properties = @($servers | ForEach-Object { Get-mdiCheckProperty -Server $_ } |
            Select-Object -ExpandProperty Name -Unique)

    $serversOk = @(foreach ($server in $servers) {
            $properties | ForEach-Object {
                $server | Select-Object -ExpandProperty $_ -ErrorAction SilentlyContinue
            }
        })

    # A server that could not be reached carries the Unreachable flag and no checks, so it must fail the
    # run rather than pass silently by having contributed nothing to measure. A server that WAS reached
    # and then failed one check part way through also carries a Comment, but keeps whatever it measured,
    # so it is judged on those results rather than being written off.
    $unreachable = @($servers | Where-Object { $_.Unreachable })

    # A check that could not be measured is recorded as 'N/A' rather than false, so that an unread
    # setting is not reported as a broken one. That means a server can answer reachability, fail every
    # read, and end up with no boolean checks at all - which would otherwise pass for the same reason an
    # empty forest did. Nothing measured is not the same as nothing wrong.
    $measured = @($servers | Where-Object {
            @(Get-mdiCheckProperty -Server $_).Count -gt 0
        })
    $unmeasured = $servers.Count - $measured.Count

    # Partially measured servers count too. A server with one readable check out of seven is not ready,
    # it is unknown, and calling the run READY on the strength of the one check that happened to work
    # is exactly the false green this whole tri-state exists to prevent. Descriptive fields are excluded
    # by the helper, because 'N/A' there is an answer rather than a gap.
    $unreadChecks = @($servers | ForEach-Object { Get-mdiUnreadCheckCount -Server $_ } |
            Measure-Object -Sum).Sum
    if ($null -eq $unreadChecks) { $unreadChecks = 0 }

    # Compared against 'False' explicitly: these are tri-state too, and 'N/A' is truthy, so a domain check
    # that could not be read used to satisfy the verdict silently. 'N/A' here means the role is absent
    # from the domain - no Exchange, no AD FS - which is a legitimate pass, so it is accepted, but a
    # $false is not. Every domain in scope is judged, not only the one the run was aimed at: these
    # settings are per-domain, and a child domain with no auditing is a blind spot for the sensor.
    $auditedDomains = @($ReportData.DomainAuditing | Where-Object { $_ })
    if ($auditedDomains.Count -eq 0) {
        # A report from before DomainAuditing existed, or a single-domain run.
        $auditedDomains = @([PSCustomObject]@{
                AdfsAuditing     = $ReportData.DomainAdfsAuditing
                ObjectAuditing   = $ReportData.DomainObjectAuditing
                ExchangeAuditing = $ReportData.DomainExchangeAuditing
            })
    }
    $domainChecksOk = @($auditedDomains | Where-Object {
            ([string] $_.AdfsAuditing.isAdfsAuditingOk -eq 'False') -or
            ([string] $_.ObjectAuditing.isObjectAuditingOk -eq 'False') -or
            ([string] $_.ExchangeAuditing.isExchangeAuditingOk -eq 'False')
        }).Count -eq 0

    # A domain check that could not be READ is not a pass. 'N/A' carries two meanings here: "this role
    # is not present in the forest", which is a legitimate pass, and "the SACL could not be read" -
    # access denied, SeSecurityPrivilege missing, the domain unreachable - which is unknown. Only the
    # Measured flag tells them apart, and without this a forest run against a child domain where the
    # account lacks audit-read rights reported READY over a domain nobody had actually verified. That
    # is the same false green the tri-state exists to prevent, and the per-domain loop multiplies the
    # chances of hitting it. Reports written before Measured existed have no flag and are accepted.
    $unmeasuredDomains = @($auditedDomains | Where-Object {
            ($null -ne $_.PSObject.Properties['AdfsAuditingMeasured'] -and $_.AdfsAuditingMeasured -eq $false) -or
            ($null -ne $_.PSObject.Properties['ObjectAuditingMeasured'] -and $_.ObjectAuditingMeasured -eq $false) -or
            ($null -ne $_.PSObject.Properties['ExchangeAuditingMeasured'] -and $_.ExchangeAuditingMeasured -eq $false)
        })
    if ($unmeasuredDomains.Count -gt 0) {
        Write-Warning ('The directory auditing configuration could not be read for {0} domain(s): {1}. They are reported as not verified rather than as passing.' -f
            $unmeasuredDomains.Count, (@($unmeasuredDomains | ForEach-Object { [string] $_.Domain }) -join ', '))
    }

    # A domain in scope that produced no servers at all was never examined. It contributes no failures
    # precisely because nothing was measured there, so without this the run could report READY over a
    # domain it had never reached - the same false green as an empty scan, only harder to spot because
    # the other domains look fine. Servers from before the Domain property existed are ignored here
    # rather than treated as belonging to no domain.
    $scopedDomains = @($ReportData.DomainsInScope | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
    $representedDomains = @($servers | ForEach-Object { [string] $_.Domain } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    $domainsExamined = if ($representedDomains.Count -eq 0) {
        $true
    } else {
        @($scopedDomains | Where-Object { $_ -notin $representedDomains }).Count -eq 0
    }
    if (-not $domainsExamined) {
        Write-Warning ('These domains were in scope but produced no servers, so they were not examined: {0}' -f
            (@($scopedDomains | Where-Object { $_ -notin $representedDomains }) -join ', '))
    }

    # A -Forest run that could not enumerate the forest fell back to a single domain. The report still
    # says "Forest", so reporting READY would be a pass over every other domain in it.
    $forestComplete = $true
    if ($null -ne $ReportData.ForestDiscovery -and
        $null -ne $ReportData.ForestDiscovery.PSObject.Properties['Complete']) {
        $forestComplete = [string] $ReportData.ForestDiscovery.Complete -ne 'False'
    }

    $return = (($serversOk -ne $true).Count -eq 0) -and
    ($unreachable.Count -eq 0) -and
    ($unmeasured -eq 0) -and
    ($unreadChecks -eq 0) -and
    ($unmeasuredDomains.Count -eq 0) -and
    $domainsExamined -and
    $forestComplete -and
    $domainChecksOk

    [bool] $return
}

#endregion

#region Main

# These pairs used to be expressed as parameter sets, which made PowerShell reject any command line
# that touched two of them: -SkipCA together with -SkipEntraConnect failed with "Parameter set cannot
# be resolved", as did -CAServer together with -EntraConnectServer. Only the genuine conflicts are
# rejected here, so every sensible combination is accepted.
if ($CAServer -and $SkipCA) {
    throw 'Use either -CAServer or -SkipCA, not both.'
}
if ($EntraConnectServer -and $SkipEntraConnect) {
    throw 'Use either -EntraConnectServer or -SkipEntraConnect, not both.'
}

# An explicit server list describes ONE domain, so combining it with -Forest is a contradiction. The
# forest branch quietly replaced each list with $null, so the scan ran across every domain and the
# names the caller supplied were never used - and nothing said so. A silently ignored parameter that
# the operator believes narrowed the scan is worse than an error.
$explicitLists = @(
    @{ Name = '-DomainController'; Value = $DomainController }
    @{ Name = '-CAServer'; Value = $CAServer }
    @{ Name = '-EntraConnectServer'; Value = $EntraConnectServer }
) | Where-Object { @($_.Value | Where-Object { $_ }).Count -gt 0 }
if ($Forest -and @($explicitLists).Count -gt 0) {
    throw ('{0} name one domain''s servers and cannot be combined with -Forest. Run without -Forest to scope the scan, or without the server list to scan the whole forest.' -f
        (@($explicitLists.Name) -join ', '))
}

# Port-related switches are only read while building the probe plan, which -SkipNetworkPorts skips
# entirely. Warned rather than rejected: -SkipNetworkPorts is a legitimate way to shorten a run, and
# these may simply be left over on the command line - but the operator must not believe NNR or RADIUS
# was validated when port probing was off.
if ($SkipNetworkPorts) {
    $ignored = @(
        @{ Name = '-NnrTargetComputer'; Set = @($NnrTargetComputer | Where-Object { $_ }).Count -gt 0 }
        @{ Name = '-TestVpnRadius'; Set = [bool] $TestVpnRadius }
        @{ Name = '-MultiForest'; Set = [bool] $MultiForest }
        @{ Name = '-PortProbeTimeoutMs'; Set = $PSBoundParameters.ContainsKey('PortProbeTimeoutMs') }
        @{ Name = '-MaxNnrTargets'; Set = $PSBoundParameters.ContainsKey('MaxNnrTargets') }
        @{ Name = '-MaxLdapTargetsPerDomain'; Set = $PSBoundParameters.ContainsKey('MaxLdapTargetsPerDomain') }
    ) | Where-Object { $_.Set }
    if (@($ignored).Count -gt 0) {
        Write-Warning ('-SkipNetworkPorts disables all port probing, so {0} will have no effect on this run.' -f
            (@($ignored.Name) -join ', '))
    }
}

if ($SkipTrend -and $PSBoundParameters.ContainsKey('BaselinePath')) {
    Write-Warning '-SkipTrend disables trend tracking, so -BaselinePath will not be read or written on this run.'
}

if (-not $Domain) { $Domain = $env:USERDNSDOMAIN }
if (-not $Domain) {
    # USERDNSDOMAIN is only populated for an interactive user logon. It is empty under SYSTEM, under a
    # scheduled task, and in a service context, so a run from any of those aborted before doing anything
    # even on a perfectly good domain member. The computer's own domain membership is the reliable
    # source, and the directory is asked only as a last resort.
    try {
        $computerSystem = Get-WmiObject -Class 'Win32_ComputerSystem' -Property 'Domain', 'PartOfDomain' -ErrorAction Stop
        if ($computerSystem.PartOfDomain) { $Domain = [string] $computerSystem.Domain }
    } catch {
        Write-Verbose ('Unable to read the computer domain from WMI: {0}' -f $_.Exception.Message)
    }
}
if (-not $Domain) {
    try {
        $Domain = [string] ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    } catch {
        Write-Verbose ('Unable to determine the current domain from the directory: {0}' -f $_.Exception.Message)
    }
}
if (-not $Domain) {
    throw 'Unable to determine the domain to work against. Use the -Domain parameter to specify it.'
}

$targetDescription = if ($Forest) { 'the forest of {0}' -f $Domain } else { $Domain }
if ($PSCmdlet.ShouldProcess($targetDescription, 'Create MDI related configuration reports')) {

    # The output folder is created up front. -BaselinePath already did this, but -Path did not, so
    # pointing it at a folder that does not exist yet ran the entire scan and then threw
    # "Could not find a part of the path" while writing the report, losing every result.
    if (Test-Path -Path $Path) {
        # Test-Path alone is satisfied by a FILE, so -Path pointing at one skipped creation, ran the
        # whole scan, and then failed to write every report into a path that is not a folder.
        if (-not (Test-Path -Path $Path -PathType Container)) {
            throw ('The output path {0} is a file. -Path must be a folder.' -f $Path)
        }
    } else {
        try {
            [void] (New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop)
            Write-mdiVerbose ('Created the output folder {0}' -f $Path)
        } catch {
            throw ('Unable to create the output folder {0}: {1}' -f $Path, $_.Exception.Message)
        }
    }

    # Write access is proven before the scan rather than after it. A read-only or unwritable folder
    # otherwise cost the operator the entire run - potentially many minutes across a large forest -
    # only to fail at the very last step with nothing kept.
    try {
        $probeFile = Join-Path -Path $Path -ChildPath ('.mdi-write-test-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
        [void] (New-Item -ItemType File -Path $probeFile -Force -ErrorAction Stop)
        Remove-Item -Path $probeFile -Force -ErrorAction SilentlyContinue
    } catch {
        throw ('The output folder {0} is not writable: {1}' -f $Path, $_.Exception.Message)
    }

    $forestInfo = if ($Forest) {
        Get-mdiForestDomain -Domain $Domain
    } else {
        [PSCustomObject]@{ Name = $Domain; Domains = @($Domain); Method = 'Parameter'; Complete = $true; Error = $null }
    }
    $domainsInScope = @($forestInfo.Domains)

    $portProbePlan = $null
    if (-not $SkipNetworkPorts) {
        Write-mdiVerbose 'Building the network port probe plan'
        # Every sensor must be able to reach every domain controller over LDAP, so the inventory is collected once for
        # the whole scope and shared by all the probes.
        $dcInventory = @(Get-mdiDomainControllerInventory -Domain $domainsInScope)
        Write-mdiVerbose ('Found {0} domain controller(s) in {1} domain(s)' -f $dcInventory.Count, $domainsInScope.Count)

        $ldapTargets = Resolve-mdiLdapTarget -DomainControllers $dcInventory -MaxPerDomain $MaxLdapTargetsPerDomain
        Write-mdiVerbose ('Using {0} LDAP target(s): {1}' -f @($ldapTargets).Count, (@($ldapTargets | ForEach-Object { $_.Name }) -join ', '))

        $nnrTargets = Resolve-mdiNnrTarget -DomainControllers $dcInventory -NnrTargetComputer $NnrTargetComputer `
            -Domain $Domain -MaxTargets $MaxNnrTargets
        Write-mdiVerbose ('Using {0} Network Name Resolution target(s): {1}' -f @($nnrTargets).Count, (@($nnrTargets | ForEach-Object { $_.Name }) -join ', '))
        if (-not $NnrTargetComputer) {
            Write-mdiVerbose 'Tip: use -NnrTargetComputer to also validate NNR against workstations and member servers'
        }

        $portProbePlan = New-mdiPortProbePlan -Domain $Domain -DomainController $ldapTargets -NnrTarget $nnrTargets `
            -WorkspaceName $WorkspaceName -TimeoutMs $PortProbeTimeoutMs -MultiForest:$MultiForest -TestVpnRadius:$TestVpnRadius
    }

    # The domain-level checks are per DOMAIN, not per forest: object auditing, Exchange auditing, AD FS
    # auditing and the Deleted Objects permission are all configured on each domain's own naming context.
    # Running them once against the root domain and presenting the answer under a forest-wide heading
    # reported a child domain as audited when nothing had been configured there at all - a green report
    # over a domain the sensor cannot see events in. Each domain is evaluated separately, and one domain
    # that cannot be read does not stop the others.
    $domainAuditing = @(foreach ($domainName in $domainsInScope) {
            Write-mdiVerbose "Testing the directory services configuration of $domainName"
            $entry = [ordered]@{ Domain = $domainName }
            # The status property name is carried per item rather than derived from the key. Building it
            # as ('is{0}Ok' -f $key) happened to be right for the three auditing checks and wrong for the
            # other two - 'isDeletedObjectsOk' instead of 'isDeletedObjectsPermissionOk' - so on a read
            # failure the consumer found $null and rendered a red "Fail" for a permission that had merely
            # not been read. Unreadable is not the same as misconfigured; that distinction is the whole
            # point of the tri-state.
            foreach ($item in @(
                    @{ Key = 'AdfsAuditing'; Status = 'isAdfsAuditingOk'; Script = { Get-mdiAdfsAuditing -Domain $domainName } },
                    @{ Key = 'ObjectAuditing'; Status = 'isObjectAuditingOk'; Script = { Get-mdiObjectAuditing -Domain $domainName -DomainSchemaVersion (Get-DomainSchemaVersion -Domain $domainName).schemaVersion } },
                    @{ Key = 'ExchangeAuditing'; Status = 'isExchangeAuditingOk'; Script = { Get-mdiExchangeAuditing -Domain $domainName } },
                    @{ Key = 'DeletedObjects'; Status = 'isDeletedObjectsPermissionOk'; Script = { Get-mdiDeletedObjectsPermission -Domain $domainName -DirectoryServiceAccount $DirectoryServiceAccount } },
                    @{ Key = 'SchemaVersion'; Status = $null; Script = { Get-DomainSchemaVersion -Domain $domainName } }
                )) {
                try {
                    $entry[$item.Key] = & $item.Script
                    $entry[($item.Key + 'Measured')] = $true
                } catch {
                    # 'N/A' rather than $false: the setting was not read, so it is unknown, not wrong.
                    # Measured records WHY it is 'N/A', because the same value also legitimately means
                    # "this role is not present in the forest", which is a pass rather than a gap.
                    Write-Warning ('Could not read {0} for {1}: {2}' -f $item.Key, $domainName, $_.Exception.Message)
                    $failure = [ordered]@{}
                    if ($item.Status) { $failure[$item.Status] = 'N/A' }
                    # details is an object with a Detail property on the success path, and the report
                    # reads details.Detail - a bare string here rendered as empty.
                    $failure['details'] = [PSCustomObject]@{
                        Detail = ('Could not be read: {0}' -f $_.Exception.Message)
                    }
                    $failure['schemaVersion'] = 'N/A'
                    $entry[$item.Key] = [PSCustomObject] $failure
                    $entry[($item.Key + 'Measured')] = $false
                }
            }
            [PSCustomObject] $entry
        })

    # The single-domain properties are kept and point at the domain the run was aimed at, so a baseline
    # taken with an earlier version still compares against the same value it recorded.
    $primaryAuditing = @($domainAuditing | Where-Object { $_.Domain -eq $Domain })[0]
    if ($null -eq $primaryAuditing) { $primaryAuditing = @($domainAuditing)[0] }

    $report = @{
        ScriptVersion          = $settings.ScriptVersion
        Domain                 = if ($Forest) { $forestInfo.Name } else { $Domain }
        Forest                 = $forestInfo.Name
        ForestDiscovery        = $forestInfo
        DomainsInScope         = $domainsInScope
        DomainControllers      = @(foreach ($domainName in $domainsInScope) {
                Write-mdiVerbose "Testing the domain controllers of $domainName"
                Get-mdiDomainControllerReadiness -Domain $domainName `
                    -DomainController $(if ($Forest) { $null } else { $DomainController }) -PortProbePlan $portProbePlan `
                    -TestSensorV3Readiness:(-not $SkipSensorV3Readiness) `
                    -CapacityPlan $(if ($CapacityPlanning) {
                        [PSCustomObject]@{ DurationSeconds = $CapacityPlanningDuration; IntervalSeconds = $CapacityPlanningInterval }
                    } else { $null })
            })
        DomainAuditing         = $domainAuditing
        DomainAdfsAuditing     = $primaryAuditing.AdfsAuditing
        DomainObjectAuditing   = $primaryAuditing.ObjectAuditing
        DomainExchangeAuditing = $primaryAuditing.ExchangeAuditing
        DomainDeletedObjects   = $primaryAuditing.DeletedObjects
        DomainSchemaVersion    = $primaryAuditing.SchemaVersion
    }
    if (-not $SkipCA) {
        $report.CAServers = @(foreach ($domainName in $domainsInScope) {
                Get-mdiCAReadiness -Domain $domainName -CAServer $(if ($Forest) { $null } else { $CAServer }) `
                    -PortProbePlan $portProbePlan -TestSensorV3Readiness:(-not $SkipSensorV3Readiness)
            })
    }
    if (-not $SkipEntraConnect) {
        $report.EntraConnectServers = @(foreach ($domainName in $domainsInScope) {
                Get-mdiEntraConnectReadiness -Domain $domainName `
                    -EntraConnectServer $(if ($Forest) { $null } else { $EntraConnectServer }) `
                    -PortProbePlan $portProbePlan -TestSensorV3Readiness:(-not $SkipSensorV3Readiness)
            })
    }

    # The remediation script is generated before the report so the report can link to it. It is produced
    # on every run because it is only ever written, never executed, and left opt-in it was rarely
    # discovered. -SkipRemediationScript suppresses it when nothing should be written beside the report.
    $remediation = $null
    if (-not $SkipRemediationScript) {
        $remediationFile = Join-Path -Path $Path -ChildPath ('Fix-MdiReadiness-{0}.ps1' -f $report.Domain)
        $remediation = New-mdiRemediationScript -ReportData $report -FilePath $remediationFile
        if ($remediation.SectionCount -gt 0) {
            Write-Warning ('Remediation script written to {0} with {1} section(s). Review it before running.' -f $remediation.Path, $remediation.SectionCount)
        } else {
            Write-mdiVerbose ('Remediation script written to {0} (nothing to remediate)' -f $remediation.Path)
        }
    }

    $htmlReportFile = Set-MdiReadinessReport -Domain $report.Domain -Path $Path -ReportData $report `
        -Remediation $remediation -BaselinePath $BaselinePath -SkipTrend:$SkipTrend

    $result = Test-mdiReadinessResult -ReportData $report

    if ($OpenHtmlReport) { Invoke-Item -Path $htmlReportFile }

    # A bare True or False at the end of a long run reads like an error rather than a verdict, so the
    # outcome is summarised for a human and the boolean is only put on the pipeline when it is asked
    # for. -FailOnIssues covers the case where a caller only needs a pass or fail signal.
    $stats = Get-mdiReportStatistics -ReportData $report
    # Counted from the same list the HTML report renders, so the two can never disagree. Deriving it
    # from (ChecksTotal - ChecksPassed) counted FAILED CHECKS while the report listed FINDINGS, and one
    # failed RequiredPorts check expands into one finding per blocked port and per unresolvable NNR
    # target - so the console consistently understated the work, on every report with a port problem.
    $issueCount = @(Get-mdiIssueList -Statistics $stats -ReportData $report).Count
    # How much of the estate was actually readable. A run where access was denied almost everywhere used
    # to print "0 issue(s) found: 5/5 checks passed", because only the checks that could be measured were
    # counted. That reads as a clean bill of health for a scan that saw almost nothing, which is the most
    # misleading output this tool can produce.
    $unreadCount = [int] $stats.ChecksUnread
    if ($stats.TotalServers -eq 0) {
        # Reporting "0/0 checks passed" as a readiness verdict invites the reader to treat a failed run
        # as a finished one. The run did not fail to find problems, it failed to look.
        Write-Host ''
        Write-Host '  SCAN INCOMPLETE  No server could be enumerated, so nothing was checked.' -ForegroundColor Red
        Write-Host '  This is not a readiness result. Check that this computer can reach a domain controller,' -ForegroundColor Red
        Write-Host '  that the account running the script may read the directory, and re-run.' -ForegroundColor Red
    } elseif ($result) {
        Write-Host ''
        Write-Host ('  READY  {0}/{1} checks passed across {2} server(s).' -f
            $stats.ChecksPassed, $stats.ChecksTotal, $stats.TotalServers) -ForegroundColor Green
    } else {
        Write-Host ''
        Write-Host ('  {0} issue(s) found: {1}/{2} checks passed across {3} server(s).' -f
            $issueCount, $stats.ChecksPassed, $stats.ChecksTotal, $stats.TotalServers) -ForegroundColor Yellow
        Write-Host '  Open the report and start with the Issues found table on the Overview tab.' -ForegroundColor Yellow
    }
    if ($unreadCount -gt 0 -and $stats.TotalServers -gt 0) {
        Write-Host ('  {0} check(s) could not be read at all, so this is only a partial picture.' -f $unreadCount) -ForegroundColor Red
        Write-Host '  The usual cause is that the account running this script cannot query those servers' -ForegroundColor Red
        Write-Host '  over WMI or the remote registry. Fix that first, then re-run.' -ForegroundColor Red
    }
    Write-Host ('  Report: {0}' -f $htmlReportFile) -ForegroundColor Cyan
    if ($remediation -and $remediation.SectionCount -gt 0) {
        Write-Host ('  Remediation: {0} ({1} section(s), review before running)' -f
            $remediation.Path, $remediation.SectionCount) -ForegroundColor Cyan
    }
    Write-Host ''

    if ($AsJson) {
        $report | ConvertTo-Json -Depth 7
    } elseif ($PassThru) {
        $result
    }

    if ($FailOnIssues -and -not $result) {
        Write-Warning ('{0} readiness issue(s) found, exiting with code {1}' -f $issueCount, [math]::Min($issueCount, 254))
        exit ([math]::Min([math]::Max($issueCount, 1), 254))
    }

    # A scan that enumerated nothing exits non-zero even without -FailOnIssues. The on-screen verdict
    # already says SCAN INCOMPLETE, but the process still exited 0, so a scheduled job checking only
    # the exit code treated "failed to look" as "found nothing wrong" - the one outcome that must
    # never be mistaken for success. 255 is used so it cannot be confused with an issue count.
    if ($stats.TotalServers -eq 0) {
        Write-Warning 'No server could be enumerated, exiting with code 255 (scan incomplete).'
        exit 255
    }
}

#endregion
