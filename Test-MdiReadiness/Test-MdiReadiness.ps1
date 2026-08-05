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
    .PARAMETER CapacityPlanningInterval
        Seconds between packet rate samples. Defaults to 5, matching the documented collection interval.
    .PARAMETER RemediationScript
        Generate a PowerShell remediation script next to the reports, containing the commands that fix the findings
        that can be fixed automatically (advanced audit policy, NTLM auditing, power scheme, Network Name Resolution
        firewall rules, stopped sensor services and clock resynchronisation). The generated script supports -WhatIf and
        must be reviewed before it is run.
    .PARAMETER BaselinePath
        Folder where a compact run history is kept, so the report can chart how readiness evolves between runs. Use the
        same path on every run. Defaults to no history.
    .PARAMETER DirectoryServiceAccount
        The Directory Service Account(s) configured for the domain, used to assert that they have read access to the
        Deleted Objects container. Without this parameter the check only reports which principals currently have access.
    .PARAMETER MaxClockSkewMinutes
        Maximum tolerated clock difference between this computer and each sensor server. Defaults to 5 minutes, which
        is the value required by the Defender for Identity documentation.
    .PARAMETER AsJson
        Emit the full report object as JSON on the pipeline instead of the boolean result, for use in a pipeline or a
        scheduled compliance job.
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
        .\Test-MdiReadiness.ps1 -Forest -RemediationScript -OpenHtmlReport

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

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'IncludeCA')]
param (
    [Parameter(Mandatory = $false, HelpMessage = 'Path to a folder where the reports are be saved')]
    [string] $Path = '.',
    [Parameter(Mandatory = $false, HelpMessage = 'Domain Name or FQDN to work against. Defaults to current domain')]
    [string] $Domain = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Scan every domain in the Active Directory forest. Requires Enterprise Admin (or equivalent) permissions')]
    [switch] $Forest,
    [Parameter(Mandatory = $false, HelpMessage = 'Specific Domain Controller(s) to work against. If not specified, it will query AD for the list of DCs in the domain')]
    [string[]] [Alias('DC')] $DomainController = $null,
    [Parameter(Mandatory = $false, ParameterSetName = 'IncludeCA', HelpMessage = 'Specific Certificate Authority server(s) to work against. If not specified, it will query AD for the members of the "Cert Publishers" group')]
    [string[]] [Alias('CA')] $CAServer = $null,
    [Parameter(Mandatory = $false, ParameterSetName = 'SkipCA', HelpMessage = 'Skip Certificate Authority servers')]
    [switch] $SkipCA,
    [Parameter(Mandatory = $false, ParameterSetName = 'IncludeEntraConnect', HelpMessage = 'Specific Entra Connect server(s) to work against. If not specified, it will query AD User for the "*configured to synchronize to tenant*" description')]
    [string[]] [Alias('EC')] $EntraConnectServer = $null,
    [Parameter(Mandatory = $false, ParameterSetName = 'SkipEntraConnect', HelpMessage = 'Skip Entra Connect servers')]
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
    [Parameter(Mandatory = $false, HelpMessage = 'Generate a PowerShell remediation script for the findings that can be fixed automatically')]
    [switch] $RemediationScript,
    [Parameter(Mandatory = $false, HelpMessage = 'Folder where a run history is kept so the report can chart the readiness trend')]
    [string] $BaselinePath = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Directory Service Account(s) that must have read access to the Deleted Objects container')]
    [string[]] [Alias('DSA')] $DirectoryServiceAccount = $null,
    [Parameter(Mandatory = $false, HelpMessage = 'Maximum tolerated clock difference, in minutes, between this computer and each sensor server')]
    [ValidateRange(1, 1440)]
    [int] $MaxClockSkewMinutes = 5,
    [Parameter(Mandatory = $false, HelpMessage = 'Emit the full report object as JSON instead of the boolean result')]
    [switch] $AsJson,
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
        if ($LocalFile -eq [string]::Empty) {
            $LocalFile = Join-Path -Path (Get-mdiRemoteTempFolder -ComputerName $ComputerName) -ChildPath ('mdi-{0}.tmp' -f , [guid]::NewGuid().GUID)
            $wmiParams['ArgumentList'] = '{0} 2>&1>{1}' -f $CommandLine, $LocalFile
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

        try {
            # Read the file using SMB
            $remoteFile = $LocalFile -replace 'C:', ('\\{0}\C$' -f $ComputerName)
            $return = Get-Content -Path $remoteFile -ErrorAction Stop
            Remove-Item -Path $remoteFile -Force
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
                Set-Content -Value $fileBytes -Encoding Byte -Path $localTempFile
                $return = Get-Content -Path $localTempFile
                Remove-Item -Path $localTempFile -Force
            } catch {
                $return = $null
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
        [PSCustomObject]@{ Success = $false; Detail = $_.Exception.Message; LatencyMs = $null }
    } finally {
        $client.Close()
    }
}

function Test-mdiUdpPort {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [int] $Port,
        [Parameter(Mandatory = $true)] [byte[]] $Payload,
        [Parameter(Mandatory = $false)] [int] $TimeoutMs = 1500
    )

    # UDP has no handshake, so a plain 'connect' proves nothing. Each UDP port is probed with a real, protocol-specific
    # request and the reply is what proves the port is open end to end.
    $udp = New-Object -TypeName System.Net.Sockets.UdpClient
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Client.SendTimeout = $TimeoutMs
        $udp.Connect($ComputerName, $Port)
        [void] $udp.Send($Payload, $Payload.Length)
        $remoteEndpoint = New-Object -TypeName System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Any, 0)
        $response = $udp.Receive([ref] $remoteEndpoint)
        $stopwatch.Stop()
        if ($response.Length -gt 0) {
            [PSCustomObject]@{ Success = $true; Detail = ('Replied with {0} bytes' -f $response.Length)
                Response = $response; LatencyMs = [int] $stopwatch.ElapsedMilliseconds
            }
        } else {
            [PSCustomObject]@{ Success = $false; Detail = 'Empty response'; Response = $null; LatencyMs = [int] $stopwatch.ElapsedMilliseconds }
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
        $udp.Close()
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

    $result = Test-mdiUdpPort -ComputerName $ComputerName -Port 137 -Payload (New-mdiNetBiosNodeStatusPacket) -TimeoutMs $TimeoutMs
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
                            Test-mdiUdpPort -ComputerName $dnsServer -Port $probe.Port -TimeoutMs $timeoutMs `
                                -Payload (New-mdiDnsQueryPacket -Name $Plan.DnsProbeName)
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
                        Test-mdiUdpPort -ComputerName $target.IP -Port $probe.Port -TimeoutMs $timeoutMs `
                            -Payload (New-mdiCldapPingPacket)
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
        Write-Verbose -Message "Unable to run the port probes on $ComputerName, falling back to probing it remotely"
        $fallbackPlan = $Plan.PSObject.Copy()
        $fallbackPlan.NnrTargets = @([PSCustomObject]@{ Name = $ComputerName; IP = $ComputerName })
        $fallbackPlan.DomainControllers = @([PSCustomObject]@{ Name = $ComputerName; IP = $ComputerName })
        $fallbackPlan.Probes = @($Plan.Probes | Where-Object { $_.Scope -in @('NetworkDevice', 'DomainController') })
        $details = @(Invoke-mdiPortProbePlan -Plan $fallbackPlan)
        $probeSource = 'This computer (inbound to the server)'
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
    $nnrFailedTargets = @($nnrProbes | Group-Object -Property Target |
            Where-Object { @($_.Group | Where-Object { $_.Success }).Count -eq 0 } |
            Select-Object -ExpandProperty Name)

    $isRequiredPortsOk = ($mandatoryFailures.Count -eq 0) -and ($nnrFailedTargets.Count -eq 0)

    [PSCustomObject]@{
        isRequiredPortsOk = $isRequiredPortsOk
        details           = [PSCustomObject]@{
            ProbedFrom       = $probeSource
            FailedRequired   = @(foreach ($failure in $mandatoryFailures) {
                    [string] $failure.Protocol + '/' + [string] $failure.Port + ' to ' + [string] $failure.Target + ': ' + [string] $failure.Detail
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
                $ip = $null
                try {
                    $adParams = @{ Identity = $name; Properties = 'DNSHostName', 'IPv4Address'; ErrorAction = 'Stop' }
                    if ($Domain) { $adParams['Server'] = $Domain }
                    $computer = Get-ADComputer @adParams
                    $name = if ($computer.DNSHostName) { $computer.DNSHostName } else { $computer.Name }
                    $ip = $computer.IPv4Address
                } catch {
                    Write-Verbose -Message "Unable to find '$name' in Active Directory, resolving it with DNS"
                }
                if (-not $ip) {
                    try { $ip = @([System.Net.Dns]::GetHostAddresses($name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0].IPAddressToString } catch {}
                }
                if ($ip) {
                    [PSCustomObject]@{ Name = $name; IP = $ip }
                } else {
                    Write-Warning ('Unable to resolve the NNR target computer {0}' -f $name)
                }
            })
    } else {
        @($DomainControllers | Where-Object { $_.IP })
    }

    if ($MaxTargets -gt 0 -and $targets.Count -gt $MaxTargets) {
        $targets = @($targets | Select-Object -First $MaxTargets)
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
    $targets = if ($MaxPerDomain -le 0) {
        @($DomainControllers | Where-Object { $_.IP })
    } else {
        @($DomainControllers | Where-Object { $_.IP } | Group-Object -Property Domain | ForEach-Object {
                $_.Group | Select-Object -First $MaxPerDomain
            })
    }
    , @($targets)
}

function Get-mdiForestDomain {
    param (
        [Parameter(Mandatory = $false)] [string] $Domain = $null
    )

    try {
        $forestParams = @{ ErrorAction = 'Stop' }
        if ($Domain) { $forestParams['Server'] = $Domain }
        $adForest = Get-ADForest @forestParams
        Write-Verbose -Message ('Found forest {0} with {1} domain(s): {2}' -f $adForest.Name, @($adForest.Domains).Count, ($adForest.Domains -join ', '))
        [PSCustomObject]@{
            Name    = $adForest.Name
            Domains = @($adForest.Domains)
        }
    } catch {
        Write-Warning ('Unable to enumerate the forest domains, falling back to the single domain {0}: {1}' -f $Domain, $_.Exception.Message)
        [PSCustomObject]@{
            Name    = $Domain
            Domains = @($Domain)
        }
    }
}

function Get-mdiDomainControllerInventory {
    param (
        [Parameter(Mandatory = $true)] [string[]] $Domain
    )

    # A consolidated inventory of every domain controller in scope. It is the list of LDAP targets each sensor must be
    # able to reach, and the default set of NNR targets.
    @(foreach ($domainName in $Domain) {
            try {
                Get-ADDomainController -Server $domainName -Filter * -ErrorAction Stop | ForEach-Object {
                    [PSCustomObject]@{
                        Name   = $_.HostName
                        IP     = $_.IPv4Address
                        Domain = $domainName
                    }
                }
            } catch {
                Write-Warning ('Unable to enumerate the domain controllers of {0}: {1}' -f $domainName, $_.Exception.Message)
            }
        })
}

#region Sensor v3.x upgrade readiness

function Get-mdiRemoteRegistryValue {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string] $Key,
        [Parameter(Mandatory = $true)] [string] $Value
    )

    $hklm = $null
    try {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, 'Registry64')
        $subKey = $hklm.OpenSubKey($Key)
        if ($null -eq $subKey) { return $null }
        $subKey.GetValue($Value)
    } catch {
        $null
    } finally {
        if ($hklm) { $hklm.Close() }
    }
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
        param([string] $Name, [object] $Status, [string] $Detail, [string] $Requirement = 'Required')
        # ArrayList rather than Generic.List[object]: converting a Generic.List[object] with @() throws
        # "Argument types do not match" on some Windows PowerShell 5.1 builds (for example 5.1.20348.4294).
        [void] $checks.Add([PSCustomObject]@{
                Name        = $Name
                Requirement = $Requirement
                Status      = $Status
                Detail      = $Detail
            })
    }

    $v3 = $settings.SensorV3

    # --- Server role: v3.x runs on domain controllers only -----------------------------------------------------
    # 'The v3.x sensor supports domain controllers, including domain controllers with these identity roles'
    # 'Use the Defender for Identity sensor v2.x for servers that aren't domain controllers and run AD FS, AD CS,
    #  or Microsoft Entra Connect.'
    $osInfo = $null
    try {
        $osInfo = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class 'Win32_OperatingSystem' `
            -Property 'Version', 'Caption', 'ProductType', 'BuildNumber' -ErrorAction Stop
    } catch {}

    # WMI returns PSObject-wrapped values. They are unwrapped into plain .NET types here because passing a wrapped
    # value to the format operator can break its dynamic binder ("Argument types do not match") in Windows PowerShell.
    $osCaption = if ($osInfo) { [string] $osInfo.Caption } else { 'N/A' }
    $osProductType = if ($osInfo) { [int] $osInfo.ProductType } else { 0 }
    $osBuildText = if ($osInfo) { [string] $osInfo.BuildNumber } else { '' }

    $isDomainController = $osProductType -eq 2
    & $addCheck 'Server is a domain controller' $isDomainController $(
        if ($null -eq $osInfo) { 'Unable to determine the server role' }
        elseif ($isDomainController) { 'Domain controller' }
        else { 'Not a domain controller - the v3.x sensor only supports domain controllers, keep using the v2.x sensor on this server' }
    )

    # --- Operating system: Windows Server 2019 or later --------------------------------------------------------
    $osBuild = 0
    if ($osBuildText) { [void] [int]::TryParse($osBuildText, [ref] $osBuild) }
    $isOsOk = $osBuild -ge $v3.MinOSBuild
    & $addCheck 'Windows Server 2019 or later' $isOsOk $(
        if ($osBuild -eq 0) { 'Unable to determine the operating system version' }
        elseif ($isOsOk) { '{0} (build {1})' -f $osCaption, $osBuild }
        else { '{0} (build {1}) - the v3.x sensor requires Windows Server 2019 or later, keep using the v2.x sensor on this server' -f $osCaption, $osBuild }
    )

    # --- Cumulative update: July 2026 or later -----------------------------------------------------------------
    $ubrValue = Get-mdiRemoteRegistryValue -ComputerName $ComputerName -Key $v3.CurrentVersionRegKey -Value 'UBR'
    $ubr = if ($null -eq $ubrValue) { $null } else { [int] $ubrValue }
    $expectedUpdate = $v3.JulyCumulativeUpdate[$osBuild]
    $isCuOk = if (-not $isOsOk) {
        $false
    } elseif ($null -eq $expectedUpdate) {
        # A build newer than the ones known to this script is assumed to be recent enough
        'N/A'
    } elseif ($null -eq $ubr) {
        $false
    } else {
        $ubr -ge [int] $expectedUpdate.Revision
    }
    & $addCheck 'July 2026 or later cumulative update' $isCuOk $(
        if (-not $isOsOk) { 'Not evaluated - the operating system is not supported by the v3.x sensor' }
        elseif ($null -eq $expectedUpdate) { 'OS build {0}.{1} is newer than the builds known to this script, verify the cumulative update level manually' -f $osBuild, $ubr }
        elseif ($null -eq $ubr) { 'Unable to read the update revision from the registry' }
        elseif ($ubr -ge [int] $expectedUpdate.Revision) { '{0} build {1}.{2} meets the July 2026 level ({3}.{4}, {5})' -f [string] $expectedUpdate.OS, $osBuild, $ubr, $osBuild, [int] $expectedUpdate.Revision, [string] $expectedUpdate.KB }
        else { '{0} build {1}.{2} is older than the July 2026 cumulative update ({3}.{4}, {5}) - install it before migrating' -f [string] $expectedUpdate.OS, $osBuild, $ubr, $osBuild, [int] $expectedUpdate.Revision, [string] $expectedUpdate.KB }
    )

    # --- Defender for Endpoint deployed and onboarded ----------------------------------------------------------
    # 'Defender for Endpoint must be onboarded on the server where the sensor runs; endpoint-only deployment isn't sufficient.'
    $senseService = Get-mdiServiceState -ComputerName $ComputerName -ServiceName $v3.MdeSenseServiceName
    $senseState = if ($senseService) { [string] $senseService.State } else { $null }
    $senseStartMode = if ($senseService) { [string] $senseService.StartMode } else { $null }
    $isSenseRunning = $senseState -eq 'Running'
    & $addCheck 'Defender for Endpoint (Sense) service is running' $isSenseRunning $(
        if ($null -eq $senseService) { 'The Sense service is not installed - onboard the server to Microsoft Defender for Endpoint' }
        elseif ($isSenseRunning) { 'Sense service is running (start mode: {0})' -f $senseStartMode }
        else { 'Sense service is {0} (start mode: {1}) - it must be running' -f $senseState, $senseStartMode }
    )

    $onboardingState = Get-mdiRemoteRegistryValue -ComputerName $ComputerName -Key $v3.MdeStatusRegKey -Value $v3.MdeOnboardingStateValue
    $isOnboarded = $null -ne $onboardingState -and [int] $onboardingState -eq 1
    & $addCheck 'Defender for Endpoint is onboarded' $isOnboarded $(
        if ($null -eq $onboardingState) { 'OnboardingState is not present under HKLM\{0} - the server is not onboarded to Defender for Endpoint' -f [string] $v3.MdeStatusRegKey }
        elseif ($isOnboarded) { 'OnboardingState = 1' }
        else { 'OnboardingState = {0} - the server is not onboarded to Defender for Endpoint' -f [int] $onboardingState }
    )

    # --- Existing v2.x sensor ----------------------------------------------------------------------------------
    # 'Doesn't have a Defender for Identity sensor v2.x already deployed' for a fresh activation. For the in-place
    # migration the v2.x sensor must instead be present and recent enough.
    $v2Service = Get-mdiServiceState -ComputerName $ComputerName -ServiceName 'AATPSensor'
    $hasV2Sensor = $null -ne $v2Service
    $v2ServiceState = if ($v2Service) { [string] $v2Service.State } else { $null }
    $v2Version = if ($SensorVersion -and $SensorVersion -ne 'N/A') { [string] $SensorVersion } else { $null }

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
    $hasCaptureComponent = -not [string]::IsNullOrWhiteSpace($captureComponent) -and $captureComponent -ne 'N/A'
    & $addCheck 'Npcap / WinPcap removed' (-not $hasCaptureComponent) $(
        if ($hasCaptureComponent) { '{0} is installed. It was used by the v2.x sensor and is not required by v3.x - remove it after the migration completes' -f $captureComponent }
        else { 'No packet capture driver installed' }
    ) 'Recommended'

    $blockers = @($checks | Where-Object { $_.Requirement -eq 'Required' -and $_.Status -ne $true })
    $migrationWarnings = @($checks | Where-Object { $_.Requirement -eq 'Migration' -and $_.Status -eq $false })

    $sensorState = if (-not $hasV2Sensor -and $isOnboarded -and $isSenseRunning) { 'No v2.x sensor (activate v3.x)' }
    elseif ($hasV2Sensor -and $v2ServiceState -ne 'Running') { 'v2.x sensor installed but not running' }
    elseif ($hasV2Sensor) { 'v2.x sensor running' }
    else { 'No Defender for Identity sensor detected' }

    # Plain concatenation instead of the format operator: the items come from a pipeline over PSObjects, which can
    # trip the Windows PowerShell format-operator binder.
    $blockerMessages = @(foreach ($blocker in $blockers) { [string] $blocker.Name + ': ' + [string] $blocker.Detail })

    [PSCustomObject]@{
        isSensorV3Ready = $blockers.Count -eq 0
        details         = [PSCustomObject]@{
            SensorState       = $sensorState
            SensorV2Version   = $v2Version
            MigrationEligible = ($blockers.Count -eq 0) -and ($migrationWarnings.Count -eq 0) -and $hasV2Sensor
            Blockers          = $blockerMessages
            Checks            = $checks.ToArray()
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
    if ($sensor -and $sensorState -ne 'Running') {
        [void] $issues.Add('The AATPSensor service is ' + $sensorState + ' (start mode: ' + $sensorStartMode + ')')
    }
    if ($updater -and $updaterState -ne 'Running') {
        [void] $issues.Add('The AATPSensorUpdater service is ' + $updaterState)
    }
    if ($sensor -and $sensorStartMode -eq 'Disabled') {
        [void] $issues.Add('The AATPSensor service start mode is Disabled')
    }

    [PSCustomObject]@{
        isSensorHealthOk = $issues.Count -eq 0
        details          = [PSCustomObject]@{
            Installed         = $true
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
        [PSCustomObject]@{
            isTimeSyncOk = $false
            details      = [PSCustomObject]@{ Detail = 'Unable to read the remote clock: ' + $_.Exception.Message }
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
        $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
        $deletedObjectsDn = 'CN=Deleted Objects,{0}' -f $ds.defaultNamingContext.Value
        $ldapPath = 'LDAP://{0}/{1}' -f $Domain, $deletedObjectsDn

        # The container is a system object, so it must be requested explicitly with the "show deleted" LDAP control
        $entry = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $ldapPath
        $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $entry
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
        $searcher.Tombstone = $true
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        [void] $searcher.PropertiesToLoad.Add('ntsecuritydescriptor')
        $result = $searcher.FindOne()

        if ($null -eq $result) {
            return [PSCustomObject]@{
                isDeletedObjectsPermissionOk = 'N/A'
                details                      = [PSCustomObject]@{ Detail = 'The Deleted Objects container could not be read'; Trustees = @() }
            }
        }

        $descriptor = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor `
            -ArgumentList ($result.Properties['ntsecuritydescriptor'][0], 0)

        # LIST_CONTENTS (0x4) and READ_PROPERTY (0x10) are what "read" means on this container
        $readMask = 0x4 -bor 0x10
        $trustees = @(foreach ($ace in $descriptor.DiscretionaryAcl) {
                if ($ace.AceType -ne 'AccessAllowed' -and $ace.AceType -ne 'AccessAllowedObject') { continue }
                if (($ace.AccessMask -band $readMask) -eq 0) { continue }
                $sid = [string] $ace.SecurityIdentifier
                $name = try {
                    (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sid).Translate(
                        [System.Security.Principal.NTAccount]).Value
                } catch { $sid }
                [PSCustomObject]@{ Sid = $sid; Name = $name }
            })

        $granted = @($trustees | Select-Object -ExpandProperty Name -Unique)

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
                Detail    = $(if ($status -eq 'N/A') {
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

    $servers = @($ReportData.DomainControllers + $ReportData.CAServers + $ReportData.EntraConnectServers |
            Where-Object { $_ -and -not $_.Comment })

    $script = New-Object -TypeName System.Collections.ArrayList
    $add = { param([string] $Line) [void] $script.Add($Line) }

    & $add '<#'
    & $add '    Microsoft Defender for Identity - generated remediation script'
    & $add ('    Source report : mdi-{0}' -f [string] $ReportData.Domain)
    & $add ('    Generated     : {0}' -f [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))
    & $add ''
    & $add '    REVIEW EVERY COMMAND BEFORE RUNNING IT. This script is generated from the findings of'
    & $add '    Test-MdiReadiness.ps1 and changes audit policy, registry values and firewall rules on'
    & $add '    domain controllers. Run it in a maintenance window and test in a lab first.'
    & $add ''
    & $add '    Run with -WhatIf to preview, or without it to apply.'
    & $add '#>'
    & $add '[CmdletBinding(SupportsShouldProcess = $true)]'
    & $add 'param()'
    & $add ''
    & $add '$ErrorActionPreference = ''Stop'''
    & $add ''

    $sections = 0

    # --- Advanced audit policy ---------------------------------------------------------------------------------
    $auditFailures = @($servers | Where-Object { $_.PSObject.Properties['AdvancedAuditing'] -and -not $_.AdvancedAuditing })
    if ($auditFailures.Count -gt 0) {
        $sections++
        & $add '#region Advanced audit policy'
        & $add '# https://aka.ms/mdi/advancedauditing'
        & $add ('# Affected: {0}' -f (@($auditFailures.FQDN) -join ', '))
        & $add 'foreach ($computer in @('
        & $add ('    ''{0}''' -f (@($auditFailures.FQDN) -join "'," + [environment]::NewLine + "    '"))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Configure the MDI advanced audit policy'')) {'
        & $add '        Invoke-Command -ComputerName $computer -ScriptBlock {'
        foreach ($row in ($settings.AdvancedAuditPolicyDCs | ConvertFrom-Csv)) {
            & $add ('            auditpol.exe /set /subcategory:"{0}" /success:enable /failure:enable' -f [string] $row.'Subcategory GUID')
        }
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
        & $add ('# Affected: {0}' -f (@($ntlmFailures.FQDN) -join ', '))
        & $add 'foreach ($computer in @('
        & $add ('    ''{0}''' -f (@($ntlmFailures.FQDN) -join "'," + [environment]::NewLine + "    '"))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Configure NTLM auditing'')) {'
        & $add '        Invoke-Command -ComputerName $computer -ScriptBlock {'
        foreach ($entry in $settings.NTLMAuditing) {
            $regPath, $regValue, $expected = $entry -split ','
            # The expected value can be a regular expression alternation, so the first branch is the value to set
            $value = (($expected -split '\|')[0]).Trim()
            & $add ('            New-ItemProperty -Path ''HKLM:\{0}'' -Name ''{1}'' -Value {2} -PropertyType DWord -Force | Out-Null' -f $regPath, $regValue, $value)
        }
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
        & $add ('    ''{0}''' -f (@($powerFailures.FQDN) -join "'," + [environment]::NewLine + "    '"))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Set the High performance power scheme'')) {'
        & $add '        Invoke-Command -ComputerName $computer -ScriptBlock {'
        & $add '            powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
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
    if ($blockedNnr.Count -gt 0) {
        $sections++
        $ruleMap = @{
            135  = @{ Name = 'MDI-NNR-RPC-In'; Protocol = 'TCP'; Display = 'MDI Network Name Resolution - NTLM over RPC (TCP 135)' }
            137  = @{ Name = 'MDI-NNR-NetBIOS-In'; Protocol = 'UDP'; Display = 'MDI Network Name Resolution - NetBIOS (UDP 137)' }
            3389 = @{ Name = 'MDI-NNR-RDP-In'; Protocol = 'TCP'; Display = 'MDI Network Name Resolution - RDP (TCP 3389)' }
        }
        $sensorIps = @($servers | ForEach-Object { [string] $_.IP } | Where-Object { $_ } | Select-Object -Unique)
        $blockedTargets = @($blockedNnr | Select-Object -ExpandProperty Target -Unique | Sort-Object)

        & $add '#region Network Name Resolution inbound firewall rules'
        & $add '# https://aka.ms/mdi/nnr/troubleshooting'
        & $add '# These rules must exist on EVERY device the sensors observe, not only on the targets listed here.'
        & $add '# Prefer deploying them through Group Policy; the commands below fix the sampled targets only.'
        & $add ('# Sampled targets that failed: {0}' -f ($blockedTargets -join ', '))
        & $add ''
        & $add '# Restrict the rules to the sensor servers so no port is opened to the whole network'
        & $add '$sensorAddresses = @('
        & $add ('    ''{0}''' -f ($sensorIps -join "'," + [environment]::NewLine + "    '"))
        & $add ')'
        & $add ''
        & $add 'foreach ($computer in @('
        & $add ('    ''{0}''' -f ($blockedTargets -join "'," + [environment]::NewLine + "    '"))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Create the MDI NNR inbound firewall rules'')) {'
        & $add '        Invoke-Command -ComputerName $computer -ArgumentList (, $sensorAddresses) -ScriptBlock {'
        & $add '            param($RemoteAddress)'
        foreach ($port in @($blockedNnr | Select-Object -ExpandProperty Port -Unique | Sort-Object)) {
            $rule = $ruleMap[[int] $port]
            if ($null -eq $rule) { continue }
            & $add ('            if (-not (Get-NetFirewallRule -Name ''{0}'' -ErrorAction SilentlyContinue)) {{' -f $rule.Name)
            & $add ('                New-NetFirewallRule -Name ''{0}'' -DisplayName ''{1}'' `' -f $rule.Name, $rule.Display)
            & $add ('                    -Direction Inbound -Action Allow -Protocol {0} -LocalPort {1} `' -f $rule.Protocol, $port)
            & $add '                    -RemoteAddress $RemoteAddress -Profile Domain | Out-Null'
            & $add '            }'
        }
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
        & $add '# The SACL on the domain root must audit Descendant User, Group, Computer and MSA objects.'
        & $add '# Configure it from the Defender portal (Settings > Identities > Advanced features >'
        & $add '# Automatic Windows auditing configuration), or apply it manually with:'
        & $add '#   https://learn.microsoft.com/defender-for-identity/deploy/configure-windows-event-collection'
        & $add 'Write-Warning ''Domain object auditing must be configured. See the link above.'''
        & $add '#endregion'
        & $add ''
    }

    # --- Sensor services ---------------------------------------------------------------------------------------
    $sensorStopped = @($servers | Where-Object { $_.PSObject.Properties['SensorHealth'] -and $_.SensorHealth -eq $false })
    if ($sensorStopped.Count -gt 0) {
        $sections++
        & $add '#region Defender for Identity sensor services'
        & $add ('# Affected: {0}' -f (@($sensorStopped.FQDN) -join ', '))
        & $add 'foreach ($computer in @('
        & $add ('    ''{0}''' -f (@($sensorStopped.FQDN) -join "'," + [environment]::NewLine + "    '"))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Start the Defender for Identity sensor services'')) {'
        & $add '        Invoke-Command -ComputerName $computer -ScriptBlock {'
        & $add '            foreach ($name in ''AATPSensorUpdater'', ''AATPSensor'') {'
        & $add '                $service = Get-Service -Name $name -ErrorAction SilentlyContinue'
        & $add '                if ($service) {'
        & $add '                    if ($service.StartType -eq ''Disabled'') { Set-Service -Name $name -StartupType Automatic }'
        & $add '                    if ($service.Status -ne ''Running'') { Start-Service -Name $name }'
        & $add '                }'
        & $add '            }'
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
        & $add ('# Affected: {0}' -f (@($timeFailures.FQDN) -join ', '))
        & $add 'foreach ($computer in @('
        & $add ('    ''{0}''' -f (@($timeFailures.FQDN) -join "'," + [environment]::NewLine + "    '"))
        & $add ')) {'
        & $add '    if ($PSCmdlet.ShouldProcess($computer, ''Resynchronise the clock'')) {'
        & $add '        Invoke-Command -ComputerName $computer -ScriptBlock {'
        & $add '            w32tm.exe /resync /force'
        & $add '            w32tm.exe /query /status'
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
        & $add ('# {0}' -f [string] $ReportData.DomainDeletedObjects.details.Detail)
        & $add ('$container = ''{0}''' -f [string] $ReportData.DomainDeletedObjects.details.Container)
        & $add '$dsaAccount = Read-Host ''Enter the Directory Service Account (DOMAIN\user)'''
        & $add 'if ($PSCmdlet.ShouldProcess($container, "Grant read access to $dsaAccount")) {'
        & $add '    dsacls.exe $container /takeownership'
        & $add '    dsacls.exe $container /G "${dsaAccount}:LCRP"'
        & $add '}'
        & $add '#endregion'
        & $add ''
    }

    # --- Sensor v3.x blockers ----------------------------------------------------------------------------------
    # @($null).Count is 1, so the null entries must be filtered out before counting
    $v3Blocked = @($servers | Where-Object { @($_.Details.SensorV3ReadyDetails.Blockers | Where-Object { $_ }).Count -gt 0 })
    if ($v3Blocked.Count -gt 0) {
        $sections++
        & $add '#region Sensor v3.x prerequisites (manual)'
        & $add '# https://learn.microsoft.com/defender-for-identity/deploy/deploy-sensor-v3'
        foreach ($srv in $v3Blocked) {
            & $add ('# {0}' -f [string] $srv.FQDN)
            foreach ($blocker in @($srv.Details.SensorV3ReadyDetails.Blockers)) {
                & $add ('#   - {0}' -f ([string] $blocker -replace '[\r\n]+', ' '))
            }
        }
        & $add '# Onboard the servers to Defender for Endpoint and install the July 2026 or later cumulative update,'
        & $add '# then re-run Test-MdiReadiness.ps1 to confirm.'
        & $add 'Write-Warning ''Sensor v3.x prerequisites require manual action. See the comments above.'''
        & $add '#endregion'
        & $add ''
    }

    if ($sections -eq 0) {
        & $add 'Write-Host ''No remediation is required: every automatically fixable check passed.'' -ForegroundColor Green'
    } else {
        & $add ('Write-Host ''Remediation complete. Re-run Test-MdiReadiness.ps1 to verify.'' -ForegroundColor Green')
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
        ChecksPassed  = [int] $Statistics.ChecksPassed
        ChecksTotal   = [int] $Statistics.ChecksTotal
        ServersTotal  = [int] $Statistics.TotalServers
        ServersReady  = @($Statistics.ServerScores | Where-Object { $_.Failed -eq 0 }).Count
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

    # Delta versus the previous run
    $previous = $points[-2]
    $current = $points[-1]
    $prevPct = ([double] ($previous.ChecksPassed -as [int]) / [double] ($previous.ChecksTotal -as [int])) * 100
    $currPct = ([double] ($current.ChecksPassed -as [int]) / [double] ($current.ChecksTotal -as [int])) * 100
    $delta = $currPct - $prevPct
    $tone = if ($delta -gt 0.5) { 'ok' } elseif ($delta -lt -0.5) { 'bad' } else { 'na' }
    $arrow = if ($delta -gt 0.5) { '&uarr;' } elseif ($delta -lt -0.5) { '&darr;' } else { '&rarr;' }
    $deltaText = '{0} {1} pt vs previous run ({2} run(s) recorded)' -f $arrow, [math]::Round($delta, 1), $points.Count

    ($parts.ToArray() -join '') + '<p><span class="pill ' + $tone + '">' + $deltaText + '</span></p>'
}

#region Capacity planning

function Get-mdiTrafficSample {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [int] $DurationSeconds,
        [Parameter(Mandatory = $true)] [int] $IntervalSeconds
    )

    $capacity = $settings.CapacityPlanning
    $samples = New-Object -TypeName System.Collections.ArrayList
    $deadline = [datetime]::Now.AddSeconds($DurationSeconds)

    do {
        try {
            $perfParams = @{
                ComputerName = $ComputerName
                Namespace    = 'root\cimv2'
                Class        = $capacity.PerfClass
                Property     = 'Name', 'PacketsPersec'
                ErrorAction  = 'Stop'
            }
            $adapters = @(Get-WmiObject @perfParams | Where-Object { $_.Name -notmatch $capacity.ExcludeAdapterName })
            if ($adapters.Count -eq 0) { return $null }

            $total = 0
            foreach ($adapter in $adapters) { $total += [double] $adapter.PacketsPersec }

            # The official tool also records compute and memory utilisation alongside the packet rate
            $cpuPercent = $null
            $availableMb = $null
            try {
                $cpu = @(Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class $capacity.CpuPerfClass `
                        -Property 'Name', 'PercentProcessorTime' -ErrorAction Stop |
                        Where-Object { $_.Name -eq '_Total' })[0]
                if ($cpu) { $cpuPercent = [double] $cpu.PercentProcessorTime }
                $memory = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\cimv2' -Class $capacity.MemoryPerfClass `
                    -Property 'AvailableMBytes' -ErrorAction Stop
                if ($memory) { $availableMb = [double] $memory.AvailableMBytes }
            } catch {
                Write-Verbose -Message ('Unable to sample CPU/memory utilisation on {0}: {1}' -f $ComputerName, $_.Exception.Message)
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
        # Highest average over any rolling window of the requested length
        $best = 0.0
        for ($i = 0; $i -lt $Sample.Count; $i++) {
            $windowEnd = $Sample[$i].Timestamp.AddSeconds($windowSeconds)
            $window = @($Sample | Where-Object { $_.Timestamp -ge $Sample[$i].Timestamp -and $_.Timestamp -le $windowEnd })
            if ($window.Count -eq 0) { continue }
            $windowAverage = ($window | ForEach-Object { [double] $_.PacketsPerSec } | Measure-Object -Average).Average
            if ($windowAverage -gt $best) { $best = $windowAverage }
        }
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
        [Parameter(Mandatory = $false)] [int] $IntervalSeconds = 5
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
    Write-Verbose -Message ("Sampling network traffic on {0} for {1}s at {2}s intervals" -f $ComputerName, $DurationSeconds, $IntervalSeconds)
    $sample = Get-mdiTrafficSample -ComputerName $ComputerName -DurationSeconds $DurationSeconds -IntervalSeconds $IntervalSeconds
    if ($null -eq $sample) {
        return & $notSized 'Missing traffic data' 'Unable to read the network performance counters over WMI'
    }

    $traffic = Get-mdiBusyPacketsPerSecond -Sample $sample -WindowMinutes $capacity.BusyWindowMinutes
    $busy = $traffic.BusyPacketsPerSec

    $cpuSamples = @($sample | Where-Object { $null -ne $_.CpuPercent } | ForEach-Object { [double] $_.CpuPercent })
    $memSamples = @($sample | Where-Object { $null -ne $_.AvailableMb } | ForEach-Object { [double] $_.AvailableMb })
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
            ErrorAction  = 'SilentlyContinue'
        }
        $csi = Get-WmiObject @csiParams

        $osParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_OperatingSystem'
            Property     = 'SystemDrive'
            ErrorAction  = 'SilentlyContinue'
        }
        $osdiskParams = @{
            ComputerName = $ComputerName
            Namespace    = 'root\cimv2'
            Class        = 'Win32_LogicalDisk'
            Property     = 'FreeSpace', 'DeviceID'
            Filter       = "DeviceID = '{0}'" -f (Get-WmiObject @osParams).SystemDrive
            ErrorAction  = 'SilentlyContinue'
        }
        $osdisk = Get-WmiObject @osdiskParams

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
        $return = [PSCustomObject]@{
            isMinHwRequirementsOk = $false
            details               = $_.Exception.Message
        }
    }
    $return
}

function Get-mdiRegistryValueSet {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName,
        [Parameter(Mandatory = $true)] [string[]] $ExpectedRegistrySet
    )

    $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, 'Registry64')
    $details = foreach ($reg in $ExpectedRegistrySet) {

        $regKeyPath, $regValue, $expectedValue = $reg -split ','
        $regKey = $hklm.OpenSubKey($regKeyPath)
        $value = $regKey.GetValue($regValue)

        [PSCustomObject]@{
            regKey        = '{0}\{1}' -f $regKeyPath, $regValue
            value         = $value
            expectedValue = $expectedValue
        }
    }

    $hklm.Close()
    $details
}

function Get-mdiNtlmAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $details = Get-mdiRegistryValueSet -ComputerName $ComputerName -ExpectedRegistrySet $settings.NTLMAuditing
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
    $details = $settings.CASettings.RegistrySet | ForEach-Object {
        Get-mdiRegistryValueSet -ComputerName $ComputerName -ExpectedRegistrySet ($_ -f $activeName.value)
    }
    [PSCustomObject]@{
        isCaAuditingOk = @($details | Where-Object { $_.value -notmatch $_.expectedValue }).Count -eq 0
        details        = $details | Select-Object regKey, value
    }
}

function Get-mdiEntraConnectAuditing {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $activeName = Get-mdiRegistryValueSet -ComputerName $ComputerName -ExpectedRegistrySet $settings.AdvancedAuditPolicyEntraConnect
    $details = $settings.AdvancedAuditPolicyEntraConnect | ForEach-Object {
        Get-mdiRegistryValueSet -ComputerName $ComputerName -ExpectedRegistrySet ($_ -f $activeName.value)
    }
    [PSCustomObject]@{
        isEntraConnectAuditingOk = @($details | Where-Object { $_.value -notmatch $_.expectedValue }).Count -eq 0
        details                  = $details | Select-Object regKey, value
    }
}

function Get-mdiCertReadiness {
    param (
        [Parameter(Mandatory = $true)] [string] $ComputerName
    )

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$ComputerName\Root",
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $details = $store.Certificates | Where-Object { $settings.RootCertificates -contains $_.Thumbprint }
    $store.Close()
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
    $return = @()
    try {
        foreach ($registryView in @('Registry32', 'Registry64')) {
            $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName, $registryView)
            $uninstallRef = $hklm.OpenSubKey($uninstallRegKey)
            $applications = $uninstallRef.GetSubKeyNames()

            foreach ($app in $applications) {
                $appDetails = $hklm.OpenSubKey($uninstallRegKey + '\' + $app)
                $appDisplayName = $appDetails.GetValue('DisplayName')
                $appVersion = $appDetails.GetValue('DisplayVersion')
                if ($appDisplayName -match 'npcap|winpcap') {
                    $return += '{0} ({1})' -f $appDisplayName, $appVersion
                }
            }
            $hklm.Close()
        }
    } catch {
        $return = 'N/A'
    }
    ($return -join ', ')
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
        $return = $_.Exception.Message
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
            ErrorAction  = 'SilentlyContinue'
        }
        $csi = Get-WmiObject @csiParams
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
        $return = $_.Exception.Message
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
            ErrorAction  = 'SilentlyContinue'
        }
        $os = Get-WmiObject @osParams
        $return = [PSCustomObject]@{
            isOsVerOk = [version]($os.Version) -ge [version]('6.3')
            details   = [PSCustomObject]@{
                Caption = $os.Caption
                Version = $os.Version
            }
        }
    } catch {
        $return = [PSCustomObject]@{
            isOsVerOk = $false
            details   = [PSCustomObject]@{
                Caption = 'N/A'
                Version = 'N/A'
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
        $return = [PSCustomObject]@{
            isAdvancedAuditingOk = $false
            details              = 'Unable to get the advanced auditing settings remotely'
        }
    }
    $return
}

function Get-mdiDsSacl {
    param (
        [Parameter(Mandatory = $true)] [string] $LdapPath,
        [Parameter(Mandatory = $true)] [object[]] $ExpectedAuditing
    )

    $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList ([adsi]$LdapPath)
    $searcher.CacheResults = $false
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
    $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
    $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
    $searcher.PropertiesToLoad.AddRange(('ntsecuritydescriptor,distinguishedname,objectsid' -split ','))
    try {
        $result = ($searcher.FindOne()).Properties

        $appliedAuditing = New-Object -TypeName Security.AccessControl.RawSecurityDescriptor -ArgumentList ($result['ntsecuritydescriptor'][0], 0) |
            ForEach-Object { $_.SystemAcl } | Select-Object *,
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
        $return = [PSCustomObject]@{
            isAuditingOk = if ($e.Exception.InnerException.ErrorCode -eq -2147016656) { 'N/A' } else { $false }
            details      = if ($e.Exception.InnerException.Message) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        }
    }
    $return
}

function Get-mdiObjectAuditing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)] [string] $Domain,
        [Parameter(Mandatory = $false)] [int] $DomainSchemaVersion = 0
    )

    Write-Verbose -Message 'Getting MDI related DS Object auditing configuration'
    $expectedAuditing = $settings.ObjectAuditing | ConvertFrom-Csv | Select-Object SecurityIdentifier, AccessMask, AuditFlagsValue, InheritedObjectAceType

    # Remove the msDS-DelegatedManagedServiceAccount entry if the AD schema version is less than 90 (Windows Server 2025)
    if ($DomainSchemaVersion -lt 90) {
        $expectedAuditing = $expectedAuditing | Where-Object { $_.InheritedObjectAceType -ne '0feb936f-47b3-49f2-9386-1dedc2c23765' }
    }

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing
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

    Write-Verbose -Message 'Getting MDI related Exchange auditing configuration'

    $expectedAuditing = $settings.ExchangeAuditing | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)

    $exchangePath = 'LDAP://CN=Microsoft Exchange,CN=Services,CN=Configuration,{0}' -f $ds.defaultNamingContext.Value
    if ([System.DirectoryServices.DirectoryEntry]::Exists($exchangePath)) {

        $ldapPath = 'LDAP://CN=Configuration,{0}' -f $ds.defaultNamingContext.Value

        $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing

        if ('N/A' -eq $result.isAuditingOk) {
            $isAuditingOk = $result.isAuditingOk
        } else {
            $appliedAuditing = $result.details
            $isAuditingOk = @(foreach ($applied in $appliedAuditing) {
                    $expectedAuditing | Where-Object { ($_.SecurityIdentifier -eq $applied.SecurityIdentifier) -and ($_.AuditFlagsValue -eq $applied.AuditFlagsValue) -and
                        ($_.InheritedObjectAceType -eq $applied.InheritedObjectAceType) -and
                        (([System.DirectoryServices.ActiveDirectoryRights]$applied.AccessMask).HasFlag(([System.DirectoryServices.ActiveDirectoryRights]($_.AccessMask)))) }
                }).Count -eq @($expectedAuditing).Count
        }
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

    Write-Verbose -Message 'Getting MDI related ADFS auditing configuration'

    $expectedAuditing = $settings.ADFSAuditing | ConvertFrom-Csv

    $ds = [adsi]('LDAP://{0}/ROOTDSE' -f $Domain)
    $ldapPath = 'LDAP://CN=ADFS,CN=Microsoft,CN=Program Data,{0}' -f $ds.defaultNamingContext.Value

    $result = Get-mdiDsSacl -LdapPath $ldapPath -ExpectedAuditing $expectedAuditing

    if ('N/A' -ne $result.isAuditingOk) {
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
    } else {
        $return = @{
            isAdfsAuditingOk = $result.isAuditingOk
            details          = 'Microsoft ADFS Program Data container not found'
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

    Write-Verbose -Message 'Getting AD Schema Version'
    $schema = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList (
        'LDAP://{0}' -f ([adsi]'LDAP://rootDSE').Properties['schemaNamingContext'].Value
    )
    $schemaVersion = $schema.Properties['objectVersion'].Value

    $return = @{
        schemaVersion = $schemaVersion
        details       = $schemaVersions[$schemaVersion]
    }
    $return
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
        Write-Verbose -Message "Searching for Domain Controllers in $Domain"
        try {
            $DomainController = @(Get-ADDomainController -Server $Domain -Filter * -ErrorAction Stop | Select-Object -ExpandProperty Name)
        } catch {
            $DomainController = $null
        }
    } else {
        Write-Verbose -Message "Using the provided list of Domain Controller(s)"
    }
    $dcs = @($DomainController | ForEach-Object {
            try {
                $getDcParams = @{
                    Identity    = if ($_ -match '\w+\.\w+') { Get-ADObject -Filter { DNSHostName -eq $_ } } else { $_ }
                    Server      = $Domain
                    Properties  = 'DNSHostName', 'IPv4Address', 'OperatingSystem'
                    ErrorAction = 'SilentlyContinue'
                }
                $dcComputer = Get-ADComputer @getDcParams
                @{
                    FQDN = $dcComputer.DNSHostName
                    IP   = $dcComputer.IPv4Address
                    OS   = $dcComputer.OperatingSystem
                }
            } catch {
                Write-Verbose $_.Exception.Message
            }
        })
    Write-Verbose -Message "Found $($dcs.Count) Domain Controller(s)"

    foreach ($dc in $dcs) {


        if (Test-Connection -ComputerName $dc.FQDN -Count 2 -Quiet) {
            $details = [ordered]@{}

            Write-Verbose -Message "Testing server requirements for $($dc.FQDN)"
            $serverRequirements = Get-mdiServerRequirements -ComputerName $dc.FQDN
            $dc.Add('ServerRequirements', $serverRequirements.isMinHwRequirementsOk)
            $details.Add('ServerRequirementsDetails', $serverRequirements.details)

            Write-Verbose -Message "Testing power settings for $($dc.FQDN)"
            $powerSettings = Get-mdiPowerScheme -ComputerName $dc.FQDN
            $dc.Add('PowerSettings', $powerSettings.isPowerSchemeOk)
            $details.Add('PowerSettingsDetails', $powerSettings.details)

            Write-Verbose -Message "Testing advanced auditing for $($dc.FQDN)"
            $advancedAuditing = Get-mdiAdvancedAuditing -ComputerName $dc.FQDN -ExpectedAuditing $settings.AdvancedAuditPolicyDCs
            $dc.Add('AdvancedAuditing', $advancedAuditing.isAdvancedAuditingOk)
            $details.Add('AdvancedAuditingDetails', $advancedAuditing.details)

            Write-Verbose -Message "Testing NTLM auditing for $($dc.FQDN)"
            $ntlmAuditing = Get-mdiNtlmAuditing -ComputerName $dc.FQDN
            $dc.Add('NtlmAuditing', $ntlmAuditing.isNtlmAuditingOk)
            $details.Add('NtlmAuditingDetails', $ntlmAuditing.details)

            Write-Verbose -Message "Testing certificates readiness for $($dc.FQDN)"
            $certificates = Get-mdiCertReadiness -ComputerName $dc.FQDN
            $dc.Add('RootCertificates', $certificates.isRootCertificatesOk)
            $details.Add('RootCertificatesDetails', $certificates.details)

            Write-Verbose -Message "Testing MDI sensor for $($dc.FQDN)"
            $sensorVersion = Get-mdiSensorVersion -ComputerName $dc.FQDN
            $dc.Add('SensorVersion', $sensorVersion)

            Write-Verbose -Message "Testing capturing component for $($dc.FQDN)"
            $capComponent = Get-mdiCaptureComponent -ComputerName $dc.FQDN
            $dc.Add('CapturingComponent', $capComponent)

            Write-Verbose -Message "Getting virtualization platform for $($dc.FQDN)"
            $machineType = Get-mdiMachineType -ComputerName $dc.FQDN
            $dc.Add('MachineType', $machineType)

            Write-Verbose -Message "Getting Operating System for $($dc.FQDN)"
            $osVer = Get-mdiOSVersion -ComputerName $dc.FQDN
            $dc.Add('OSVersion', $osVer.isOsVerOk)
            $details.Add('OSVersionDetails', $osVer.details)

            if ($PortProbePlan) {
                Write-Verbose -Message "Testing required network ports for $($dc.FQDN)"
                $requiredPorts = Get-mdiRequiredPorts -ComputerName $dc.FQDN -Plan $PortProbePlan
                $dc.Add('RequiredPorts', $requiredPorts.isRequiredPortsOk)
                $details.Add('RequiredPortsDetails', $requiredPorts.details)
            }

            Write-Verbose -Message "Testing sensor health for $($dc.FQDN)"
            $sensorHealth = Get-mdiSensorHealth -ComputerName $dc.FQDN
            if ($sensorHealth.isSensorHealthOk -ne 'N/A') { $dc.Add('SensorHealth', $sensorHealth.isSensorHealthOk) }
            $details.Add('SensorHealthDetails', $sensorHealth.details)

            Write-Verbose -Message "Testing time synchronization for $($dc.FQDN)"
            $timeSync = Get-mdiTimeSync -ComputerName $dc.FQDN -MaxSkewMinutes $MaxClockSkewMinutes
            $dc.Add('TimeSync', $timeSync.isTimeSyncOk)
            $details.Add('TimeSyncDetails', $timeSync.details)

            if ($TestSensorV3Readiness) {
                Write-Verbose -Message "Testing sensor v3.x upgrade readiness for $($dc.FQDN)"
                $sensorV3 = Get-mdiSensorV3Readiness -ComputerName $dc.FQDN -SensorVersion $sensorVersion
                $dc.Add('SensorV3Ready', $sensorV3.isSensorV3Ready)
                $details.Add('SensorV3ReadyDetails', $sensorV3.details)
            }

            # Capacity planning applies to domain controllers only: 'There is no need to run it against servers that
            # are only AD FS, AD CS, or Entra Connect'
            if ($CapacityPlan) {
                Write-Verbose -Message "Estimating sensor capacity for $($dc.FQDN)"
                $capacity = Get-mdiCapacityPlanning -ComputerName $dc.FQDN `
                    -DurationSeconds $CapacityPlan.DurationSeconds -IntervalSeconds $CapacityPlan.IntervalSeconds
                if ($capacity.isCapacityOk -ne 'N/A') { $dc.Add('CapacitySufficient', $capacity.isCapacityOk) }
                $details.Add('CapacityDetails', $capacity.details)
            }

        } else {
            $dc.Add('Comment', 'Server is not available')
            Write-Warning ('{0} is not available' -f $dc.FQDN)
        }

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
        Write-Verbose -Message "Searching for CA servers in $Domain"
        try {
            $CertPublishersSID = $((Get-ADDomain).DomainSID.Value + "-517")
            $CAServer = Get-ADGroupMember -Server $Domain -Identity $CertPublishersSID -ErrorAction Stop | Where-Object { $_.objectClass -eq 'computer' }
        } catch {
            $CAServer = $null
        }
    } else {
        Write-Verbose -Message "Using the provided list of CA server(s)"
    }
    $cas = @($CAServer | ForEach-Object {
            try {
                $caComputer = Get-ADComputer -Identity $_ -Server $Domain -Properties DNSHostName, IPv4Address, OperatingSystem -ErrorAction SilentlyContinue
                @{
                    FQDN = $caComputer.DNSHostName
                    IP   = $caComputer.IPv4Address
                    OS   = $caComputer.OperatingSystem
                }
            } catch {
                Write-Verbose $_.Exception.Message
            }
        })
    Write-Verbose -Message "Found $($cas.Count) CA server(s)"

    foreach ($ca in $cas) {

        if (Test-Connection -ComputerName $ca.FQDN -Count 2 -Quiet) {
            $details = [ordered]@{}

            Write-Verbose -Message "Testing server requirements for $($ca.FQDN)"
            $serverRequirements = Get-mdiServerRequirements -ComputerName $ca.FQDN
            $ca.Add('ServerRequirements', $serverRequirements.isMinHwRequirementsOk)
            $details.Add('ServerRequirementsDetails', $serverRequirements.details)

            Write-Verbose -Message "Testing power settings for $($ca.FQDN)"
            $powerSettings = Get-mdiPowerScheme -ComputerName $ca.FQDN
            $ca.Add('PowerSettings', $powerSettings.isPowerSchemeOk)
            $details.Add('PowerSettingsDetails', $powerSettings.details)

            Write-Verbose -Message "Testing advanced auditing for $($ca.FQDN)"
            $advancedAuditingCA = Get-mdiAdvancedAuditing -ComputerName $ca.FQDN -ExpectedAuditing $settings.AdvancedAuditPolicyCAs
            $ca.Add('AdvancedAuditingCA', $advancedAuditingCA.isAdvancedAuditingOk)
            $details.Add('AdvancedAuditingCADetails', $advancedAuditingCA.details)

            Write-Verbose -Message "Testing CA auditing for $($ca.FQDN)"
            $caAuditing = Get-mdiCAAuditing -ComputerName $ca.FQDN
            $ca.Add('CAAuditing', $caAuditing.isCaAuditingOk)
            $details.Add('CAAuditingDetails', $caAuditing.details)

            Write-Verbose -Message "Testing certificates readiness for $($ca.FQDN)"
            $certificates = Get-mdiCertReadiness -ComputerName $ca.FQDN
            $ca.Add('RootCertificates', $certificates.isRootCertificatesOk)
            $details.Add('RootCertificatesDetails', $certificates.details)

            Write-Verbose -Message "Testing MDI sensor for $($ca.FQDN)"
            $sensorVersion = Get-mdiSensorVersion -ComputerName $ca.FQDN
            $ca.Add('SensorVersion', $sensorVersion)

            Write-Verbose -Message "Testing capturing component for $($ca.FQDN)"
            $capComponent = Get-mdiCaptureComponent -ComputerName $ca.FQDN
            $ca.Add('CapturingComponent', $capComponent)

            Write-Verbose -Message "Getting virtualization platform for $($ca.FQDN)"
            $machineType = Get-mdiMachineType -ComputerName $ca.FQDN
            $ca.Add('MachineType', $machineType)

            Write-Verbose -Message "Getting Operating System for $($ca.FQDN)"
            $osVer = Get-mdiOSVersion -ComputerName $ca.FQDN
            $ca.Add('OSVersion', $osVer.isOsVerOk)
            $details.Add('OSVersionDetails', $osVer.details)

            if ($PortProbePlan) {
                Write-Verbose -Message "Testing required network ports for $($ca.FQDN)"
                $requiredPorts = Get-mdiRequiredPorts -ComputerName $ca.FQDN -Plan $PortProbePlan
                $ca.Add('RequiredPorts', $requiredPorts.isRequiredPortsOk)
                $details.Add('RequiredPortsDetails', $requiredPorts.details)
            }

            Write-Verbose -Message "Testing sensor health for $($ca.FQDN)"
            $sensorHealth = Get-mdiSensorHealth -ComputerName $ca.FQDN
            if ($sensorHealth.isSensorHealthOk -ne 'N/A') { $ca.Add('SensorHealth', $sensorHealth.isSensorHealthOk) }
            $details.Add('SensorHealthDetails', $sensorHealth.details)

            Write-Verbose -Message "Testing time synchronization for $($ca.FQDN)"
            $timeSync = Get-mdiTimeSync -ComputerName $ca.FQDN -MaxSkewMinutes $MaxClockSkewMinutes
            $ca.Add('TimeSync', $timeSync.isTimeSyncOk)
            $details.Add('TimeSyncDetails', $timeSync.details)

            if ($TestSensorV3Readiness) {
                Write-Verbose -Message "Testing sensor v3.x upgrade readiness for $($ca.FQDN)"
                $sensorV3 = Get-mdiSensorV3Readiness -ComputerName $ca.FQDN -SensorVersion $sensorVersion
                $ca.Add('SensorV3Ready', $sensorV3.isSensorV3Ready)
                $details.Add('SensorV3ReadyDetails', $sensorV3.details)
            }

        } else {
            $ca.Add('Comment', 'Server is not available')
            Write-Warning ('{0} is not available' -f $ca.FQDN)
        }

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
        Write-Verbose -Message "Searching for Entra Connect servers in $Domain"
        try {
            $EntraConnectServer = Get-ADUser -LDAPFilter "(description=*configured to synchronize to tenant*)" -Properties description | ForEach-Object { $desc = $_.description; if ($desc.Length -gt 142) { $spaceIdx = $desc.IndexOf(" ", 142); if ($spaceIdx -gt 142) { $ecsrv = $desc.Substring(142, $spaceIdx - 142); try { (Get-ADComputer $ecsrv -ErrorAction Stop).distinguishedName } catch {} } } }
        } catch {
            $EntraConnectServer = $null
        }
    } else {
        Write-Verbose -Message "Using the provided list of Entra Connect server(s)"
    }
    $ecs = @($EntraConnectServer | ForEach-Object {
            try {
                $ecsComputer = Get-ADComputer -Identity $_ -Server $Domain -Properties DNSHostName, IPv4Address, OperatingSystem -ErrorAction SilentlyContinue
                @{
                    FQDN = $ecsComputer.DNSHostName
                    IP   = $ecsComputer.IPv4Address
                    OS   = $ecsComputer.OperatingSystem
                }
            } catch {
                Write-Verbose $_.Exception.Message
            }
        })
    Write-Verbose -Message "Found $($ecs.Count) Entra Connect server(s)"

    foreach ($ec in $ecs) {

        if (Test-Connection -ComputerName $ec.FQDN -Count 2 -Quiet) {
            $details = [ordered]@{}

            Write-Verbose -Message "Testing server requirements for $($ec.FQDN)"
            $serverRequirements = Get-mdiServerRequirements -ComputerName $ec.FQDN
            $ec.Add('ServerRequirements', $serverRequirements.isMinHwRequirementsOk)
            $details.Add('ServerRequirementsDetails', $serverRequirements.details)

            Write-Verbose -Message "Testing power settings for $($ec.FQDN)"
            $powerSettings = Get-mdiPowerScheme -ComputerName $ec.FQDN
            $ec.Add('PowerSettings', $powerSettings.isPowerSchemeOk)
            $details.Add('PowerSettingsDetails', $powerSettings.details)

            Write-Verbose -Message "Testing advanced auditing for $($ec.FQDN)"
            $AdvancedAuditingEntraConnect = Get-mdiAdvancedAuditing -ComputerName $ec.FQDN -ExpectedAuditing $settings.AdvancedAuditPolicyEntraConnect
            $ec.Add('AdvancedAuditingEntraConnect', $AdvancedAuditingEntraConnect.isAdvancedAuditingOk)
            $details.Add('AdvancedAuditingEntraConnectDetails', $AdvancedAuditingEntraConnect.details)

            Write-Verbose -Message "Testing MDI sensor for $($ec.FQDN)"
            $sensorVersion = Get-mdiSensorVersion -ComputerName $ec.FQDN
            $ec.Add('SensorVersion', $sensorVersion)

            Write-Verbose -Message "Testing capturing component for $($ec.FQDN)"
            $capComponent = Get-mdiCaptureComponent -ComputerName $ec.FQDN
            $ec.Add('CapturingComponent', $capComponent)

            Write-Verbose -Message "Getting virtualization platform for $($ec.FQDN)"
            $machineType = Get-mdiMachineType -ComputerName $ec.FQDN
            $ec.Add('MachineType', $machineType)

            Write-Verbose -Message "Getting Operating System for $($ec.FQDN)"
            $osVer = Get-mdiOSVersion -ComputerName $ec.FQDN
            $ec.Add('OSVersion', $osVer.isOsVerOk)
            $details.Add('OSVersionDetails', $osVer.details)

            if ($PortProbePlan) {
                Write-Verbose -Message "Testing required network ports for $($ec.FQDN)"
                $requiredPorts = Get-mdiRequiredPorts -ComputerName $ec.FQDN -Plan $PortProbePlan
                $ec.Add('RequiredPorts', $requiredPorts.isRequiredPortsOk)
                $details.Add('RequiredPortsDetails', $requiredPorts.details)
            }

            Write-Verbose -Message "Testing sensor health for $($ec.FQDN)"
            $sensorHealth = Get-mdiSensorHealth -ComputerName $ec.FQDN
            if ($sensorHealth.isSensorHealthOk -ne 'N/A') { $ec.Add('SensorHealth', $sensorHealth.isSensorHealthOk) }
            $details.Add('SensorHealthDetails', $sensorHealth.details)

            Write-Verbose -Message "Testing time synchronization for $($ec.FQDN)"
            $timeSync = Get-mdiTimeSync -ComputerName $ec.FQDN -MaxSkewMinutes $MaxClockSkewMinutes
            $ec.Add('TimeSync', $timeSync.isTimeSyncOk)
            $details.Add('TimeSyncDetails', $timeSync.details)

            if ($TestSensorV3Readiness) {
                Write-Verbose -Message "Testing sensor v3.x upgrade readiness for $($ec.FQDN)"
                $sensorV3 = Get-mdiSensorV3Readiness -ComputerName $ec.FQDN -SensorVersion $sensorVersion
                $ec.Add('SensorV3Ready', $sensorV3.isSensorV3Ready)
                $details.Add('SensorV3ReadyDetails', $sensorV3.details)
            }

        } else {
            $ec.Add('Comment', 'Server is not available')
            Write-Warning ('{0} is not available' -f $ec.FQDN)
        }

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

    $allServers = @($ReportData.DomainControllers + $ReportData.CAServers + $ReportData.EntraConnectServers |
            Where-Object { $_ })
    $reachable = @($allServers | Where-Object { -not $_.Comment })
    $unreachable = @($allServers | Where-Object { $_.Comment })

    # Every boolean property on a server object is a readiness check, so the score works for domain controllers,
    # CA servers and Entra Connect servers alike without hard-coding the individual check names.
    $serverScores = @(foreach ($srv in $reachable) {
            $bools = @($srv.PSObject.Properties | Where-Object { $_.Value -is [bool] })
            $passed = @($bools | Where-Object { $_.Value }).Count
            [PSCustomObject]@{
                FQDN   = [string] $srv.FQDN
                Passed = $passed
                Total  = $bools.Count
                Failed = $bools.Count - $passed
            }
        })

    $checkTotals = @{}
    foreach ($srv in $reachable) {
        foreach ($prop in @($srv.PSObject.Properties | Where-Object { $_.Value -is [bool] })) {
            if (-not $checkTotals.ContainsKey($prop.Name)) { $checkTotals[$prop.Name] = @{ Pass = 0; Total = 0 } }
            $checkTotals[$prop.Name].Total++
            if ($prop.Value) { $checkTotals[$prop.Name].Pass++ }
        }
    }

    $portRecords = @(Get-mdiPortResultRecord -Server $reachable | Where-Object { $_.Applicable -ne $false })
    $nnrRecords = @($portRecords | Where-Object { $_.Group -eq 'NNR' })

    # An NNR target is only resolvable when at least one primary method answers, which is exactly what the
    # 'Low success rate of active name resolution' health alert measures.
    $nnrTargets = @($nnrRecords | Group-Object -Property Server, Target)
    $nnrResolvable = @($nnrTargets | Where-Object { @($_.Group | Where-Object { $_.Success }).Count -gt 0 })

    $v3Servers = @($reachable | Where-Object { $_.Details.SensorV3ReadyDetails })

    [PSCustomObject]@{
        TotalServers      = $allServers.Count
        ReachableServers  = $reachable.Count
        UnreachableCount  = $unreachable.Count
        DomainCount       = @($ReportData.DomainsInScope).Count
        ServerScores      = $serverScores
        ChecksPassed      = ($serverScores | Measure-Object -Property Passed -Sum).Sum
        ChecksTotal       = ($serverScores | Measure-Object -Property Total -Sum).Sum
        CheckTotals       = $checkTotals
        PortsTotal        = $portRecords.Count
        PortsOpen         = @($portRecords | Where-Object { $_.Success }).Count
        PortsBlocked      = @($portRecords | Where-Object { -not $_.Success }).Count
        PortsRequiredFail = @($portRecords | Where-Object { -not $_.Success -and $_.Requirement -eq 'Required' }).Count
        NnrTargetCount    = $nnrTargets.Count
        NnrResolvable     = $nnrResolvable.Count
        NnrRecords        = $nnrRecords
        V3Evaluated       = $v3Servers.Count
        V3Ready           = @($v3Servers | Where-Object { $_.SensorV3Ready }).Count
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

function Get-mdiOverviewHtml {
    param (
        [Parameter(Mandatory = $true)] [object] $Statistics,
        [Parameter(Mandatory = $true)] [object] $ReportData
    )

    $stats = $Statistics
    $lines = New-Object -TypeName System.Collections.ArrayList

    $readyServers = @($stats.ServerScores | Where-Object { $_.Failed -eq 0 }).Count
    $notReady = $stats.ReachableServers - $readyServers
    $scorePct = if ($stats.ChecksTotal -gt 0) { [int] [math]::Round(($stats.ChecksPassed / $stats.ChecksTotal) * 100) } else { 0 }

    $sensorServers = @($stats.ReachableList | Where-Object { $_.Details.SensorHealthDetails })
    $sensorInstalled = @($sensorServers | Where-Object { $_.Details.SensorHealthDetails.Installed })
    $sensorHealthy = @($sensorInstalled | Where-Object { $_.SensorHealth -eq $true })

    # --- KPI cards ---------------------------------------------------------------------------------------------
    $kpis = @(
        @{ Label = 'Servers scanned'; Value = $stats.TotalServers; Sub = ('{0} domain(s) in scope' -f $stats.DomainCount); Tone = 'info' }
        @{ Label = 'Servers fully ready'; Value = ('{0}/{1}' -f $readyServers, $stats.ReachableServers)
            Sub = $(if ($notReady -gt 0) { '{0} need attention' -f $notReady } else { 'All checks passed' })
            Tone = $(if ($notReady -gt 0) { 'bad' } else { 'ok' })
        }
        @{ Label = 'Required ports open'; Value = ('{0}/{1}' -f $stats.PortsOpen, $stats.PortsTotal)
            Sub = $(if ($stats.PortsRequiredFail -gt 0) { '{0} required port(s) blocked' -f $stats.PortsRequiredFail } else { 'No required port blocked' })
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

    foreach ($srv in $stats.UnreachableList) {
        [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $srv.FQDN; Area = 'Connectivity'
                Issue = 'Server is not available and could not be tested'
            })
    }
    foreach ($srv in $stats.ReachableList) {
        $portDetails = $srv.Details.RequiredPortsDetails
        $v3Details = $srv.Details.SensorV3ReadyDetails
        # Specific findings are far more actionable than a generic "<check> failed" line, so the summary row is only
        # emitted when no detailed reason is available for that check. Note @($null).Count is 1, hence the filter.
        $hasPortDetail = @($portDetails.FailedRequired | Where-Object { $_ }).Count -gt 0 -or
        @($portDetails.NnrFailedTargets | Where-Object { $_ }).Count -gt 0
        $hasV3Detail = @($v3Details.Blockers | Where-Object { $_ }).Count -gt 0

        foreach ($prop in @($srv.PSObject.Properties | Where-Object { $_.Value -is [bool] -and -not $_.Value })) {
            if ($prop.Name -eq 'RequiredPorts' -and $hasPortDetail) { continue }
            if ($prop.Name -eq 'SensorV3Ready' -and $hasV3Detail) { continue }
            $area = if ($prop.Name -eq 'RequiredPorts') { 'Network' } elseif ($prop.Name -eq 'SensorV3Ready') { 'Sensor v3.x' } else { 'Configuration' }
            $severity = if ($prop.Name -eq 'SensorV3Ready') { 'Medium' } else { 'High' }
            [void] $issues.Add([PSCustomObject]@{ Severity = $severity; Server = [string] $srv.FQDN; Area = $area
                    Issue = (ConvertTo-mdiFriendlyName ([string] $prop.Name)) + ' check failed'
                })
        }
        foreach ($blocked in @($portDetails.FailedRequired)) {
            [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $srv.FQDN; Area = 'Network'; Issue = [string] $blocked })
        }
        foreach ($target in @($portDetails.NnrFailedTargets)) {
            [void] $issues.Add([PSCustomObject]@{ Severity = 'High'; Server = [string] $srv.FQDN; Area = 'Name resolution'
                    Issue = 'No NNR method could resolve ' + [string] $target
                })
        }
        foreach ($blocker in @($v3Details.Blockers)) {
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

    [void] $lines.Add('<section class="card wide"><h3>Issues found</h3>')
    if ($issues.Count -eq 0) {
        [void] $lines.Add('<p class="empty-state">No issues were found. Every evaluated prerequisite passed on every server.</p>')
    } else {
        [void] $lines.Add('<div class="table-scroll"><table class="data"><thead><tr><th class="nowrap">Severity</th><th class="left nowrap">Server</th><th class="nowrap">Area</th><th class="left">Finding</th></tr></thead><tbody>')
        foreach ($issue in ($issues.ToArray() | Sort-Object @{E = { if ($_.Severity -eq 'High') { 0 } else { 1 } } }, Server, Area)) {
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
        $skew = if ($null -ne $sync.SkewSeconds) { [string] ([int] $sync.SkewSeconds) + ' s' } else { 'n/a' }
        [void] $lines.Add(('<tr><td class="mono">{0}</td><td class="{1}">{2}</td><td class="{1}">{3}</td><td class="mono">{4}</td><td class="left">{5}</td></tr>' -f
                (ConvertTo-mdiHtmlEncoded ([string] $srv.FQDN)),
                $(if ($ok) { 'green' } else { 'red' }), $(if ($ok) { 'Yes' } else { 'No' }),
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
    [void] $lines.Add('<div class="table-scroll"><table>')
    [void] $lines.Add('<tr><th class="left">Server</th><th>Sensor supported</th><th>Busy packets/sec</th><th>Average</th><th>Peak</th><th>Traffic band</th><th>Sensor needs</th><th>Server has</th><th>CPU used</th><th>RAM free</th><th class="left">Detail</th></tr>')

    foreach ($srv in ($servers | Sort-Object FQDN)) {
        $c = $srv.Details.CapacityDetails
        $status = [string] $c.Status

        if ($null -eq $c.BusyPacketsPerSec) {
            [void] $lines.Add(('<tr><td class="mono">{0}</td><td class="grey">{1}</td><td class="grey" colspan="8">n/a</td><td class="left">{2}</td></tr>' -f
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
        $cores = '{0} core(s){1}' -f [int] $c.PhysicalCores, $(if ($c.HyperThreaded) { ' *' } else { '' })
        $cpuUsed = if ($null -ne $c.AvgCpuPercent) { '{0}% avg / {1}% max' -f [int] $c.AvgCpuPercent, [int] $c.MaxCpuPercent } else { 'n/a' }
        $ramFree = if ($null -ne $c.MinAvailableRamGb) { '{0} GB min' -f (ConvertTo-mdiSvgNumber ([double] $c.MinAvailableRamGb)) } else { 'n/a' }
        [void] $lines.Add(('<tr><td class="mono">{0}</td><td class="{1}">{2}</td><td class="mono">{3}</td><td class="mono">{4}</td><td class="mono">{5}</td><td class="mono">{6}</td><td class="mono">{7} core / {8} GB</td><td class="mono">{9} / {10} GB</td><td class="mono">{11}</td><td class="mono">{12}</td><td class="left">{13}</td></tr>' -f
                (ConvertTo-mdiHtmlEncoded ([string] $srv.FQDN)), $class, (ConvertTo-mdiHtmlEncoded $status),
                [int] $c.BusyPacketsPerSec, [int] $c.AveragePacketsPerSec, [int] $c.PeakPacketsPerSec,
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

    $partial = @($servers | Where-Object { $_.Details.CapacityDetails.FullBusyWindow -eq $false })
    if ($partial.Count -gt 0) {
        $seconds = [int] (@($servers.Details.CapacityDetails.SampleSeconds) | Measure-Object -Maximum).Maximum
        [void] $lines.Add(('<p class="muted"><b>Estimate only.</b> The sample covered {0} second(s) per server, shorter than the {1}-minute busy window the official method uses, so the whole sample was averaged instead. Re-run with a longer <code>-CapacityPlanningDuration</code>, or use the official <a href="{2}">TriSizingTool</a> which samples over 24 hours.</p>' -f
                $seconds, [int] $capacity.BusyWindowMinutes, $capacity.OfficialToolUrl))
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
            if ($applicable.Count -eq 0) {
                '<td class="grey" title="{0}">N/A</td>' -f (ConvertTo-mdiHtmlEncoded (@($srvRecords.Detail)[0]))
            } else {
                $ok = @($applicable | Where-Object { $_.Success })
                $failed = @($applicable | Where-Object { -not $_.Success })
                if ($failed.Count -eq 0) {
                    $suffix = if ($applicable.Count -gt 1) { ' ({0}/{0})' -f $applicable.Count } else { '' }
                    '<td class="green">OK{0}</td>' -f $suffix
                } else {
                    # A failed 'at least one of' NNR method is only a warning by itself; the verdict is per target below
                    $class = if ($probeRecords[0].Requirement -eq 'Required') { 'red' } else { 'amber' }
                    $tooltip = (@(foreach ($f in $failed) { [string] $f.Target + ': ' + [string] $f.Detail })) -join ' | '
                    '<td class="{0}" title="{1}">{2}/{3} open</td>' -f $class, (ConvertTo-mdiHtmlEncoded $tooltip), $ok.Count, $applicable.Count
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
            foreach ($targetGroup in ($srvNnr | Group-Object -Property Target | Sort-Object Name)) {
                $cells = foreach ($probe in $nnrProbes) {
                    $record = @($targetGroup.Group | Where-Object { $_.Id -eq $probe.Id })[0]
                    if ($null -eq $record) {
                        '<td class="grey">N/A</td>'
                    } elseif ($record.Success) {
                        '<td class="green" title="{0}">Open</td>' -f (ConvertTo-mdiHtmlEncoded $record.Detail)
                    } else {
                        '<td class="red" title="{0}">Blocked</td>' -f (ConvertTo-mdiHtmlEncoded $record.Detail)
                    }
                }
                $primaryOk = @($targetGroup.Group | Where-Object { $_.Group -eq 'NNR' -and $_.Success }).Count -gt 0
                $verdict = if ($primaryOk) { '<td class="green">Yes</td>' } else { '<td class="red">No</td>' }
                [void] $lines.Add(('<tr><td style="text-align:left">{0}</td><td style="text-align:left">{1}</td>{2}{3}</tr>' -f
                        (ConvertTo-mdiHtmlEncoded $srv), (ConvertTo-mdiHtmlEncoded $targetGroup.Name), ($cells -join ''), $verdict))
            }
        }
        [void] $lines.Add('</table></div>')
    }

    # --- Actionable failure list -------------------------------------------------------------------------------
    $failures = @($records | Where-Object { $_.Applicable -ne $false -and -not $_.Success })
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

    # --- Probe latency -----------------------------------------------------------------------------------------
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
                } elseif ($status -eq 'N/A' -or $null -eq $status) {
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
            if ($_.SensorV3Ready) { '<td class="green">Yes</td>' } else { '<td class="red">No</td>' }
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
  --warn:#8f3a06; --warn-bg:#fbe8d0; --na:#6b7280; --na-bg:#e6e9ee;
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
        [Parameter(Mandatory = $false)] [object] $Remediation = $null
    )

    $jsonReportFile = Join-Path -Path $Path -ChildPath "mdi-$Domain.json"
    Write-Verbose "Creating detailed json report: $jsonReportFile"
    $ReportData | ConvertTo-Json -Depth 7 | Out-File -FilePath $jsonReportFile -Force
    $jsonReportFilePath = (Resolve-Path -Path $jsonReportFile).Path

    $convertServerTable = {
        param($Servers, $SkippedMessage, $EmptyMessage)
        if ($Servers) {
            $properties = [collections.arraylist] @($Servers | Get-Member -MemberType NoteProperty |
                    Where-Object { $_.Definition -match '(^System.Boolean|^bool)\s+' }).Name
            $propsToAdd = @('SensorVersion', 'CapturingComponent', 'MachineType', 'Comment')
            if ($null -ne $properties) {
                $properties.Insert(0, 'FQDN')
                [void] $properties.AddRange($propsToAdd)
            } else {
                $properties = [collections.arraylist]@('FQDN', 'Comment')
            }
            $regReplacePattern = '<th>(?!FQDN)(?!{0})(\w+)' -f ($propsToAdd -join '|')
            $table = ((($Servers | Sort-Object FQDN | Select-Object $properties | ConvertTo-Html -Fragment) `
                        -replace $regReplacePattern, '<th><a href="https://aka.ms/mdi/$1">$1</a>') `
                    -replace '<td>True', '<td class="green">True') `
                -replace '<td>False', '<td class="red">False' `
                -join [environment]::NewLine
            # The first column holds the FQDN: left-align both its header and its cells so they line up
            $table = $table -replace '<th>FQDN</th>', '<th class="left">FQDN</th>'
            $table = $table -replace '<tr><td>', '<tr><td class="mono">'
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

    $htmlDS = '<div class="table-scroll">' + ((((($ReportData | Select-Object @{N = 'Domain'; E = { $Domain } },
                        @{N = 'ObjectAuditing'; E = { $_.DomainObjectAuditing.isObjectAuditingOk } },
                        @{N = 'ExchangeAuditing'; E = { $_.DomainExchangeAuditing.isExchangeAuditingOk } },
                        @{N = 'AdfsAuditing'; E = { $_.DomainAdfsAuditing.isAdfsAuditingOk } }  | ConvertTo-Html -Fragment) `
                        -replace '<th>(?!Domain)(\w+)', '<th><a href="https://aka.ms/mdi/$1">$1</a>') `
                    -replace '<td>True', '<td class="green">True') `
                -replace '<td>False', '<td class="red">False') `
            -replace '<th>Domain</th>', '<th class="left">Domain</th>' `
            -join [environment]::NewLine) + '</div>'

    $allServers = @($ReportData.DomainControllers + $ReportData.CAServers + $ReportData.EntraConnectServers | Where-Object { $_ })

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
        '<p class="muted">No remediation script was generated. Re-run with <code>-RemediationScript</code> to produce a ready-to-run <code>Fix-MdiReadiness-' +
        (ConvertTo-mdiHtmlEncoded $Domain) + '.ps1</code> containing the commands that fix the findings above (advanced audit policy, NTLM auditing, power scheme, Network Name Resolution firewall rules, stopped sensor services and clock resynchronisation).</p>'
    }

    $stats = Get-mdiReportStatistics -ReportData $ReportData
    $htmlOverview = Get-mdiOverviewHtml -Statistics $stats -ReportData $ReportData

    $htmlTrend = if ($BaselinePath) {
        $baseline = Get-mdiBaselineHistory -BaselinePath $BaselinePath -Domain $Domain -Statistics $stats
        Write-Verbose ('Baseline history: {0} ({1} run(s))' -f $baseline.Path, @($baseline.History).Count)
        New-mdiTrendChart -History $baseline.History
    } else {
        '<p class="muted">Trend tracking is disabled. Re-run with <code>-BaselinePath</code> pointing at a folder to record history and chart how readiness evolves between runs.</p>'
    }

    $htmlDeletedObjects = if ($ReportData.DomainDeletedObjects) {
        $status = $ReportData.DomainDeletedObjects.isDeletedObjectsPermissionOk
        $cls = if ($status -eq $true) { 'ok' } elseif ($status -eq 'N/A') { 'na' } else { 'bad' }
        $label = if ($status -eq $true) { 'Pass' } elseif ($status -eq 'N/A') { 'Informational' } else { 'Fail' }
        '<p><span class="pill ' + $cls + '">' + $label + '</span> ' +
        (ConvertTo-mdiHtmlEncoded ([string] $ReportData.DomainDeletedObjects.details.Detail)) + '</p>'
    } else {
        '<p class="muted">Not evaluated</p>'
    }

    $isReady = Test-mdiReadinessResult -ReportData $ReportData
    $verdictClass = if ($isReady) { 'ok' } else { 'bad' }
    $verdictText = if ($isReady) { 'All prerequisites met' } else { 'Action required' }
    $issueCount = ($stats.ChecksTotal - $stats.ChecksPassed) + $stats.UnreachableCount
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
  <span>Generated by <a href="https://aka.ms/mdi/Test-MdiReadiness">Test-MdiReadiness.ps1</a> on @@TIMESTAMP@@</span>
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
    Replace('@@TIMESTAMP@@', (ConvertTo-mdiHtmlEncoded ([datetime]::Now.ToString('yyyy-MM-dd HH:mm'))))

    $htmlReportFile = Join-Path -Path $Path -ChildPath "mdi-$Domain.html"
    Write-Verbose "Creating html report: $htmlReportFile"
    $htmlContent | Out-File -FilePath $htmlReportFile -Force -Encoding utf8
    (Resolve-Path -Path $htmlReportFile).Path
}

function Test-mdiReadinessResult {
    param (
        [Parameter(Mandatory = $true)] [object[]] $ReportData
    )
    $properties = @($ReportData.DomainControllers | Get-Member -MemberType NoteProperty |
            Where-Object { $_.Definition -match '(^System.Boolean|^bool)\s+' }).Name

    $serversOk = @(foreach ($server in @($ReportData.DomainControllers + $ReportData.CAServers + $ReportData.EntraConnectServers | Where-Object { $_ })) {
            $properties | ForEach-Object {
                $server | Select-Object -ExpandProperty $_ -ErrorAction SilentlyContinue
            }
        })

    $return = (($serversOk -ne $true).Count -eq 0) -and
    $ReportData.DomainAdfsAuditing.isAdfsAuditingOk -and
    $ReportData.DomainObjectAuditing.isObjectAuditingOk -and
    $ReportData.DomainExchangeAuditing.isExchangeAuditingOk

    $return
}

#endregion

#region Main

if (-not $Domain) { $Domain = $env:USERDNSDOMAIN }
if (-not $Domain) {
    throw 'Unable to determine the domain to work against. Use the -Domain parameter to specify it.'
}

$targetDescription = if ($Forest) { 'the forest of {0}' -f $Domain } else { $Domain }
if ($PSCmdlet.ShouldProcess($targetDescription, 'Create MDI related configuration reports')) {

    $forestInfo = if ($Forest) { Get-mdiForestDomain -Domain $Domain } else { [PSCustomObject]@{ Name = $Domain; Domains = @($Domain) } }
    $domainsInScope = @($forestInfo.Domains)

    $portProbePlan = $null
    if (-not $SkipNetworkPorts) {
        Write-Verbose -Message 'Building the network port probe plan'
        # Every sensor must be able to reach every domain controller over LDAP, so the inventory is collected once for
        # the whole scope and shared by all the probes.
        $dcInventory = @(Get-mdiDomainControllerInventory -Domain $domainsInScope)
        Write-Verbose -Message ('Found {0} domain controller(s) in {1} domain(s)' -f $dcInventory.Count, $domainsInScope.Count)

        $ldapTargets = Resolve-mdiLdapTarget -DomainControllers $dcInventory -MaxPerDomain $MaxLdapTargetsPerDomain
        Write-Verbose -Message ('Using {0} LDAP target(s): {1}' -f @($ldapTargets).Count, (@($ldapTargets | ForEach-Object { $_.Name }) -join ', '))

        $nnrTargets = Resolve-mdiNnrTarget -DomainControllers $dcInventory -NnrTargetComputer $NnrTargetComputer `
            -Domain $Domain -MaxTargets $MaxNnrTargets
        Write-Verbose -Message ('Using {0} Network Name Resolution target(s): {1}' -f @($nnrTargets).Count, (@($nnrTargets | ForEach-Object { $_.Name }) -join ', '))
        if (-not $NnrTargetComputer) {
            Write-Verbose -Message 'Tip: use -NnrTargetComputer to also validate NNR against workstations and member servers'
        }

        $portProbePlan = New-mdiPortProbePlan -Domain $Domain -DomainController $ldapTargets -NnrTarget $nnrTargets `
            -WorkspaceName $WorkspaceName -TimeoutMs $PortProbeTimeoutMs -MultiForest:$MultiForest -TestVpnRadius:$TestVpnRadius
    }

    $report = @{
        Domain                 = if ($Forest) { $forestInfo.Name } else { $Domain }
        Forest                 = $forestInfo.Name
        DomainsInScope         = $domainsInScope
        DomainControllers      = @(foreach ($domainName in $domainsInScope) {
                Write-Verbose -Message "Testing the domain controllers of $domainName"
                Get-mdiDomainControllerReadiness -Domain $domainName `
                    -DomainController $(if ($Forest) { $null } else { $DomainController }) -PortProbePlan $portProbePlan `
                    -TestSensorV3Readiness:(-not $SkipSensorV3Readiness) `
                    -CapacityPlan $(if ($CapacityPlanning) {
                        [PSCustomObject]@{ DurationSeconds = $CapacityPlanningDuration; IntervalSeconds = $CapacityPlanningInterval }
                    } else { $null })
            })
        DomainAdfsAuditing     = Get-mdiAdfsAuditing -Domain $Domain
        DomainObjectAuditing   = Get-mdiObjectAuditing -Domain $Domain -DomainSchemaVersion (Get-DomainSchemaVersion -Domain $Domain).schemaVersion
        DomainExchangeAuditing = Get-mdiExchangeAuditing -Domain $Domain
        DomainDeletedObjects   = Get-mdiDeletedObjectsPermission -Domain $Domain -DirectoryServiceAccount $DirectoryServiceAccount
        DomainSchemaVersion    = Get-DomainSchemaVersion -Domain $Domain
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

    # The remediation script is generated before the report so the report can link to it
    $remediation = $null
    if ($RemediationScript) {
        $remediationFile = Join-Path -Path $Path -ChildPath ('Fix-MdiReadiness-{0}.ps1' -f $report.Domain)
        $remediation = New-mdiRemediationScript -ReportData $report -FilePath $remediationFile
        if ($remediation.SectionCount -gt 0) {
            Write-Warning ('Remediation script written to {0} with {1} section(s). Review it before running.' -f $remediation.Path, $remediation.SectionCount)
        } else {
            Write-Verbose -Message ('Remediation script written to {0} (nothing to remediate)' -f $remediation.Path)
        }
    }

    $htmlReportFile = Set-MdiReadinessReport -Domain $report.Domain -Path $Path -ReportData $report -Remediation $remediation

    $result = Test-mdiReadinessResult -ReportData $report

    if ($OpenHtmlReport) { Invoke-Item -Path $htmlReportFile }

    if ($AsJson) {
        $report | ConvertTo-Json -Depth 7
    } else {
        $result
    }

    if ($FailOnIssues -and -not $result) {
        $stats = Get-mdiReportStatistics -ReportData $report
        $failedCount = ($stats.ChecksTotal - $stats.ChecksPassed) + $stats.UnreachableCount
        Write-Warning ('{0} readiness issue(s) found, exiting with code {1}' -f $failedCount, [math]::Min($failedCount, 254))
        exit ([math]::Min([math]::Max($failedCount, 1), 254))
    }
}

#endregion
