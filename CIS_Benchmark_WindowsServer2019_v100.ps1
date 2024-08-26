

<#
.SYNOPSIS
    DSC script to harden Windows Server 2019 VM baseline policies for CSBP.
.DESCRIPTION
    This script aims to harden Windows Server 2019 VM baseline policies using Desired State Configurations (DSC) for CIS Benchmark Windows Server 2019 Version 1.0.0 supported by ZCSPM.
.NOTE
    Copyright (c) ZCSPM. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    # PREREQUISITE
    * Windows PowerShell version 5 and above
        1. To check PowerShell version type "$PSVersionTable.PSVersion" in PowerShell and you will find PowerShell version,
        2. To Install powershell follow link https://docs.microsoft.com/en-us/powershell/scripting/install/installing-windows-powershell?view=powershell-6
    * DSC modules should be installed
        1. AuditPolicyDsc
        2. SecurityPolicyDsc
        3. NetworkingDsc
        4. PSDesiredStateConfiguration
        
        To check Azure AD version type "Get-InstalledModule -Name <ModuleName>" in PowerShell window
        You can Install the required modules by executing below command.
            Install-Module -Name <ModuleName> -MinimumVersion <Version>
.EXAMPLE
    
    .\CIS_Benchmark_WindowsServer2019_v100.ps1 [Script will generate MOF files in directory]
    Start-DscConfiguration -Path .\CIS_Benchmark_WindowsServer2019_v100  -Force -Verbose -Wait
#>

# Configuration Definition
Configuration CIS_Benchmark_WindowsServer2019_v100 {
    param (
        [string[]]$ComputerName = 'localhost'
    )
 
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'NetworkingDsc'
 
    Node $ComputerName {

        AccountPolicy AccountPolicies 
        {
            Name                                        = 'PasswordPolicies'

            # CceId: CCE-36286-3
            # DataSource: Security Policy
            # Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'

            # CceId: CCE-37063-5
            # DataSource: Security Policy
            # Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'

            # CceId: CCE-37432-2
            # DataSource: Security Policy
            # Ensure 'Accounts: Guest account status' is set to 'Disabled' 
            #Accounts_Guest_account_status = 'Disabled'


            # CceId: CCE-36534-6
            # DataSource: Security Policy
            # Ensure 'Minimum password length' is set to '14 or more character'
            Minimum_Password_Length                     = '14'

            # CceId: CCE-37073-4
            # DataSource: Security Policy
            # Ensure 'Minimum password age' is set to '1 or more day'
            Minimum_Password_Age                        = '2'

            # CceId: CCE-37166-6
            # DataSource: Security Policy
            #  Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history                     = '24'

            # CceId: CCE-37167-4
            # DataSource: Security Policy
            # Ensure 'Maximum password age' is set to '70 or fewer days, but not 0'
            Maximum_Password_Age                        = '50'

            # CceId: CCE-
            # DataSource: Security Policy
            # Ensure 'Ensure 'Account lockout duration' is set to '15 or more minute(s)'
            Account_lockout_duration                    = '15'
            
            # CceId: CCE-
            # DataSource: Security Policy
            # Ensure 'Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'
            Account_lockout_threshold                    = '5'

            # CceId: CCE-
            # DataSource: Security Policy
            # Ensure Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
            Reset_account_lockout_counter_after          = '15'

        }

        # CceId: CCE-38325-7
        # DataSource: Security Policy
        # Ensure 'Take ownership of files or other objects' is set to 'Administrators'
        UserRightsAssignment Takeownershipoffilesorotherobjects {
            Policy   = 'Take_ownership_of_files_or_other_objects'
            Identity = 'Administrators'
        }

        # CceId: CCE-37877-8 - 2.2.30
        # DataSource: Security Policy
        # Ensure 'Force shutdown from a remote system' is set to 'Administrators'
        UserRightsAssignment Forceshutdownfromaremotesystem {
            Policy   = 'Force_shutdown_from_a_remote_system'
            Identity = 'Administrators'
        }

        # CceId: CCE-38328-1
        # DataSource: Security Policy
        # Ensure 'Shut down the system' is set to 'Administrators'
        UserRightsAssignment Shutdownthesystem {
            Policy   = 'Shut_down_the_system'
            Identity = 'Administrators'
        }

        # CceId: CCE-37613-7 - 2.2.46
        # DataSource: Security Policy
        #  Ensure 'Restore files and directories' is set to 'Administrators'
        UserRightsAssignment Restorefilesanddirectories {
            Policy   = 'Restore_files_and_directories'
            Identity = 'Administrators'
        }

        # CceId: CCE-37430-6
        # DataSource: Security Policy
        # Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Replaceaprocessleveltoken {
            Policy   = 'Replace_a_process_level_token'
            Identity = 'LOCAL SERVICE, NETWORK SERVICE'
        }

        # CceId:
        # DataSource: Security Policy
        <# Ensure 'Increase a process working set' is set to 'Administrators, Local Service'
        UserRightsAssignment Increaseaprocessworkingset {
            Policy   = 'Increase_a_process_working_set'
            Identity = 'Administrators,  Local Service'
        }#>

        # CceId: CCE-36052-9
        # DataSource: Security Policy
        # Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
        UserRightsAssignment Profilesystemperformance {
            Policy   = 'Profile_system_performance'
            Identity = 'Administrators, NT SERVICE\WdiServiceHost'
        }

        # CceId: CCE-37131-0
        # DataSource: Security Policy
        # Ensure 'Profile single process' is set to 'Administrators'
        UserRightsAssignment Profilesingleprocess {
            Policy   = 'Profile_single_process'
            Identity = 'Administrators'
        }

        # CceId: CCE-36143-6
        # DataSource: Security Policy
        # Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
        UserRightsAssignment Performvolumemaintenancetasks {
            Policy   = 'Perform_volume_maintenance_tasks'
            Identity = 'Administrators'
        }

        # CceId: CCE-38113-7
        # DataSource: Security Policy
        # Ensure 'Modify firmware environment values' is set to 'Administrators'
        UserRightsAssignment Modifyfirmwareenvironmentvalues {
            Policy   = 'Modify_firmware_environment_values'
            Identity = 'Administrators'
        }

        # CceId: CCE-36054-5
        # DataSource: Security Policy
        # Ensure 'Modify an object label' is set to 'No One'
        UserRightsAssignment Modifyanobjectlabel {
            Policy   = 'Modify_an_object_label'
            Identity = 'No One'
        }

        # CceId: CCE-36495-0
        # DataSource: Security Policy
        # Ensure 'Lock pages in memory' is set to 'No One'
        UserRightsAssignment Lockpagesinmemory {
            Policy   = 'Lock_pages_in_memory'
            Identity = 'No One'
        }

        # CceId: 
        # DataSource: Security Policy
        # Ensure 'Access  this computer from the network' is set to 'Administrators, Authenticated Users' (DC only)
        UserRightsAssignment  Accessthiscomputerfromthenetwork {
            Policy   = 'Access_this_computer_from_the_network'
            Identity = 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'
        }

        # CceId: CCE-36318-4 - 2.2.35
        # DataSource: Security Policy
        # Ensure 'Load and unload device drivers' is set to 'Administrators'
        UserRightsAssignment Loadandunloaddevicedrivers {
            Policy   = 'Load_and_unload_device_drivers'
            Identity = 'Administrators'
        }    

        # CceId: CCE-36867-0 
        # DataSource: Security Policy
        # Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity = 'Guests'
        }

        # CceId: CCE-36877-9
        # DataSource: Security Policy
        # Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy   = 'Deny_log_on_as_a_service'
            Identity = 'Guests'
        }

        # CceId: CCE-36923-1
        # DataSource: Security Policy
        # Ensure (L2) 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = 'Administrators' 
        }

        # CceId: CCE-36532-0
        # DataSource: Security Policy
        # Ensure 'Create permanent shared objects' is set to 'No One'
        UserRightsAssignment Createpermanentsharedobjects {
            Policy   = 'Create_permanent_shared_objects'
            Identity = 'No One'
        }

        # CceId: CCE-37453-8
        # DataSource: Security Policy
        # Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Createglobalobjects {
            Policy   = 'Create_global_objects'
            Identity = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        }

        # CceId: CCE-36861-3
        # DataSource: Security Policy
        # Ensure 'Create a token object' is set to 'No One'
        UserRightsAssignment Createatokenobject {
            Policy   = 'Create_a_token_object'
            Identity = 'No One'
        }
        

        # CceId: CCE-35821-8
        # DataSource: Security Policy
        # Ensure 'Create a pagefile' is set to 'Administrators'
        UserRightsAssignment Createapagefile {
            Policy   = 'Create_a_pagefile'
            Identity = 'Administrators'
        }

        # CceId:
        # DataSource: Security Policy
        # Ensure 'Bypass traverse checking' is set to 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service'
        UserRightsAssignment Bypasstraversechecking {
            Policy   = 'Bypass_traverse_checking'
            Identity = 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service'
        }

        # CceId: CCE-37700-2
        # DataSource: Security Policy       
        # Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethetimezone {
            Policy   = 'Change_the_time_zone'
            Identity = 'Administrators, LOCAL SERVICE'
        }

        # CceId: CCE-35912-5
        # DataSource: Security Policy
        # Ensure 'Back up files and directories' is set to 'Administrators'
        UserRightsAssignment Backupfilesanddirectories {
            Policy   = 'Back_up_files_and_directories'
            Identity = 'Administrators'
        }

        # CceId: CCE-36876-1
        # DataSource: Security Policy
        # Ensure 'Act as part of the operating system' is set to 'No One'
        UserRightsAssignment Actaspartoftheoperatingsystem {
            Policy   = 'Act_as_part_of_the_operating_system'
            Identity = 'No One'
        }

        # CceId: CCE-37056-9
        # DataSource: Security Policy
        # Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
        UserRightsAssignment AccessCredentialManagerasatrustedcaller {
            Policy   = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity = 'No One'
        }

        # CceId: CCE-35823-4 - 2.2.18
        # DataSource: Security Policy
        # Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only)
        UserRightsAssignment Createsymboliclinks {
            Policy   = 'Create_symbolic_links'
            Identity = 'Administrators'
        }

        # CceId: CCE-37659-0 - 2.2.7
        # DataSource: Security Policy
        # Ensure 'Allow log on locally' is set to 'Administrators'
        UserRightsAssignment Allowlogonlocally {
            Policy   = 'Allow_log_on_locally'
            Identity = 'Administrators, ENTERPRISE DOMAIN CONTROLLERS' 
        }

        # CceId: CCE-37639-2
        # DataSource: Security Policy
        # Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Generatesecurityaudits {
            Policy   = 'Generate_security_audits'
            Identity = 'LOCAL SERVICE, NETWORK SERVICE'
        }

        # CceId: CCE-37146-8
        # DataSource: Security Policy
        # Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy   = 'Deny_log_on_locally'
            Identity = 'Guests'
        }

        # CceId: CCE-37452-0 - 2.2.12
        # DataSource: Security Policy
        # Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethesystemtime {
            Policy   = 'Change_the_system_time'
            Identity = 'Administrators, LOCAL SERVICE'
        }

        # CceId: CCE-35906-7
        # DataSource: Security Policy
        # Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)
        UserRightsAssignment  Manageauditingandsecuritylog {
            Policy   = 'Manage_auditing_and_security_log'
            Identity = 'Administrators'
        }

        # CceId: CCE-36860-5
        # DataSource: Security Policy
        # Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC only)
        UserRightsAssignment  Enablecomputeranduseraccountstobetrustedfordelegation {
            Policy   = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity = 'Administrators'
        }

        # CceId: CCE-37954-5
        # DataSource: Security Policy
        # Ensure 'Deny access to this computer from the network' is set to 'Guests' (DC only)
        UserRightsAssignment  Denyaccesstothiscomputerfromthenetwork {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = 'Guests'
        }

        # CceId: CCE-38326-5 - 2.2.34
        # DataSource: Security Policy
        # Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'
        UserRightsAssignment Increaseschedulingpriority {
            Policy   = 'Increase_scheduling_priority'
            Identity = 'Administrators, Window Manager\Window Manager Group'
        }


        # CceId: CCE-37072-6
        # DataSource: Security Policy
        # Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)
        UserRightsAssignment  AllowlogonthroughRemoteDesktopServices {
            Policy   = 'Allow_log_on_through_Remote_Desktop_Services'
            Identity = 'Administrators'
        }

  	# CceId: 2.2.5
        # DataSource: Security Policy
        # Ensure 'L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only) 
        UserRightsAssignment  Addworkstationstodomain {
            Policy   = 'Add_workstations_to_domain'
            Identity = 'Administrators'
        }

 	# CceId: 2.2.6
        # DataSource: Security Policy
        # Ensure 'L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only) 
        UserRightsAssignment  Adjustmemoryquotasforaprocess {
            Policy   = 'Adjust_memory_quotas_for_a_process'
            Identity = 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
        }


	# CceId: 2.2.20
        # DataSource: Security Policy
        # Ensure '(L1) Ensure 'Debug programs' is set to 'Administrators' (Automated)  
        UserRightsAssignment  Debugprograms {
            Policy   = 'Debug_programs'
            Identity = 'Administrators'
        }

	# CceId: 2.2.20
        # DataSource: Security Policy
        # Ensure '(L1) Ensure 'Debug programs' is set to 'Administrators' (Automated)  
        UserRightsAssignment  Synchronizedirectoryservicedata {
            Policy   = 'Synchronize_directory_service_data'
            Identity = 'No One' 
        }

######

        # CceId: 
        # DataSource: Audit Policy
        # Ensure 'Audit Group Membership' is set to 'Success'
        AuditPolicySubcategory 'Audit Group Membership (Success)' {
            Name      = 'Group Membership'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # CceId: CCE-38327-3
        # DataSource: Audit Policy
        # Ensure 'Audit Authentication Policy Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success)' {
            Name      = 'Authentication Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # CceId: CCE-38028-7
        # DataSource: Audit Policy
        # Ensure 'Audit Audit Policy Change' is set to include 'Success'
        AuditPolicySubcategory 'Audit Audit Policy Change (Success)' {
            Name      = 'Audit Policy change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # CceId: CCE-36059-4 
        # DataSource: Audit Policy
        # Ensure 'Audit Process Creation' is set to include 'Success'
        AuditPolicySubcategory 'Audit Process Creation (Success)' {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
    
        # CceId: CCE-37620-2
        # DataSource: Audit Policy
        # Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Object Access Events (Success)' {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Other Object Access Events (Failure)' {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: 
        # DataSource: Audit Policy
        # Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success)' {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure)' {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: CCE-37133-6
        # DataSource: Audit Policy
        # Ensure 'Audit Account Lockout' is set to 'Failure'
        AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
            Name      = 'Account Lockout'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: CCE-38036-0
        # DataSource: Audit Policy
        # Ensure 'Audit Logon' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Logon (Success)' {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        <#AuditPolicySubcategory 'Audit Logon (Failure)' {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: 
        # DataSource: Audit Policy
        # Ensure 'Audit Credential Validation' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Credential Validation (Success)' {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Credential Validation (Failure)' {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: CCE-37132-8
        # DataSource: Audit Policy
        # Ensure 'Audit System Integrity' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit System Integrity (Success)' {
            Name      = 'System Integrity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit System Integrity (Failure)' {
            Name      = 'System Integrity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
	
        # CceId: CCE-36266-5
        # DataSource: Audit Policy
        # Ensure 'Audit Special Logon' is set to 'Success'
        AuditPolicySubcategory 'Audit Special Logon (Success)' {
            Name      = 'Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        
	# CceId: 
        # DataSource: Audit Policy
        # Ensure 'Audit PNP Activity' is set to 'Success'
        AuditPolicySubcategory 'Audit PNP Activity (Success)' {
            Name      = 'PNP Activity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # CceId: CCE-36322-6
        # DataSource: Audit Policy
        # Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: CCE-38237-4
        # DataSource: Audit Policy
        # Ensure 'Audit Logoff' is set to 'Success'
        AuditPolicySubcategory 'Audit Logoff (Success)' {
            Name      = 'Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # CceId: CCE-36267-3
        # DataSource: Audit Policy
        # Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
           Name      = 'Sensitive Privilege Use'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: CCE-37856-2
        # DataSource: Audit Policy
        # Ensure 'Audit User Account Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
           Name      = 'User Account Management'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }

        # CceId: CCE-36144-4
        # DataSource: Audit Policy
        # Ensure 'Audit Security System Extension' is set to 'Success'
        AuditPolicySubcategory 'Audit Security System Extension (Success)' {
           Name      = 'Security System Extensionn'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

        # CceId: CCE-38114-5
        # DataSource: Audit Policy
        # Ensure 'Audit Security State Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Security State Change (Success)' {
           Name      = 'Security State Change'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

        # CceId: CCE-38034-5
        # DataSource: Audit Policy
        # Ensure 'Audit Security Group Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Security Group Management (Success)' {
           Name      = 'Security Group Management'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }

        # CceId: CCE-38028-7
        # DataSource: Audit Policy
        # Ensure 'Audit Removable Storage' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Removable Storage (Success)' {
           Name      = 'Removable Storage'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
           Name      = 'Removable Storage'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.1.2
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' (DC Only) 
	AuditPolicySubcategory 'Audit Kerberos Authentication Service (Success)' {
            Name      = 'Kerberos Authentication Service'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Kerberos Authentication Service (Failure)' {
            Name      = 'Kerberos Authentication Service'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 / 17.1.3
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only)  
	AuditPolicySubcategory 'Audit Kerberos Service Ticket Operations (Success)' {
            Name      = 'Kerberos Service Ticket Operations'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Kerberos Service Ticket Operations (Failure)' {
            Name      = 'Kerberos Service Ticket Operations'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 / 17.1.3
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only)  
	AuditPolicySubcategory 'Audit Kerberos Service Ticket Operations (Success)' {
            Name      = 'Kerberos Service Ticket Operations'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Kerberos Service Ticket Operations (Failure)' {
            Name      = 'Kerberos Service Ticket Operations'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.2.1
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'  
	AuditPolicySubcategory 'Audit Application Group Management (Success)' {
            Name      = 'Application Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Application Group Management (Failure)' {
            Name      = 'Application Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.2.2
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Computer Account Management' is set to include 'Success' (DC only)  
	AuditPolicySubcategory 'Audit Computer Account Managementt (Success)' {
            Name      = 'Computer Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Computer Account Management (Failure)' {
            Name      = 'Computer Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.2.3
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Distribution Group Management' is set to include 'Success' (DC only)  
	AuditPolicySubcategory 'Audit Computer Account Management (Success)' {
            Name      = 'Computer Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
      
	# CceId: CCE-38028-7 - 17.2.4
        # DataSource: Audit Policy
        # L1) Ensure 'Audit Other Account Management Events' is set to include 'Success' (DC only) 
	AuditPolicySubcategory 'Audit Other Account Management Events (Success)' {
            Name      = 'Other Account Management Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.4.1
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Directory Service Access' is set to include 'Failure' (DC only) 
	AuditPolicySubcategory 'Audit Directory Service Access (Failure)' {
            Name      = 'Directory Service Access'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.4.2
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Directory Service Changes' is set to include 'Success' (DC only) 
	AuditPolicySubcategory 'Audit Directory Service Changes (Success)' {
            Name      = 'Directory Service Changes'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.6.1
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'  
	AuditPolicySubcategory 'Audit Detailed File Share (Failure)' {
            Name      = 'Detailed File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.6.2
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit File Share' is set to 'Success and Failure'   
	AuditPolicySubcategory 'Audit File Share (Success)' {
            Name      = 'File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
	AuditPolicySubcategory 'Audit File Share (Failure)' {
            Name      = 'File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.7.3
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success' 
	AuditPolicySubcategory 'Audit Authorization Policy Change (Success)' {
            Name      = 'Authorization Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }


	# CceId: CCE-38028-7 - 17.7.5
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'  
	AuditPolicySubcategory 'Audit Detailed File Share (Failure)' {
            Name      = 'Other Policy Change Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.9.1
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'  
	AuditPolicySubcategory 'Audit IPsec Driver (Success)' {
            Name      = 'IPsec Driver'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
	AuditPolicySubcategory 'Audit IPsec Driver (Failure)' {
            Name      = 'IPsec Driver'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

	# CceId: CCE-38028-7 - 17.9.2
        # DataSource: Audit Policy
        # (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'  
	AuditPolicySubcategory 'Audit Other System Events (Success)' {
            Name      = 'Other System Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
	AuditPolicySubcategory 'Audit Other System Events (Failure)' {
            Name      = 'Other System Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        
	}

        SecurityOption AccountSecurityOptions {
            Name                                   = 'AccountSecurityOptions'

        # CceId: CCE-36056-0
        # DataSource: Registry Policy
        # Ensure 'Windows Search Service' is set to 'Disabled'
        # Windows_Search_Service           =  'Disabled'    

        # CceId: CCE-36056-0
        # DataSource: Registry Policy
        # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
        # Interactive_logon_Do_not_display_last_user_name                                                                 = 'Enabled'
        
        # CceId: CCE-37637-6
        # DataSource: Registry Policy
        # Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
        Interactive_logon_Do_not_require_CTRL_ALT_DEL                                                                   = 'Disabled'
        
        # CceId: CCE-36325-9
        # DataSource: Registry Policy
        # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
        Microsoft_network_client_Digitally_sign_communications_always                                                   = 'Enabled'

        # CceId: CCE-36269-9
        # DataSource: Registry Policy
        # Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
        Microsoft_network_client_Digitally_sign_communications_if_server_agrees                                         = 'Enabled'

        # CceId: CCE-37863-8
        # DataSource: Registry Policy
        # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
        Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers                                   = 'Disabled'

	# CceId: CCE-37615-2 - 2.3.1.1
        # DataSource: Registry Policy
        # Ensure (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts' 
        Accounts_Block_Microsoft_accounts                               = 'Users cant add or log on with Microsoft accounts'

	# CceId: CCE-37615-2 - 2.3.1.4
        # DataSource: Registry Policy
        # (L1) Configure 'Accounts: Rename administrator account' 
        Accounts_Rename_administrator_account                     =  'Principal'                                 

	# CceId: CCE-37615-2 - 2.3.1.4
        # DataSource: Registry Policy
        # (L1) Configure 'Accounts: Rename guest account' 
        Accounts_Rename_guest_account                              = 'Temporal'       
	

        # CceId: CCE-37615-2
        # DataSource: Registry Policy
        # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
        Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only                                       = 'Enabled'

        # CceId: CCE-36788-8
        # DataSource: Registry Policy
        # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
        Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on                                                  = 'Disabled'


        # CceId: CCE-36347-3
        # DataSource: Registry Policy
        # Configure 'Network access: Remotely accessible registry paths and sub-paths' 
        # BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
        Network_access_Remotely_accessible_registry_paths_and_subpaths                                                 = 'System\CurrentControlSet\Control\Print\Printers|#|System\CurrentControlSet\Services\Eventlog|#|Software\Microsoft\OLAP Server|#|Software\Microsoft\Windows NT\CurrentVersion\Print|#|Software\Microsoft\Windows NT\CurrentVersion\Windows|#|System\CurrentControlSet\Control\ContentIndex|#|System\CurrentControlSet\Control\Terminal Server|#|System\CurrentControlSet\Control\Terminal Server\UserConfig|#|System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration|#|Software\Microsoft\Windows NT\CurrentVersion\Perflib|#|System\CurrentControlSet\Services\SysmonLog'

        # CceId: CCE-37194-8
        # DataSource: Registry Policy
        # Configure 'Network access: Remotely accessible registry paths' 
        # BUG - https://github.com/PowerShell/SecurityPolicyDsc/issues/83
        Network_access_Remotely_accessible_registry_paths                                                               = 'System\CurrentControlSet\Control\ProductOptions|#|System\CurrentControlSet\Control\Server Applications|#|Software\Microsoft\Windows NT\CurrentVersion'


        # CceId: CCE-36858-9
        # DataSource: Registry Policy
        # Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
        Network_security_LDAP_client_signing_requirements = 'Negotiate signing'

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' is set to 'Enabled'
        # System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies = 'Enabled'

        # CceId: CCE-37623-6  
        # DataSource: Registry Policy
        # Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
        Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - local users authenticate as themselves'

        # CceId: CCE-35907-5
        # DataSource: Registry Policy
        # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
        Audit_Shut_down_system_immediately_if_unable_to_log_security_audits                                             = 'Disabled'

        # CceId: CCE-37850-5
        # DataSource: Registry Policy
        # Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
        Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'

        # CceId: CCE-37972-7
        # DataSource: Registry Policy
        # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
        Microsoft_network_server_Disconnect_clients_when_logon_hours_expire                                             = 'Enabled'

        # CceId: CCE-35988-5
        # DataSource: Registry Policy
        # Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
        Microsoft_network_server_Digitally_sign_communications_if_client_agrees                                         = 'Enabled'

        # CceId: CCE-37864-6
        # DataSource: Registry Policy
        # Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
        Microsoft_network_server_Digitally_sign_communications_always                                                   = 'Enabled'

        # CceId: CCE-37755-6
        # DataSource: Registry Policy
        # (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
        Network_security_Configure_encryption_types_allowed_for_Kerberos                = 'RC4_HMAC_MD5', 'AES128_HMAC_SHA1', 'AES256_HMAC_SHA1', 'FUTURE'

	# CceId: CCE-37755-6 / 2.3.11.7
        # DataSource: Registry Policy
        # (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
        Network_security_LAN_Manager_authentication_level  = 'Send NTLMv2 responses only. Refuse LM & NTLM'

	# CceId: CCE-37755-6 / 2.3.11.9
        # DataSource: Registry Policy
        # (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients  = 'Both options checked' #'Require NTLMv2 session security, Require 128-bit encryption'

	# CceId: CCE-37755-6 / 2.3.11.10
        # DataSource: Registry Policy
        # (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers   = 'Both options checked' #'Require NTLMv2 session security, Require 128-bit encryption' 

	# CceId: CCE-37755-6 / 2.3.11.11
        # DataSource: Registry Policy
        # (L1) Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts' 
        Network_Security_Restrict_NTLM_Audit_Incoming_NTLM_Traffic = 'Enable auditing for all accounts'

	# CceId: CCE-37755-6 / 2.3.11.12
        # DataSource: Registry Policy
        # (L1) Ensure 'Network security: Restrict NTLM: Audit NTLM authentication in this domain' is set to 'Enable all' (DC only)
        Network_Security_Restrict_NTLM_Audit_NTLM_authentication_in_this_domain  = 'Enable all'

	# CceId: CCE-37755-6 / 2.3.11.13
        # DataSource: Registry Policy
        # (L1) Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher 
        Network_Security_Restrict_NTLM_Outgoing_NTLM_traffic_to_remote_servers  = 'Audit all'

        # CceId: CCE-37701-0
        # DataSource: Registry Policy
        # Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
        Devices_Allowed_to_format_and_eject_removable_media                                                             = 'Administrators'

        # CceId: CCE-37942-0
        # DataSource: Registry Policy
        # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
        Devices_Prevent_users_from_installing_printer_drivers                                                           = 'Enabled'


	# CceId: 2.3.5.1
        # DataSource: Registry Policy
        #  (L1) Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)
        Domain_controller_Allow_server_operators_to_schedule_tasks                                                   = 'Disabled'


	# CceId: 2.3.5.1
        # DataSource: Registry Policy
        # (L1) Ensure 'Domain controller: Allow vulnerable Netlogon secure channel connections' is set to 'Not Configured' (DC Only)
        #Domain_controller_Allow_vulnerable_Netlogon_secure_channel_connections                                   = 'Not Configured'

	# CceId: 2.3.5.3
        # DataSource: Registry Policy
        #  (L1) Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always' (DC Only) 
        #Domain_controller_LDAP_server_channel_binding_token_requirements                                   = 'Always'

 	# CceId: 2.3.5.4
        # DataSource: Registry Policy
        #  (L1) Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only) 
        Domain_controller_LDAP_server_signing_requirements                                   = 'Require signing'

 	# CceId: 2.3.5.5
        # DataSource: Registry Policy
        #  (L1) Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only) 
        Domain_controller_Refuse_machine_account_password_changes                             = 'Disabled'

	# CceId: 2.3.6.1
        # DataSource: Registry Policy
        # Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled' 
        Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always                 = 'Enabled'

	# CceId: 2.3.6.2
        # DataSource: Registry Policy
        # (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled' 
        Domain_member_Digitally_encrypt_secure_channel_data_when_possible                  = 'Enabled'

	# CceId: 2.3.6.3
        # DataSource: Registry Policy
        # (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled' (
        Domain_member_Digitally_sign_secure_channel_data_when_possible                  = 'Enabled'


	# CceId: 2.3.6.4
        # DataSource: Registry Policy
        # (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled' 
        Domain_member_Disable_machine_account_password_changes                  = 'Disabled'


	# CceId: 2.3.6.5
        # DataSource: Registry Policy
        #(L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0' (
        Domain_member_Maximum_machine_account_password_age                  = '30'

	# CceId: 2.3.6.6
        # DataSource: Registry Policy
        # (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled' 
        Domain_member_Require_strong_Windows_2000_or_later_session_key      = 'Enabled'

	# CceId: 2.3.7.2
        # DataSource: Registry Policy
        # L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled' 
        Interactive_logon_Do_not_display_last_user_name                    = 'Enabled'


	# CceId: 2.3.7.3
        # DataSource: Registry Policy
        # (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0' 
        Interactive_logon_Machine_inactivity_limit                        = '900'

	# CceId: 2.3.7.4
        # DataSource: Registry Policy
        # (L1) Configure 'Interactive logon: Message text for users attempting to log on' (
        Interactive_logon_Message_text_for_users_attempting_to_log_on      = 'Youre attempting to log on'

	# CceId: 2.3.7.5
        # DataSource: Registry Policy
        # (L1) Configure 'Interactive logon: Message title for users attempting to log on' 
        Interactive_logon_Message_title_for_users_attempting_to_log_on    = 'log on'

	# CceId: 2.3.7.7
        # DataSource: Registry Policy
        # (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days' 
        Interactive_logon_Prompt_user_to_change_password_before_expiration      = '6'

	# CceId: 2.3.7.9
        # DataSource: Registry Policy
        # (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days' 
        Interactive_logon_Smart_card_removal_behavior          = 'Lock Workstation'

	# CceId: 2.3.10.1
        # DataSource: Registry Policy
        # (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled' 
        Network_access_Allow_anonymous_SID_Name_translation       = 'Disabled'

	# CceId: 2.3.10.7
        # DataSource: Registry Policy
        # (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled' 
        Network_access_Named_Pipes_that_can_be_accessed_anonymously     = 'LSARPC, NETLOGON, SAMR'

	# CceId: 2.3.10.10
        # DataSource: Registry Policy
        # (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' 
        Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares  = 'Enabled'

	# CceId: 2.3.10.12
        # DataSource: Registry Policy
        # (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' 
        Network_access_Shares_that_can_be_accessed_anonymously        = 'None'

	# CceId: 2.3.10.4
        # DataSource: Registry Policy
        # (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled' 
        Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication  = 'Enabled' 

        # CceId: CCE-38341-4 ++
        # DataSource: Registry Policy
        # Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
        Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM                                           = 'Enabled'

        # CceId: CCE-38047-7
        # DataSource: Registry Policy
        # Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
        Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities                  = 'Disabled'

        # CceId: CCE-36148-5
        # DataSource: Registry Policy
        # Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
        Network_access_Let_Everyone_permissions_apply_to_anonymous_users                                                = 'Disabled'

        # CceId: CCE-36148-5
        # DataSource: Registry Policy
        # Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
        Network_security_Allow_LocalSystem_NULL_session_fallback                                                = 'Disabled'

        # CceId: CCE-38046-9
        # DataSource: Registry Policy
        # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute, but not 0'
        Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'


        # CceId: CCE-37701-0
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
        User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode            = 'Prompt for consent on the secure desktop'


 	# CceId: CCE-37701-0 - 2.3.15.1
        # DataSource: Registry Policy
        # (L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems
        System_objects_Require_case_insensitivity_for_non_Windows_subsystems     = 'Enabled'

	# CceId: CCE-37701-0 - 2.3.15.2
        # DataSource: Registry Policy
        # (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled' Windows subsystems
        System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links  = 'Enabled'

	# CceId: CCE-37701-0 - 2.3.17.1
        # DataSource: Registry Policy
        # (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' 
        User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account     = 'Enabled'

	# CceId: CCE-37701-0 - 2.3.17.1
        # DataSource: Registry Policy
        # (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' 
        User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users    = 'Automatically deny elevation request'


	# CceId: CCE-37701-0 - 2.3.17.1
        # DataSource: Registry Policy
        # (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' 
        User_Account_Control_Detect_application_installations_and_prompt_for_elevation     = 'Enabled'

	# CceId: CCE-37701-0 - 2.3.17.5
        # DataSource: Registry Policy
        # (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' (
        User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations    = 'Enabled'

	# CceId: CCE-37701-0 - 2.3.17.7
        # DataSource: Registry Policy
        # (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' (
        User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation     = 'Enabled'

	# CceId: CCE-37701-0 - 2.3.17.8
        # DataSource: Registry Policy
        # (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled' 
        User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'

        }
        
        # CceId: CCE-37864-6
        # DataSource: Registry Policy
        # Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
        <#Registry 'SupportedEncryptionTypes' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Sofware\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueName = 'SupportedEncryptionTypes'
            ValueType = 'DWord'
            ValueData = '2147483644'
        }#>

         # CceId: 
        # DataSource: Registry Policy
        <# Ensure 'Allow Cortana above lock screen' is set to 'Disabled'
        Registry 'AllowCortanaAboveLock' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCortanaAboveLock'
            ValueType = 'DWord'
            ValueData = '0'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only)
        <#Registry 'RestrictRemoteSam' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictRemoteSam'
            ValueType = 'DWord'
            ValueData = 'O:BAG:BAD:(A  RC   BA)'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
        Registry 'NullSessionShares' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName = 'NullSessionShares'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36173-3
        # DataSource: Registry Policy
        # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
        Registry 'LmCompatibilityLevel' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'LmCompatibilityLevel'
            ValueType = 'DWord'
            ValueData = '5'
        }

        # CceId: CCE-37835-6
        # DataSource: Registry Policy
        # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'NTLMMinServerSec' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'NTLMMinServerSec'
            ValueType = 'DWord'
            ValueData = '537395200'
        }

        # CceId: CCE-37553-5 
        # DataSource: Registry Policy
        # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'NTLMMinClientSec' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'NTLMMinClientSec'
            ValueType = 'DWord'
            ValueData = '537395200'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: CCE-36863-9 
        # DataSource: Registry Policy
        <# Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled' 
        Registry 'EnableUIADesktopToggle' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableUIADesktopToggle'
            ValueType = 'DWord'
            ValueData = '0'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Allow Cortana' is set to 'Disabled'
        Registry 'AllowCortana' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCortana'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Enable 'Turn on behavior monitoring'
        Registry 'DisableBehaviorMonitoring' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection'
            ValueName = 'DisableBehaviorMonitoring'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        <# Enable 'Send file samples when further analysis is required' for 'Send Safe Samples'
        Registry 'SubmitSamplesConsent' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet'
            ValueName = 'SubmitSamplesConsent'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Scan removable drives' is set to 'Enabled'
        Registry 'DisableRemovableDriveScanning' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan'
            ValueName = 'DisableRemovableDriveScanning'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        <# Ensure 'Detect change from default RDP port' is configured
        Registry 'PortNumber' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp'
            ValueName = 'PortNumber'
            ValueType = 'DWord'
            ValueData = '3389'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        <# Ensure 'Allow search and Cortana to use location' is set to 'Disabled'
        Registry 'AllowSearchToUseLocation' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowSearchToUseLocation'
            ValueType = 'DWord'
            ValueData = '0'
        }#>

       

        # CceId: 
        # DataSource: Registry Policy
        <# Ensure 'Allow Input Personalization' is set to 'Disabled'
        Registry 'AllowInputPersonalization' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization'
            ValueName = 'AllowInputPersonalization'
            ValueType = 'DWord'
            ValueData = '0'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        <# Ensure 'Shutdown: Clear virtual memory pagefile' is set to 'Enabled'
        Registry 'ClearPageFileAtShutdown' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management'
            ValueName = 'ClearPageFileAtShutdown'
            ValueType = 'DWord'
            ValueData = '0'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        <# Ensure 'Recovery console: Allow floppy copy and access to all drives and all folders' is set to 'Disabled'
        Registry 'AllowAllPaths' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand'
            ValueName = 'AllowAllPaths'
            ValueType = 'DWord'
            ValueData = '0'
        }#>

        # CceId: CCE-36864-7
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
        Registry 'ConsentPromptBehaviorUser' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'ConsentPromptBehaviorUser'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Specify the interval to check for definition updates' is set to 'Enabled:1'
        Registry 'SignatureUpdateInterval' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Signature Updates'
            ValueName = 'SignatureUpdateInterval'
            ValueType = 'DWord'
            ValueData = '8'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        <# Ensure 'Windows Firewall: Public: Allow unicast response' is set to 'No'
        Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Allow unicast response' is set to 'No'
        <#Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Allow unicast response' is set to 'No'
        <#Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '0'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'
        Registry 'AllowLocalPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'AllowLocalPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37346-4
        # DataSource: Registry Policy
        # Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
        Registry 'EnableAuthEpResolution' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName = 'EnableAuthEpResolution'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37843-0
        # DataSource: Registry Policy
        <# Ensure 'Enable Windows NTP Client' is set to 'Enabled'
        Registry 'NTPClientEnabled' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: CCE-36512-2
        # DataSource: Registry Policy
        # Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
        Registry 'EnumerateAdministrators' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueName = 'EnumerateAdministrators'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36925-6
        # DataSource: Registry Policy
        # Ensure 'Include command line in process creation events' is set to 'Disabled'
        Registry 'ProcessCreationIncludeCmdLine_Enabled' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType = 'DWord'
            ValueData = '1'
        }

        
        # CceId: CCE-36254-1
        # DataSource: Registry Policy
        # Ensure 'Allow Basic authentication' is set to 'Disabled'
        Registry 'AllowBasic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowBasic'
            ValueType = 'DWord'
            ValueData = '0'
        } 
        

        # CceId: CCE-38338-0
        # DataSource: Registry Policy
        # Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
        Registry 'fMinimizeConnections' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueName = 'fMinimizeConnections'
            ValueType = 'DWord'
            ValueData = '3'
        }

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.81.1 (L1) Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled' 
	Registry 'DisableAutomaticRestartSignOnAndLock' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
	    ValueName = 'DisableAutomaticRestartSignOn'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

        # CceId: CCE-37526-1
        # DataSource: Registry Policy
        # Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSetupLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }

        # CceId: CCE-38276-2
        # DataSource: Registry Policy
        # Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSetupLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        # CceId: CCE-38217-6
        # DataSource: Registry Policy
        # Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
        Registry 'NoAutorun' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoAutorun'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37695-4
        # DataSource: Registry Policy
        # Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
        Registry 'MaxSizeSecurityLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '196608'
        }

        # CceId: CCE-37145-0
        # DataSource: Registry Policy
        # Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSecurityLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        # CceId: CCE-38002-2
        # DataSource: Registry Policy
        # Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
        Registry 'NC_AllowNetBridge_NLA' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_AllowNetBridge_NLA'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38348-9
        # DataSource: Registry Policy
        # Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
        Registry 'NoLockScreenSlideshow' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenSlideshow'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38347-1
        # DataSource: Registry Policy
        # Ensure 'Prevent enabling lock screen camera' is set to 'Enabled' 
        Registry 'NoLockScreenCamera' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenCamera'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37126-0
        # DataSource: Registry Policy
        # Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
        Registry 'DisableEnclosureDownload' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName = 'DisableEnclosureDownload'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.1.2.2
        # DataSource: Registry Policy
        # (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled' (
        Registry 'AllowInputPersonalization' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization'
            ValueName = 'AllowInputPersonalization'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.1.2.2
        # DataSource: Registry Policy
        # (L2) Ensure 'Allow Online Tips' is set to 'Disabled'
        Registry 'AllowOnlineTips' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'AllowOnlineTips'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.4.2
        # DataSource: Registry Policy
        # (L1) Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled' 
        Registry 'RpcAuthnLevelPrivacyEnabled' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print'
            ValueName = 'RpcAuthnLevelPrivacyEnabled'
            ValueType = 'DWord'
            ValueData = '1'
        }


	# CceId: CCE-37126-0 - 18.4.3
        # DataSource: Registry Policy
        # (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)' 
        Registry 'ConfigureSMBv1clientdriver' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10'
            ValueName = 'Start'
            ValueType = 'DWord'
            ValueData = '4'
        }

	# CceId: CCE-37126-0 - 18.4.5
        # DataSource: Registry Policy
        # (L1) Ensure 'Enable Certificate Padding' is set to 'Enabled' 
        Registry 'EnableCertPaddingCheck' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Wintrust\Config'
            ValueName = 'EnableCertPaddingCheck'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.4.6
        # DataSource: Registry Policy
        # (L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled' 
        Registry 'DisableExceptionChainValidation' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            ValueName = 'DisableExceptionChainValidation'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.4.7
        # DataSource: Registry Policy
        # (L1) Ensure 'LSA Protection' is set to 'Enabled'
        Registry 'RunAsPPL' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RunAsPPL'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.4.8
        # DataSource: Registry Policy
        # (L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)' 
        Registry 'NodeType' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
            ValueName = 'NodeType'
            ValueType = 'DWord'
            ValueData = '2'
        }

	# CceId: CCE-37126-0 - 18.4.9
        # DataSource: Registry Policy
        # (L1) Ensure 'WDigest Authentication' is set to 'Disabled'
        Registry 'UseLogonCredential' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            ValueName = 'UseLogonCredential'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.5.1
        # DataSource: Registry Policy
        #(L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled' 
        Registry 'AutoAdminLogon' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueName = 'AutoAdminLogon'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.5.2
        # DataSource: Registry Policy
        # (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled' 
        Registry 'DisableIP6SourceRouting' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueName = 'DisableIPSourceRouting'
            ValueType = 'DWord'
            ValueData = '2'
        }

	# CceId: CCE-37126-0 - 18.5.3
        # DataSource: Registry Policy
        # (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source outing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled' 
        Registry 'DisableIPSourceRouting' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'DisableIPSourceRouting'
            ValueType = 'DWord'
            ValueData = '2'
        }

	# CceId: CCE-37126-0 - 18.5.4
        # DataSource: Registry Policy
        # (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled' 
        Registry 'EnableICMPRedirect' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'EnableICMPRedirect'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.5.5
        # DataSource: Registry Policy
        # (L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes' 
        Registry 'KeepAliveTime' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'KeepAliveTime'
            ValueType = 'DWord'
            ValueData = '300000'
        }

	# CceId: CCE-37126-0 - 18.5.6
        # DataSource: Registry Policy
        # (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled' 
        Registry 'NoNameReleaseOnDemand' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
            ValueName = 'NoNameReleaseOnDemand'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.5.7
        # DataSource: Registry Policy
        # (L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses' is set to 'Disabled' 
        Registry 'PerformRouterDiscovery' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'PerformRouterDiscovery'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.5.8
        # DataSource: Registry Policy
        # (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled' 
        Registry 'SafeDllSearchMode' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager'
            ValueName = 'SafeDllSearchMode'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.5.9
        # DataSource: Registry Policy
        # (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds' 
        Registry 'ScreenSaverGracePeriod' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueName = 'ScreenSaverGracePeriod'
            ValueType = 'String'
            ValueData = '5'
        }


	# CceId: CCE-37126-0 - 18.5.10
        # DataSource: Registry Policy
        # (L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3' 
        Registry 'TcpMaxDataRetransmissionsIPv6' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'
            ValueName = 'TcpMaxDataRetransmissions'
            ValueType = 'DWord'
            ValueData = '3'
        }

	# CceId: CCE-37126-0 - 18.5.11
        # DataSource: Registry Policy
        # (L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3' 
        Registry 'TcpMaxDataRetransmissions' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'TcpMaxDataRetransmissions'
            ValueType = 'DWord'
            ValueData = '3'
        }

	# CceId: CCE-37126-0 - 18.5.12
        # DataSource: Registry Policy
        # (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less' 
        Registry 'WarningLevel' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
            ValueName = 'WarningLevel'
            ValueType = 'DWord'
            ValueData = '90'
        }


	# CceId: CCE-37126-0 - 18.6.4.1
        # DataSource: Registry Policy
        # (L1) Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'
        Registry 'EnableNetbios' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName = 'EnableNetbios'
            ValueType = 'DWord'
            ValueData = '2'
        }

	# CceId: CCE-37126-0 - 18.6.5.1
        # DataSource: Registry Policy
        # (L2) Ensure 'Enable Font Providers' is set to 'Disabled'
        Registry 'EnableFontProviders' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableFontProviders'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.6.9.1
        # DataSource: Registry Policy
        # (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' 
        Registry 'AllowLLTDIOOnDomain' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
            ValueName = 'AllowLLTDIOOnDomain'
            ValueType = 'DWord'
            ValueData = '0'
        }
	Registry 'AllowLLTDIOOnPublicNet' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
            ValueName = 'AllowLLTDIOOnPublicNet'
            ValueType = 'DWord'
            ValueData = '0'
        }
	Registry 'EnableLLTDIO' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
            ValueName = 'EnableLLTDIO'
            ValueType = 'DWord'
            ValueData = '0'
        }
	Registry 'ProhibitLLTDIOOnPrivateNet' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
            ValueName = 'ProhibitLLTDIOOnPrivateNet'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.6.9.2
        # DataSource: Registry Policy
        # (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled' 
        Registry 'AllowRspndrOnDomain' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
            ValueName = 'AllowRspndrOnDomain'
            ValueType = 'DWord'
            ValueData = '0'
        }
	Registry 'AllowRspndrOnPublicNet' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
            ValueName = 'AllowRspndrOnPublicNet'
            ValueType = 'DWord'
            ValueData = '0'
        }
	Registry 'EnableRspndr' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
            ValueName = 'EnableRspndr'
            ValueType = 'DWord'
            ValueData = '0'
        }
	Registry 'ProhibitRspndrOnPrivateNet' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
            ValueName = 'ProhibitRspndrOnPrivateNet'
            ValueType = 'DWord'
            ValueData = '0'
        }


	# CceId: CCE-37126-0 - 18.6.10.2
        # DataSource: Registry Policy
        # (L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled' 
        Registry 'DisabledMicrosoftP2PNetworkingServices' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet'
            ValueName = 'Disabled'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.6.11.4
        # DataSource: Registry Policy
        # (L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled' 
        Registry 'NC_StdDomainUserSetLocation' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_StdDomainUserSetLocation'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.6.14.1
        # DataSource: Registry Policy
        # (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication", "Require Integrity", and “Require Privacy” set for all NETLOGON and SYSVOL shares' 
        Registry '\\*\NETLOGON' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName = '\\*\NETLOGON'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'
        }
	Registry '\\*\SYSVOL' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName = '\\*\SYSVOL'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'
        }

	# CceId: CCE-37126-0 - 18.6.19.2.1
        # DataSource: Registry Policy
        # (L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)') 
        Registry 'DisabledComponents' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'
            ValueName = 'DisabledComponents'
            ValueType = 'DWord'
            ValueData = '255'
        }

	# CceId: CCE-37126-0 - 18.6.20.1
        # DataSource: Registry Policy
        # (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' 
        Registry 'EnableRegistrars' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
            ValueName = 'EnableRegistrars'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'DisableUPnPRegistrar' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
            ValueName = 'DisableUPnPRegistrar'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'DisableInBand802DOT11Registrar' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
            ValueName = 'DisableInBand802DOT11Registrar'
            ValueType = 'DWord'
            ValueData = '0'
        }
        Registry 'DisableFlashConfigRegistrar' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
            ValueName = 'DisableFlashConfigRegistrar'
            ValueType = 'DWord'
            ValueData = '0'
        }
	Registry 'DisableWPDRegistrar' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
            ValueName = 'DisableWPDRegistrar'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.6.20.2
        # DataSource: Registry Policy
        # (L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled' 
        Registry 'DisableWcnUi' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI'
            ValueName = 'DisableWcnUi'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.7.1
        # DataSource: Registry Policy
        # (L1) Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'  
        Registry 'RegisterSpoolerRemoteRpcEndPoint' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'RegisterSpoolerRemoteRpcEndPoint'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.7.2
        # DataSource: Registry Policy
        # (L1) Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled' '  
        Registry 'RedirectionguardPolicy' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'RedirectionguardPolicy'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.7.3
        # DataSource: Registry Policy
        # (L1) Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP' (
        Registry 'RpcUseNamedPipeProtocol' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueName = 'RpcUseNamedPipeProtocol'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.7.4
        # DataSource: Registry Policy
        # (L1) Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default' 
        Registry 'RpcAuthentication' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueName = 'RpcAuthentication'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.7.5
        # DataSource: Registry Policy
        # (L1) Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP' (
        Registry 'RpcProtocols' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueName = 'RpcProtocols'
            ValueType = 'DWord'
            ValueData = '5'
        }

	# CceId: CCE-37126-0 - 18.7.6
        # DataSource: Registry Policy
        # (L1) Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher 
        Registry 'ForceKerberosForRpc' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueName = 'ForceKerberosForRpc'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.7.7
        # DataSource: Registry Policy
        # (L1) Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' 
        Registry 'RpcTcpPort' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueName = 'RpcTcpPort'
            ValueType = 'DWord'
            ValueData = '0'
        }


	# CceId: CCE-37126-0 - 18.7.8
        # DataSource: Registry Policy
        # (L1) Ensure 'Limits print driver installation to Administrators' is set to 'Enabled' 
        Registry 'RestrictDriverInstallationToAdministrators' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            ValueName = 'RestrictDriverInstallationToAdministrators'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.7.9
        # DataSource: Registry Policy
        # (L1) Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'  
        Registry 'CopyFilesPolicy'{
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'CopyFilesPolicy'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.7.10
        # DataSource: Registry Policy
        # (L1) Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt' 
        Registry 'NoWarningNoElevationOnInstall' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            ValueName = 'NoWarningNoElevationOnInstall'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.7.11
        # DataSource: Registry Policy
        # (L1) Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt' 
        Registry 'UpdatePromptSettings' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            ValueName = 'UpdatePromptSettings'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: CCE-37126-0 - 18.8.1.1
        # DataSource: Registry Policy
        # (L2) Ensure 'Turn off notifications network usage' is set to 'Enabled' 
        Registry 'NoCloudApplicationNotification' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
            ValueName = 'NoCloudApplicationNotification'
            ValueType = 'DWord'
            ValueData = '1'
        }

	# CceId: CCE-37126-0 - 18.9.4.1
        # DataSource: Registry Policy
        # (L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'  
        Registry 'AllowEncryptionOracle ' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
            ValueName = 'AllowEncryptionOracle'
            ValueType = 'DWord'
            ValueData = '1'
        }


	# CceID: CCE-36918-5
	# DataSource: Registry Policy
	# 18.9.4.2 (L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled' (Automated)

	Registry 'AllowProtectedCreds' {
	    Ensure      = 'Present'
  	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
  	    ValueName   = 'AllowProtectedCreds'
   	    ValueType   = 'DWord'
 	    ValueData   = '1'
	}

	# CceID: CCE-36918-5
	# DataSource: Registry Policy
	# 18.9.5.1 (NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' set to 'Enabled' (Automated)

	Registry 'EnableVirtualizationBasedSecurity' {
	    Ensure      = 'Present'
  	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
  	    ValueName   = 'EnableVirtualizationBasedSecurity'
   	    ValueType   = 'DWord'
 	    ValueData   = '1'
	}

	# CceID: CCE-36918-5
	# DataSource: Registry Policy
	# 18.9.5.2 (NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher

	Registry 'RequirePlatformSecurityFeatures' {
	    Ensure      = 'Present'
  	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
  	    ValueName   = 'RequirePlatformSecurityFeatures'
   	    ValueType   = 'DWord'
 	    ValueData   = '1'
	}

	# CceID: CCE-36918-5
	# DataSource: Registry Policy
	# 18.9.5.3 (NG) Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock' 

	Registry 'HypervisorEnforcedCodeIntegrity' {
	    Ensure      = 'Present'
  	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
  	    ValueName   = 'HypervisorEnforcedCodeIntegrity'
   	    ValueType   = 'DWord'
 	    ValueData   = '1'
	}

	# CceID: CCE-39051-2
	# DataSource: Registry Policy
	# 18.9.7.2 (L1) Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled' (Automated)

	Registry 'PreventDeviceMetadataFromNetwork' {
    	    Ensure      = 'Present'
    	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'
    	    ValueName   = 'PreventDeviceMetadataFromNetwork'
    	    ValueType   = 'DWord'
   	    ValueData   = '1'
	}

	# CceID: CCE-37015-8
	# DataSource: Registry Policy
	# 18.9.19.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE' (Automated)

	Registry 'NoBackgroundPolicy' {
    	    Ensure      = 'Present'
    	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
    	    ValueName   = 'NoBackgroundPolicy'
    	    ValueType   = 'DWord'
    	    ValueData   = '0'
	}

	# CceID: CCE-37016-6
	# DataSource: Registry Policy
	# 18.9.19.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE' (Automated)

	Registry 'NoGPOListChangesGPNoChange' {
   	    Ensure      = 'Present'
    	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
    	    ValueName   = 'NoGPOListChanges'
    	    ValueType   = 'DWord'
   	    ValueData   = '0'
	}

	# CceID: CCE-37017-4
	# DataSource: Registry Policy
	# 18.9.19.4 (L1) Ensure 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE' (Automated)

	Registry 'NoBackgroundPolicy1' {
	    Ensure      = 'Present'
	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
	    ValueName   = 'NoBackgroundPolicy'
	    ValueType   = 'DWord'
	    ValueData   = '0'
	}

	# CceID: CCE-37018-2
	# DataSource: Registry Policy
	# 18.9.19.5 (L1) Ensure 'Configure security policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE' (Automated)

	Registry 'NoGPOListChanges' {
	    Ensure      = 'Present'
	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
	    ValueName   = 'NoGPOListChanges'
	    ValueType   = 'DWord'
 	    ValueData   = '0'
	}	

	# CceID: CCE-36368-0
	# 18.9.19.7 (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled' (Automated)

	Registry 'DisableBkGndGroupPolicy' {
	    Ensure      = 'Absent'
	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
	    ValueName   = 'DisableBkGndGroupPolicy'
	}

	# CceID: CCE-37016-6
	# DataSource: Registry Policy
	# 18.9.20.1.2 (L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled' 

	Registry 'PreventHandwritingDataSharing' {
	    Ensure      = 'Present'
 	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC'
 	    ValueName   = 'PreventHandwritingDataSharing'
  	    ValueType   = 'DWord'
  	    ValueData   = '1'
	}

	# CceID: CCE-37017-4
	# DataSource: Registry Policy
	# 18.9.20.1.3 (L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled' (Automated)

	Registry 'PreventHandwritingErrorReports' {
	    Ensure      = 'Present'
	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports'
	    ValueName   = 'PreventHandwritingErrorReports'
	    ValueType   = 'DWord'
	    ValueData   = '1'
	}

	# CceID: CCE-37018-2
	# DataSource: Registry Policy
	# 18.9.20.1.5 (L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled' (Automated)

	Registry 'NoWebServices' {
	    Ensure      = 'Present'
	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
	    ValueName   = 'NoWebServices'
	    ValueType   = 'DWord'
	    ValueData   = '1'
	}

	# CceID: CCE-37019-0
	# DataSource: Registry Policy
	# 18.9.20.1.6 (L2) Ensure 'Turn off printing over HTTP' is set to 'Enabled' (Automated)

	Registry 'DisableHTTPPrinting' {
	    Ensure      = 'Present'
	    Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
	    ValueName   = 'DisableHTTPPrinting'
	    ValueType   = 'DWord'
	    ValueData   = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
	Registry 'NoRegistration' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control'
	    ValueName = 'NoRegistration'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
	Registry 'DisableContentFileUpdates' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion'
	    ValueName = 'DisableContentFileUpdates'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
	Registry 'NoOnlinePrintsWizard' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
	    ValueName = 'NoOnlinePrintsWizard'
  	    ValueType = 'DWord'
 	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
	Registry 'NoPublishingWizard' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
	    ValueName = 'NoPublishingWizard'
   	    ValueType = 'DWord'
 	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
	Registry 'CEIP' {
 	   Ensure    = 'Present'
  	   Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client'
  	   ValueName = 'CEIP'
  	   ValueType = 'DWord'
  	   ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
	Registry 'CEIPEnable' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
	    ValueName = 'CEIPEnable'
 	    ValueType = 'DWord'
 	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'

	# Configure 'Disabled' value in 'Windows Error Reporting'
	Registry 'DisabledWER' {
  	    Ensure    = 'Present'
  	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
  	    ValueName = 'Disabled'
  	    ValueType = 'DWord'
 	    ValueData = '1'
	}
	# Configure 'DoReport' value in 'ErrorReporting'
	Registry 'DoReportER' {
    	    Ensure    = 'Present'
   	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting'
    	    ValueName = 'DoReport'
    	    ValueType = 'DWord'
    	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'

	# Configure 'DevicePKInitBehavior' value to 'Automatic'
	Registry 'DevicePKInitBehavior' {
 	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters'
 	    ValueName = 'DevicePKInitBehavior'
 	    ValueType = 'DWord'
 	    ValueData = '0' 
	}
	# Configure 'DevicePKInitEnabled' value to 'Enabled'
	Registry 'DevicePKInitEnabled' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters'
	    ValueName = 'DevicePKInitEnabled'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'
	Registry 'DeviceEnumerationPolicy' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
	    ValueName = 'DeviceEnumerationPolicy'
	    ValueType = 'DWord'
	    ValueData = '0' 
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Configure password backup directory' is set to 'Enabled: Active Directory'
	Registry 'BackupDirectory' {
  	  Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
	    ValueName = 'BackupDirectory'
	    ValueType = 'DWord'
	    ValueData = '2'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'
	Registry 'PwdExpirationProtectionEnabled' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
	    ValueName = 'PwdExpirationProtectionEnabled'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Enable password encryption' is set to 'Enabled'
	Registry 'ADPasswordEncryptionEnabled' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
	    ValueName = 'ADPasswordEncryptionEnabled'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'
	Registry 'PasswordComplexity' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
	    ValueName = 'PasswordComplexity'
	    ValueType = 'DWord'
	    ValueData = '4'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'
	Registry 'PasswordLength' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
	    ValueName = 'PasswordLength'
	    ValueType = 'DWord'
	    ValueData = '15'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'
	Registry 'PasswordAgeDays' {
   	    Ensure    = 'Present'
   	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
	    ValueName = 'PasswordAgeDays'
	    ValueType = 'DWord'
	    ValueData = '30'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Post-authentication actions: Grace period (hours)' is set to 'Enabled: 8 or fewer hours, but not 0'
	Registry 'PostAuthenticationResetDelay' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
	    ValueName = 'PostAuthenticationResetDelay'
	    ValueType = 'DWord'
	    ValueData = '8'  # Set to 8 hours or fewer, but not 0
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Post-authentication actions: Actions' is set to 'Enabled: Reset the password and logoff the managed account' or higher
	Registry 'PostAuthenticationActions' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
	    ValueName = 'PostAuthenticationActions'
	    ValueType = 'DWord'
	    ValueData = '3'  # Assuming '3-5' corresponds to 'Reset the password and logoff the managed account' or higher
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'
	Registry 'BlockUserInputMethodsForSignIn' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International'
	    ValueName = 'BlockUserInputMethodsForSignIn'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
	Registry 'DontEnumerateConnectedUsers' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
	    ValueName = 'DontEnumerateConnectedUsers'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off picture password sign-in' is set to 'Enabled'
	Registry 'BlockDomainPicturePassword' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
	    ValueName = 'BlockDomainPicturePassword'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'
	Registry 'AllowCrossDeviceClipboard' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
	    ValueName = 'AllowCrossDeviceClipboard'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Allow upload of User Activities' is set to 'Disabled'
	Registry 'UploadUserActivities' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
	    ValueName = 'UploadUserActivities'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'
	Registry 'DCSettingIndex' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
	    ValueName = 'DCSettingIndex'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'
	Registry 'ACSettingIndexDurConStan' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
	    ValueName = 'ACSettingIndex'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
	Registry 'DCSettingIndexPassOnBattery' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
	    ValueName = 'DCSettingIndex'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'
	Registry 'ACSettingIndex' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
	    ValueName = 'ACSettingIndex'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.9.47.5.1 Ensure (L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled' 
	Registry 'DisableQueryRemoteServer' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
	    ValueName = 'DisableQueryRemoteServer'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.9.47.11.1 (L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled' 
	Registry 'ScenarioExecutionEnabled' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-878188dd50a6299d}'
	    ValueName = 'ScenarioExecutionEnabled'
	    ValueType = 'DWord'
	    ValueData = '0'
	}


	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off the advertising ID' is set to 'Enabled'
	Registry 'DisabledByGroupPolicy' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
	    ValueName = 'DisabledByGroupPolicy'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'
	Registry 'AllowSharedLocalAppData' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager'
	    ValueName = 'AllowSharedLocalAppData'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# (L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled' 
	Registry 'EnhancedAntiSpoofing' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
	    ValueName = 'EnhancedAntiSpoofing'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Allow Use of Camera' is set to 'Disabled'
	Registry 'AllowCamera' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Camera'
	    ValueName = 'AllowCamera'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'
	Registry 'DisableConsumerAccountStateContent' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
	    ValueName = 'DisableConsumerAccountStateContent'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'
	Registry 'RequirePinForPairing' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect'
	    ValueName = 'RequirePinForPairing'
	    ValueType = 'DWord'
	    ValueData = '1'  # 1 o 2 para 'Enabled: First Time' o 'Always'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'
	Registry 'AllowTelemetry1' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
	    ValueName = 'AllowTelemetry'
	    ValueType = 'DWord'
	    ValueData = '1'  # 1 para 'Send required diagnostic data', 2 para 'Diagnostic data off (not recommended)'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'
	Registry 'DisableEnterpriseAuthProxy' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
	    ValueName = 'DisableEnterpriseAuthProxy'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Disable OneSettings Downloads' is set to 'Enabled'
	Registry 'DisableOneSettingsDownloads' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
	    ValueName = 'DisableOneSettingsDownloads'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Enable OneSettings Auditing' is set to 'Enabled'
	Registry 'EnableOneSettingsAuditing' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
	    ValueName = 'EnableOneSettingsAuditing'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'
	Registry 'LimitDiagnosticLogCollection' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
	    ValueName = 'LimitDiagnosticLogCollection'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Limit Dump Collection' is set to 'Enabled'
	Registry 'LimitDumpCollection' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
	    ValueName = 'LimitDumpCollection'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Toggle user control over Insider builds' is set to 'Disabled'
	Registry 'AllowBuildPreview' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'
	    ValueName = 'AllowBuildPreview'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Enable App Installer' is set to 'Disabled'
	Registry 'EnableAppInstaller' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
	    ValueName = 'EnableAppInstaller'
	    ValueType = 'DWord'
 	   ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Enable App Installer Experimental Features' is set to 'Disabled'
	Registry 'EnableExperimentalFeatures' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
	    ValueName = 'EnableExperimentalFeatures'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Enable App Installer Hash Override' is set to 'Disabled'
	Registry 'EnableHashOverride' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
	    ValueName = 'EnableHashOverride'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'
	Registry 'EnableMSAppInstallerProtocol' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
	    ValueName = 'EnableMSAppInstallerProtocol'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off location' is set to 'Enabled'
	Registry 'DisableLocation' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
	    ValueName = 'DisableLocation'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'
	Registry 'AllowMessageSync' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging'
	    ValueName = 'AllowMessageSync'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'
	Registry 'DisableUserAuth' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftAccount'
	    ValueName = 'DisableUserAuth'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.5.2 (L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled' 
	Registry 'SpynetReportingMMAPS' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
	    ValueName = 'SpynetReporting'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.6.1.1 (L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'  
	Registry 'ExploitGuard_ASR_Rules' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
	    ValueName = 'ExploitGuard_ASR_Rules'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.6.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (
	Registry 'StateRule_ASR_Rules1' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = '26190899-1602-49e8-8b27-eb1d0a1ce869'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules2' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = '3b576869-a4ec-4529-8536-b80a7769e899'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules3' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = '56a863a9-875e-4185-98a7-b882c64b5ce5'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules4' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules5' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules6' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules7' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules8' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules9' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules10' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules11' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = 'd3e037e1-3eb8-44c8-a917-57927947596d'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules12' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
	    ValueType = 'String'
	    ValueData = '1'
	}
	Registry 'StateRule_ASR_Rules13' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
	    ValueName = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
	    ValueType = 'String'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.6.3.1 (L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block' 
	Registry 'EnableNetworkProtectionDangerWebsites' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
	    ValueName = 'EnableNetworkProtection'
	    ValueType = 'DWord'
	    ValueData = '1'
	}


	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.7.1 (L1) Ensure 'Enable file hash computation feature' is set to 'Enabled'
	Registry 'EnableFileHashComputation' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
	    ValueName = 'EnableFileHashComputation'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.10.1 (L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled' 
	Registry 'DisableIOAVProtection' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
	    ValueName = 'DisableIOAVProtection'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.10.2 (L1) Ensure 'Turn off real-time protection' is set to 'Disabled' 
	Registry 'DisableRealtimeMonitoring' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
	    ValueName = 'DisableRealtimeMonitoring'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	#18.10.42.10.4 (L1) Ensure 'Turn on script scanning' is set to 'Enabled' 
	Registry 'DisableScriptScanning' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
	    ValueName = 'DisableScriptScanning'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.12.1 (L2) Ensure 'Configure Watson events' is set to 'Disabled' 
	Registry 'DisableGenericRePorts' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
	    ValueName = 'DisableGenericRePorts'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.13.1 (L1) Ensure 'Scan packed executables' is set to 'Enabled' 
	Registry 'DisablePackedExeScanning' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
	    ValueName = 'DisablePackedExeScanning'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.13.3 (L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled' 
	Registry 'DisableEmailScanning' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
	    ValueName = 'DisableEmailScanning'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.16 (L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block' 
	Registry 'PUAProtection' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
	    ValueName = 'PUAProtection'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.42.17 (L1) Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled' 
	Registry 'DisableAntiSpyware' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
	    ValueName = 'DisableAntiSpyware'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.50.1 (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled' 
	Registry 'DisableFileSyncNGSC1' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
	    ValueName = 'DisableFileSyncNGSC'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.55.1 (L2) Ensure 'Turn off Push To Install service' is set to 'Enabled' 
	Registry 'DisableFileSyncNGSC' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall'
	    ValueName = 'DisablePushToInstall'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 
	Registry 'fSingleSessionPerUser' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
	    ValueName = 'fSingleSessionPerUser'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.56.3.3.1 (L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled' 
	Registry 'fDisableCcm' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
	    ValueName = 'fDisableCcm'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.56.3.3.2 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled' 
	Registry 'fDisableCdm' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
	    ValueName = 'fDisableCdm'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.56.3.3.3 (L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled' 
	Registry 'fDisableLPT' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
	    ValueName = 'fDisableLPT'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.56.3.3.4 (L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled' (
	Registry 'fDisablePNPRedir' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
	    ValueName = 'fDisablePNPRedir'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.56.3.9.3 (L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'
	Registry 'SecurityLayer' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
	    ValueName = 'SecurityLayer'
	    ValueType = 'DWord'
	    ValueData = '2'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.56.3.10.1 (L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)' 
	Registry 'MaxIdleTime' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
	    ValueName = 'MaxIdleTime'
	    ValueType = 'DWord'
	    ValueData = '900000'
	}
	# CceId: 
	# DataSource: Registry Policy
	# 18.10.56.3.10.2 (L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute' 
	Registry 'MaxDisconnectionTime' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
	    ValueName = 'MaxDisconnectionTime'
	    ValueType = 'DWord'
	    ValueData = '6000'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.58.2 (L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search' (
	Registry 'AllowCloudSearch' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
	    ValueName = 'AllowCloudSearch'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.58.4 (L2) Ensure 'Allow search highlights' is set to 'Disabled' 
	Registry 'EnableDynamicContentInWSB' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
	    ValueName = 'EnableDynamicContentInWSB'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.62.1 (L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled' 
	Registry 'NoGenTicketKMS' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
	    ValueName = 'NoGenTicket'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.79.1 (L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled' (
	Registry 'AllowSuggestedAppsInWindowsInkWorkspace' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
	    ValueName = 'AllowSuggestedAppsInWindowsInkWorkspace'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.79.2 (L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled' 
	Registry 'AllowWindowsInkWorkspace' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
	    ValueName = 'AllowWindowsInkWorkspace'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.80.3 (L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled' 
	Registry 'SafeForScripting' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
	    ValueName = 'SafeForScripting'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.86.1 (L2) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled' 
	Registry 'EnableScriptBlockLogging' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
	    ValueName = 'EnableScriptBlockLogging'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.86.2 (L2) Ensure 'Turn on PowerShell Transcription' is set to 'Enabled' 
	Registry 'EnableTranscripting' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
	    ValueName = 'EnableTranscripting'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.88.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled' 
	Registry 'AllowAutoConfig' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
	    ValueName = 'AllowAutoConfig'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.89.1 (L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled' 
	Registry 'AllowRemoteShellAccess' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS'
	    ValueName = 'AllowRemoteShellAccess'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.91.2.1 (L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled' 
	Registry 'DisallowExploitProtectionOverride' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
	    ValueName = 'DisallowExploitProtectionOverride'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.92.1.1 (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
	Registry 'NoAutoRebootWithLog' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
	    ValueName = 'NoAutoRebootWithLog'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.92.2.1 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled' 
	Registry 'NoAutoUpdate' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
	    ValueName = 'NoAutoUpdate'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.92.2.2 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day' 
	Registry 'ScheduledInstallDay' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
	    ValueName = 'ScheduledInstallDay'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.92.4.1 (L1) Ensure 'Manage preview builds' is set to 'Disabled' 
	Registry 'ManagePreviewBuildsPolicyValue' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	    ValueName = 'ManagePreviewBuildsPolicyValue'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.92.4.2 (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days' 
	Registry 'DeferFeatureUpdates' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	    ValueName = 'DeferFeatureUpdates'
	    ValueType = 'DWord'
	    ValueData = '1'
	}
	Registry 'DeferFeatureUpdatesPeriodInDays' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	    ValueName = 'DeferFeatureUpdatesPeriodInDays'
	    ValueType = 'DWord'
	    ValueData = '180'
	}

	# CceId: 
	# DataSource: Registry Policy
	# 18.10.92.4.3 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' 
	Registry 'DeferQualityUpdates' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	    ValueName = 'DeferQualityUpdates'
	    ValueType = 'DWord'
	    ValueData = '1'
	}
	Registry 'DeferQualityUpdatesPeriodInDays' {
	    Ensure    = 'Present'
	    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	    ValueName = 'DeferQualityUpdatesPeriodInDays'
	    ValueType = 'DWord'
	    ValueData = '0'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
	Registry 'NoToastApplicationNotificationOnLockScreen' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
	    ValueName = 'NoToastApplicationNotificationOnLockScreen'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'
	Registry 'NoImplicitFeedback' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\Software\Policies\Microsoft\Assistance\Client\1.0'
	    ValueName = 'NoImplicitFeedback'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'
	Registry 'SaveZoneInformation' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
	    ValueName = 'SaveZoneInformation'
	    ValueType = 'DWord'
	    ValueData = '2'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
	Registry 'ScanWithAntiVirus' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
	    ValueName = 'ScanWithAntiVirus'
	    ValueType = 'DWord'
	    ValueData = '3'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'
	Registry 'ConfigureWindowsSpotlight' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\Software\Policies\Microsoft\Windows\CloudContent'
	    ValueName = 'ConfigureWindowsSpotlight'
 	    ValueType = 'DWord'
	    ValueData = '2'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'
	Registry 'DisableThirdPartySuggestions' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\Software\Policies\Microsoft\Windows\CloudContent'
	    ValueName = 'DisableThirdPartySuggestions'
 	   ValueType = 'DWord'
 	   ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'
	Registry 'DisableTailoredExperiencesWithDiagnosticData' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\Software\Policies\Microsoft\Windows\CloudContent'
	    ValueName = 'DisableTailoredExperiencesWithDiagnosticData'
 	    ValueType = 'DWord'
 	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'
	Registry 'DisableWindowsSpotlightFeatures' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\Software\Policies\Microsoft\Windows\CloudContent'
 	    ValueName = 'DisableWindowsSpotlightFeatures'
 	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'
	Registry 'DisableSpotlightCollectionOnDesktop' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
	    ValueName = 'DisableSpotlightCollectionOnDesktop'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
	Registry 'NoInplaceSharing' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
	    ValueName = 'NoInplaceSharing'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

	# CceId: 
	# DataSource: Registry Policy
	# Ensure 'Prevent Codec Download' is set to 'Enabled'
	Registry 'PreventCodecDownload' {
	    Ensure    = 'Present'
	    Key       = 'HKCU\Software\Policies\Microsoft\WindowsMediaPlayer'
	    ValueName = 'PreventCodecDownload'
	    ValueType = 'DWord'
	    ValueData = '1'
	}

        # CceId: CCE-36326-7 
        # DataSource: Registry Policy
        # Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' 
        Registry 'NoLMHash' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'NoLMHash'
            ValueType = 'DWord'
            ValueData = '1'
        }

        
        # CceId:  
        # DataSource: Registry Policy
        # Ensure 'Continue experiences on this device' is set to 'Disabled' 
        Registry 'EnableCdp' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableCdp'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36388-7
        # DataSource: Registry Policy
        # Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
        Registry 'OfferRemoteAssistance' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'OfferRemoteAssistance'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37912-3
        # DataSource: Registry Policy
        # Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
        Registry 'DriverLoadPolicy' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueName = 'DriverLoadPolicy'
            ValueType = 'DWord'
            ValueData = '3'
        }
        
        

        # CceId: CCE-37775-4
        # DataSource: Registry Policy
        # Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionApplicationLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        

        # CceId: CCE-36000-8
        # DataSource: Registry Policy
        # Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
        Registry 'DisableRunAs' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'DisableRunAs'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38318-2
        # DataSource: Registry Policy
        # Ensure 'Disallow Digest authentication' is set to 'Enabled'
        Registry 'AllowDigest' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowDigest'
            ValueType = 'DWord'
            ValueData = '0'
        }

        

        # CceId: CCE-37636-8
        # DataSource: Registry Policy
        # Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
        Registry 'NoAutoplayfornonVolume' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoAutoplayfornonVolume'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38354-7
        # DataSource: Registry Policy
        # Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
        Registry 'MSAOptional' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'MSAOptional'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
        Registry 'AllowIndexingEncryptedStoresOrItems' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'
        Registry 'BlockUserFromSh owingAccountDetailsOnSignin' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'BlockUserFromShowingAccountDetailsOnSignin'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only)
        Registry 'RestrictAnonymousSAM' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictAnonymousSAM'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36077-6
        # DataSource: Registry Policy
        # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)
        Registry 'RestrictAnonymous' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictAnonymous'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37567-5
        # DataSource: Registry Policy
        # Ensure 'Require secure RPC communication' is set to 'Enabled'
        Registry 'fEncryptRPCTraffic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fEncryptRPCTraffic'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: NOT_ASSIGNED
        # Control no: AZ-WIN-00143
        # DataSource: Registry Policy
        # Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
        Registry 'NC_ShowSharedAccessUI' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_ShowSharedAccessUI'
            ValueType = 'DWord'
            ValueData = '0'
        }

        

        # CceId: CCE-37534-5
        # DataSource: Registry Policy
        # Ensure 'Do not display the password reveal button' is set to 'Enabled'
        Registry 'DisablePasswordReveal' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
            ValueName = 'DisablePasswordReveal'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36627-8
        # DataSource: Registry Policy
        # Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
        Registry 'MinEncryptionLevel' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'DWord'
            ValueData = '3'
        }

        

        # CceId: CCE-37490-0
        # DataSource: Registry Policy
        # Ensure 'Always install with elevated privileges' is set to 'Disabled'
        Registry 'AlwaysInstallElevated' {
            Ensure    = 'Present'
            Key       = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'AlwaysInstallElevated'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36400-0
        # DataSource: Registry Policy
        # Ensure 'Allow user control over installs' is set to 'Disabled'
        Registry 'EnableUserControl' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueName = 'EnableUserControl'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38223-4
        # DataSource: Registry Policy
        # Ensure 'Allow unencrypted traffic' is set to 'Disabled'
        Registry 'AllowUnencryptedTraffic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'DWord'
            ValueData = '0'
        }


        # CceId: CCE-36223-6
        # DataSource: Registry Policy
        # Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
        Registry 'DisablePasswordSaving' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DisablePasswordSaving'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37946-1
        # DataSource: Registry Policy
        # Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
        Registry 'DeleteTempDirsOnExit' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DeleteTempDirsOnExit'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38353-9
        # DataSource: Registry Policy
        # Ensure 'Do not display network selection UI' is set to 'Enabled'
        Registry 'DontDisplayNetworkSelectionUI' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37929-7
        # DataSource: Registry Policy
        # Ensure 'Always prompt for password upon connection' is set to 'Enabled'
        Registry 'fPromptForPassword' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fPromptForPassword'
            ValueType = 'DWord'
            ValueData = '1'
        }

        

        # CceId: CCE-37948-7
        # DataSource: Registry Policy
        # Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeApplication' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }

        # CceId: CCE-37948-7
        # DataSource: Registry Policy
        # Ensure 'Do not show feedback notifications' is set to 'Enabled'
        Registry 'DoNotShowFeedbackNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'DoNotShowFeedbackNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38180-6
        # DataSource: Registry Policy
        # Ensure 'Do not use temporary folders per session' is set to 'Disabled'
        Registry 'PerSessionTempDir' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'PerSessionTempDir'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Enable insecure guest logons' is set to 'Disabled'
        Registry 'AllowInsecureGuestAuth' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36021-4
        # DataSource: Registry Policy
        # Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
        Registry 'RestrictNullSessAccess' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName = 'RestrictNullSessAccess'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37528-7
        # DataSource: Registry Policy
        # Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
        Registry 'AllowDomainPINLogon' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
            ValueName = 'AllowDomainPINLogon'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36494-3
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
        Registry 'FilterAdministratorToken' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'FilterAdministratorToken'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37861-2
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
        <#Registry 'AllowLocalPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }#>

        

        # CceId: CCE-38239-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPrivate' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36268-1
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
        <#Registry 'AllowLocalIPsecPolicyMerge' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalIPsecPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }#>

        # CceId: CCE-37330-8
        # DataSource: Registry Policy
        # Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'
        Registry 'UserAuthentication' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'UserAuthentication'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37330-8
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
        Registry 'turuoffNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'turuoffNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36875-3
        # DataSource: Registry Policy
        # Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
        Registry 'NoDriveTypeAutoRun' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'DWord'
            ValueData = '255'
        }

        # CceId: CCE-36146-9 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
        Registry 'OutboundActionDefault' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
            ValueName = 'OutboundActionDefault'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37621-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No''
        Registry 'DisableNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DisableNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36625-2
        # DataSource: Registry Policy
        # Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
        Registry 'DisableWebPnPDownload' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
            ValueName = 'DisableWebPnPDownload'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37064-0
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
        Registry 'EnableVirtualization' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableVirtualization'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37064-0
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
        Registry 'PromptOnSecureDesktop' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'PromptOnSecureDesktop'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36869-6 
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
        Registry 'EnableLUA' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableLUA'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36869-6 
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
        Registry 'EnableInstallerDetection' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableInstallerDetection'
            ValueType = 'DWord'
            ValueData = '1'
        }

        
        # CceId: CCE-36062-8
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallDomain' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

         # CceId: CCE-37809-1
        # DataSource: Registry Policy
        # Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
        Registry 'NoDataExecutionPrevention' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoDataExecutionPrevention'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-35893-7
        # DataSource: Registry Policy
        # Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled' 
        Registry 'DisableLockScreenAppNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'DisableLockScreenAppNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36092-5
        # DataSource: Registry Policy
        # Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSystemLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }

        # CceId: CCE-36160-0
        # DataSource: Registry Policy
        # Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
        Registry 'RetentionSystemLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName = 'Retention'
            ValueType = 'String'
            ValueData = '0'
        }

        # CceId: CCE-37644-2
        # DataSource: Registry Policy
        # Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
        Registry 'ProtectionMode' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager'
            ValueName = 'ProtectionMode'
            ValueType = 'String'
            ValueData = '1'
        }

        # CceId: CCE-37885-1 
        # DataSource: Registry Policy
        # Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
        Registry 'ObCaseInsensitive' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'
            ValueName = 'ObCaseInsensitiv'
            ValueType = 'String'
            ValueData = '1'
        }

        # CceId: CCE-37862-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPublic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37434-8 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)
        Registry 'OutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'OutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37434-8 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
        Registry 'DefaultOutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36660-9
        # DataSource: Registry Policy
        # Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
        Registry 'NoHeapTerminationOnCorruption' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoHeapTerminationOnCorruption'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38041-0 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
        Registry 'OffNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
            ValueName = 'OffNotifications'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37163-3 
        # DataSource: Registry Policy
        <# Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
        Registry 'ExitOnMSICW' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'
            ValueName = 'ExitOnMSICW'
            ValueType = 'DWord'
            ValueData = '1'
        }#>

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'
        Registry 'DisableWindowsConsumerFeatures' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37450-4 
        # DataSource: Registry Policy
        # Ensure 'Turn off multicast name resolution' is set to 'Enabled' 
        Registry 'EnableMulticast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName = 'EnableMulticast'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36809-2 
        # DataSource: Registry Policy
        # Ensure 'Turn off shell protocol protected mode' is set to 'Disabled' 
        Registry 'PreXPSP2ShellProtocolBehavior' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explore r'
            ValueName = 'PreXPSP2ShellProtocolBehavior'
            ValueType = 'DWord'
            ValueData = '0'
        }
	
        # CceId: CCE-37057-7 
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' 
        Registry 'EnableSecureUIAPaths' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'EnableSecureUIAPaths'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-35859-8  
        # DataSource: Registry Policy
        # Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' 
        Registry 'EnableSmartScreen' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableSmartScreen'
            ValueType = 'DWord'
            ValueData = '1'
        }
	Registry 'EnableSmartScree2n' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'ShellSmartScreenLevel'
            ValueType = 'String'
            ValueData = 'Block'
        }

        # CceId: CCE-37281-3
        # DataSource: Registry Policy
        # Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
        Registry 'fAllowToGetHelp' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fAllowToGetHelp'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36940-5
        # DataSource: Registry Policy
        # Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'
        Registry 'LocalSettingOverrideSpynetReporting' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            ValueName = 'LocalSettingOverrideSpynetReporting'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Configure SMB v1 server' is set to 'Disabled'
        Registry 'SMB1' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueName = 'SMB1'
            ValueType = 'DWord'
            ValueData = '0'
        }

	# CceId: 
        # DataSource: Registry Policy
        # L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)' 
	 Firewall EnableFirewallDomainProfile {
            Name        = "Windows Firewall: Domain: Firewall state"
            Enabled     = "True"   # Configura el estado del firewall en 'On'
            Profile     = "Domain" # Aplica la configuración al perfil de dominio
            Ensure      = "Present"
        }

 	# CceId: 
        # DataSource: Registry Policy
        # (L1) Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (DC only) 
	Service DisableSpoolerService {
            Name         = "Spooler"         # Nombre del servicio que deseas deshabilitar
            StartupType  = "Disabled"        # Configura el servicio para que esté deshabilitado
            State        = "Stopped"         # Asegura que el servicio esté detenido
            Ensure       = "Present"         # Garantiza que el servicio esté configurado
        }

	Registry FirewallInboundBlock {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
            ValueName = "DefaultInboundAction"
            ValueData = 1
            ValueType = "Dword"
            Ensure    = "Present"
        }

	# CceId: 9.1.3
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No' (
	Registry DisableFirewallDomainNotifications {
	    Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfilee'
            ValueName = 'DisableNotifications'
	    ValueType = 'Dword'
            ValueData = '1'
        }

	# CceId: 9.1.4
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is  set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log' 
	Registry SetFirewallLogFileName {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueName = 'LogFilePath'
            ValueData = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
            ValueType = "ExpandString"
            Ensure    = "Present"
        }

	# CceId: 9.1.5
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater' 
	Registry SetFirewallLogFileSize {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
            ValueName = "LogFileSize"
            ValueData = 16384
            ValueType = "Dword"
            Ensure    = "Present"
        }

	# CceId: 9.1.6
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes' 
	Registry SetFirewallLogDroppedPackets {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
            ValueName = "LogDroppedPackets"
            ValueData = 1
            ValueType = "Dword"
            Ensure    = "Present"
        }
	
	# CceId: 9.1.7
        # DataSource: Registry Policy
        # L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes' (
	Registry SetFirewallLogSuccessfulConnections {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
            ValueName = "LogSuccessfulConnections"
            ValueData = 1
            ValueType = "Dword"
            Ensure    = "Present"
        }
	



	# CceId: 9.2.2
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)' 
	Registry SetFirewallPrivateInboundAction {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
            ValueName = "DefaultInboundAction"
            ValueData = 1
            ValueType = "Dword"
            Ensure    = "Present"
        }
	
	
	# CceId: 9.2.4
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log' 
	Registry SetFirewallPrivateLogFilePath {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
            ValueName = "LogFilePath"
            ValueData = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
            ValueType = "String"
            Ensure    = "Present"
        }

	# CceId: 9.2.5
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater' 
	Registry SetFirewallPrivateLogFileSize {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
            ValueName = "LogFileSize"
            ValueData = 16384
            ValueType = "Dword"
            Ensure    = "Present"
        }
	
	# CceId: 9.2.6
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes' 
	Registry SetFirewallPrivateLogDroppedPackets {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
            ValueName = "LogDroppedPackets"
            ValueData = 1
            ValueType = "Dword"
            Ensure    = "Present"
        }
	
	# CceId: 9.2.7
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes' 
	Registry SetFirewallPrivateLogSuccessfulConnections {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
            ValueName = "LogSuccessfulConnections"
            ValueData = 1
            ValueType = "Dword"
            Ensure    = "Present"
        }
	
	# CceId: 9.3.2
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)' 
	Registry SetFirewallPublicInboundAction {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
            ValueName = "DefaultInboundAction"
            ValueData = 1
            ValueType = "Dword"
            Ensure    = "Present"
        } 

	# CceId: 9.3.3
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Public: Settings: Display a  notification' is set to 'No'  
	Registry SetFirewallPublicNotifications {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
            ValueName = "DisableNotifications"
            ValueData = 1
            ValueType = "Dword"
            Ensure    = "Present"
        }

	# CceId: 9.3.4
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No' 
	Registry SetFirewallPublicLocalPolicyMerge {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
            ValueName = "AllowLocalPolicyMerge"
            ValueData = 0
            ValueType = "Dword"
            Ensure    = "Present"
        }

	# CceId: 9.3.5
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No' 
	Registry SetFirewallPublicLocalIPsecPolicyMerge {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
            ValueName = "AllowLocalIPsecPolicyMerge"
            ValueData = 0
            ValueType = "Dword"
            Ensure    = "Present"
        }

	# CceId: 9.3.6
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'  
	Registry SetFirewallPublicLogFilePath {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
            ValueName = "LogFilePath"
            ValueData = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
            ValueType = "String"
            Ensure    = "Present"
        }

	# CceId: 9.3.7
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Public: Logging: Size limit  (KB)' is set to '16,384 KB or greater'
	Registry SetFirewallPublicLogFileSize {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
            ValueName = "LogFileSize"
            ValueData = 16384
            ValueType = "DWord"
            Ensure    = "Present"
        }

	# CceId: 9.3.8
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes' 
	Registry SetFirewallPublicLogDroppedPackets {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
            ValueName = "LogDroppedPackets"
            ValueData = 1
            ValueType = "DWord"
            Ensure    = "Present"
        }

	# CceId: 9.3.9
        # DataSource: Registry Policy
        # (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes' 
	Registry SetFirewallPublicLogSuccessfulConnections {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
            ValueName = "LogSuccessfulConnections"
            ValueData = 1
            ValueType = "DWord"
            Ensure    = "Present"
        }


    }
}
CIS_Benchmark_WindowsServer2019_v100

