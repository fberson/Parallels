<#  
.SYNOPSIS  
    PArallels RAS auto-deploy script for Azure MarketPlace Deployments
.NOTES  
    File Name  : RAS_Azure_MP_Install.ps1
    Author     : Freek Berson
    Version    : v0.0.11
    Date       : Jan 29 2024
.EXAMPLE
    .\RAS_Azure_MP_Install.ps1
#>

#Collect Parameters
param(
    [Parameter(Mandatory = $true)]
    [string]$domainJoinUserName,

    [Parameter(Mandatory = $true)]
    [string]$domainJoinPassword,

    [Parameter(Mandatory = $true)]
    [string]$domainName,

    [Parameter(Mandatory = $true)]
    [string]$resourceID,

    [Parameter(Mandatory = $true)]
    [string]$tenantID,

    [Parameter(Mandatory = $true)]
    [string]$keyVaultName,

    [Parameter(Mandatory = $true)]
    [string]$secretName,

    [Parameter(Mandatory = $true)]
    [string]$primaryConnectionBroker,

    [Parameter(Mandatory = $true)]
    [string]$numberofCBs,

    [Parameter(Mandatory = $true)]
    [string]$numberofSGs,

    [Parameter(Mandatory = $true)]
    [string]$prefixCBName,

    [Parameter(Mandatory = $true)]
    [string]$prefixSGName,

    [Parameter(Mandatory = $true)]
    [string]$customerUsageAttributionID
)


function New-ImpersonateUser {

    [cmdletbinding()]
    Param( 
        [Parameter(ParameterSetName="ClearText", Mandatory=$true)][string]$Username, 
        [Parameter(ParameterSetName="ClearText", Mandatory=$true)][string]$Domain, 
        [Parameter(ParameterSetName="ClearText", Mandatory=$true)][string]$Password, 
        [Parameter(ParameterSetName="Credential", Mandatory=$true, Position=0)][PSCredential]$Credential, 
        [Parameter()][Switch]$Quiet 
    ) 
 
    #Import the LogonUser Function from advapi32.dll and the CloseHandle Function from kernel32.dll
    if (-not ([System.Management.Automation.PSTypeName]'Import.Win32').Type) {
        Add-Type -Namespace Import -Name Win32 -MemberDefinition @'
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LogonUser(string user, string domain, string password, int logonType, int logonProvider, out IntPtr token);
  
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CloseHandle(IntPtr handle);
'@ -ErrorAction SilentlyContinue
    }
    #Set Global variable to hold the Impersonation after it is created so it may be ended after script run
    $Global:ImpersonatedUser = @{} 
    #Initialize handle variable so that it exists to be referenced in the LogonUser method
    $tokenHandle = 0 
 
    #Pass the PSCredentials to the variables to be sent to the LogonUser method
    if ($Credential) { 
        Get-Variable Username, Domain, Password | ForEach-Object { 
            Set-Variable $_.Name -Value $Credential.GetNetworkCredential().$($_.Name)} 
    } 
 
    #Call LogonUser and store its success. [ref]$tokenHandle is used to store the token "out IntPtr token" from LogonUser.
    $returnValue = [Import.Win32]::LogonUser($Username, $Domain, $Password, 2, 0, [ref]$tokenHandle) 
 
    #If it fails, throw the verbose with the error code
    if (!$returnValue) { 
        $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error(); 
        Write-Host "Impersonate-User failed a call to LogonUser with error code: $errCode" 
        throw [System.ComponentModel.Win32Exception]$errCode 
    } 
    #Successful token stored in $tokenHandle
    else { 
        #Call the Impersonate method with the returned token. An ImpersonationContext is returned and stored in the
        #Global variable so that it may be used after script run.
        $Global:ImpersonatedUser.ImpersonationContext = [System.Security.Principal.WindowsIdentity]::Impersonate($tokenHandle) 
     
        #Close the handle to the token. Voided to mask the Boolean return value.
        [void][Import.Win32]::CloseHandle($tokenHandle) 
 
        #Write the current user to ensure Impersonation worked and to remind user to revert back when finished.
        if (!$Quiet) { 
            Write-Host "You are now impersonating user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" 
            Write-Host "It is very important that you call Remove-ImpersonateUser when finished to revert back to your user."
        } 
    } 

    Function Global:Remove-ImpersonateUser { 
        <#
        .SYNOPSIS
        Used to revert back to the orginal user after New-ImpersonateUser is called. You can only call this function once; it is deleted after it runs.
  
        .INPUTS
        None. You cannot pipe objects to Remove-ImpersonateUser
  
        .OUTPUTS
        None. Remove-ImpersonateUser does not generate any output.
        #> 
 
        #Calling the Undo method reverts back to the original user.
        $ImpersonatedUser.ImpersonationContext.Undo() 
 
        #Clean up the Global variable and the function itself.
        Remove-Variable ImpersonatedUser -Scope Global 
        Remove-Item Function:\Remove-ImpersonateUser 
    } 
}
function Set-RunOnceScriptForAllUsers {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    # Ensure the script file exists
    if (-not (Test-Path $ScriptPath)) {
        Write-Error "Script file does not exist at the specified path: $ScriptPath"
        return
    }

    # Registry path for RunOnce in HKLM
    $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

    # Create a command to run PowerShell with the specified script
    $command = "PowerShell -File `"$ScriptPath`""

    # Add the command to the RunOnce registry key
    try {
        Set-ItemProperty -Path $registryPath -Name "RunMyScriptOnceForAllUsers" -Value $command
        Write-Host "The script at '$ScriptPath' will be executed at the next logon of any user."
    }
    catch {
        Write-Error "Failed to set registry value. Error: $_"
    }
}

#Set variables
$EvergreenURL = 'https://download.parallels.com/ras/latest/RASInstaller.msi'
$Temploc = 'C:\install\RASInstaller.msi'
$secdomainJoinPassword = ConvertTo-SecureString $domainJoinPassword -AsPlainText -Force
$installPath = "C:\install"

# Check if the install path already exists
if (-not (Test-Path -Path $installPath)) { New-Item -Path $installPath -ItemType Directory }

#Configute logging
$Logfile = "C:\install\RAS_Azure_MP_Install.log"
function WriteLog {
    Param ([string]$LogString)
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$Stamp $LogString"
    Add-content $LogFile -value $LogMessage
}

#Disable Server Manager from starting at logon
schtasks /Change /TN "Microsoft\Windows\Server Manager\ServerManager"  /Disable

# Disable IE ESC for Administrators and users
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0

#Create Firewall Rules
WriteLog "Configuring Firewall Rules"
New-NetFirewallRule -DisplayName "Parallels RAS Administration (TCP)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 68, 80, 81, 1234, 135, 443, 445, 20001, 20002, 20003, 20009, 20020, 20030, 20443, 30004, 30006
New-NetFirewallRule -DisplayName "Parallels RAS Administration (TCP)" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 80, 443, 20000, 20009, 30004, 30006

#Disable UAC & Sharing Wizard to allow Remote Install of RAS Agent
WriteLog "Disable UAC & Sharing Wizard"
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -Value 0
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SharingWizardOn -Name CheckedValue -Value 0

# Split the string and extract values
$parts = $resourceID -split '/'
$SubscriptionId = $parts[2]

# Create a PowerShell object with the extracted values
$data = @{
    SubscriptionId = $SubscriptionId
    domainJoinUserName = $domainJoinUserName
    keyVaultName   = $keyVaultName
    secretName     = $secretName
    tenantID       = $tenantID
    customerUsageAttributionID = $customerUsageAttributionID
}

# Convert the object to JSON
$json = $data | ConvertTo-Json

# Write the JSON to a file
$json | Out-File -FilePath "C:\install\output.json"

#Download the latest RAS installer 
WriteLog "Dowloading most recent Parallels RAS Installer"
$RASMedia = New-Object net.webclient
$RASMedia.Downloadfile($EvergreenURL, $Temploc)
WriteLog "Dowloading most recent Parallels RAS Installer done"

#Impersonate user to install RAS
WriteLog "Impersonating user"
New-ImpersonateUser -Username $domainJoinUserName -Domain $domainName  -Password $domainJoinPassword

#Install RAS Console & PowerShell role
WriteLog "Install Connection Broker role"
Start-Process msiexec.exe -ArgumentList "/i C:\install\RASInstaller.msi ADDFWRULES=1 ADDLOCAL=F_Console,F_PowerShell /qn /log C:\install\RAS_Install.log" -Wait

# Enable RAS PowerShell module
Import-Module 'C:\Program Files (x86)\Parallels\ApplicationServer\Modules\RASAdmin\RASAdmin.psd1'

#Create new RAS PowerShell Session
New-RASSession -Username $domainJoinUserName -Password $secdomainJoinPassword -Server $primaryConnectionBroker

#Deploy Run Once script to launch post deployment actions at next admin logon
Set-RunOnceScriptForAllUsers -ScriptPath 'C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.15\Downloads\0\RAS_Azure_MP_Register.ps1'

Remove-RASSession

#Remove impersonation
Remove-ImpersonateUser

WriteLog "Finished installing RAS..."
