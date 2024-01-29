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
    [string]$localAdminUser,

    [Parameter(Mandatory = $true)]
    [string]$localAdminPassword,

    [Parameter(Mandatory = $true)]
    [string]$MyAccountEmail,

    [Parameter(Mandatory = $true)]
    [string]$MyAccountpassword,

    [Parameter(Mandatory = $true)]
    [string]$resourceID,

    [Parameter(Mandatory = $true)]
    [string]$tenantID,

    [Parameter(Mandatory = $true)]
    [string]$keyVaultName,

    [Parameter(Mandatory = $true)]
    [string]$secretName
)
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




$hostname = hostname
$localAdminPasswordSecure = ConvertTo-SecureString $localAdminPassword -AsPlainText -Force
$MyAccountpassordSecure = ConvertTo-SecureString $MyAccountpassword -AsPlainText -Force
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

#Set variables
$EvergreenURL = 'https://download.parallels.com/ras/latest/RASInstaller.msi'
$Temploc = 'C:\install\RASInstaller.msi'

#Disable Server Manager from starting at logon
schtasks /Change /TN "Microsoft\Windows\Server Manager\ServerManager"  /Disable

# Disable IE ESC for Administrators and users
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0

#Log The ResourceUsageId
WriteLog "resourceID:"
WriteLog $resourceID

# Split the string and extract values
$parts = $resourceID -split '/'
$SubscriptionId = $parts[2]

# Create a PowerShell object with the extracted values
$data = @{
    SubscriptionId = $SubscriptionId
    localAdminUser = $localAdminUser
    keyVaultName   = $keyVaultName
    secretName     = $secretName
    tenantID       = $tenantID
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

#Installer location and RDS Server mand wait for completion
WriteLog "Start RAS install..."
Start-Process msiexec.exe -ArgumentList "/i C:\install\RASInstaller.msi /quiet /passive /norestart ADDFWRULES=1 /log C:\install\RAS_Install.log" -Wait

#Add all members from local administrators group user as root admin
WriteLog "Configuring Root admins..."
$allLocalAdmins = Get-LocalGroupMember -Group "Administrators"
Foreach ($localAdmin in $allLocalAdmins) {
    cmd /c "`"C:\Program Files (x86)\Parallels\ApplicationServer\x64\2XRedundancy.exe`" -c -AddRootAccount $localAdmin"
}

# Enable RAS PowerShell module
Import-Module 'C:\Program Files (x86)\Parallels\ApplicationServer\Modules\RASAdmin\RASAdmin.psd1'

Set-RunOnceScriptForAllUsers -ScriptPath 'C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.15\Downloads\0\RAS_Azure_MP_Register.ps1'

#Create new RAS PowerShell Session
New-RASSession -Username $localAdminUser -Password $localAdminPasswordSecure

#Activate Parallels My account
Invoke-RASLicenseActivate -Email $MyAccountEmail -Password $MyAccountpassordSecure
invoke-RASApply

#Add host as RDSH
New-RASRDS "localhost" -NoInstall -ErrorAction Ignore
invoke-RASApply

# Publish sample Applications & RDSH Desktop
New-RASPubRDSDesktop -Name "Published Desktop"
New-RASPubRDSApp -Name "Calculator" -Target "C:\Windows\System32\calc.exe" -PublishFrom All -WinType Maximized
New-RASPubRDSApp -Name "Paint" -Target "C:\Windows\System32\mspaint.exe" -PublishFrom All -WinType Maximized
New-RASPubRDSApp -Name "WordPad" -Target "C:\Program Files\Windows NT\Accessories\wordpad.exe"  -PublishFrom All -WinType Maximized 
invoke-RASApply

#Set domain to Workgroup access
Set-RASAuthSettings -AllTrustedDomains $false -Domain Workgroup/$hostname
invoke-RASApply

WriteLog "Finished installing RAS..."
