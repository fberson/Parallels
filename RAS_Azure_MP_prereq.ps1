<#  
.SYNOPSIS  
    Parallels RAS prereq script Azure MarketPlace Deployments
.NOTES  
    File Name  : RAS_Azure_MP_prereq.ps1
    Author     : Freek Berson
    Version    : v0.0.13
    Date       : March 26 2024
.EXAMPLE
    .\RAS_Azure_MP_prereq.ps1
#>

#Collect Parameters
param(
    [Parameter(Mandatory = $true)]
    [string]$domainJoinUserName
)


#Set variables
$installPath = "C:\install"

#Set Windows Update to "Download Only" to prevent automatic installation of updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2

# Check if the install path already exists
if (-not (Test-Path -Path $installPath)) { New-Item -Path $installPath -ItemType Directory }

#Configute logging
$Logfile = "C:\install\RAS_Azure_MP_SG_prereq.log"
function WriteLog {
    Param ([string]$LogString)
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$Stamp $LogString"
    Add-content $LogFile -value $LogMessage
}

#Create Firewall Rules
WriteLog "Configuring Firewall Rules"
New-NetFirewallRule -DisplayName "Parallels RAS Administration (TCP)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 68, 80, 81, 1234, 135, 443, 445, 20001, 20002, 20003, 20009, 20020, 20030, 20443, 30004, 30006
New-NetFirewallRule -DisplayName "Parallels RAS Administration (UDP)" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 80, 443, 20000, 20009, 30004, 30006

#Disable UAC & Sharing Wizard to allow Remote Install of RAS Agent
WriteLog "Disable UAC & Sharing Wizard"
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -Value 0
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SharingWizardOn -Name CheckedValue -Value 0

# Add Parallels RAS install user to local administrators group
WriteLog "Adding Parallels RAS install user to local administrators group"
Add-LocalGroupMember -Group "Administrators" -Member $domainJoinUserName

#Reboot the server to apply all changes
shutdown /r /t 0
