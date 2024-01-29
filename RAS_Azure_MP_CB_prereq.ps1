<#  
.SYNOPSIS  
    Parallels RAS Connection Broker prereq script Azure MarketPlace Deployments
.NOTES  
    File Name  : RAS_Azure_MP_Install.ps1
    Author     : Freek Berson
    Version    : v0.0.11
    Date       : Jan 29 2024
.EXAMPLE
    .\RAS_Azure_MP_Install.ps1
#>

#Set variables
$EvergreenURL = 'https://download.parallels.com/ras/latest/RASInstaller.msi'
$Temploc = 'C:\install\RASInstaller.msi'
$installPath = "C:\install"

# Check if the install path already exists
if (-not (Test-Path -Path $installPath)) { New-Item -Path $installPath -ItemType Directory }

#Configute logging
$Logfile = "C:\install\RAS_Azure_MP_CB_prereq.log"
function WriteLog {
    Param ([string]$LogString)
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$Stamp $LogString"
    Add-content $LogFile -value $LogMessage
}

#Create Firewall Rules
WriteLog "Configuring Firewall Rules"
New-NetFirewallRule -DisplayName "Allow TCP 135, 445, 20001, 200002, 200003 20030 for RAS Administration" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 135, 445, 20001,20002,20003,20030

#Disable UAC & Sharing Wizard to allow Remote Install of RAS Agent
WriteLog "Disable UAC & Sharing Wizard"
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -Value 0
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SharingWizardOn -Name CheckedValue -Value 0

#Download the latest RAS installer
WriteLog "Dowloading most recent Parallels RAS Installer"
$RASMedia = New-Object net.webclient
$RASMedia.Downloadfile($EvergreenURL, $Temploc)

#Impersonate user to install RAS
WriteLog "Impersonating user"
$RasAdminPassword = 'MaltaRules1!'
$RasAdminUser = 'domainjoin@prasmpdemo.com'
New-ImpersonateUser -Username $RasAdminUser -Domain 'prasmpdemo.com'  -Password $RasAdminPassword

#Install RAS Connection Broker role
WriteLog "Install Connection Broker role"
Start-Process msiexec.exe -ArgumentList "/i C:\install\RASInstaller.msi ADDFWRULES=1 ADDLOCAL=F_Controller /qn /log C:\install\RAS_Install.log" -Wait

#Remove impersonation
Remove-ImpersonateUser