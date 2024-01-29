<#  
.SYNOPSIS  
    Parallels RAS Secure Gateway prereq script Azure MarketPlace Deployments
.NOTES  
    File Name  : RAS_Azure_MP_Install.ps1
    Author     : Freek Berson
    Version    : v0.0.11
    Date       : Jan 29 2024
.EXAMPLE
    .\RAS_Azure_MP_Install.ps1
#>
$installPath = "C:\install"

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
New-NetFirewallRule -DisplayName "Allow TCP 80, 81, 135, 443, 445 and 20009, 200020, 49179 for RAS Administration" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80, 81, 135, 443, 445, 20009, 20020, 49179
New-NetFirewallRule -DisplayName "Allow UDP 20009,20020" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 20009,20020

#Disable UAC & Sharing Wizard to allow Remote Install of RAS Agent
WriteLog "Disable UAC & Sharing Wizard"
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -Value 0
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SharingWizardOn -Name CheckedValue -Value 0
