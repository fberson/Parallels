<#  
.SYNOPSIS  
    RAS auto-deploy script for Azure MarketPlace Deployments
.NOTES  
    File Name  : RAS_Install.ps1
    Author     : Freek Berson
    Version    : v0.0.4
    Date       : Dec 09 2024
.EXAMPLE
    .\RAS_Install.ps1
#>

#Collect Parameters
param(
    [Parameter(Mandatory=$true)]
    [string]$localAdminUser,

    [Parameter(Mandatory=$true)]
    [string]$localAdminPassword,

    [Parameter(Mandatory=$true)]
    [string]$MyAccountEmail,

    [Parameter(Mandatory=$true)]
    [string]$MyAccountpassord,

    [Parameter(Mandatory=$true)]
    [string]$ResourceUsageId

)
$hostname = hostname
$localAdminPasswordSecure = ConvertTo-SecureString $localAdminPassword -AsPlainText -Force
$MyAccountpassordSecure = ConvertTo-SecureString $MyAccountpassord -AsPlainText -Force
$installPath = "C:\install"

# Check if the install path already exists
if (-not (Test-Path -Path $installPath)) {New-Item -Path $installPath -ItemType Directory}

#Configute logging
$Logfile = "C:\install\RAS_InstallScript.log"
function WriteLog
{
    Param ([string]$LogString)
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$Stamp $LogString"
    Add-content $LogFile -value $LogMessage
}

#Set variables
$EvergreenURL = 'https://download.parallels.com/ras/latest/RASInstaller.msi'
$Temploc = 'C:\install\RASInstaller.msi' 

#Log The ResourceUsageId
WriteLog "ResourceUsageId:"
WriteLog $ResourceUsageId

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
Foreach ($localAdmin in $allLocalAdmins)
{
    cmd /c "`"C:\Program Files (x86)\Parallels\ApplicationServer\x64\2XRedundancy.exe`" -c -AddRootAccount $localAdmin"
}

# Enable RAS PowerShell module
Import-Module 'C:\Program Files (x86)\Parallels\ApplicationServer\Modules\RASAdmin\RASAdmin.psd1'

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
