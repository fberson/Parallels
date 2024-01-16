<#  
.SYNOPSIS  
    PArallels RAS register script for Azure MarketPlace Deployments
.NOTES  
    File Name  : RAS_Azure_MP_Register.ps1
    Author     : Freek Berson
    Version    : v0.0.7
    Date       : Jan 16 2024
.EXAMPLE
    .\RAS_Azure_MP_Register.ps1
#>

function IsSupportedOS {
    if ([System.Environment]::Is64BitOperatingSystem) {
        try {
            $processorArchitecture = (Get-CimInstance -ClassName Win32_Processor).Architecture
            if ($processorArchitecture -eq 5) {
                Write-Host "ARM Based operating systems are supported by this script." -ForegroundColor red
                return $false
            }
        }
        catch {
            Write-Host "Failed to retrieve processor architecture: $_" -ForegroundColor red
            return $true
        }
    }
    return $true
}

function Test-InternetConnection {
    param (
        [int]$TimeoutMilliseconds = 5000
    )

    $request = [System.Net.WebRequest]::Create("http://www.google.com")
    $request.Timeout = $TimeoutMilliseconds

    try {
        $response = $request.GetResponse()
        $response.Close()
        return $true
    }
    catch {
        Write-Host "Internet connectivity is not available, check connectivity and try again." -ForegroundColor Red
        return $false
    }
}

function ConfigureNuGet {
    param()

    $requiredVersion = '2.8.5.201'
    $nugetProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -Force

    if (!$nugetProvider) {
        Install-PackageProvider -Name NuGet -Force
    }
    else {
        $installedVersion = $nugetProvider.Version

        if ($installedVersion -lt $requiredVersion) {
            Write-Host "The installed NuGet provider version is $($installedVersion). Required version is $($requiredVersion) or higher."
            Install-PackageProvider -Name NuGet -Force
        }
    }
}

function import-AzureModule {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    # Check if the module is already imported
    $module = Get-Module -Name $ModuleName -ListAvailable
    if (-not $module) {
        Write-Host "Required module '$ModuleName' is not imported. Installing and importing..."
        # Install the module if not already installed
        if (-not (Get-Module -Name $ModuleName -ListAvailable)) {
            Install-Module -Name $ModuleName -Scope CurrentUser -Force
        }
        # Import the module
        Import-Module -Name $ModuleName -Force
    }
}

function get-AzureDetailsFromJSON {
    try {
        # Define the path to the JSON file
        $jsonFilePath = "C:\install\output.json"

        # Read the JSON content from the file
        $jsonContent = Get-Content -Path $jsonFilePath | Out-String

        # Convert JSON content to a PowerShell object
        $data = $jsonContent | ConvertFrom-Json

        return $data
    }
    catch {
        Write-Host "Error reading JSON file with Azure details." -ForegroundColor Red
        return $false
    }
}

function get-resourceUsageId {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true)]
        [string]$appPublisherName,
        [Parameter(Mandatory = $true)]
        [string]$appProductName

    )
    #Get the resourceUsageId
    Set-AzContext -SubscriptionId $SubscriptionId
        
    $managedAppName = (get-azresource -ResourceType 'Microsoft.Solutions/applications' | Where-Object { ($_.Plan.Publisher -match $appPublisherName) -and ($_.Plan.product -match $appProductName) -and ($_.kind -match 'MarketPlace') }).name
    
    $managedAppResourceGroupName = (get-azresource -ResourceType 'Microsoft.Solutions/applications' | Where-Object { ($_.Plan.Publisher -match $appPublisherName) -and ($_.Plan.product -match $appProductName) -and ($_.kind -match 'MarketPlace') }).ResourceGroupName
    
    $resource = Get-AzResource -ResourceType "Microsoft.Solutions/applications" -ResourceGroupName $managedAppResourceGroupName -Name $managedAppName
    
    $resourceUsageId = $resource.Properties.billingDetails.resourceUsageId

    return $resourceUsageId[1]
}

function get-keyVaultSecret {
    param {
        [Parameter(Mandatory = $true)]
        [string]$keyVaultName,
        [Parameter(Mandatory = $true)]
        [string]$secretName

    }
    return = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName
}

# BEGIN SCRIPT

Clear-Host

Write-Host '*** This script will register Parallels RAS and import a license key ***' -ForegroundColor Green
Write-Host 'Please authenticate towards Azure to complete the setup.' `n

$appPublisherName = 'Parallels'
$appProductName = 'parallelsras-preview'

if (-not (IsSupportedOS)) {
    Read-Host "Press any key to continue..."
    exit
}

if (-not (Test-InternetConnection)) {
    Read-Host "Press any key to continue..."
    exit
}

#Check if NuGet 2.8.5.201 or higher is installed, if not install it
try {
    ConfigureNuGet
}
Catch {
    Write-Host "ERROR: trying to install latest NuGet version"
    Write-Host $_Write-Host $_.Exception.Message
    exit
}

# Check and import the required Azure PowerShell module
try {
    import-AzureModule "Az.Accounts"
    import-AzureModule "Az.Resources"
}
Catch {
    Write-Host "ERROR: trying to import required modules import Az.Accounts, AzureAD, Az.Resources, Az.network, and Az.keyVault"
    Write-Host $_.Exception.Message
    exit
}

# Get Azure details from JSON file
try {
    $retreivedData = get-AzureDetailsFromJSON 
}
Catch {
    Write-Host "ERROR: retreiving Azure details from JSON file"
    Write-Host $_.Exception.Message
    exit
}

# Connect to Azure and Azure AD
try {
    $currentUser = Connect-AzAccount -Tenant $retreivedData.tenantID
}
Catch {
    Write-Host "ERROR: trying to run Connect-AzAccount and Connect-AzureAD"
    Write-Host $_.Exception.Message
}

#Get the resourceUsageId
try {
    $resourceUsageId = get-resourceUsageId -SubscriptionId $retreivedData.SubscriptionId -appPublisherName $appPublisherName -appProductName $appProductName
}
Catch {
    Write-Host "ERROR: trying to read resource usage id from managed app"
    Write-Host $_.Exception.Message
    exit
}

#Get the keyvault secret
try {
    $localAdminPasswordSecure = ConvertTo-SecureString (get-keyVaultSecret(-keyVaultName $retreivedData.keyVaultName -secretName $retreivedData.secretName)) -AsPlainText -Force
}
Catch {
    Write-Host "ERROR: trying to read resource usage id from managed app"
    Write-Host $_.Exception.Message
    exit
}

#Contact MA to get Parallels RAS License key
Write-Host $resourceUsageId[1]

# Register Parallels RAS with the license key
New-RASSession -Username $retreivedData.localAdminUser -Password $localAdminPasswordSecure

# Disable IE ESC for Administrators and users
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 1