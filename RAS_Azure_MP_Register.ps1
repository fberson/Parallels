<#  
.SYNOPSIS  
    RAS retreive license from MA and register
.NOTES  
    File Name  : RAS_Azure_MP_Register.ps1
    Author     : Freek Berson
    Version    : v0.0.1
    Date       : Jan 15 2024
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

function set-AzureTenant {
    # Retrieve Azure tenants
    $tenants = Get-AzTenant

    # Display the list of tenants and prompt the user to select one
    $i = 1
    $selectedTenant = $null

    Write-Host "Azure Tenants:" -ForegroundColor Yellow
    foreach ($tenant in $tenants) {
        Write-Host "$i. $($tenant.Name) - $($tenant.TenantId)"
        $i++
    }

    $validSelection = $false
    while (-not $validSelection) {
        $selection = Read-Host ('>> Select a tenant by entering the corresponding number')
        
        if ($selection -match '^\d+$') {
            $selection = [int]$selection
            if ($selection -ge 1 -and $selection -le $tenants.Count) {
                $validSelection = $true
            }
        }
        
        if (-not $validSelection) {
            Write-Host "Invalid input. Please enter a valid number between 1 and $($tenants.Count)" -ForegroundColor Red
        }
    }

    $selectedTenant = $tenants[$selection - 1]

    # Store the selected tenant ID in tenantId variable
    $tenantId = $selectedTenant.TenantId

    Write-Host "Selected Tenant ID: $tenantId`n" -ForegroundColor Green

    # Return the selected tenant ID
    return $tenantId
}

# Define the path to the JSON file
$jsonFilePath = "C:\install\output.json"

# Read the JSON content from the file
$jsonContent = Get-Content -Path $jsonFilePath | Out-String

# Convert JSON content to a PowerShell object
$data = $jsonContent | ConvertFrom-Json

# Import the values into variables
$SubscriptionId = $data.SubscriptionId
$ResourceGroup = $data.ResourceGroup
$ApplicationName = $data.ApplicationName

# Output the variables
"Subscription ID: $SubscriptionId"
"Resource Group: $ResourceGroup"
"Application Name: $ApplicationName"

Clear-Host

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
    #exit
}

# Check and import the required Azure PowerShell module
try {
    import-AzureModule "Az.Accounts"
    #import-AzureModule "AzureAD"
    import-AzureModule "Az.Resources"
}
Catch {
    Write-Host "ERROR: trying to import required modules import Az.Accounts, AzureAD, Az.Resources, Az.network, and Az.keyVault"
    Write-Host $_.Exception.Message
    #exit
}

# Connect to Azure and Azure AD
try {
    $currentUser = Connect-AzAccount
    Connect-AzureAD | Out-Null
}
Catch {
    Write-Host "ERROR: trying to run Connect-AzAccount and Connect-AzureAD"
    Write-Host $_.Exception.Message
    #exit
}

# Set Azure tenant
try {
    $selectedTenantId = set-AzureTenant
}
Catch {
    Write-Host "ERROR: trying to get Azure Tenants"
    Write-Host $_.Exception.Message
    #exit
}

#Get the resourceUsageId
Set-AzContext -SubscriptionId $SubscriptionId
$resource = Get-AzResource -ResourceType "Microsoft.Solutions/applications" -ResourceGroupName $ResourceGroup -Name $ApplicationName
$resourceUsageId = $resource.Properties.billingDetails.resourceUsageId

#Contact MA to get Parallels RAS License key
Write-Host "resourceUsageId:"$resourceUsageId

# Disable IE ESC for Administrators and users
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 1



