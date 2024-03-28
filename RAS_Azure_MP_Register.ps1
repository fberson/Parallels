<#  
.SYNOPSIS  
    PArallels RAS register script for Azure MarketPlace Deployments
.NOTES  
    File Name  : RAS_Azure_MP_Register.ps1
    Author     : Freek Berson
    Version    : v0.0.14
    Date       : March 28 2024
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
    Set-AzContext -SubscriptionId $SubscriptionId
    $managedAppName = (get-azresource -ResourceType 'Microsoft.Solutions/applications' | Where-Object { ($_.Plan.Publisher -match $appPublisherName) -and ($_.Plan.product -match $appProductName) -and ($_.kind -match 'MarketPlace') }).name
    $managedAppResourceGroupName = (get-azresource -ResourceType 'Microsoft.Solutions/applications' | Where-Object { ($_.Plan.Publisher -match $appPublisherName) -and ($_.Plan.product -match $appProductName) -and ($_.kind -match 'MarketPlace') }).ResourceGroupName
    $resource = (Get-AzResource -ResourceType "Microsoft.Solutions/applications" -ResourceGroupName $managedAppResourceGroupName -Name $managedAppName)
    $resourceUsageId = $resource.Properties.billingDetails.resourceUsageId
    return $resourceUsageId
}

function get-keyVaultSecret {
    param (
        [Parameter(Mandatory = $true)]
        [string]$keyVaultName,
        [Parameter(Mandatory = $true)]
        [string]$secretName

    )
    return Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName
}


function CreateVMReaderRole {
    param(        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    #Create custom role definition
    $existingRoleDefinition = Get-AzRoleDefinition -Name "VM Reader Parallels RAS" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($null -eq $existingRoleDefinition) {
        $role = Get-AzRoleDefinition "Virtual Machine Contributor"
        $role.Id = $null
        $role.Name = "VM Reader Parallels RAS"
        $role.Description = "Provides read access to Microsoft.Compute"
        $role.Actions.Clear()
        $role.Actions.Add("Microsoft.Compute/*/read")
        $role.AssignableScopes.clear()
        $role.AssignableScopes.Add("/subscriptions/$SubscriptionId")
        New-AzRoleDefinition -Role $role | Out-Null
    }
}


function New-AzureAppRegistration {
    param(        
        [Parameter(Mandatory = $true)]
        [string]$appName
    )
 
    # Check if the AzADServicePrincipal already exists
    $ADServicePrincipal = Get-AzADServicePrincipal -DisplayName $appName
    if ($null -ne $ADServicePrincipal) {
        Write-Host "AD Service Principal with name '$appName' already exists. Please choose a different name."
        return
    }

    if (!($myApp = Get-AzADServicePrincipal -DisplayName $appName -ErrorAction SilentlyContinue)) {
        $myApp = New-AzADServicePrincipal -DisplayName $appName
    }
    return (Get-AzADServicePrincipal -DisplayName $appName)
}

function Set-AzureVNetResourcePermissions {
    param (
        [Parameter(Mandatory = $true)]
        [string]$vnetId,

        [Parameter(Mandatory = $true)]
        [string]$ObjectId
    )
    
    #Add contributor permissions to the vnet for the app registration 
    $roleAssignment = New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName "Contributor" -Scope $vnetId | Out-Null
        
    # Return the selected vnet
    return $roleAssignment

}

function Add-AzureAppRegistrationPermissions {
    param (
        [Parameter(Mandatory = $true)]
        [string]$appName
    )
    # Get the app registration
    $applicationID = (Get-AzADApplication -DisplayName $appName).AppId

    #Add Group.Read.All permission
    Add-AzADAppPermission -ApplicationId $applicationID -ApiId "00000003-0000-0000-c000-000000000000" -PermissionId 5b567255-7703-4780-807c-7be8301ae99b -Type Role
    Add-AzADAppPermission -ApplicationId $applicationID -ApiId "00000003-0000-0000-c000-000000000000" -PermissionId df021288-bdef-4463-88db-98f22de89214 -Type Role
}
function New-AzureADAppClientSecret {
    param(     
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$applicationID
    )
    Remove-AzureADApplicationPasswordCredential -ObjectId (Get-AzADApplication -ApplicationId '$applicationID').ObjectId -KeyId (Get-AzureADApplicationPasswordCredential -ObjectId (Get-AzureADApplication -Filter "AppId eq '$applicationID'").ObjectId | Where-Object CustomKeyIdentifier -EQ $null).KeyId
    $secretStartDate = Get-Date
    $secretEndDate = $secretStartDate.AddYears(1)
    $webApiSecret = New-AzADAppCredential -StartDate $secretStartDate -EndDate $secretEndDate -ApplicationId $applicationID -CustomKeyIdentifier ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("Parallels RAS secret")))
    return $webApiSecret    
}

function Set-azureResourceGroupPermissions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$objectId,

        [Parameter(Mandatory = $true)]
        [string]$resourceGroupID
    )

    # Assign the contributor role to the service principal on the resource group
    New-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName "Contributor" -Scope $resourceGroupID | Out-Null
}

function Add-UserAccessAdministrationRole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$objectId,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )

    # Assign User Access Administrator role to the app registration at the subscription level
    New-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName "User Access Administrator" -Scope "/subscriptions/$SubscriptionId" | Out-Null
}

function Add-VMReaderRole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$objectId,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    # Assign VM Reader role to the app registration at the subscription level
    New-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName "VM Reader Parallels RAS" -Scope "/subscriptions/$SubscriptionId" | Out-Null
}

function Set-azureKeyVaultSecret {
    [CmdletBinding()]
    param (
               
        [Parameter(Mandatory = $true)]
        [string]$keyVaultName,
    
        [Parameter(Mandatory = $true)]
        [string]$SecretValue,
        
        [Parameter(Mandatory = $true)]
        [string]$SecretName
        
    )

    # Add the secret to the Key Vault
    $secret = ConvertTo-SecureString -String $SecretValue -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $keyVaultName  -Name $SecretName -SecretValue $secret | Out-Null

    return $KeyVaultName
}

# BEGIN SCRIPT

# Disable IE ESC for Administrators and users
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0

# Disable Edge first run experience
New-item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'HideFirstRunExperience' -Value 1 -Force | Out-Null


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
    Write-Host 'Installing required Azure Powershell modules.' `n
    ConfigureNuGet
}
Catch {
    Write-Host "ERROR: trying to install latest NuGet version"
    Write-Host $_Write-Host $_.Exception.Message
    exit
}

# Check and import the required Azure PowerShell module
try {
    import-AzureModule "Az.Resources"
    import-AzureModule "Az.KeyVault"
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
    Write-Host 'Please authenticate towards Azure to complete the setup.' `n
    $currentUser = Connect-AzAccount -Tenant $retreivedData.tenantID -AuthScope MicrosoftGraphEndpointResourceId
}
Catch {
    Write-Host "ERROR: trying to run Connect-AzAccount and Connect-AzureAD"
    Write-Host $_.Exception.Message
}

#Get the resourceUsageId
try {
    Write-Host 'Performing post-installation steps...' `n
    $appPublisherName = $retreivedData.appPublisherName
    $appProductName = $retreivedData.appProductName
    $resourceUsageId = get-resourceUsageId -SubscriptionId $retreivedData.SubscriptionId -appPublisherName $appPublisherName -appProductName $appProductName
}
Catch {
    Write-Host "ERROR: trying to read resource usage id from managed app"
    Write-Host $_.Exception.Message
    exit
}

#Get the keyvault secret
try {
    $localAdminPasswordSecure = (get-keyVaultSecret -keyVaultName $retreivedData.keyVaultName -secretName $retreivedData.secretName).secretValue
}
Catch {
    Write-Host "ERROR: trying to read resource usage id from managed app"
    Write-Host $_.Exception.Message
    exit
}


#Create Azure app registration if specified
if ($retreivedData.providerSelection -ne "noProvider") {

    # Create a custom role to allow reading all compute resource
    try {
        CreateVMReaderRole -SubscriptionId $retreivedData.SubscriptionId
    }
    Catch {
        Write-Host "ERROR: creating custom role to allow reding VM resources"
        Write-Host $_.Exception.Message
        exit
    }

    # Create the app registration
    try {
        $app = New-AzureAppRegistration -appName $retreivedData.providerAppRegistrationName
        Write-Host "App registration name: "$app.DisplayName -ForegroundColor Green
    }
    Catch {
        Write-Host "ERROR: trying to create the App Registration"
        Write-Host $_.Exception.Message
        exit
    }

    # Set permissions on the virtual network
    try {
        Set-azureVNetResourcePermissions -vnetId $retreivedData.vnetId -objectId $app.Id
    }
    Catch {
        Write-Host "ERROR: trying to configure contributor permissons on vnet"
        Write-Host $_.Exception.Message
        exit
    }

    # Set the required Graph API permissions on the created app registration
    try {
        Add-AzureAppRegistrationPermissions -appName $app.DisplayName
    }
    Catch {
        Write-Host "ERROR: trying to set app registration Graph API permissions"
        Write-Host $_.Exception.Message
        exit
    }

    # Create a client secret on the app registration and capture the secret key
    try {
        $secret = New-AzureADAppClientSecret -TenantId $retreivedData.tenantID -applicationID $app.AppId
    }
    Catch {
        Write-Host "ERROR: trying to create the App Registration client secret"
        Write-Host $_.Exception.Message
        exit
    }

    # Add app registration contributor permissions on resource group
    try {
        $rg = set-azureResourceGroupPermissions -resourceGroupID $retreivedData.mgrID  -objectId $app.Id
    }
    Catch {
        Write-Host "ERROR: trying to create the resource group and set contributor permissions"
        Write-Host $_.Exception.Message
        exit
    }

    # Add User Access Administratrion permission on subscription to the app registration
    try {
        Add-UserAccessAdministrationRole -objectId $app.Id -SubscriptionId $retreivedData.SubscriptionId
    }
    Catch {
        Write-Host "ERROR: trying to set User Access Administration role"
        WWrite-Host $_.Exception.Message
        exit
    }

    # Add VM Reader permission on subscription to the app registration
    try {
        Add-VMReaderRole -objectId $app.Id -SubscriptionId $retreivedData.SubscriptionId
    }
    Catch {
        Write-Host "ERROR: trying to set VM Reader role"
        WWrite-Host $_.Exception.Message
        exit
    }

    # Store client secret in Azure KeyVault
    try {
        $selectedKeyVaultName = Set-azureKeyVaultSecret -keyVaultName $retreivedData.keyVaultName -SecretValue $secret -SecretName $retreivedData.providerAppRegistrationName
    }
    Catch {
        Write-Host "ERROR: trying to create a new Azure KeyVault and adding the client secret"
        Write-Host $_.Exception.Message
        exit
    }
}

# Register Parallels RAS with the license key - REQUIRES UPDATES
New-RASSession -Username $retreivedData.domainJoinUserName -Password $localAdminPasswordSecure -Server $retreivedData.primaryConnectionBroker

<#
#Set Azure Marketplace related settings in RAS db
Set-RASAzureMarketplaceDeploymentSettings -SubscriptionID $retreivedData.SubscriptionId -TenantID $retreivedData.tenantID 
-CustomerUsageAttributionID $retreivedData.customerUsageAttributionID -ManagedAppResourceUsageID $resourceUsageId[1]

# Invoke-apply
invoke-RASApply

#Create Azure or AVD in RAS if specified
if ($retreivedData.providerSelection -eq "AVDProvider") {
    New-RASProvider -AVD -Name $retreivedData.providerName -AppRegistrationName $retreivedData.providerAppRegistrationName
}
if ($retreivedData.providerSelection -eq "AzureProvider") {
    New-RASProvider $retreivedData.providerName -Azure -Version Azure -TenantID $retreivedData.tenantID -SubscriptionID $retreivedData.SubscriptionId -ProviderUsername $retreivedData.providerAppRegistrationName -ProviderPassword $pass -NoInstallproviderAppRegistrationName
}
#>

# Invoke-apply and remove session
invoke-RASApply
Remove-RASSession

#restart secundary RAS servers to complete installation
for ($i = 2; $i -le $retreivedData.numberofCBs; $i++) {
    $connectionBroker = $retreivedData.prefixCBName + "-" + $i + "." + $retreivedData.domainName
    restart-computer -computername $connectionBroker -WsmanAuthentication Kerberos -force
}
for ($i = 1; $i -le $retreivedData.numberofSGs; $i++) {
    $secureGateway = $retreivedData.prefixSGName + "-" + $i + "." + $retreivedData.domainName
    restart-computer -computername $secureGateway -WsmanAuthentication Kerberos -force
}

Write-Host 'Registration of Parallels RAS is completed.' `n
Read-Host "Press any key to open the Parallels RAS console..."

Start-Process -FilePath "C:\Program Files (x86)\Parallels\ApplicationServer\2XConsole.exe"
