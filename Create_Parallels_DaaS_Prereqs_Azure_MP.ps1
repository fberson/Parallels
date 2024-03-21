#Collect Parameters
param(
    [Parameter(Mandatory = $true)]
    [string]$location,

    [Parameter(Mandatory = $true)]
    [string]$appRegistrationName,

    [Parameter(Mandatory = $true)]
    [string]$keyVaultName,

    [Parameter(Mandatory = $true)]
    [string]$resourceGroupNameInfra,

    [Parameter(Mandatory = $true)]
    [string]$resourceGroupNameVMs,

    [Parameter(Mandatory = $true)]
    [string]$azureTenantID,

    [Parameter(Mandatory = $true)]
    [string]$azureSubscriptionID,

    [Parameter(Mandatory = $false)]
    [string]$localEnvJson
    
)

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

function create-CustomRole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]$RoleName
    )
    #Create custom role definition
    $existingRoleDefinition = Get-AzRoleDefinition -Name $RoleName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($null -eq $existingRoleDefinition) {
        $role = Get-AzRoleDefinition "Virtual Machine Contributor"
        $role.Id = $null
        $role.Name = $RoleName
        $role.Description = "Allows to add and delete role assignments"
        $role.Actions.Clear()
        $role.Actions.Add("Microsoft.Authorization/roleAssignments/write")
        $role.Actions.Add("Microsoft.Authorization/roleAssignments/delete")
        $role.AssignableScopes.clear()
        $role.AssignableScopes.Add("/subscriptions/$SubscriptionId")
        New-AzRoleDefinition -Role $role | Out-Null
    }
}

function add-AppRegistrationToCustomRole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectId,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]$RoleName
    )
    # Assign VM Reader role to the app registration at the subscription level
    New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope "/subscriptions/$SubscriptionId" | Out-Null
}

function new-AzureAppRegistration {
    $appName = $appRegistrationName
    if (!($myApp = Get-AzADServicePrincipal -DisplayName $appName -ErrorAction SilentlyContinue)) {
        $myApp = New-AzADServicePrincipal -DisplayName $appName
    }
    return (Get-AzADServicePrincipal -DisplayName $appName)
}

function new-AzureADAppClientSecret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$applicationID
    )

    # Get the ObjectId of the application based on the AppId
    $appObjectId = (Get-AzADApplication -Filter "AppId eq '$applicationID'").Id

    # Get the KeyId of the password credential where CustomKeyIdentifier is null
    $credentialKeyId = (Get-AzADAppCredential -ObjectId $appObjectId | Where-Object CustomKeyIdentifier -eq $null).KeyId

    # Remove the password credential based on the KeyId
    Remove-AzADAppCredential -ObjectId $appObjectId -KeyId $credentialKeyId

    $secretStartDate = Get-Date
    $secretEndDate = $secretStartDate.AddYears(1)
    $webApiSecret = New-AzADAppCredential -StartDate $secretStartDate -EndDate $secretEndDate -ApplicationId $applicationID -CustomKeyIdentifier ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("DaaS secret")))
    return $webApiSecret
}

function new-AzureKeyVaultWithSecret {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]$Location,

        [Parameter(Mandatory = $true)]
        [string]$SecretValue,

        [Parameter(Mandatory = $true)]
        [string]$SecretName,

        [Parameter(Mandatory = $true)]
        [string]$SubsciptionID
    )

    Write-Host `n"Azure Keyvault:" -ForegroundColor Yellow

    # Prompt the user to enter the Key Vault name and validate it
    $validSelection = $false
    while (-not $validSelection) {
        $KeyVaultName = Read-Host ">> Enter the name for the new Azure Key Vault to store secrets"
        if ($KeyVaultName -match '^[A-Za-z][\w-]{1,22}[A-Za-z0-9]$') {
            $validSelection = $true
        }

        if (-not $validSelection) {
            Write-Host "Invalid Key Vault name. Key Vault names must be between 3 and 24 characters in length. They must begin with a letter, end with a letter or digit, and contain only alphanumeric characters and dashes. Consecutive dashes are not allowed." -ForegroundColor Red
        }
    }

    Set-AzContext -SubscriptionId $SubsciptionID

    # Check if the Key Vault already exists
    $existingKeyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue

    if ($existingKeyVault) {
        # Key Vault already exists
        $useExisting = Read-Host "A Key Vault with the name '$KeyVaultName' already exists. Do you want to use the existing Key Vault? (Y/N)"
        if ($useExisting -eq 'Y') {
            Write-Output "Using the existing Key Vault '$KeyVaultName'."
            $keyVault = $existingKeyVault
        }
        else {
            Write-Output "Aborting operation."
            return
        }
    }
    else {
        # Create a new Key Vault
        $keyVault = New-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -Location $Location
    }

    # Add the secret to the Key Vault
    $secret = ConvertTo-SecureString -String $SecretValue -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $KeyVault.VaultName  -Name $SecretName -SecretValue $secret | Out-Null
    Write-Host "Added a new secret with the name $($SecretName) to the Key Vault $($KeyVaultName.VaultName)." -ForegroundColor Green

    return $KeyVaultName
}

function set-AdminConsent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ApplicationId,

        [Parameter(Mandatory)]
        [string]$TenantId
    )

    $Context = Get-AzContext

    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
        $context.Account, $context.Environment, $TenantId, $null, "Never", $null, "74658136-14ec-4630-ad9b-26e160ff0fc6")

    $headers = @{
        'Authorization'          = 'Bearer ' + $token.AccessToken
        'X-Requested-With'       = 'XMLHttpRequest'
        'x-ms-client-request-id' = [guid]::NewGuid()
        'x-ms-correlation-id'    = [guid]::NewGuid()
    }

    $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$ApplicationId/Consent?onBehalfOfAll=true"
    Invoke-RestMethod -Uri $url -Headers $headers -Method POST -ErrorAction Stop
}

function add-AzureAppRegistrationPermissions {
    param (
        [Parameter(Mandatory = $true)]
        [string]$appName,

        [Parameter(Mandatory = $false)]
        [string]$localEnvJson
    )
    # Get the app registration
    $applicationID = (Get-AzADApplication -Filter "displayName eq '$appName'").AppId

    $apiId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph's API ID

    # Get the Microsoft Graph Service Principal
    $graphSP = Get-AzADServicePrincipal -Filter "displayName eq 'Microsoft Graph'"

    # Define the desired permissions
    $desiredApplicationPermissions = @(
        "User.Read.All",
        "Domain.Read.All",
        "GroupMember.Read.All"
    )

    # Iterate over the desired permissions and add them to your application
    foreach ($permissionValue in $desiredApplicationPermissions) {
        $permissionId = ($graphSP.AppRole | Where-Object { $_.Value -eq $permissionValue }).Id
        if ($permissionId) {
            Add-AzADAppPermission -ApplicationId $applicationID -ApiId $apiId -PermissionId $permissionId -Type Role
            Write-Host "Added permission: $permissionValue with ID: $permissionId"
        }
        else {
            Write-Host "Failed to find application permission: $permissionValue"
        }
    }

    $desiredDelegatedPermissions = @(
        "email",
        "openid",
        "profile",
        "Group.Read.All"
    )

    # Iterate over the desired delegated permissions and add them to your application
    foreach ($permissionValue in $desiredDelegatedPermissions) {
        $permissionId = ($graphSP.Oauth2PermissionScope | Where-Object { $_.Value -eq $permissionValue }).Id
        if ($permissionId) {
            Add-AzADAppPermission -ApplicationId $applicationID -ApiId $apiId -PermissionId $permissionId -Type Scope
            Write-Host "Added permission: $permissionValue with ID: $permissionId"
        }
        else {
            Write-Host "Failed to find delegated permission: $permissionValue"
        }
    }

    $optionalClaimsJson = @"
        {
         "idToken": [
            {
                "name": "upn"
            },
            {
                "name": "email"
            },
            {
                "name": "groups"
            }
        ],
        "accessToken": [
            {
                "name": "groups"
            }
        ],
        "saml2Token": [
            {
                "name": "groups"
            }
        ]
    }
"@

    $authenticationJson = @"
        {
            "RedirectUri": [
                "https://cloud.parallels.com/discovery",
                "https://cloud.parallels.com/signin-oidc",
                "https://cloudadmin.parallels.com/login",
                "https://cloudadmin.parallels.com/signin-oidc"
            ]
        }
"@
    if ($localEnvJson.Length -gt 0) {
        $authenticationJson = $localEnvJson
    }


    $AppReg = Get-AzADApplication -Filter "displayName eq '$appName'"
    $WebData = $AppReg.Web | ConvertFrom-Json
    $WebData.implicitGrantSettings.enableIdTokenIssuance = $true
    $JsonOutput = $WebData | ConvertTo-Json
    $AppReg | Update-AzADApplication -Web $JsonOutput

    # add optionalclaims to application
    $AppReg | Update-AzADApplication  -OptionalClaim $optionalClaimsJson
    # add logout url to application
    $authenticationObj = $authenticationJson | ConvertFrom-Json -AsHashtable
    $AppReg | Update-AzADApplication -Web $authenticationObj
    $AppReg | Update-AzADApplication -GroupMembershipClaim "SecurityGroup"
}

Write-Host "Starting the script to create the prerequisites for Parallels DaaS in Azure" -ForegroundColor Cyan
Write-host "Powershell version:"$PSVersionTable.PSVersion -ForegroundColor green

# Check and import the required Azure PowerShell module
try {
    Write-Host "import-AzureModule Az.Accounts"
    import-AzureModule "Az.Accounts"
    Write-Host "import-AzureModule Az.Resources"
    import-AzureModule "Az.Resources"
    Write-Host "import-AzureModule Az.keyVault"
    import-AzureModule "Az.keyVault"
}
Catch {
    Write-Host "ERROR: trying to import required modules import Az.Accounts, Az.Resources, and Az.keyVault"
    Write-Host $_.Exception.Message
    #exit
}

# Set Tenant
try {
    Write-Host "Set Tenant"
    $selectedTenantId = $azureTenantID
}
Catch {
    Write-Host "ERROR: trying to get Azure Tenants"
    Write-Host $_.Exception.Message
    #exit
}

# Provide list of available Azure subscriptions and allow setting active subscription
try {
    Write-Host "Set Subscription"
    $selectedSubscriptionID = $azureSubscriptionID
}
Catch {
    Write-Host "ERROR: trying to set Azure subscription"
    Write-Host $_.Exception.Message
    #exit
}

# Provide list of available Azure locations and allow setting active location
try {
    Write-Host "Set location"
    $selectedAzureLocation = $location
}
Catch {
    Write-Host "ERROR: trying to get Azure Location"
    Write-Host $_.Exception.Message
    #exit
}

# Register the required Azure resource providers
try {
    Write-Host "Register-AzResourceProvider Microsoft.Network and Microsoft.Compute"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Network"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Compute"
}
Catch {
    Write-Host "ERROR: trying to register required Azure resource providers"
    Write-Host $_.Exception.Message
    #exit
}

# Create a custom role to allow adding and deleting role assinments
try {
    Write-Host "Create custom role Daas Role Assignment"
    create-CustomRole -SubscriptionId $selectedSubscriptionID -RoleName "Daas Role Assignment"
}
Catch {
    Write-Host "ERROR: creating custom role to allow adding and deleting role assinments"
    Write-Host $_.Exception.Message
    #exit
}

# Prompt for the app name and create the app registration
try {
    Write-Host "Create app registration"
    $app = new-AzureAppRegistration
    Write-Host "App registration name: "$app.DisplayName -ForegroundColor Green
}
Catch {
    Write-Host "ERROR: trying to create the App Registration"
    Write-Host $_.Exception.Message
    #exit
}

# Assign Contributor role to the app registration on Infrastructure RG
try {
    Write-Host "Assign Contributor role to the app registration on Infrastructure RG"
    New-AzRoleAssignment -ObjectId $app.Id -RoleDefinitionName "Contributor" -Scope $rgInfra.ResourceId | Out-Null
}
Catch {
    Write-Host "ERROR: trying to assign contributor role to the app registration on Infrastructure RG"
    Write-Host $_.Exception.Message
    #exit
}

# Assign Contributor role to the app registration on VMs RG
try {
    Write-Host "Assign Contributor role to the app registration on VMs RG"
    New-AzRoleAssignment -ObjectId $app.Id -RoleDefinitionName "Contributor" -Scope $rgVms.ResourceId | Out-Null
}
Catch {
    Write-Host "ERROR: trying to assign contributor role to the app registration on VMs RG"
    Write-Host $_.Exception.Message
    #exit
}

# Set the required Graph API permissions on the created app registration
try {
    Write-Host "Set app registration Graph API permissions"
    add-AzureAppRegistrationPermissions -appName $app.DisplayName -localEnvJson $localEnvJson
}
Catch {
    Write-Host "ERROR: trying to set app registration Graph API permissions"
    Write-Host $_.Exception.Message
    #exit
}

# Create a client secret on the app registration and capture the secret key
try {
    Write-Host "Create client secret on the app registration"
    $secret = new-AzureADAppClientSecret -TenantId $selectedTenantId -applicationID $app.AppId
}
Catch {
    Write-Host "ERROR: trying to create the App Registration client secret"
    Write-Host $_.Exception.Message
    #exit
}

# Add DaaS Role Assignment Role permission on subscription to the app registration
try {
    Write-Host "Add DaaS Role Assignment Role permission on subscription to the app registration"
    add-AppRegistrationToCustomRole -objectId $app.Id -SubscriptionId $selectedSubscriptionID -RoleName "Daas Role Assignment"
}
Catch {
    Write-Host "ERROR: trying to set User Access Administration role"
    WWrite-Host $_.Exception.Message
    #exit
}

# Grant admin consent to an the app registration
try {
    Write-Host "Grant admin consent to an the app registration"
    set-AdminConsent -ApplicationId $app.AppId -TenantId $selectedTenantId
}
Catch {
    Write-Host "ERROR: trying to grant admin consent to an the app registration"
    Write-Host $_.Exception.Message
    #exit
}

# Add an Azure Keyvault and store the Client Secret in it
try {
    Write-Host "Add an Azure Keyvault and store the Client Secret in it"
    $selectedKeyVaultName = new-AzureKeyVaultWithSecret -ResourceGroupName $rgInfra.ResourceGroupName -Location $selectedAzureLocation -SecretValue $secret.SecretText -SecretName "daas-spn-client-secret" -SubsciptionID $selectedSubscriptionID
}
Catch {
    Write-Host "ERROR: trying to create a new Azure KeyVault and adding the client secret"
    Write-Host $_.Exception.Message
    #exit
}

#Create summary information
Write-Host "`n* App registration created, permissions configured and secret created." -ForegroundColor Cyan
Write-host "* Below is the information that has to be provided via Parallels DaaS portal!" -ForegroundColor Cyan
Write-Host "1. Tenant ID: "$selectedTenantId
Write-Host "2. Subscription ID: "$selectedSubscriptionID
Write-Host "3. Application(client) ID: "$app.AppId
Write-Host "4. Client secret value stored in KV "$selectedKeyVaultName
Write-Host "5. Infrastructure resource group name: "$rgInfra.ResourceGroupName
Write-Host "6. VMs resource group name: "$rgVms.ResourceGroupName
