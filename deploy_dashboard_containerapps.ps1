param(
    [string]$ResourceGroup = "cloud-anomaly-rg",
    [string]$Location = "westeurope",
    [string]$CloudLocation = "francecentral",
    [string]$ContainerAppEnv = "cloud-anomaly-env",
    [string]$ContainerAppName = "",
    [string]$AcrName = "",
    [string]$ContainerName = "cloud-anomaly-dashboard",
    [string]$ContainerRegistryImage = "cloud-anomaly-dashboard:latest",
    [string]$ContainerNameResultsBlob = "detected_threats.csv",
    [string]$ContainerNameStorage = "logs"
)

$ErrorActionPreference = "Stop"

if (-not $env:AZURE_CONFIG_DIR) {
    $env:AZURE_CONFIG_DIR = Join-Path $PSScriptRoot ".azure-config"
}
if (-not (Test-Path $env:AZURE_CONFIG_DIR)) {
    New-Item -ItemType Directory -Path $env:AZURE_CONFIG_DIR | Out-Null
}

function Invoke-AzChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    & az @Args
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: az $($Args -join ' ')"
    }
}

function Test-AzCommandSucceeded {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        & az @Args 1>$null 2>$null
        return ($LASTEXITCODE -eq 0)
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
}

function Get-AzOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        return (& az @Args 2>$null)
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
}

function New-RandomName {
    param(
        [string]$Prefix,
        [int]$Length = 4
    )

    $suffix = -join ((48..57) + (97..122) | Get-Random -Count $Length | ForEach-Object { [char]$_ })
    return ("{0}{1}" -f $Prefix, $suffix).ToLower()
}

if (-not $ContainerAppName) {
    $ContainerAppName = New-RandomName -Prefix "cloud-anomaly-dashboard-"
}

if (-not $AcrName) {
    $AcrName = (New-RandomName -Prefix "cloudanomalyacr" -Length 4).Replace("-", "")
}

Write-Host "Ensuring resource group exists..."
$GroupExists = Get-AzOutput @("group", "exists", "--name", $ResourceGroup, "-o", "tsv")
if ($LASTEXITCODE -ne 0) {
    throw "Unable to check resource group existence."
}
if ($GroupExists -ne "true") {
    Invoke-AzChecked @("group", "create", "--name", $ResourceGroup, "--location", $Location)
}

Write-Host "Registering Azure providers..."
Invoke-AzChecked @("provider", "register", "--namespace", "Microsoft.App")
Invoke-AzChecked @("provider", "register", "--namespace", "Microsoft.OperationalInsights")
Invoke-AzChecked @("provider", "register", "--namespace", "Microsoft.ContainerRegistry")

Write-Host "Creating Azure Container Registry..."
$AcrExists = Test-AzCommandSucceeded @("acr", "show", "--name", $AcrName, "--resource-group", $ResourceGroup, "-o", "none")
if (-not $AcrExists) {
    Invoke-AzChecked @("acr", "create", "--name", $AcrName, "--resource-group", $ResourceGroup, "--sku", "Basic", "--location", $CloudLocation)
}

Write-Host "Enabling admin access on ACR..."
Invoke-AzChecked @("acr", "update", "--name", $AcrName, "--admin-enabled", "true")

$AcrLoginServer = (& az acr show --name $AcrName --query loginServer -o tsv)
if ($LASTEXITCODE -ne 0 -or -not $AcrLoginServer) {
    throw "Unable to retrieve ACR login server."
}

Write-Host "Building dashboard image in Azure..."
Invoke-AzChecked @("acr", "build", "--registry", $AcrName, "--image", $ContainerRegistryImage, ".")

Write-Host "Creating Container Apps environment..."
$EnvExists = Test-AzCommandSucceeded @("containerapp", "env", "show", "--name", $ContainerAppEnv, "--resource-group", $ResourceGroup, "-o", "none")
if (-not $EnvExists) {
    Invoke-AzChecked @("containerapp", "env", "create", "--name", $ContainerAppEnv, "--resource-group", $ResourceGroup, "--location", $CloudLocation)
}

$ConnectionString = (& az storage account show-connection-string --name cloudanomaly2krt --resource-group $ResourceGroup --query connectionString -o tsv)
if ($LASTEXITCODE -ne 0 -or -not $ConnectionString) {
    throw "Unable to retrieve storage connection string."
}

$AcrUsername = (& az acr credential show --name $AcrName --query username -o tsv)
$AcrPassword = (& az acr credential show --name $AcrName --query "passwords[0].value" -o tsv)
if ($LASTEXITCODE -ne 0 -or -not $AcrUsername -or -not $AcrPassword) {
    throw "Unable to retrieve ACR credentials."
}

Write-Host "Creating or updating Container App..."
$CreateArgs = @(
    "containerapp", "create",
    "--name", $ContainerAppName,
    "--resource-group", $ResourceGroup,
    "--environment", $ContainerAppEnv,
    "--image", "$AcrLoginServer/$ContainerRegistryImage",
    "--target-port", "8501",
    "--ingress", "external",
    "--registry-server", $AcrLoginServer,
    "--registry-username", $AcrUsername,
    "--registry-password", $AcrPassword,
    "--env-vars",
    "AZURE_STORAGE_CONNECTION_STRING=$ConnectionString",
    "AZURE_STORAGE_CONTAINER=$ContainerNameStorage",
    "AZURE_RESULTS_BLOB=$ContainerNameResultsBlob",
    "LOCAL_RESULTS_CSV=$ContainerNameResultsBlob"
)

$CreateOutput = & az @CreateArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    $UpdateArgs = @(
        "containerapp", "update",
        "--name", $ContainerAppName,
        "--resource-group", $ResourceGroup,
        "--image", "$AcrLoginServer/$ContainerRegistryImage",
        "--registry-server", $AcrLoginServer,
        "--registry-username", $AcrUsername,
        "--registry-password", $AcrPassword,
        "--set-env-vars",
        "AZURE_STORAGE_CONNECTION_STRING=$ConnectionString",
        "AZURE_STORAGE_CONTAINER=$ContainerNameStorage",
        "AZURE_RESULTS_BLOB=$ContainerNameResultsBlob",
        "LOCAL_RESULTS_CSV=$ContainerNameResultsBlob"
    )
    Invoke-AzChecked $UpdateArgs
}
else {
    Write-Host $CreateOutput
}

$AppUrl = (& az containerapp show --name $ContainerAppName --resource-group $ResourceGroup --query properties.configuration.ingress.fqdn -o tsv)
if ($LASTEXITCODE -eq 0 -and $AppUrl) {
    Write-Host ""
    Write-Host "Dashboard deployed on Azure Container Apps."
    Write-Host "Container App : $ContainerAppName"
    Write-Host "URL           : https://$AppUrl"
}
else {
    Write-Host ""
    Write-Host "Deployment completed, but the URL could not be retrieved automatically."
    Write-Host "Container App : $ContainerAppName"
}
