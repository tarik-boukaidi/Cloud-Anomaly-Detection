param(
    [string]$ResourceGroup = "cloud-anomaly-rg",
    [string]$Location = "francecentral",
    [string]$StorageAccount = "",
    [string]$FunctionApp = "",
    [string]$ContainerName = "logs",
    [string]$ModelBlob = "random_forest_model.pkl",
    [string]$ResultsBlob = "detected_threats.csv",
    [string]$UseAzureModel = "true"
)

$ErrorActionPreference = "Stop"

function New-RandomName {
    param(
        [string]$Prefix,
        [int]$Length = 4
    )

    $suffix = -join ((48..57) + (97..122) | Get-Random -Count $Length | ForEach-Object { [char]$_ })
    return ("{0}{1}" -f $Prefix, $suffix).ToLower()
}

if (-not $StorageAccount) {
    $StorageAccount = New-RandomName -Prefix "cloudanomaly"
}

if (-not $FunctionApp) {
    $FunctionApp = New-RandomName -Prefix "cloud-anomaly-func-"
}

Write-Host "Creating resource group..."
$GroupExists = az group exists --name $ResourceGroup -o tsv
if ($GroupExists -eq "true") {
    Write-Host "Resource group already exists, reusing it."
} else {
    az group create --name $ResourceGroup --location $Location
}

Write-Host "Creating storage account..."
az storage account create --name $StorageAccount --resource-group $ResourceGroup --location $Location --sku Standard_LRS

$ConnectionString = az storage account show-connection-string --name $StorageAccount --resource-group $ResourceGroup --query connectionString -o tsv
if (-not $ConnectionString) {
    throw "Unable to retrieve storage connection string."
}

Write-Host "Creating blob container..."
az storage container create --name $ContainerName --connection-string $ConnectionString

Write-Host "Creating Function App..."
Write-Host "Registering Microsoft.Web provider if needed..."
az provider register --namespace Microsoft.Web --wait
az functionapp create --resource-group $ResourceGroup --consumption-plan-location $Location --os-type Linux --runtime python --runtime-version 3.12 --functions-version 4 --name $FunctionApp --storage-account $StorageAccount

Write-Host "Setting application settings..."
az functionapp config appsettings set `
    --resource-group $ResourceGroup `
    --name $FunctionApp `
    --settings `
    AZURE_STORAGE_CONNECTION_STRING="$ConnectionString" `
    AZURE_STORAGE_CONTAINER="$ContainerName" `
    AZURE_MODEL_BLOB="$ModelBlob" `
    AZURE_RESULTS_BLOB="$ResultsBlob" `
    USE_AZURE_MODEL="$UseAzureModel"

Write-Host ""
Write-Host "Azure resources are ready."
Write-Host "Resource Group : $ResourceGroup"
Write-Host "Storage Account: $StorageAccount"
Write-Host "Function App    : $FunctionApp"
Write-Host ""
Write-Host "Next step:"
Write-Host "func azure functionapp publish $FunctionApp"
