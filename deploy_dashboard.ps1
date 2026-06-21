param(
    [string]$ResourceGroup = "cloud-anomaly-rg",
    [string]$Location = "swedencentral",
    [string]$AppServicePlan = "cloud-anomaly-plan-sweden",
    [string]$WebAppName = "",
    [string]$StorageAccount = "cloudanomaly2krt",
    [string]$ContainerName = "logs",
    [string]$ResultsBlob = "detected_threats.csv"
)

$ErrorActionPreference = "Stop"

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

function New-RandomName {
    param(
        [string]$Prefix,
        [int]$Length = 4
    )

    $suffix = -join ((48..57) + (97..122) | Get-Random -Count $Length | ForEach-Object { [char]$_ })
    return ("{0}{1}" -f $Prefix, $suffix).ToLower()
}

if (-not $WebAppName) {
    $WebAppName = New-RandomName -Prefix "cloud-anomaly-dashboard-"
}

Write-Host "Ensuring resource group exists..."
$GroupExists = (& az group exists --name $ResourceGroup -o tsv)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to check resource group existence."
}
if ($GroupExists -ne "true") {
    Invoke-AzChecked @("group", "create", "--name", $ResourceGroup, "--location", $Location)
}

Write-Host "Creating App Service plan..."
Invoke-AzChecked @("appservice", "plan", "create", "--name", $AppServicePlan, "--resource-group", $ResourceGroup, "--is-linux", "--sku", "B1", "--location", $Location)

Write-Host "Creating Web App..."
Invoke-AzChecked @("webapp", "create", "--resource-group", $ResourceGroup, "--plan", $AppServicePlan, "--name", $WebAppName, "--runtime", "PYTHON:3.12")

$ConnectionString = (& az storage account show-connection-string --name $StorageAccount --resource-group $ResourceGroup --query connectionString -o tsv)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to retrieve storage connection string for $StorageAccount."
}
if (-not $ConnectionString) {
    throw "Unable to retrieve storage connection string for $StorageAccount."
}

Write-Host "Setting app settings..."
Invoke-AzChecked @(
    "webapp", "config", "appsettings", "set",
    "--resource-group", $ResourceGroup,
    "--name", $WebAppName,
    "--settings",
    "SCM_DO_BUILD_DURING_DEPLOYMENT=true",
    "ENABLE_ORYX_BUILD=true",
    "WEBSITES_PORT=8501",
    "AZURE_STORAGE_CONNECTION_STRING=$ConnectionString",
    "AZURE_STORAGE_CONTAINER=$ContainerName",
    "AZURE_RESULTS_BLOB=$ResultsBlob",
    "LOCAL_RESULTS_CSV=$ResultsBlob"
)

Invoke-AzChecked @(
    "webapp", "config", "appsettings", "delete",
    "--resource-group", $ResourceGroup,
    "--name", $WebAppName,
    "--setting-names", "WEBSITE_RUN_FROM_PACKAGE"
)

Write-Host "Setting startup command..."
Invoke-AzChecked @(
    "webapp", "config", "set",
    "--resource-group", $ResourceGroup,
    "--name", $WebAppName,
    "--startup-file", "bash -lc 'python -m pip install --user -r requirements.txt && python -m streamlit run dashboard.py --server.address 0.0.0.0 --server.port 8501'"
)

Write-Host "Packaging dashboard..."
$ZipPath = "dashboard_deploy.zip"
if (Test-Path $ZipPath) {
    Remove-Item $ZipPath
}

Compress-Archive -Path dashboard.py,requirements.txt,.streamlit,ensah.png,uae.png -DestinationPath $ZipPath

Write-Host "Deploying dashboard..."
Invoke-AzChecked @("webapp", "deployment", "source", "config-zip", "--resource-group", $ResourceGroup, "--name", $WebAppName, "--src", $ZipPath)

Write-Host ""
Write-Host "Dashboard deployed."
Write-Host "Web App Name : $WebAppName"
Write-Host "Next step    : az webapp browse --resource-group $ResourceGroup --name $WebAppName"
