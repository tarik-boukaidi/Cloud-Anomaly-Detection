# Azure Deployment

This project is prepared for two separate Azure deployments:

1. The anomaly detection pipeline as an Azure Functions timer trigger.
2. The Streamlit dashboard as a containerized web app.

## 1. Pipeline on Azure Functions

### Prerequisites

- Azure CLI installed
- Azure Functions Core Tools v4 installed
- An Azure Storage Account
- A Function App created in Azure

### Local setup

Create a local settings file from the example:

```bash
copy local.settings.json.example local.settings.json
```

Fill the values with your Azure storage connection string and blob names.

### Deploy

```bash
az login
func azure functionapp publish <function-app-name>
```

## 2. Dashboard on Azure

The dashboard is ready to run as a container.
If Docker is not installed on your machine, you can still deploy it because Azure will build the image for you.

### Option A: Build locally with Docker

```bash
docker build -t cloud-anomaly-dashboard .
```

### Run locally

```bash
docker run -p 8501:8501 cloud-anomaly-dashboard
```

### Option B: Build and deploy entirely on Azure

Use Azure Container Apps and Azure Container Registry.

Run:

```powershell
.\deploy_dashboard_containerapps.ps1
```

The container starts with:

```bash
streamlit run dashboard.py --server.address=0.0.0.0 --server.port=8501
```

### Environment variables for the dashboard

- `AZURE_STORAGE_CONNECTION_STRING`
- `AZURE_STORAGE_CONTAINER`
- `AZURE_RESULTS_BLOB`
- `LOCAL_RESULTS_CSV`
- `AZURE_MODEL_URL` if you want the dashboard to reuse the same model location logic

## 3. Environment variables for the pipeline

- `AZURE_STORAGE_CONNECTION_STRING`
- `AZURE_STORAGE_CONTAINER`
- `AZURE_MODEL_BLOB`
- `AZURE_RESULTS_BLOB`
- `AZURE_INPUT_BLOB`
- `AZURE_MODEL_URL`
- `USE_AZURE_MODEL`

## 4. What the architecture now does

- Logs are stored in Azure Blob Storage.
- The pipeline runs in Azure Functions.
- The model is loaded from Azure Blob Storage.
- The results are written back to Azure Blob Storage.
- The dashboard reads the results and visualizes them.
