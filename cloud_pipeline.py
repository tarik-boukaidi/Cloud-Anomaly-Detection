"""
Cloud-first anomaly detection pipeline for the project.

Flow:
1. Load logs from Azure Blob Storage if available, otherwise generate synthetic logs.
2. Preprocess logs into features.
3. Load an existing model from Blob/local cache or train a fresh IsolationForest.
4. Score each log entry and mark anomalies.
5. Save the enriched results locally and optionally push them to Azure Blob Storage.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

try:
    from azure.storage.blob import BlobServiceClient
except ImportError:  # pragma: no cover - optional for local runs
    BlobServiceClient = None


DEFAULT_CONTAINER = "logs"
DEFAULT_RESULTS_BLOB = "detected_threats.csv"
DEFAULT_MODEL_BLOB = "models/isolation_forest.pkl"
DEFAULT_MODEL_CACHE = "model_cache.pkl"
DEFAULT_RESULTS_CSV = "detected_threats.csv"


FEATURE_COLUMNS = [
    "bytes_transferred",
    "hour",
    "day_of_week",
    "source_ip_0",
    "source_ip_1",
    "source_ip_2",
    "source_ip_3",
    "dest_ip_0",
    "dest_ip_1",
    "dest_ip_2",
    "dest_ip_3",
    "ua_length",
    "path_length",
    "failed_action",
    "critical_log",
]


@dataclass
class PipelineConfig:
    n_samples: int = 500
    use_azure_model: bool = True
    input_blob_name: Optional[str] = None
    output_blob_name: Optional[str] = DEFAULT_RESULTS_BLOB
    model_blob_name: Optional[str] = DEFAULT_MODEL_BLOB
    container_name: str = DEFAULT_CONTAINER
    azure_model_url: str = ""
    local_results_csv: str = DEFAULT_RESULTS_CSV
    local_model_cache: str = DEFAULT_MODEL_CACHE
    allow_local_fallback: bool = False


def get_env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def get_bool_env(name: str, default: bool = False) -> bool:
    return get_env(name, "true" if default else "false").lower() in {"1", "true", "yes", "y"}


def get_blob_service_client():
    connection_string = get_env("AZURE_STORAGE_CONNECTION_STRING")
    if not connection_string or BlobServiceClient is None:
        return None
    return BlobServiceClient.from_connection_string(connection_string)


def _container_name(default_name: str = DEFAULT_CONTAINER) -> str:
    return get_env("AZURE_STORAGE_CONTAINER", default_name)


def _download_blob_to_path(container_name: str, blob_name: str, local_path: str) -> bool:
    client = get_blob_service_client()
    if client is None:
        return False

    try:
        blob_client = client.get_blob_client(container=container_name, blob=blob_name)
        data = blob_client.download_blob().readall()
        Path(local_path).write_bytes(data)
        return True
    except Exception:
        return False


def _upload_path_to_blob(container_name: str, blob_name: str, local_path: str) -> bool:
    client = get_blob_service_client()
    if client is None:
        return False

    try:
        blob_client = client.get_blob_client(container=container_name, blob=blob_name)
        with open(local_path, "rb") as file_obj:
            blob_client.upload_blob(file_obj, overwrite=True)
        return True
    except Exception:
        return False


def _load_csv_from_blob(container_name: str, blob_name: str) -> Optional[pd.DataFrame]:
    client = get_blob_service_client()
    if client is None:
        return None

    try:
        blob_client = client.get_blob_client(container=container_name, blob=blob_name)
        content = blob_client.download_blob().readall().decode("utf-8")
        return pd.read_csv(StringIO(content))
    except Exception:
        return None


def generate_cloud_logs(n_samples: int = 500, anomaly_ratio: float = 0.15) -> pd.DataFrame:
    """Generate synthetic logs that look like cloud/security telemetry."""

    normal_paths = ["/api/users", "/api/data", "/login", "/health", "/api/orders"]
    suspicious_paths = ["/admin", "/ssh-login", "/api/heavy", "/debug"]
    normal_ips = [f"192.168.1.{i}" for i in range(50, 150)]
    suspicious_ips = [f"89.45.22.{i}" for i in range(1, 255)]
    suspicious_ips += [f"101.22.{i}.{j}" for i in range(1, 20) for j in range(1, 20)]

    base_time = datetime.utcnow()
    anomaly_count = max(1, int(n_samples * anomaly_ratio))
    rows = []

    def make_row(is_anomaly: bool) -> list:
        timestamp = base_time - timedelta(seconds=int(np.random.randint(0, 3600)))
        if is_anomaly:
            source_ip = np.random.choice(suspicious_ips)
            protocol = np.random.choice(["SSH", "FTP", "HTTPS"])
            action = np.random.choice(["failed", "dropped", "allowed"], p=[0.6, 0.3, 0.1])
            bytes_transferred = int(np.random.randint(100000, 500000))
            user_agent = np.random.choice(["Hydra", "BotNet", "Curl"])
            request_path = np.random.choice(suspicious_paths)
            log_type = "CRITICAL" if bytes_transferred > 300000 else "WARNING"
        else:
            source_ip = np.random.choice(normal_ips)
            protocol = np.random.choice(["HTTP", "HTTPS", "DNS"])
            action = np.random.choice(["allowed", "failed"], p=[0.9, 0.1])
            bytes_transferred = int(np.random.randint(1000, 100000))
            user_agent = np.random.choice(["Mozilla/5.0", "Chrome", "Curl"])
            request_path = np.random.choice(normal_paths)
            log_type = "INFO" if action == "allowed" else "WARNING"

        return [
            timestamp,
            source_ip,
            "10.0.0.1",
            protocol,
            action,
            bytes_transferred,
            log_type,
            user_agent,
            request_path,
        ]

    for _ in range(n_samples - anomaly_count):
        rows.append(make_row(False))
    for _ in range(anomaly_count):
        rows.append(make_row(True))

    df = pd.DataFrame(
        rows,
        columns=[
            "timestamp",
            "source_ip",
            "dest_ip",
            "protocol",
            "action",
            "bytes_transferred",
            "log_type",
            "user_agent",
            "request_path",
        ],
    )
    return df.sample(frac=1.0, random_state=42).reset_index(drop=True)


def preprocess_logs(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "source_ip", "dest_ip"])

    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    df["failed_action"] = (df["action"].astype(str).str.lower().isin(["failed", "dropped"])).astype(int)
    df["critical_log"] = (df["log_type"].astype(str).str.upper() == "CRITICAL").astype(int)
    df["ua_length"] = df["user_agent"].astype(str).str.len()
    df["path_length"] = df["request_path"].astype(str).str.len()

    def split_ip(ip: str) -> list[int]:
        parts = str(ip).split(".")
        parts = (parts + ["0", "0", "0", "0"])[:4]
        return [int(part) if str(part).isdigit() else 0 for part in parts]

    source_parts = df["source_ip"].apply(split_ip)
    dest_parts = df["dest_ip"].apply(split_ip)

    for idx in range(4):
        df[f"source_ip_{idx}"] = source_parts.apply(lambda parts, i=idx: parts[i])
        df[f"dest_ip_{idx}"] = dest_parts.apply(lambda parts, i=idx: parts[i])

    return df


def _load_model_from_blob_or_url(config: PipelineConfig) -> Optional[IsolationForest]:
    container_name = config.container_name

    if config.use_azure_model and config.model_blob_name:
        cache_path = config.local_model_cache
        if _download_blob_to_path(container_name, config.model_blob_name, cache_path):
            try:
                return joblib.load(cache_path)
            except Exception:
                pass

    if config.azure_model_url:
        try:
            import requests

            response = requests.get(config.azure_model_url, timeout=30)
            response.raise_for_status()
            Path(config.local_model_cache).write_bytes(response.content)
            return joblib.load(config.local_model_cache)
        except Exception:
            pass

    if config.allow_local_fallback:
        local_model_path = Path(config.local_model_cache)
        if local_model_path.exists():
            try:
                return joblib.load(local_model_path)
            except Exception:
                return None

    return None


def _fit_model(df: pd.DataFrame) -> IsolationForest:
    model = IsolationForest(contamination=0.15, random_state=42, n_estimators=100)
    model.fit(df[FEATURE_COLUMNS].fillna(0))
    return model


def score_logs(df: pd.DataFrame, config: PipelineConfig) -> pd.DataFrame:
    processed = df.copy()
    features = processed[FEATURE_COLUMNS].fillna(0)

    model = _load_model_from_blob_or_url(config)
    model_source = "azure"

    if model is None:
        model = _fit_model(processed)
        joblib.dump(model, config.local_model_cache)
        model_source = "local"

        if config.use_azure_model and config.model_blob_name:
            _upload_path_to_blob(config.container_name, config.model_blob_name, config.local_model_cache)

    processed["anomaly_flag"] = (model.predict(features) == -1).astype(int)
    processed["anomaly_score"] = (-model.decision_function(features)).round(6)
    processed["model_source"] = model_source
    return processed


def load_input_logs(config: PipelineConfig) -> pd.DataFrame:
    container_name = config.container_name

    if config.input_blob_name:
        blob_df = _load_csv_from_blob(container_name, config.input_blob_name)
        if blob_df is not None and not blob_df.empty:
            return blob_df

    return generate_cloud_logs(config.n_samples)


def finalize_results(df: pd.DataFrame) -> pd.DataFrame:
    output = df.copy()
    output["prediction"] = output["anomaly_flag"]
    output["is_anomaly"] = output["anomaly_flag"]
    output["hour"] = output["timestamp"].dt.hour
    output = output.sort_values(by=["prediction", "timestamp"], ascending=[False, False]).reset_index(drop=True)
    return output


def run_pipeline(
    n_samples: int = 500,
    use_azure: bool = True,
    azure_url: str = "",
    input_blob_name: Optional[str] = None,
    output_blob_name: Optional[str] = DEFAULT_RESULTS_BLOB,
    allow_local_fallback: Optional[bool] = None,
):
    if allow_local_fallback is None:
        allow_local_fallback = get_bool_env("ALLOW_LOCAL_FALLBACK", False)

    config = PipelineConfig(
        n_samples=n_samples,
        use_azure_model=use_azure,
        input_blob_name=input_blob_name,
        output_blob_name=output_blob_name,
        model_blob_name=get_env("AZURE_MODEL_BLOB", DEFAULT_MODEL_BLOB) or DEFAULT_MODEL_BLOB,
        container_name=_container_name(DEFAULT_CONTAINER),
        azure_model_url=azure_url,
        local_results_csv=get_env("LOCAL_RESULTS_CSV", DEFAULT_RESULTS_CSV) or DEFAULT_RESULTS_CSV,
        local_model_cache=get_env("LOCAL_MODEL_CACHE", DEFAULT_MODEL_CACHE) or DEFAULT_MODEL_CACHE,
        allow_local_fallback=allow_local_fallback,
    )

    print("=" * 60)
    print("CLOUD ANOMALY DETECTION PIPELINE")
    print("=" * 60)
    print("Loading input logs...")

    raw_df = load_input_logs(config)
    print(f"Loaded {len(raw_df)} rows")

    print("Preprocessing...")
    processed_df = preprocess_logs(raw_df)

    required_missing = [column for column in FEATURE_COLUMNS if column not in processed_df.columns]
    if required_missing:
        raise ValueError(f"Missing required feature columns: {', '.join(required_missing)}")

    print("Scoring logs...")
    scored_df = score_logs(processed_df, config)
    results_df = finalize_results(scored_df)

    print("Saving results locally...")
    results_df.to_csv(config.local_results_csv, index=False)

    if config.output_blob_name:
        uploaded = _upload_path_to_blob(config.container_name, config.output_blob_name, config.local_results_csv)
        print(f"Upload to Azure Blob: {'ok' if uploaded else 'failed'}")

    if not config.allow_local_fallback and Path(config.local_results_csv).exists():
        try:
            Path(config.local_results_csv).unlink()
        except Exception:
            pass

    anomaly_count = int(results_df["anomaly_flag"].sum())
    total_count = len(results_df)
    anomaly_rate = round((anomaly_count / total_count) * 100, 2) if total_count else 0.0

    print(f"Threats detected: {anomaly_count} / {total_count} ({anomaly_rate}%)")
    print("Pipeline finished.")

    return results_df


if __name__ == "__main__":
    azure_url = get_env("AZURE_MODEL_URL", "")
    input_blob = get_env("AZURE_INPUT_BLOB", "") or None
    output_blob = get_env("AZURE_OUTPUT_BLOB", DEFAULT_RESULTS_BLOB) or DEFAULT_RESULTS_BLOB
    use_azure = get_env("USE_AZURE_MODEL", "true").lower() in {"1", "true", "yes", "y"}

    print(f"Mode: {'AZURE' if use_azure else 'LOCAL'}")
    run_pipeline(
        n_samples=int(get_env("N_SAMPLES", "500")),
        use_azure=use_azure,
        azure_url=azure_url,
        input_blob_name=input_blob,
        output_blob_name=output_blob,
    )
