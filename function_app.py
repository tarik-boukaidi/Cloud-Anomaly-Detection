import logging
import os

import azure.functions as func

from pipeline import run_pipeline

app = func.FunctionApp()


@app.timer_trigger(schedule="0 */5 * * * *", arg_name="mytimer", run_on_startup=False, use_monitor=False)
def cloud_anomaly_pipeline(mytimer: func.TimerRequest) -> None:
    if mytimer.past_due:
        logging.info("Timer is past due.")

    logging.info("Starting cloud anomaly detection pipeline.")

    azure_url = os.getenv("AZURE_MODEL_URL", "")
    input_blob = os.getenv("AZURE_INPUT_BLOB", "") or None
    output_blob = os.getenv("AZURE_OUTPUT_BLOB", "detected_threats.csv")
    use_azure = os.getenv("USE_AZURE_MODEL", "true").lower() in {"1", "true", "yes", "y"}

    run_pipeline(
        n_samples=500,
        use_azure=use_azure,
        azure_url=azure_url,
        input_blob_name=input_blob,
        output_blob_name=output_blob,
        allow_local_fallback=False,
    )

    logging.info("Cloud anomaly detection pipeline completed.")
