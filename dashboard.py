import os

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    from azure.storage.blob import BlobServiceClient
except ImportError:  # pragma: no cover
    BlobServiceClient = None


st.set_page_config(
    page_title="Detection d'anomalies dans le Cloud par IA",
    layout="wide",
    page_icon="ensah.png",
)

st_autorefresh(interval=3000, key="refresh")


def get_env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def load_csv_from_azure_or_local():
    connection_string = get_env("AZURE_STORAGE_CONNECTION_STRING")
    container_name = get_env("AZURE_STORAGE_CONTAINER")
    results_blob = get_env("AZURE_RESULTS_BLOB")
    azure_csv_url = get_env("AZURE_RESULTS_URL")
    local_csv = get_env("LOCAL_RESULTS_CSV", "detected_threats.csv")
    allow_local_fallback = get_env("ALLOW_LOCAL_FALLBACK", "false").lower() in {"1", "true", "yes", "y"}

    if connection_string and container_name and results_blob and BlobServiceClient is not None:
        try:
            service_client = BlobServiceClient.from_connection_string(connection_string)
            blob_client = service_client.get_blob_client(container=container_name, blob=results_blob)
            from io import StringIO

            data = blob_client.download_blob().readall().decode("utf-8")
            return pd.read_csv(StringIO(data))
        except Exception:
            pass

    if azure_csv_url and requests is not None:
        try:
            response = requests.get(azure_csv_url, timeout=30)
            response.raise_for_status()
            from io import StringIO

            return pd.read_csv(StringIO(response.text))
        except Exception:
            pass

    if allow_local_fallback:
        return pd.read_csv(local_csv)

    raise RuntimeError("Azure results are not available and local fallback is disabled.")


st.markdown(
    """
<style>
html, body {
    background-color: #ffffff !important;
}
h1 {
    color: #0b3d91;
    font-weight: 700;
}
.card {
    background: linear-gradient(135deg, #f5f9ff, #e3f0ff);
    padding: 20px;
    border-radius: 12px;
    box-shadow: 0px 4px 12px rgba(0,0,0,0.08);
}
[data-testid="metric-container"] {
    background: linear-gradient(135deg, #e8f1ff, #ffffff);
    border-left: 6px solid #0b3d91;
    border-radius: 10px;
    padding: 15px;
}
.section {
    margin-top: 25px;
}
.dataframe {
    border-radius: 10px;
}
</style>
""",
    unsafe_allow_html=True,
)

col1, col2, col3 = st.columns([1, 6, 1])

with col1:
    st.image("ensah.png", width=90)

with col2:
    st.markdown(
        "<h1 style='text-align:center;'>Detection d'anomalies dans le Cloud par IA</h1>",
        unsafe_allow_html=True,
    )

with col3:
    st.image("uae.png", width=90)

st.markdown("---")

try:
    df = load_csv_from_azure_or_local()
except Exception:
    st.warning("Aucune donnee disponible")
    st.stop()

if df.empty:
    st.warning("Aucune menace detectee")
    st.stop()

df = df.sort_values(by="timestamp", ascending=False)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Menaces totales", len(df))
c2.metric("IP attaquantes", df["source_ip"].nunique())
c3.metric("Protocoles", df["protocol"].nunique())
c4.metric("Endpoints cibles", df["request_path"].nunique())

left, right = st.columns([2, 1])

with left:
    st.markdown('<div class="section">', unsafe_allow_html=True)
    st.subheader("Journal des menaces")
    st.dataframe(df.head(100), width="stretch")

    st.subheader("Volume de donnees suspect")
    fig1 = px.histogram(
        df,
        x="bytes_transferred",
        nbins=25,
        color_discrete_sequence=["#0b3d91"],
    )
    fig1.update_layout(plot_bgcolor="white", paper_bgcolor="white")
    st.plotly_chart(fig1, width="stretch")

with right:
    st.subheader("Repartition des protocoles")
    fig2 = px.pie(
        df,
        names="protocol",
        color_discrete_sequence=["#0b3d91", "#4a90e2", "#87c1ff"],
    )
    fig2.update_traces(textfont_color="black")
    fig2.update_layout(paper_bgcolor="white")
    st.plotly_chart(fig2, width="stretch")

    st.subheader("Top IP attaquantes")
    fig3 = px.bar(
        df["source_ip"].value_counts().head(10),
        color_discrete_sequence=["#1f77b4"],
    )
    fig3.update_layout(plot_bgcolor="white", paper_bgcolor="white")
    st.plotly_chart(fig3, width="stretch")

st.markdown("---")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Endpoints cibles")
    fig4 = px.bar(
        df["request_path"].value_counts(),
        color_discrete_sequence=["#0b3d91"],
    )
    fig4.update_layout(plot_bgcolor="white", paper_bgcolor="white")
    st.plotly_chart(fig4, width="stretch")

with col2:
    st.subheader("User Agents suspects")
    fig5 = px.bar(
        df["user_agent"].value_counts().head(10),
        color_discrete_sequence=["#4a90e2"],
    )
    fig5.update_layout(plot_bgcolor="white", paper_bgcolor="white")
    st.plotly_chart(fig5, width="stretch")

st.markdown("---")
st.subheader("Activite des attaques par heure")

fig6 = px.line(
    df.groupby("hour").size().reset_index(name="count"),
    x="hour",
    y="count",
    markers=True,
    color_discrete_sequence=["#0b3d91"],
)
fig6.update_layout(plot_bgcolor="white", paper_bgcolor="white")
st.plotly_chart(fig6, width="stretch")

st.markdown("---")
st.markdown(
    "<center style='color:#0b3d91;'>Plateforme de detection d'anomalies basee sur l'IA - Projet Cloud & Cybersecurite</center>",
    unsafe_allow_html=True,
)
