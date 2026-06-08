import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

st.set_page_config(
    page_title="Détection d’anomalies dans le Cloud par IA",
    layout="wide",
    page_icon="ensah.png"
)

st_autorefresh(interval=3000, key="refresh")

st.markdown("""
<style>

/* GLOBAL */
html, body {
    background-color: #ffffff !important;
}

/* TITLE */
h1 {
    color: #0b3d91;
    font-weight: 700;
}

/* CARDS */
.card {
    background: linear-gradient(135deg, #f5f9ff, #e3f0ff);
    padding: 20px;
    border-radius: 12px;
    box-shadow: 0px 4px 12px rgba(0,0,0,0.08);
}

/* METRICS */
[data-testid="metric-container"] {
    background: linear-gradient(135deg, #e8f1ff, #ffffff);
    border-left: 6px solid #0b3d91;
    border-radius: 10px;
    padding: 15px;
}

/* SECTIONS */
.section {
    margin-top: 25px;
}

/* TABLE */
.dataframe {
    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)

col1, col2, col3 = st.columns([1,6,1])

with col1:
    st.image("ensah.png", width=90)

with col2:
    st.markdown(
        "<h1 style='text-align:center;'>Détection d’anomalies dans le Cloud par IA</h1>",
        unsafe_allow_html=True
    )

with col3:
    st.image("uae.png", width=90)

st.markdown("---")

try:
    df = pd.read_csv("detected_threats.csv")
except:
    st.warning("Aucune donnée disponible")
    st.stop()

if df.empty:
    st.warning("Aucune menace détectée")
    st.stop()

df = df.sort_values(by="timestamp", ascending=False)

c1, c2, c3, c4 = st.columns(4)

c1.metric("Menaces totales", len(df))
c2.metric("IP attaquantes", df['source_ip'].nunique())
c3.metric("Protocoles", df['protocol'].nunique())
c4.metric("Endpoints ciblés", df['request_path'].nunique())

left, right = st.columns([2,1])

with left:

    st.markdown('<div class="section">', unsafe_allow_html=True)
    st.subheader("Journal des menaces")

    st.dataframe(df.head(100), width='stretch')

    st.subheader("Volume de données suspect")

    fig1 = px.histogram(
        df,
        x="bytes_transferred",
        nbins=25,
        color_discrete_sequence=["#0b3d91"]
    )

    fig1.update_layout(
        plot_bgcolor="white",
        paper_bgcolor="white"
    )

    st.plotly_chart(fig1, width='stretch')

with right:

    st.subheader("Répartition des protocoles")

    fig2 = px.pie(
        df,
        names="protocol",
        color_discrete_sequence=["#0b3d91", "#4a90e2", "#87c1ff"]
    )

    fig2.update_traces(textfont_color='black')
    fig2.update_layout(
        paper_bgcolor="white"
    )

    st.plotly_chart(fig2, width='stretch')

    st.subheader("Top IP attaquantes")

    fig3 = px.bar(
        df['source_ip'].value_counts().head(10),
        color_discrete_sequence=["#1f77b4"]
    )

    fig3.update_layout(
        plot_bgcolor="white",
        paper_bgcolor="white"
    )

    st.plotly_chart(fig3, width='stretch')

st.markdown("---")

col1, col2 = st.columns(2)

with col1:

    st.subheader("Endpoints ciblés")

    fig4 = px.bar(
        df['request_path'].value_counts(),
        color_discrete_sequence=["#0b3d91"]
    )

    fig4.update_layout(
        plot_bgcolor="white",
        paper_bgcolor="white"
    )

    st.plotly_chart(fig4, width='stretch')

with col2:

    st.subheader("User Agents suspects")

    fig5 = px.bar(
        df['user_agent'].value_counts().head(10),
        color_discrete_sequence=["#4a90e2"]
    )

    fig5.update_layout(
        plot_bgcolor="white",
        paper_bgcolor="white"
    )

    st.plotly_chart(fig5, width='stretch')

st.markdown("---")

st.subheader("Activité des attaques par heure")

fig6 = px.line(
    df.groupby("hour").size().reset_index(name="count"),
    x="hour",
    y="count",
    markers=True,
    color_discrete_sequence=["#0b3d91"]
)

fig6.update_layout(
    plot_bgcolor="white",
    paper_bgcolor="white"
)

st.plotly_chart(fig6, width='stretch')


st.markdown("---")
st.markdown(
    "<center style='color:#0b3d91;'>Plateforme de détection d’anomalies basée sur l’IA - Projet Cloud & Cybersécurité</center>",
    unsafe_allow_html=True
)