# Cloud Anomaly Detection Dashboard

A machine learning project for detecting anomalies in cloud environments, with an interactive Streamlit dashboard for monitoring and visualizing detected threats.

## Project Overview

Cloud Anomaly Detection Dashboard is an AI-based project designed to identify abnormal behavior in cloud/system activity, including:

- Unusual resource or traffic patterns
- Suspicious source IP activity
- Failed access attempts
- Abnormal protocol usage
- Potential security anomalies

The project uses a trained machine learning model to detect anomalies, and the model was deployed on Microsoft Azure Cloud to make the solution more scalable and closer to a real-world cloud environment.

## Key Features

- Machine learning-based anomaly detection
- Interactive dashboard built with Streamlit
- Visualization of detected threats and anomalies
- Microsoft Azure cloud deployment for the ML model
- Auto-refresh dashboard for updated monitoring
- Analysis of source IPs, protocols, endpoints, user agents, and suspicious activity

## Dashboard

The dashboard displays:

- Total detected threats
- Number of attacking source IPs
- Protocol distribution
- Targeted endpoints
- Suspicious user agents
- Attack activity by hour
- Detected anomaly records from cloud/system logs

## Tech Stack

- Python
- Streamlit
- Pandas
- Plotly
- Machine Learning model saved as `.pkl`
- Microsoft Azure Cloud
- CSV-based anomaly/threat data

## Repository Structure

```text
Cloud-Anomaly-Detection/
├── dashboard.py
├── detected_threats.csv
├── downloaded_model.pkl
├── ensah.png
└── uae.png
