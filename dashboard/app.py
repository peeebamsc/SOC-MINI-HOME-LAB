import requests
import pandas as pd
import streamlit as st
import os

API_URL = os.environ.get(
    "SOC_LAB_API_URL",
    "http://127.0.0.1:8010",
)

st.set_page_config(
    page_title="SOC//LAB",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SOC//LAB")
st.caption("Security Operations & Detection Engineering Platform")

st.sidebar.header("SOC Operations")
st.sidebar.info("Environment: Local Lab")
st.sidebar.write("API: 127.0.0.1:8010")
st.sidebar.success("Automatic refresh: Every 5 seconds")

if st.sidebar.button("Refresh Data"):
    st.rerun()


def fetch_data(endpoint):
    """Retrieve current data from the SOC//LAB API."""

    response = requests.get(
        f"{API_URL}{endpoint}",
        timeout=5,
    )

    response.raise_for_status()

    return response.json()


@st.fragment(run_every="5s")
def monitoring_dashboard():
    """Refresh security monitoring data every five seconds."""

    try:
        health = fetch_data("/health")
        stats = fetch_data("/stats")
        events = fetch_data("/events")
        alerts = fetch_data("/alerts")

    except (requests.RequestException, ValueError) as error:
        st.error(f"Unable to connect to SOC//LAB API: {error}")
        return

    st.success(f"API Status: {health['status']}")

    st.divider()

    st.subheader("Security Monitoring Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Events", stats["total_events"])
    col2.metric("Failed Logins", stats["failed_logins"])
    col3.metric("Successful Logins", stats["successful_logins"])
    col4.metric("Security Alerts", stats["total_alerts"])

    st.divider()

    st.subheader("Security Alerts")

    if alerts["alerts"]:
        alerts_df = pd.DataFrame(alerts["alerts"])

        st.dataframe(
            alerts_df,
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Alert Investigation")

        selected_ip = st.selectbox(
            "Select source IP",
            alerts_df["source_ip"].unique().tolist(),
            key="investigation_source_ip",
        )

        selected_alerts = alerts_df[
            alerts_df["source_ip"] == selected_ip
        ]

        st.dataframe(
            selected_alerts,
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info("No security alerts detected.")

    st.divider()

    st.subheader("Security Event Log")

    if events["events"]:
        events_df = pd.DataFrame(events["events"])

        st.dataframe(
            events_df,
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info("No security events available.")


monitoring_dashboard()

st.divider()

st.caption("SOC//LAB v1.0 — Synthetic security monitoring environment")