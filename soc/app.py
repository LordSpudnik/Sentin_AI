import os
import time
import pandas as pd
import streamlit as st

from simulator import SentinAITrafficSimulator


st.set_page_config(
    page_title="SentinAI SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)


@st.cache_resource
def load_simulator():
    return SentinAITrafficSimulator(
        dataset_path=os.path.join("CNS Dataset", "Processed", "processed_network_dataset.csv"),
        model_path=os.path.join("models", "best_model.pkl"),
        log_path=os.path.join("soc", "alerts_log.csv"),
        sleep_seconds=0.2
    )


def compute_metrics(df: pd.DataFrame):
    total_events = len(df)
    ddos_count = int((df["predicted_label"] == "DDoS").sum()) if not df.empty else 0
    benign_count = int((df["predicted_label"] == "BENIGN").sum()) if not df.empty else 0
    critical_count = int((df["severity"] == "CRITICAL").sum()) if not df.empty else 0

    return total_events, ddos_count, benign_count, critical_count


def main():
    st.title("🛡️ SentinAI: SOC Analyst Dashboard")
    st.markdown("**Anomaly-Based Network Intrusion Detection System**")

    simulator = load_simulator()

    if "alerts_df" not in st.session_state:
        st.session_state.alerts_df = pd.DataFrame()

    if "stream_started" not in st.session_state:
        st.session_state.stream_started = False

    st.sidebar.header("Simulation Controls")
    num_events = st.sidebar.slider("Number of events to simulate", 5, 100, 20, 5)
    auto_refresh = st.sidebar.checkbox("Stream events with delay", value=True)
    delay = st.sidebar.slider("Delay between events (seconds)", 0.0, 2.0, 0.2, 0.1)

    col_btn1, col_btn2, col_btn3 = st.sidebar.columns(3)

    with col_btn1:
        start_clicked = st.button("▶ Start")

    with col_btn2:
        batch_clicked = st.button("⚡ Batch")

    with col_btn3:
        clear_clicked = st.button("🗑 Clear")

    if clear_clicked:
        st.session_state.alerts_df = pd.DataFrame()
        st.success("Dashboard alerts cleared.")

    if batch_clicked:
        batch_df = simulator.simulate_batch(
            num_events=num_events,
            shuffle=True,
            log_events=True
        )
        st.session_state.alerts_df = batch_df
        st.success(f"Loaded {len(batch_df)} events in batch mode.")

    if start_clicked:
        st.session_state.stream_started = True

    if st.session_state.stream_started:
        alerts = []

        placeholder_metrics = st.empty()
        placeholder_table = st.empty()
        placeholder_charts = st.empty()

        for event in simulator.stream_events(
            num_events=num_events,
            shuffle=True,
            log_events=True,
            delay=delay if auto_refresh else 0
        ):
            alerts.append(event)
            current_df = pd.DataFrame(alerts)
            st.session_state.alerts_df = current_df

            total_events, ddos_count, benign_count, critical_count = compute_metrics(current_df)

            with placeholder_metrics.container():
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total Events", total_events)
                c2.metric("DDoS Alerts", ddos_count)
                c3.metric("Benign Traffic", benign_count)
                c4.metric("Critical Alerts", critical_count)

            with placeholder_table.container():
                st.subheader("Live Alerts")
                st.dataframe(
                    current_df[[
                        "timestamp",
                        "attacker_ip",
                        "target_ip",
                        "target_port",
                        "predicted_label",
                        "confidence",
                        "severity",
                        "recommended_action",
                        "true_label"
                    ]],
                    use_container_width=True,
                    hide_index=True
                )

            with placeholder_charts.container():
                st.subheader("Alert Analytics")

                col1, col2 = st.columns(2)

                with col1:
                    label_counts = current_df["predicted_label"].value_counts()
                    st.bar_chart(label_counts)

                with col2:
                    severity_counts = current_df["severity"].value_counts()
                    st.bar_chart(severity_counts)

                if not current_df.empty:
                    port_counts = current_df["target_port"].value_counts().head(10)
                    st.subheader("Top Target Ports")
                    st.bar_chart(port_counts)

        st.session_state.stream_started = False
        st.success("Streaming complete.")

    if not st.session_state.alerts_df.empty:
        df = st.session_state.alerts_df.copy()

        st.markdown("---")
        st.subheader("Current Dashboard Snapshot")

        total_events, ddos_count, benign_count, critical_count = compute_metrics(df)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Events", total_events)
        c2.metric("DDoS Alerts", ddos_count)
        c3.metric("Benign Traffic", benign_count)
        c4.metric("Critical Alerts", critical_count)

        st.subheader("Alerts Table")
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.subheader("Model Performance Snapshot in Current Stream")
        if "true_label" in df.columns:
            correct = (df["predicted_label"] == df["true_label"]).sum()
            accuracy = correct / len(df) if len(df) > 0 else 0
            st.write(f"**Correct predictions in current stream:** {correct} / {len(df)}")
            st.write(f"**Stream accuracy snapshot:** {accuracy:.2%}")

        st.subheader("Incident Response Recommendations")
        critical_df = df[df["severity"] == "CRITICAL"]

        if not critical_df.empty:
            st.error("Critical incident(s) detected.")
            st.dataframe(
                critical_df[[
                    "timestamp",
                    "attacker_ip",
                    "target_ip",
                    "target_port",
                    "predicted_label",
                    "confidence",
                    "recommended_action"
                ]],
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No critical incidents in the current stream.")


if __name__ == "__main__":
    main()