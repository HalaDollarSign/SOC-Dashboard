import streamlit as st
import pandas as pd
import time
import json
from src.detector import ThreatDetector
from src.parser import LogParser

# Configure Streamlit page settings and layout
st.set_page_config(
    page_title="SOC Threat Monitor Enterprise",
    page_icon="🛡️",
    layout="wide"
)

# Main dashboard header titles
st.title("🛡️ Enterprise SOC Dashboard & Threat Monitor")
st.markdown("Advanced real-time network traffic analysis, log ingestion, automated blacklisting, and incident reporting.")

# Initialize ThreatDetector instance within session state persistence
if 'detector' not in st.session_state:
    st.session_state.detector = ThreatDetector(threshold=5, time_window=10)

# Sidebar setup: Control & Ingestion Center
st.sidebar.header("🕹️ Control & Ingestion Center")

# Section 1: Manual traffic simulation controls
st.sidebar.subheader("Live Packet Simulator")
ip_input = st.sidebar.text_input("Source IP Address", value="192.168.1.50")

if st.sidebar.button("Simulate Request"):
    is_threat = st.session_state.detector.analyze_ip(ip_input)
    if is_threat:
        st.sidebar.error(f"🚨 ALERT! Anomaly / Attack from IP: {ip_input}!")
    else:
        st.sidebar.success(f"Traffic normal for IP: {ip_input}")

st.sidebar.markdown("---")

# Section 2: Batch log ingestion via file uploader
st.sidebar.subheader("Log Batch Ingestion")
uploaded_file = st.sidebar.file_uploader("Upload traffic log (CSV)", type=["csv"])

if uploaded_file is not None:
    logs_df = LogParser.parse_log_file(uploaded_file)
    if logs_df is not None:
        st.sidebar.success("Logs successfully ingested!")
        for _, row in logs_df.iterrows():
            st.session_state.detector.analyze_ip(row["source_ip"])
    else:
        st.sidebar.error("Invalid log format. Check columns.")

# Main dashboard analytical layout columns
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Monitored Sources Status")
    if st.session_state.detector.request_history:
        data = []
        for ip, timestamps in st.session_state.detector.request_history.items():
            status = "BLOCKED 🔴" if ip in st.session_state.detector.blacklist else "Active 🟢"
            data.append({"Source IP": ip, "Active Requests": len(timestamps), "Status": status})
        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True)
        
        # Analytics Volume Chart visualization
        st.subheader("📈 Traffic Volume per IP")
        chart_data = pd.DataFrame(
            {ip: len(ts) for ip, ts in st.session_state.detector.request_history.items()},
            index=["Requests"]
        ).T
        st.bar_chart(chart_data)
    else:
        st.info("No recorded traffic in the buffer. Use simulator or upload logs.")

with col2:
    st.subheader("⚙️ Detection Rules & Incident Response")
    st.metric(label="Alarm Threshold", value=f"{st.session_state.detector.threshold} requests")
    st.metric(label="Time Window", value=f"{st.session_state.detector.time_window} seconds")
    
    # Incident Response Action Center (Manual block / unblock control)
    st.markdown("### 🚫 Active Blacklist Management")
    block_target = st.text_input("Target IP for Action")
    
    c_block, c_unblock = st.columns(2)
    with c_block:
        if st.button("Block IP"):
            if block_target:
                st.session_state.detector.block_ip(block_target)
                st.success(f"IP {block_target} added to blacklist.")
                st.rerun()
    with c_unblock:
        if st.button("Unblock IP"):
            if block_target:
                st.session_state.detector.unblock_ip(block_target)
                st.success(f"IP {block_target} removed from blacklist.")
                st.rerun()

    # Display current active blacklist state
    if st.session_state.detector.blacklist:
        st.warning(f"Blacklisted IPs: {list(st.session_state.detector.blacklist)}")
    else:
        st.info("Blacklist is currently empty.")

    # Section 3: Incident Report Export
    st.markdown("### 📥 Incident Report Export")
    if st.session_state.detector.request_history:
        # Prepare report dictionary
        report_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "blacklisted_ips": list(st.session_state.detector.blacklist),
            "traffic_summary": {ip: len(ts) for ip, ts in st.session_state.detector.request_history.items()}
        }
        json_report = json.dumps(report_data, indent=4)
        
        st.download_button(
            label="Download Incident Report (JSON)",
            data=json_report,
            file_name="soc_incident_report.json",
            mime="application/json"
        )
    else:
        st.info("No data available for report export.")

    if st.button("Reset Alert History & Buffer"):
        st.session_state.detector.request_history.clear()
        st.session_state.detector.blacklist.clear()
        st.rerun()