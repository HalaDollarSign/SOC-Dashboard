# 🛡️ Enterprise SOC Dashboard & Threat Monitor

A modular, real-time Security Operations Center (SOC) dashboard and threat monitoring system built with Python and Streamlit. Designed for Blue Team operations, this application performs network traffic analysis, sliding-window rate limiting, automated/manual IP blacklisting, log ingestion, and incident reporting.

---

## 🚀 Key Features

* **Real-Time Traffic Analysis:** Monitors incoming source IPs and evaluates traffic patterns against dynamic threshold rules.
* **Sliding-Window Rate Limiter:** Protects endpoints from volumetric anomalies and DDoS attacks by analyzing request frequencies within a configurable time window.
* **Automated & Manual IP Blacklisting:** Automatically isolates sources that breach security thresholds and provides an Incident Response Action Center for manual block/unblock operations.
* **Log Ingestion & Validation:** Parses and validates network traffic log files (CSV format) to feed historical or batch data into the detection engine.
* **Incident Reporting:** Exports comprehensive security incident summaries and blacklist statuses to structured JSON reports.
* **Automated Testing:** Fully covered by unit tests using `pytest` to guarantee robust detection logic and schema validation.

---

## 🛠️ Tech Stack

* **Language:** Python 3.9+
* **Framework:** Streamlit (Web UI & Interactive Dashboard)
* **Data Processing:** Pandas
* **Testing:** Pytest

---

## 📂 Project Architecture

```text
SOC-Dashboard/
│
├── data/
│   └── sample_traffic.csv     # Sample network traffic logs for batch testing
│
├── src/
│   ├── __init__.py
│   ├── app.py                 # Main Streamlit dashboard application
│   ├── detector.py            # Threat detection, sliding window & blacklisting logic
│   └── parser.py              # Log ingestion and schema validation utility
│
├── tests/
│   └── test_detector.py       # Unit tests for detection and parsing logic
│
├── requirements.txt           # Project dependencies
└── README.md                  # Project documentation


⚙️ Installation & Running Locally
1.Clone the repository:
	git clone [https://github.com/HalaDollarSign/SOC-Dashboard.git](https://github.com/twoj-login/SOC-Dashboard.git)
	cd SOC-Dashboard
2.Install dependencies:
	pip install -r requirements.txt
3.Run unit tests:
	python -m pytest
4.Launch the SOC dashboard:
	python -m streamlit run src/app.py

	Usage Overview
Live Packet Simulator: Simulate incoming requests from specific IP addresses via the sidebar to test anomaly detection in real time.

Batch Ingestion: Upload the provided data/sample_traffic.csv file to ingest bulk logs and analyze volume spikes using integrated charts.

Incident Response: Manage active threats, inspect blocked sources, and download structured JSON incident reports for post-incident analysis.