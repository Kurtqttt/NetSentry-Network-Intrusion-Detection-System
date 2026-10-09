# 🛡️ NetSentry — Network Intrusion Detection System

**A Python-powered network security monitoring, threat hunting, and incident management platform.**

NetSentry is a cybersecurity portfolio project designed to analyze network traffic, identify suspicious activity through rule-based detection, and support security investigations through an interactive dashboard.

Built with Python, Streamlit, Pandas, and Plotly, NetSentry demonstrates practical **blue-team operations, network traffic analysis, intrusion detection, and incident response workflows**.

---

## ✨ Key Features

| Feature                            | Description                                                                             |
| ---------------------------------- | --------------------------------------------------------------------------------------- |
| 🔍 **Network Traffic Analysis**    | Analyze structured CSV traffic and PCAP/PCAPNG captures.                                |
| 🚨 **Intrusion Detection Engine**  | Detect potential SYN scans, UDP scans, host sweeps, high packet rates, and SYN bursts.  |
| 📊 **Interactive Dashboard**       | Visualize traffic trends, protocol distributions, source IPs, and alerts.               |
| 🎯 **Threat Hunting**              | Filter traffic by IP address, protocol, destination port, packet size, and time range.  |
| 🗂️ **Incident Management**        | Track incident status, document investigation notes, and maintain an incident register. |
| 📥 **Data Export**                 | Export filtered traffic, detection alerts, and incident records to CSV.                 |
| 🧪 **Simulated Traffic Generator** | Generate repeatable test traffic to validate detection rules.                           |

## 🧰 Technology Stack

* 🐍 **Python** — Core application and detection logic
* 🐼 **Pandas** — Traffic data processing and analysis
* 📈 **Plotly** — Interactive visualizations
* 🌐 **Streamlit** — Web-based monitoring dashboard
* 🦈 **Wireshark / TShark** — Packet capture parsing

## 🏗️ Project Structure

```text
NetSentry/
├── src/
│   ├── netsentry.py          # Main dashboard
│   ├── detection_engine.py   # Rule-based detection engine
│   └── incident_manager.py   # Incident tracking and storage
├── tools/
│   └── generate_sample.py    # Simulated traffic generator
├── data/
│   └── sample_traffic.csv    # Generated test dataset
├── reports/                  # Report output directory
├── requirements.txt          # Python dependencies
├── .gitignore                # Excluded files and sensitive data
└── README.md
```

## ⚙️ Installation and Setup

### Prerequisites

* 💻 Windows 10 or Windows 11
* 🐍 A compatible Python installation
* 📦 Internet access for installing dependencies
* 🦈 Wireshark with TShark for PCAP/PCAPNG analysis

### 1. Clone the Repository

```cmd
git clone https://github.com/YOUR-USERNAME/NetSentry-Network-Intrusion-Detection.git
cd NetSentry-Network-Intrusion-Detection
```

Replace `YOUR-USERNAME` with the repository owner's GitHub username.

### 2. Create a Virtual Environment

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install Dependencies

```cmd
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Generate Sample Traffic

```cmd
python tools\generate_sample.py
```

The generator creates simulated traffic for testing detection rules without requiring a live network capture.

### 5. Launch NetSentry

```cmd
python -m streamlit run src\netsentry.py
```

Open the local dashboard URL shown in the terminal, then load the built-in sample traffic from the sidebar.

## 🚨 Detection Capabilities

NetSentry currently implements the following rule-based detection scenarios:

* **TCP SYN Port Scan:** Identifies a source probing multiple destination ports using initial TCP SYN packets.
* **UDP Port Scan:** Flags potential UDP probing across multiple destination ports.
* **Network Host Sweep:** Identifies a source contacting multiple destination IPs on the same port.
* **High Packet Rate:** Flags sources generating unusually high packet volumes within a one-minute window.
* **TCP SYN Burst:** Identifies a high volume of initial TCP connection attempts.

Detection thresholds are configurable in the source code. Multiple rules may trigger on the same traffic, so findings should be reviewed together.

## 🗂️ Incident Investigation Workflow

1. 📡 Load a supported traffic dataset.
2. 🔎 Review the detection alerts and supporting evidence.
3. 🎯 Filter traffic to investigate a source, destination, or protocol.
4. 📝 Record investigation notes and update the incident status.
5. 📥 Export relevant traffic, alerts, or incident records for further review.

## 🔐 Security and Responsible Use

NetSentry is an **educational security monitoring prototype**, not a replacement for a production IDS or SIEM.

* Detection alerts are indicators for investigation, not proof of malicious activity.
* False positives and false negatives are possible.
* Analyze only traffic you own or are explicitly authorized to inspect.
* Review datasets and exported reports for sensitive information before sharing them.
* Do not commit credentials, private investigation notes, or real packet captures to a public repository.

## 🚀 Future Enhancements

* 🧪 Automated unit and integration tests
* ⚙️ Configurable detection thresholds
* 🧠 Baseline-based anomaly detection
* 🌍 Optional threat-intelligence enrichment
* 📄 Enhanced incident reports
* 📋 Improved incident audit history
* 🔔 Configurable alert notifications

## 👨‍💻 About This Project

NetSentry was developed as a hands-on cybersecurity portfolio project to explore network monitoring, defensive security engineering, threat hunting, and incident response using Python.

**Focus areas:** Blue Team • Network Security • Intrusion Detection • Threat Hunting • Security Analytics

---

⭐ If you find this project useful for learning, feel free to star the repository and explore the code.
