\# NetSentry — Network Intrusion Detection System



NetSentry is a Python-based cybersecurity portfolio project for network traffic analysis, rule-based intrusion detection, threat hunting, and incident management.



\## Features



\* \*\*Network traffic analysis:\*\* Analyze CSV datasets and PCAP/PCAPNG captures.

\* \*\*Detection engine:\*\* Identify potential TCP SYN scans, UDP port scans, network host sweeps, high packet rates, and SYN bursts.

\* \*\*Interactive dashboard:\*\* Visualize traffic timelines, protocols, sources, and alerts.

\* \*\*Threat hunting:\*\* Filter events by IP address, protocol, destination port, packet size, and time range.

\* \*\*Incident management:\*\* Record investigation notes and manage incident statuses.

\* \*\*Data exports:\*\* Download filtered traffic, alerts, and incident records as CSV.

\* \*\*Sample dataset:\*\* Generate simulated traffic for repeatable testing.



\## Technology Stack



\* Python

\* Pandas

\* Streamlit

\* Plotly

\* Wireshark/TShark for packet capture parsing



\## Installation



Requires Windows and a compatible Python installation.



```cmd

python -m venv .venv

.venv\\Scripts\\activate

python -m pip install -r requirements.txt

```



\## Run the Project



Generate sample traffic:



```cmd

python tools\\generate\_sample.py

```



Launch the dashboard:



```cmd

python -m streamlit run src\\netsentry.py

```



Use the dashboard sidebar to load the sample traffic or upload a supported dataset.



\## Detection Rules



\* Possible TCP SYN port scan

\* Possible UDP port scan

\* Possible network host sweep

\* High packet rate

\* Large TCP SYN burst



Detection thresholds are configurable. Multiple alerts may describe the same underlying activity.



\## Project Structure



```text

NetSentry/

├── src/

│   ├── netsentry.py

│   ├── detection\_engine.py

│   └── incident\_manager.py

├── tools/

│   └── generate\_sample.py

├── data/

├── reports/

├── requirements.txt

├── .gitignore

└── README.md

```



\## Limitations and Responsible Use



NetSentry is an educational, rule-based prototype. Alerts are indicators requiring investigation, not proof of an attack. Packet capture analysis requires Wireshark/TShark.



Only analyze traffic you own or have permission to inspect. Do not publish sensitive packet captures, credentials, or private incident notes.



\## Future Improvements



\* Unit tests and automated testing

\* Persistent incident audit history

\* Configurable detection thresholds

\* Threat-intelligence integrations

\* Improved incident report generation



\## Author



Developed as a cybersecurity and blue-team portfolio project.



