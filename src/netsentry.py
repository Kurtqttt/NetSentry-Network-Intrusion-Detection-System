from detection_engine import detect_alerts
from incident_manager import export_incidents, update_incident

import io
import shutil
import subprocess
import tempfile
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_FILE = ROOT / "data" / "sample_traffic.csv"

FIELDS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "packet_length", "tcp_syn", "tcp_ack"
]


def normalize_data(df):
    missing = [column for column in FIELDS if column not in df.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))

    df = df[FIELDS].copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

    for column in ["src_port", "dst_port", "packet_length", "tcp_syn", "tcp_ack"]:
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0)

    df = df.dropna(subset=["timestamp", "src_ip", "dst_ip"])
    df["protocol"] = df["protocol"].astype(str).str.upper()
    return df


def find_tshark():
    found = shutil.which("tshark")
    if found:
        return found

    candidates = [
        Path("C:/Program Files/Wireshark/tshark.exe"),
        Path("C:/Program Files (x86)/Wireshark/tshark.exe"),
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    return None


def read_pcap(uploaded_file):
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError(
            "TShark was not found. Install Wireshark and ensure TShark is included."
        )

    suffix = Path(uploaded_file.name).suffix.lower()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(uploaded_file.getvalue())
        temp_path = Path(tmp.name)

    fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport",
        "tcp.dstport", "udp.srcport", "udp.dstport", "_ws.col.Protocol",
        "frame.len", "tcp.flags.syn", "tcp.flags.ack"
    ]

    try:
        command = [tshark, "-n", "-r", str(temp_path), "-T", "fields"]
        for field in fields:
            command.extend(["-e", field])
        command.extend(["-E", "header=y", "-E", "separator=,", "-E", "quote=d"])

        result = subprocess.run(
            command, capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "TShark could not read this capture.")

        raw = pd.read_csv(io.StringIO(result.stdout))
        if raw.empty:
            raise ValueError("No packets were found in this capture.")

        raw.columns = fields
        raw["timestamp"] = pd.to_datetime(
            pd.to_numeric(raw["frame.time_epoch"], errors="coerce"),
            unit="s", utc=True, errors="coerce"
        )
        raw["src_ip"] = raw["ip.src"]
        raw["dst_ip"] = raw["ip.dst"]
        raw["src_port"] = raw["tcp.srcport"].fillna(raw["udp.srcport"])
        raw["dst_port"] = raw["tcp.dstport"].fillna(raw["udp.dstport"])
        raw["protocol"] = raw["_ws.col.Protocol"].fillna("OTHER")
        raw["packet_length"] = raw["frame.len"]
        raw["tcp_syn"] = raw["tcp.flags.syn"].fillna(0)
        raw["tcp_ack"] = raw["tcp.flags.ack"].fillna(0)

        return normalize_data(raw[FIELDS])
    finally:
        temp_path.unlink(missing_ok=True)




st.set_page_config(page_title="NetSentry IDS", page_icon="🛡️", layout="wide")
st.title("🛡️ NetSentry")
st.caption("Network traffic analysis and rule-based intrusion indicators")

with st.sidebar:
    st.header("Traffic input")
    st.write("Load simulated data or analyze a CSV/PCAP capture.")
    use_sample = st.button("Load built-in sample traffic", use_container_width=True)
    uploaded = st.file_uploader(
        "Upload traffic file",
        type=["csv", "pcap", "pcapng"]
    )

if use_sample:
    st.session_state["use_sample"] = True

df = None
error = None

try:
    if uploaded is not None:
        if uploaded.name.lower().endswith(".csv"):
            df = normalize_data(pd.read_csv(uploaded))
        else:
            df = read_pcap(uploaded)
        st.session_state["use_sample"] = False
    elif st.session_state.get("use_sample", False):
        if not SAMPLE_FILE.exists():
            st.warning("Sample file not found. Run: python tools\\generate_sample.py")
        else:
            df = normalize_data(pd.read_csv(SAMPLE_FILE))
except Exception as exc:
    error = str(exc)

if error:
    st.error(error)

if df is None:
    st.info("Choose **Load built-in sample traffic** in the sidebar to begin.")
    st.markdown(
        "### Detection rules\n"
        "- **Possible SYN port scan:** at least 10 unique destination ports "
        "from SYN packets without ACK.\n"
        "- **High packet rate:** at least 30 packets from a source in one minute.\n"
    )
    st.stop()

alerts = detect_alerts(df)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Packets analyzed", f"{len(df):,}")
col2.metric("Unique sources", df["src_ip"].nunique())
col3.metric("Unique destinations", df["dst_ip"].nunique())
col4.metric("Alerts", len(alerts))

st.subheader("Traffic timeline")
timeline = df.copy()
timeline["time_bucket"] = timeline["timestamp"].dt.floor("min")
timeline_counts = (
    timeline.groupby(["time_bucket", "protocol"])
    .size().reset_index(name="packets")
)
if not timeline_counts.empty:
    fig = px.line(
        timeline_counts, x="time_bucket", y="packets", color="protocol",
        markers=True, title="Packets per minute by protocol"
    )
    st.plotly_chart(fig, use_container_width=True)

left, right = st.columns(2)
with left:
    st.subheader("Protocol distribution")
    protocol_counts = df["protocol"].value_counts().rename_axis("protocol").reset_index(name="packets")
    st.plotly_chart(
        px.pie(protocol_counts, names="protocol", values="packets", hole=0.4),
        use_container_width=True
    )
with right:
    st.subheader("Top source IPs")
    source_counts = df["src_ip"].value_counts().head(10).rename_axis("source").reset_index(name="packets")
    st.plotly_chart(
        px.bar(source_counts, x="source", y="packets"),
        use_container_width=True
    )

st.subheader("Detection alerts")
if alerts.empty:
    st.success("No configured detection rules were triggered.")
else:
    st.dataframe(alerts, use_container_width=True, hide_index=True)
    st.download_button(
        "Download alerts CSV",
        alerts.to_csv(index=False).encode("utf-8"),
        file_name="netsentry_alerts.csv",
        mime="text/csv"
    )


st.subheader("Threat Hunting")

with st.expander("Search and filter network events", expanded=True):
    search_ip = st.text_input(
        "Source or destination IP contains",
        placeholder="Example: 192.0.2.10",
    )

    filter_col1, filter_col2, filter_col3 = st.columns(3)

    with filter_col1:
        available_protocols = sorted(df["protocol"].astype(str).unique())
        hunt_protocols = st.multiselect(
            "Protocols",
            available_protocols,
            default=available_protocols,
        )

    with filter_col2:
        min_port, max_port = st.slider(
            "Destination port range",
            min_value=0,
            max_value=65535,
            value=(0, 65535),
        )

    with filter_col3:
        min_packet_size = st.number_input(
            "Minimum packet size (bytes)",
            min_value=0,
            value=0,
            step=100,
        )

    start_time = df["timestamp"].min()
    end_time = df["timestamp"].max()

    if pd.notna(start_time) and pd.notna(end_time):
        time_range = st.slider(
            "Time range (UTC)",
            min_value=start_time.to_pydatetime(),
            max_value=end_time.to_pydatetime(),
            value=(
                start_time.to_pydatetime(),
                end_time.to_pydatetime(),
            ),
            format="HH:mm:ss",
        )
    else:
        time_range = None

filtered = df.copy()

if search_ip.strip():
    query = search_ip.strip()
    filtered = filtered[
        filtered["src_ip"].astype(str).str.contains(query, regex=False, na=False)
        | filtered["dst_ip"].astype(str).str.contains(query, regex=False, na=False)
    ]

filtered = filtered[
    filtered["protocol"].astype(str).isin(hunt_protocols)
    & filtered["dst_port"].between(min_port, max_port)
    & (filtered["packet_length"] >= min_packet_size)
]

if time_range is not None:
    start, end = time_range
    filtered = filtered[
        filtered["timestamp"].between(
            pd.Timestamp(start), pd.Timestamp(end)
        )
    ]

st.metric("Matching packets", f"{len(filtered):,}")
st.dataframe(filtered, use_container_width=True, hide_index=True)

st.download_button(
    "Export matching events",
    filtered.to_csv(index=False).encode("utf-8"),
    file_name="netsentry_hunt_results.csv",
    mime="text/csv",
)

st.caption(
    "NetSentry is a learning and triage tool. Alerts are indicators, not proof "
    "of malicious activity. Only inspect traffic you are authorized to analyze."
)


st.divider()
st.subheader("Incident Management")

if alerts.empty:
    st.info("No alerts are currently available to manage.")
else:
    alert_options = {
        f"{row['rule_id']} | {row['severity']} | {row['source']} | {row['alert']}":
        row.to_dict()
        for _, row in alerts.iterrows()
    }

    selected_label = st.selectbox(
        "Select an alert to investigate",
        options=list(alert_options.keys()),
    )
    selected_alert = alert_options[selected_label]

    saved_incidents = {
        "|".join([
            str(item.get("rule_id", "")),
            str(item.get("source", "")),
            str(item.get("destination", "")),
            str(item.get("evidence", "")),
        ]): item
        for item in export_incidents()
    }

    incident_key = "|".join([
        str(selected_alert.get("rule_id", "")),
        str(selected_alert.get("source", "")),
        str(selected_alert.get("destination", "")),
        str(selected_alert.get("evidence", "")),
    ])
    previous = saved_incidents.get(incident_key, {})

    st.write("**Evidence:**", selected_alert.get("evidence", ""))
    st.write("**Destination:**", selected_alert.get("destination", ""))

    status_options = ["Open", "Investigating", "Resolved", "False Positive"]
    previous_status = previous.get("status", "Open")
    status_index = (
        status_options.index(previous_status)
        if previous_status in status_options else 0
    )

    with st.form("incident_update_form"):
        status = st.selectbox(
            "Incident status",
            status_options,
            index=status_index,
        )
        notes = st.text_area(
            "Investigation notes",
            value=previous.get("notes", ""),
            placeholder="Record what you checked and what you found...",
        )
        submitted = st.form_submit_button("Save incident")

        if submitted:
            update_incident(selected_alert, status, notes)
            st.success("Incident details saved.")
            st.rerun()

all_incidents = export_incidents()
st.write(f"Saved incidents: **{len(all_incidents)}**")

if all_incidents:
    st.dataframe(
        pd.DataFrame(all_incidents),
        use_container_width=True,
        hide_index=True,
    )
    incident_csv = pd.DataFrame(all_incidents).to_csv(index=False).encode("utf-8")
    st.download_button(
        "Export incident register",
        incident_csv,
        file_name="netsentry_incidents.csv",
        mime="text/csv",
    )