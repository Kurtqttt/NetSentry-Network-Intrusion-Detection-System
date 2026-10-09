
import pandas as pd

# Educational detection thresholds; tune these for the network being monitored.
SYN_SCAN_PORTS = 10
UDP_SCAN_PORTS = 10
PORT_SWEEP_HOSTS = 10
HIGH_PACKET_RATE = 30
SYN_BURST_COUNT = 20

ALERT_COLUMNS = [
    "severity",
    "score",
    "rule_id",
    "alert",
    "source",
    "destination",
    "evidence",
    "recommendation",
]


def detect_alerts(df):
    """Return explainable, rule-based alerts from normalized packet metadata."""
    alerts = []

    def add(severity, score, rule_id, name, source, destination,
            evidence, recommendation):
        alerts.append({
            "severity": severity,
            "score": score,
            "rule_id": rule_id,
            "alert": name,
            "source": str(source),
            "destination": str(destination),
            "evidence": evidence,
            "recommendation": recommendation,
        })

    if df.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    data = df.copy()
    data["protocol"] = data["protocol"].astype(str).str.upper()

    for col in ["src_port", "dst_port", "tcp_syn", "tcp_ack"]:
        data[col] = pd.to_numeric(data[col], errors="coerce").fillna(0)

    # Rule NS-001: SYN scan against many ports on one destination.
    syn = data[
        (data["protocol"] == "TCP")
        & (data["tcp_syn"] == 1)
        & (data["tcp_ack"] == 0)
    ]

    if not syn.empty:
        groups = syn.groupby(["src_ip", "dst_ip"])
        for (src, dst), group in groups:
            port_count = int(group["dst_port"].nunique())
            if port_count >= SYN_SCAN_PORTS:
                add(
                    "High", 90, "NS-001", "Possible TCP SYN port scan",
                    src, dst,
                    f"{port_count} unique destination ports; "
                    f"{len(group)} SYN packets",
                    "Review the source, destination ports, and surrounding traffic."
                )

    # Rule NS-002: UDP probing across many destination ports.
    udp = data[data["protocol"] == "UDP"]
    if not udp.empty:
        for (src, dst), group in udp.groupby(["src_ip", "dst_ip"]):
            port_count = int(group["dst_port"].nunique())
            if port_count >= UDP_SCAN_PORTS:
                add(
                    "Medium", 70, "NS-002", "Possible UDP port scan",
                    src, dst,
                    f"{port_count} unique UDP destination ports",
                    "Check whether the traffic matches an authorized service discovery task."
                )

    # Rule NS-003: One source contacting many destination hosts on one port.
    for port, group in data.groupby("dst_port"):
        for src, source_group in group.groupby("src_ip"):
            hosts = int(source_group["dst_ip"].nunique())
            if hosts >= PORT_SWEEP_HOSTS:
                add(
                    "Medium", 65, "NS-003", "Possible network host sweep",
                    src, f"Destination port {int(port)}",
                    f"Contacted {hosts} unique destination IPs on this port",
                    "Verify whether the source is an authorized scanner or management system."
                )

    # Rule NS-004: High packet rate in a one-minute window.
    timed = data.dropna(subset=["timestamp"]).copy()
    if not timed.empty:
        timed["minute"] = timed["timestamp"].dt.floor("min")
        counts = timed.groupby(["src_ip", "minute"]).size()

        for src, count in counts[counts >= HIGH_PACKET_RATE].items():
            source, minute = src
            add(
                "Medium", 60, "NS-004", "High packet rate",
                source, "Multiple destinations",
                f"{int(count)} packets in minute starting {minute}",
                "Inspect traffic volume and determine whether the burst is expected."
            )

    # Rule NS-005: Large burst of initial TCP SYN packets to one destination.
    if not syn.empty:
        for (src, dst), group in syn.groupby(["src_ip", "dst_ip"]):
            count = len(group)
            if count >= SYN_BURST_COUNT:
                add(
                    "High", 85, "NS-005", "Large TCP SYN burst",
                    src, dst,
                    f"{count} initial SYN packets",
                    "Investigate connection attempts and check for service availability issues."
                )

    if not alerts:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    result = pd.DataFrame(alerts, columns=ALERT_COLUMNS)

    # Keep the highest-scoring instance of duplicate rule/source/destination alerts.
    result = result.sort_values("score", ascending=False)
    result = result.drop_duplicates(
        subset=["rule_id", "source", "destination", "evidence"]
    )
    return result.reset_index(drop=True)