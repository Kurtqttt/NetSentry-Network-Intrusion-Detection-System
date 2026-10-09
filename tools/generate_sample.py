
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent.parent / "data" / "sample_traffic.csv"

FIELDS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "packet_length", "tcp_syn", "tcp_ack"
]


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    start = datetime.now(timezone.utc).replace(microsecond=0)
    rows = []

    # Simulated SYN scan: 12 destination ports in 12 seconds.
    for i in range(12):
        rows.append({
            "timestamp": (start + timedelta(seconds=i)).isoformat(),
            "src_ip": "192.0.2.10",
            "dst_ip": "198.51.100.20",
            "src_port": 51000 + i,
            "dst_port": 20 + i,
            "protocol": "TCP",
            "packet_length": 60,
            "tcp_syn": 1,
            "tcp_ack": 0,
        })

    # Simulated high packet rate.
    for i in range(35):
        rows.append({
            "timestamp": (start + timedelta(seconds=i)).isoformat(),
            "src_ip": "203.0.113.50",
            "dst_ip": "198.51.100.20",
            "src_port": 52000 + i,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_length": 120,
            "tcp_syn": 0,
            "tcp_ack": 1,
        })

    # Ordinary background traffic.
    rows.extend([
        {
            "timestamp": (start + timedelta(seconds=5)).isoformat(),
            "src_ip": "192.0.2.25",
            "dst_ip": "198.51.100.53",
            "src_port": 53000,
            "dst_port": 53,
            "protocol": "UDP",
            "packet_length": 74,
            "tcp_syn": 0,
            "tcp_ack": 0,
        },
        {
            "timestamp": (start + timedelta(seconds=8)).isoformat(),
            "src_ip": "192.0.2.25",
            "dst_ip": "198.51.100.20",
            "src_port": 53001,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_length": 100,
            "tcp_syn": 0,
            "tcp_ack": 1,
        },
    ])

    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Sample traffic created: {OUTPUT}")
    print(f"Packets generated: {len(rows)}")
    print("Note: all records are simulated test data.")


if __name__ == "__main__":
    main()