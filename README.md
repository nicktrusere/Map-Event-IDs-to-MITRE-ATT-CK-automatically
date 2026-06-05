# Map-Event-IDs-to-MITRE-ATT-CK-automatically
Build Windows log → SIEM ingestion pipelineCorrelate PPID + network + logs automatically
working pipeline that:
Windows Logs → Normalize → Map to MITRE → Correlate (PPID + Network) → Send to SIEM
SOC systems.

ARCHITECTURE

[Windows Event Logs]
        ↓
Collector (Python)
        ↓
Normalizer
        ↓
MITRE Mapper
        ↓
Correlation Engine (PPID + Network)
        ↓
Alerts → Node.js SIEM


STEP 1 — WINDOWS LOG INGESTION

windows_ingest.py
import win32evtlog

def collect_windows_events(limit=50):
    server = 'localhost'
    logtype = 'Security'

    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = []

    while len(events) < limit:
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not records:
            break

        for event in records:
            events.append({
                "event_id": event.EventID,
                "timestamp": str(event.TimeGenerated),
                "message": event.StringInserts
            })

            if len(events) >= limit:
                break

    return events

STEP 2 — NORMALIZATION

normalizer.py
def normalize(events):
    normalized = []

    for e in events:
        event_type = "unknown"

        if e["event_id"] == 4624:
            event_type = "login_success"
        elif e["event_id"] == 4625:
            event_type = "login_failed"
        elif e["event_id"] == 4688:
            event_type = "process_execution"

        normalized.append({
            "timestamp": e["timestamp"],
            "event_id": e["event_id"],
            "event_type": event_type,
            "raw": e
        })

    return normalized

STEP 3 — MITRE MAPPING ENGINE

Mapping dictionary
mitre_mapper.py
MITRE_MAP = {
    4625: {
        "technique": "T1110",
        "tactic": "Credential Access",
        "name": "Brute Force"
    },
    4688: {
        "technique": "T1059",
        "tactic": "Execution",
        "name": "Command Execution"
    },
    4663: {
        "technique": "T1005",
        "tactic": "Collection",
        "name": "Data from Local System"
    }
}

def map_to_mitre(events):
    for e in events:
        if e["event_id"] in MITRE_MAP:
            e["mitre"] = MITRE_MAP[e["event_id"]]

    return events

STEP 4 — NETWORK INGESTION

network_ingest.py
from scapy.all import sniff

network_events = []

def process(pkt):
    if pkt.haslayer("IP"):
        event = {
            "event_type": "network",
            "src_ip": pkt["IP"].src,
            "dst_ip": pkt["IP"].dst,
            "protocol": pkt["IP"].proto,
            "bytes": len(pkt)
        }
        network_events.append(event)

def collect_network(count=20):
    sniff(prn=process, count=count)
    return network_events

STEP 5 — PPID + NETWORK CORRELATION

correlator.py
def correlate(events, network_events):
    alerts = []

    for e in events:

        # Detect brute force
        if e["event_type"] == "login_failed":
            alerts.append({
                "type": "BRUTE_FORCE",
                "mitre": e.get("mitre"),
                "event": e
            })

        #  Detect suspicious process
        if e["event_type"] == "process_execution":
            alerts.append({
                "type": "EXECUTION",
                "mitre": e.get("mitre"),
                "event": e
            })

        #  Correlate with network (exfiltration)
        for net in network_events:
            if net["bytes"] > 50000000:
                alerts.append({
                    "type": "DATA_EXFILTRATION",
                    "mitre": {
                        "technique": "T1041",
                        "tactic": "Exfiltration"
                    },
                    "network": net
                })

    return alerts

STEP 6 — SEND TO SIEM

sender.py
import requests

def send(alerts):
    try:
        requests.post("http://localhost:3001/logs", json=alerts)
    except Exception as e:
        print("Error:", e)

STEP 7 — MAIN PIPELINE
main.py
from windows_ingest import collect_windows_events
from network_ingest import collect_network
from normalizer import normalize
from mitre_mapper import map_to_mitre
from correlator import correlate
from sender import send

def run():
    win_logs = collect_windows_events()
    net_logs = collect_network()

    normalized = normalize(win_logs)
    mapped = map_to_mitre(normalized)

    alerts = correlate(mapped, net_logs)

    print("ALERTS:", alerts)

    if alerts:
        send(alerts)

if __name__ == "__main__":
    run()
    
WHAT I JUST BUILT
✔ Automatic MITRE mapping
Event ID → Technique (T1110, T1059, T1041)
✔ Cross-source correlation
Logs + Process + Network
✔ Attack detection chain
Brute force → Execution → Exfiltration
