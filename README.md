# 🛡️ Aegis NetShield: AI Forensic & Mitigation Engine

AI-Driven Forensic Systems for Real-Time Anomaly Detection and  Threat Mitigation in Cybersecurity Infrastructures

---

## 🚀 Getting Started

### 1. Requirements & Installation

Create a virtual environment and install project dependencies:

```bash
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Linux / WSL (Bash)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

### 2. Starting the Application

```bash
# Start the FastAPI & Dashboard server
python app.py
```

Then open **`http://127.0.0.1:8000`** in your browser.

> [!NOTE]
> Do not open `static/index.html` directly as a local file (`file://`); the dashboard requires the FastAPI server and SSE live stream on `http://127.0.0.1:8000`.

---

### 3. Live Packet Sniffing & Interface Selection

The engine supports two operational sniffing modes:

1. **Simulated Traffic Generator**: Generates realistic network flows, baseline benign traffic, and allows injecting simulated attack scenarios (Volumetric DDoS, SSH Brute-Force Spray, Port Scan Sweeps).
2. **Live Sniffer (Real Network Traffic)**:
   - Captures real incoming/outgoing network packets on your host adapter.
   - Automatically discovers network interfaces (Wi-Fi, Ethernet, Loopback, virtual switches).
   - Allows selecting target network adapters directly from the web dashboard.
   - **Windows Requirement**: For Layer 2 raw packet sniffing on Windows, install the free [Npcap Driver](https://npcap.com/) (or WinPcap) with *"Install Npcap in WinPcap API-compatible Mode"* checked.
   - **Linux Requirement**: Run with root / sudo permissions (`sudo .venv/bin/python app.py`) or grant capture capabilities (`setcap cap_net_raw,cap_net_admin=eip`).

---

### 4. System Capabilities

- **XGBoost Machine Learning Classifier**: Classifies flows into `BENIGN`, `DDOS_FLOOD`, or `BRUTE_FORCE_SPRAY` with high confidence.
- **Shannon Port Entropy Sweep Detector**: Computes real-time entropy over sliding destination port windows to identify subtle horizontal and vertical reconnaissance scans (`PORT_SCAN`).
- **Automated Mitigation Matrix**: Automatically generates 60-second hardware/software perimeter containment drop rules with auto-expiry leases and instant manual revoke capability.
- **Real-Time Visual Defense Radar**: Canvas node map visualizing active endpoints, glowing firewall barriers, particle flow streams, and spark collisions.
