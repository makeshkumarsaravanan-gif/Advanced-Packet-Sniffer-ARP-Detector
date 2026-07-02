# Advanced Packet Sniffer & ARP Spoofing Detector

A robust, modular Network Security Auditing tool developed in Python using the Scapy engine. This tool incorporates a dual-mode operational architecture featuring a real-time raw network Packet Sniffer (Layer 3/4) alongside a stateful behavioral Address Resolution Protocol (ARP) Poisoning and Spoofing Detector (Layer 2).

---

## 🚀 Core Functionalities & Architecture

The system operates across three separate structural scripts designed to segment network capturing, payload processing, and security alert logging:

1. **Interface Controller Router (`main.py`):** The primary Command-Line Interface (CLI) application hub that dynamically prompts the administrator for execution options and verifies low-level network adapter attachments.
2. **Promiscuous Packet Sniffer (`sniffer.py`):** Hooks into the local hardware network interface to intercept live frames, unpacking IP payload structures and resolving upper-layer operational protocols like TCP and UDP dynamically on screen.
3. **Stateful ARP Auditor (`detector.py`):** Tracks and establishes a persistent dynamic runtime Look-Up Table (LUT) linking IP addresses to hardware physical MAC addresses. If an external attacker attempts a Man-in-the-Middle (MitM) positioning vulnerability trigger by broadcasting conflicting MAC data blocks, the engine catches it instantly, raises a Red Visual Alert, and commits structural entries into the secure local log auditing space.

---

## 🛠️ Repository Directory Blueprint

```text
arp_project/
├── main.py                # System router & administrative setup panel
├── sniffer.py             # Layer 3 / Layer 4 promiscuous capturing engine
├── detector.py            # Layer 2 behavior monitoring system
├── Project_Documentation_Makesh.pdf # Complete corporate technical evaluation report
├── .gitignore              # Safeguards runtime environment parameters from deployment
└── logs/
    └── attack_alerts.log  # Secure threat logs with sub-second timestamps
⚙️ Environment Configuration & Deployment
Follow these absolute sequential instructions inside your Linux Mint terminal interface layout to mount and fire up the auditing tool chain:

1. System Dependency Mounting
Ensure standard low-level system package handles are operational inside an isolated environment wrapper layout:

Bash
cd ~/arp_project
source venv/bin/activate

# Install the required Scapy processing engine
pip install scapy
2. Live Application Bootup
Because raw hardware interface socket capturing requires kernel-level clearance access boundaries on Linux architectures, execute the launcher path using sudo explicitly linked to the project's virtual environment:

Bash
sudo ./venv/bin/python main.py
3. Threat Simulation & Attack Output Profile
When Option 2 (ARP Detector Engine) is listening live on an active interface topology (e.g., wlp2s0), any anomalous mapping changes trigger instant real-time cryptographic threat alerts on the console buffer screen:

Plaintext
[*] Starting ARP Spoof Detector on interface: wlp2s0...
[-] Monitoring local network mappings. Press Ctrl+C to exit.
==================================================
[*] Learned: 192.168.1.1 is at c0:38:96:82:11:05

⚠️ ALERT: Potential ARP Spoofing Detected! IP [192.168.1.99] changed MAC from [00:11:22:33:44:55] to [AA:BB:CC:DD:EE:FF]!
All confirmed instances are automatically written directly into logs/attack_alerts.log with detailed machine timestamps for immediate security audit assessments.
