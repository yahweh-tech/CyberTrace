# 🛡️ CyberTrace: VoIP & AI Threat Intelligence Forensic Platform

**CyberTrace** is an advanced Digital Forensics and Incident Response (DFIR) & Threat Intelligence investigation platform built with Django. Designed to analyze modern attack vectors—such as conversational vishing, deepfake voice synthesis, fraudulent VoIP infrastructure, AI system vulnerabilities, and malicious binary payloads—CyberTrace unifies OSINT, network packet inspection, binary reverse engineering, and threat matrix mapping into a single, cohesive case management workflow.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Architecture & Tech Stack](#-architecture--tech-stack)
- [Module Breakdown](#-module-breakdown)
- [Investigation Workflow](#-investigation-workflow)
- [Installation & Setup](#-installation--setup)
- [Environment Configuration](#-environment-configuration)
- [Running the Project](#-running-the-project)
- [Running Automated Tests](#-running-automated-tests)
- [Directory Structure](#-directory-structure)

---

## ✨ Key Features

1. **📁 Case & Evidence Management (`investigations`, `evidence`, `timeline`)**
   - Track cases across lifecycle states: `PENDING`, `IN_PROGRESS`, and `COMPLETED`.
   - Attach digital evidence files (PCAP, binaries, audio, images, documents).
   - Automated timeline event logging for transparent forensic chain of custody.

2. **📞 VoIP & Phone Intelligence (`number_lookup`)**
   - Query global numbers via NumVerify API.
   - Detect virtual burner numbers, VoIP providers, carriers, country codes, and line types to unmask caller spoofing origins.

3. **🌐 Infrastructure: IP Intelligence (`ip_lookup`)**
   - Geolocate suspected IP addresses via open IP-API protocols.
   - Unmask proxy/VPN routing, ISP, carrier ASN, and coordinates with one-click **Google Maps** pivot navigation.

4. **🌍 Infrastructure: Domain Intelligence (`domain_lookup`)**
   - Query domain ownership, registrar metadata, DNS name servers, and lifecycle dates via RDAP.
   - Identify active C2 drop sites, exfiltration hosts, and phishing campaigns.

5. **📡 SIP Packet & Media Forensics (`packet_analysis`)**
   - Deep inspection of `.pcap` and `.pcapng` network captures via **Scapy**.
   - Protocol breakdowns, top talkers, suspicious ports, and cleartext credential scanning.
   - Extraction of SIP/VoIP signaling headers (`Call-ID`, `From`, `To`, `User-Agent`, `Via`, `Contact`).

6. **⚙️ Reverse Engineering & Malware Static Triage (`reverse_engineering`)**
   - **Isolated Static Analysis**: Inspect Windows PE and Linux ELF binaries without host execution.
   - **Hashes & Signatures**: MD5, SHA-1, SHA-256, and Imphash (Import Hash).
   - **Shannon Entropy & Packer Detection**: Section-by-section entropy analysis to detect UPX, Themida, VMProtect, or custom packing/encryption.
   - **Disassembly Engine**: Entry-point disassembly rendered via **Capstone Engine**.
   - **Tradecraft & ATT&CK Mapping**: Automatic detection of Process Injection (T1055), Anti-Debugging (T1497/T1622), Keylogging (T1056), and C2 networking (T1071).
   - **Actionable IOC Pivot**: Hardcoded C2 IPs and domains extracted from strings can be queried in `ip_lookup` and `domain_lookup` with 1 click.

7. **🤖 AI Threat Matrix: MITRE ATLAS™ (`mitre_atlas`)**
   - Audit generative AI and voice synthesis systems against adversarial tactics and techniques.
   - Calculate risk severity scores (0–100) and generate actionable mitigation guidance.

8. **📄 Forensic Attribution Reports (`reports`)**
   - Compile findings across all investigation modules into structured CSV and audit summaries.

---

## 🛠️ Architecture & Tech Stack

- **Backend Framework**: Python 3.10+, Django 6.0+
- **Database**: SQLite (default, easily adaptable to PostgreSQL/MySQL)
- **Static Packet Analysis**: [Scapy](https://scapy.net/)
- **Binary Forensics & Disassembly**: [pefile](https://github.com/erocarrera/pefile), [Capstone Engine](https://www.capstone-engine.org/)
- **Styling & UI**: Bootstrap 5.3, Bootstrap Icons
- **External Intelligence APIs**:
  - NumVerify / APILayer (Phone Intelligence)
  - IP-API (IP Geolocation & Proxy Detection)
  - RDAP (Domain Registry & Registrar Data)

---

## 🔍 Investigation Workflow

```
                   [ Victim / Incident Report ]
                                │
        ┌───────────────────────┼────────────────────────┐
        ▼                       ▼                        ▼
[ Phone Number ]        [ IP / Domain ]          [ Downloaded File / PCAP ]
        │                       │                        │
        ▼                       ▼                        ▼
 number_lookup        ip_lookup / domain_lookup    packet_analysis / reverse_engineering
        │                       │                        │
        │                       │     ┌──────────────────┘
        │                       │     │  (Extracts hardcoded C2 IPs & Domains)
        │                       ▼     ▼
        └──────────────► [ Investigation Case File ]
                                │
               ┌────────────────┴────────────────┐
               ▼                                 ▼
      [ MITRE ATLAS Assessment ]       [ Export Forensic CSV Report ]
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.10, 3.11, or 3.12+
- Git

### 1. Clone or Open the Repository
```bash
git clone <repository_url>
cd adl
```

### 2. Create and Activate a Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## ⚙️ Environment Configuration

Create a `.env` file in the root project folder (alongside `manage.py`):

```env
SECRET_KEY="your-secret-key-here"
DEBUG=True

# Optional: NumVerify API key for phone number lookup (free tier from https://numverify.com)
NUMVERIFY_API_KEY="your_numverify_api_key"
```

> **Note on API Keys:**
> - `number_lookup` requires `NUMVERIFY_API_KEY`.
> - `ip_lookup` and `domain_lookup` use free open public endpoints and **do not** require API keys.
> - `reverse_engineering`, `packet_analysis`, and `mitre_atlas` run **100% locally** on your machine.

---

## 🖥️ Running the Project

### 1. Run Migrations
```bash
python manage.py migrate
```

### 2. (Optional) Create an Administrative User
```bash
python manage.py createsuperuser
```

### 3. Start the Development Server
```bash
python manage.py runserver
```

Open your browser and navigate to:
```
http://127.0.0.1:8000/
```

---

## 🧪 Pre-Built Test Samples

Ready-to-use sample artifacts are included in `media/sample_test_files/` for testing:

- **`sample_windows_beacon.exe`**: 64-bit Windows PE binary with simulated C2 IP and domain for testing reverse engineering triage.
- **`sample_obfuscated_dropper.ps1`**: PowerShell script testing IOC regex extraction.
- **`sample_high_entropy_packed.bin`**: High-entropy payload testing packer and encryption detection.

These files can be downloaded directly from the web interface on the **Reverse Engineering Upload** page.

---

## 🔬 Running Automated Tests

Run the full Django test suite (covering authentication, case routing, entropy scoring, PE header analysis, and view workflows):

```bash
python manage.py test
```

To run tests for a specific module:
```bash
python manage.py test reverse_engineering
python manage.py test packet_analysis
python manage.py test mitre_atlas
```

---

## 📂 Directory Structure

```
adl/
├── accounts/               # User authentication & custom User model
├── api/                    # REST API endpoints
├── common/                 # Shared utilities
├── core/                   # Shared choices and constants
├── dashboard/              # Central case overview & analytics
├── domain_lookup/          # RDAP domain registration intelligence
├── evidence/               # File evidence collection
├── investigations/         # Core case management workflows
├── ip_lookup/              # IP geolocation & proxy tracking
├── media/                  # Uploaded evidence, captures & sample files
│   └── sample_test_files/  # Pre-built benign test samples
├── mitre_atlas/            # AI Security Matrix & Assessment engine
├── number_lookup/          # VoIP & phone number intelligence
├── packet_analysis/        # PCAP inspection & SIP header parsing
├── project/                # Django project settings & URL routing
├── reports/                # Forensic CSV generation & export
├── reverse_engineering/    # Binary triage, entropy & Capstone disassembly
├── static/                 # CSS, JavaScript & branding assets
├── templates/              # HTML templates
├── timeline/               # Audit event logging
├── manage.py               # Django CLI management script
├── requirements.txt        # Python package dependencies
└── README.md               # Project documentation
```

---

## ⚖️ License & Ethical Usage

### License
This project is licensed under the **GNU General Public License v3.0 (GPLv3)**. See the [LICENSE](LICENSE) file for the complete license terms.

### Ethical Usage & Research Disclaimer
This software is designed strictly for authorized cybersecurity investigations, digital forensics and incident response (DFIR), academic research, and defensive threat analysis. All reverse engineering routines are purely static, isolated, and do not execute foreign code on the host machine.
