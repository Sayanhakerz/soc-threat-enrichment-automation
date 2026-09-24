# 🛡️ SOC Threat Detection & IOC Enrichment Automation

### Automated Security Operations Center Alert Detection, Threat Intelligence Enrichment, Risk Assessment & Incident Reporting

A hands-on SOC automation project using **Suricata IDS**, **Python**, **AbuseIPDB**, **VirusTotal**, and **MITRE ATT&CK** to detect network security events, enrich indicators, calculate risk, explain the risk decision, and generate structured incident reports.

## 🎯 Project Objective

The pipeline automatically:

1. Detects suspicious network activity
2. Parses Suricata EVE JSON events
3. Extracts source and destination indicators
4. Queries external threat-intelligence platforms
5. Calculates alert priority and risk
6. Explains the risk decision
7. Maps applicable detections to MITRE ATT&CK
8. Generates a structured SOC incident report

## 🏗️ Architecture

```text
Network Activity
      ↓
Suricata IDS
      ↓
EVE JSON Logs
      ↓
Python Parser
      ↓
IOC Extraction
      ↓
┌───────────────┬────────────────┐
│               │                │
▼               ▼                │
AbuseIPDB    VirusTotal          │
│               │                │
└───────┬───────┘                │
        ▼                        │
   SOC Risk Engine               │
        ↓                        │
  Risk Explanation               │
        ↓                        │
 MITRE ATT&CK Mapping            │
        ↓                        │
 Automated Incident Report ◄─────┘
```

## 🔄 SOC Investigation Workflow

```text
Network Event
     ↓
Suricata Detection
     ↓
EVE JSON Event
     ↓
IOC Extraction
     ↓
AbuseIPDB + VirusTotal
     ↓
Alert Priority
     ↓
Risk Calculation
     ↓
Risk Explanation
     ↓
MITRE ATT&CK Mapping
     ↓
Automated Incident Report
```

## 🚀 Key Features

### Suricata IDS
- Network intrusion detection
- Custom detection rules
- EVE JSON event generation
- Severity-based alert processing
- Stateful log processing

### IOC Extraction
The Python parser extracts:
- Source IP
- Destination IP
- Protocol
- Interface
- Suricata signature
- Severity
- Alert metadata

Private/internal IP addresses are identified separately from public IPs.

### Threat Intelligence

**AbuseIPDB**
- Abuse confidence score
- Country
- ISP
- Domain
- Usage type
- Total reports
- Last reported timestamp

**VirusTotal**
- Reputation
- Malicious detections
- Suspicious detections
- Harmless detections
- Undetected results
- Country
- ASN
- Autonomous System owner

Private IP addresses are skipped for public threat-intelligence lookups.

## 🧠 SOC Risk Engine

The risk engine combines:
- Suricata severity
- AbuseIPDB abuse confidence score
- VirusTotal malicious detection count

It produces:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

It also generates human-readable reasons explaining the calculated risk.

Example:

```text
Risk Level : CRITICAL

Risk Reasons:
- High AbuseIPDB score combined with high-severity Suricata alert
- VirusTotal reports multiple malicious detections
- AbuseIPDB abuse confidence score is elevated
- VirusTotal has multiple malicious engine detections
```

## 🚦 Alert Priority

| Suricata Severity | Alert Priority |
|---|---|
| 1 | CRITICAL |
| 2 | HIGH |
| 3 | MEDIUM |
| Other | LOW |

Priority and calculated risk are separate concepts.

## 🗺️ MITRE ATT&CK Mapping

Mappings are maintained in:

```text
config/mitre_mapping.yaml
```

Each mapping can contain:
- Tactic
- Technique ID
- Technique name
- Confidence
- Detection rationale

Example:

```text
ET SCAN Potential SSH Scan
        ↓
Discovery
        ↓
T1046 - Network Service Scanning
```

Mappings are confidence-rated because an IDS signature does not automatically prove successful execution of an ATT&CK technique.

## 📄 Automated Incident Reporting

Processed alerts generate unique Markdown incident reports containing:

- Detection time
- Alert signature
- Suricata severity
- Alert priority
- Risk level
- Risk reasons
- Source and destination IPs
- AbuseIPDB results
- VirusTotal results
- MITRE ATT&CK mapping
- Analyst notes
- Investigation workflow
- Automation status

## 📁 Project Structure

```text
soc-threat-enrichment-automation/
│
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example
│
├── config/
│   ├── config.yaml
│   └── mitre_mapping.yaml
│
├── rules/
│   └── custom.rules
│
├── src/
│   ├── main.py
│   ├── parser.py
│   ├── enrichment.py
│   ├── virustotal.py
│   ├── risk_engine.py
│   ├── reporter.py
│   └── mitre_mapper.py
│
├── data/
│   ├── sample_eve.json
│   ├── state.json
│   └── reports/
│
├── screenshots/
│
└── docs/
    └── architecture.md
```

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Suricata | Network IDS |
| Python | Automation and processing |
| AbuseIPDB | IP reputation |
| VirusTotal | Threat intelligence |
| MITRE ATT&CK | Adversary behavior mapping |
| YAML | Configuration |
| JSON | Event processing |
| Markdown | Incident reporting |
| Linux | SOC lab environment |
| Git | Version control |

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd soc-threat-enrichment-automation
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 🔐 API Configuration

Create a local `.env` file:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

Never commit `.env` to Git.

Use `.env.example` as the configuration reference.

## ▶️ Running the Parser

```bash
python3 src/parser.py
```

The parser maintains state so previously processed EVE JSON lines are not repeatedly processed.

## 🧪 Example Detection

```text
NEW SOC ALERT
      ↓
Source IP Extraction
      ↓
AbuseIPDB Lookup
      ↓
VirusTotal Lookup
      ↓
Risk Calculation
      ↓
MITRE ATT&CK Mapping
      ↓
Incident Report
```

Example analyst output:

```text
Alert Priority  : HIGH

Suricata Severity : 2
AbuseIPDB Score   : 100
VT Malicious      : 11

Risk Level        : CRITICAL
```

Threat-intelligence values depend on the external services and the IP being investigated.

## 🧪 Validation Performed

The project has been validated through:

- Suricata configuration testing
- Custom rule detection
- EVE JSON parsing
- Stateful event processing
- AbuseIPDB API enrichment
- VirusTotal API enrichment
- Risk-engine testing
- Alert-priority testing
- MITRE ATT&CK mapping testing
- Automated report generation
- End-to-end pipeline validation
- Python syntax compilation
- Git working-tree validation

Final validation:

```text
Python compilation     PASS
Git working tree       CLEAN
Suricata IDS           ACTIVE
Threat enrichment      ACTIVE
Risk engine            ACTIVE
MITRE mapping          ACTIVE
Incident reporting     ACTIVE
```

## 📸 Project Evidence

Implementation screenshots are stored under:

```text
screenshots/
```

Evidence includes:
- Custom Suricata detection
- IOC parsing
- AbuseIPDB enrichment
- Risk engine
- Integrated risk assessment
- Automated incident reporting
- MITRE ATT&CK mapping
- Stateful processing
- Alert priority
- Risk explanation
- End-to-end pipeline validation

## 🔒 Security Considerations

API credentials are intentionally excluded from version control.

```text
.env
```

is ignored by Git.

Only placeholder credentials should appear in:

```text
.env.example
```

Private/internal IP addresses are not submitted to public threat-intelligence APIs.

## ⚠️ Important Interpretation Note

Threat-intelligence results are supporting evidence, not standalone proof of malicious activity.

An automated risk classification should be treated as an analyst-triage signal that helps prioritize investigation.

MITRE ATT&CK mappings include confidence and rationale because an IDS signature does not necessarily prove that a specific ATT&CK technique was successfully executed.

## 🔮 Future Improvements

- Wazuh integration
- Elasticsearch/OpenSearch integration
- Alert deduplication
- IOC caching
- Additional threat-intelligence providers
- Email/Slack alerting
- Dashboard visualization
- Automated case management
- Docker deployment
- Cloud SOC deployment
- Expanded MITRE ATT&CK coverage
- Automated unit and integration testing

## 👨‍💻 Skills Demonstrated

### SOC Operations
- Alert triage
- IOC investigation
- Threat-intelligence enrichment
- Risk prioritization
- Incident reporting

### Network Security
- IDS concepts
- Suricata
- Network traffic analysis
- Detection rules
- IP analysis

### Security Automation
- Python
- REST APIs
- JSON parsing
- Stateful processing
- Automated reporting

### Threat Intelligence
- AbuseIPDB
- VirusTotal
- IOC enrichment
- Reputation analysis

### Threat Detection Frameworks
- MITRE ATT&CK
- Detection-to-technique mapping
- Confidence-based analysis

### Linux / DevOps
- Linux administration
- Virtual environments
- Git
- Configuration management
- Log processing

## 📌 Project Status

**Status: Functional SOC Automation Lab**

Core detection, enrichment, risk assessment, MITRE mapping, and automated reporting components are implemented and validated.

## 📜 Disclaimer

This project is designed for educational, defensive-security, and authorized laboratory use.

Only monitor and test systems and networks for which you have explicit authorization.
