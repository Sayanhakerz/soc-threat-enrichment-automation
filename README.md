<div align="center">

# 🛡️ SOC Threat Detection & IOC Enrichment Automation

### End-to-End SOC Alert Triage, Threat Intelligence, Risk Assessment & Incident Reporting

<p>
  <strong>Suricata IDS</strong> •
  <strong>Python</strong> •
  <strong>AbuseIPDB</strong> •
  <strong>VirusTotal</strong> •
  <strong>MITRE ATT&CK</strong>
</p>

<p>
  <img src="https://img.shields.io/badge/IDS-Suricata-red?style=for-the-badge" alt="Suricata">
  <img src="https://img.shields.io/badge/Python-Automation-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Threat%20Intel-AbuseIPDB-orange?style=for-the-badge" alt="AbuseIPDB">
  <img src="https://img.shields.io/badge/Threat%20Intel-VirusTotal-black?style=for-the-badge" alt="VirusTotal">
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge" alt="MITRE ATT&CK">
  <img src="https://img.shields.io/badge/Linux-SOC%20Lab-yellow?style=for-the-badge&logo=linux" alt="Linux">
</p>

<p>
  <strong>🟢 Functional SOC Automation Lab</strong>
</p>

</div>

---

## 🎯 Project Overview

This project simulates a practical **Security Operations Center alert-triage pipeline**.

It takes security events detected by **Suricata IDS**, extracts relevant indicators, enriches public IPs using external threat-intelligence platforms, calculates alert priority and risk, explains the risk decision, maps detections to **MITRE ATT&CK**, and generates structured incident reports.

### Core Objective

```text
Raw Security Alert
        ↓
IOC Investigation
        ↓
Threat Intelligence
        ↓
Risk Assessment
        ↓
MITRE ATT&CK Context
        ↓
Incident Documentation
```

This project demonstrates practical skills relevant to:

- 🛡️ SOC Analyst L1
- 🔐 Junior SOC Analyst
- 💻 Cybersecurity Intern
- 🛡️ Security Operations Intern
- 🔵 Blue Team Intern
- 🔎 Security Monitoring Analyst

---

# 🧠 What This Project Demonstrates

This project focuses on the workflow surrounding a security alert rather than simply installing security tools.

```text
              SECURITY ALERT
                    ↓
            Understand Detection
                    ↓
              Extract IOC
                    ↓
          Investigate the IOC
                    ↓
        Threat Intelligence Lookup
                    ↓
             Assess Severity
                    ↓
          Prioritize the Alert
                    ↓
        Calculate Security Risk
                    ↓
        Explain Risk Decision
                    ↓
        MITRE ATT&CK Mapping
                    ↓
        Document Investigation
```

### Practical SOC capabilities demonstrated

- Security monitoring
- Alert triage
- IOC investigation
- Threat intelligence
- Risk-based prioritization
- Incident documentation
- Detection engineering
- Security automation
- Linux security operations
- Git-based project management

---

# 🏗️ Architecture

<div align="center">

<pre>
                    Network Activity
                           │
                           ▼
                    ┌─────────────┐
                    │  Suricata   │
                    │     IDS     │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  EVE JSON   │
                    │    Logs     │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │    Python   │
                    │    Parser   │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ IOC Extract │
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
       ┌─────────────┐          ┌─────────────┐
       │ AbuseIPDB   │          │ VirusTotal  │
       │ Enrichment  │          │ Enrichment  │
       └──────┬──────┘          └──────┬──────┘
              │                         │
              └────────────┬────────────┘
                           ▼
                    ┌─────────────┐
                    │ Risk Engine │
                    └──────┬──────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Risk Explanation │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ MITRE ATT&CK     │
                  │ Mapping          │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Incident Report  │
                  └──────────────────┘
</pre>

</div>

---

# 🔄 SOC Investigation Workflow

<table>
<tr>
<th>Stage</th>
<th>Technology / Process</th>
<th>Output</th>
</tr>

<tr>
<td><strong>1. Detection</strong></td>
<td>Suricata IDS</td>
<td>Security Alert</td>
</tr>

<tr>
<td><strong>2. Parsing</strong></td>
<td>Python EVE JSON Parser</td>
<td>Structured Event</td>
</tr>

<tr>
<td><strong>3. IOC Extraction</strong></td>
<td>Source / Destination Analysis</td>
<td>Investigation Indicators</td>
</tr>

<tr>
<td><strong>4. Enrichment</strong></td>
<td>AbuseIPDB + VirusTotal</td>
<td>Threat Intelligence</td>
</tr>

<tr>
<td><strong>5. Prioritization</strong></td>
<td>Suricata Severity</td>
<td>Alert Priority</td>
</tr>

<tr>
<td><strong>6. Risk Assessment</strong></td>
<td>Risk Engine</td>
<td>Risk Level</td>
</tr>

<tr>
<td><strong>7. Explanation</strong></td>
<td>Risk Reasoning</td>
<td>Supporting Evidence</td>
</tr>

<tr>
<td><strong>8. ATT&CK Mapping</strong></td>
<td>MITRE ATT&CK</td>
<td>Tactic / Technique</td>
</tr>

<tr>
<td><strong>9. Reporting</strong></td>
<td>Automated Reporter</td>
<td>Incident Report</td>
</tr>
</table>

---

# 🛡️ Core Features

## 1️⃣ Suricata IDS

The project uses **Suricata** as the network intrusion detection engine.

Capabilities include:

- Network intrusion detection
- Custom detection rules
- EVE JSON logging
- Severity-based processing
- Structured security events

Example custom detection:

```text
SOC LAB - ICMP Ping Detected
```

---

## 2️⃣ Stateful EVE JSON Processing

The Python parser processes Suricata EVE JSON incrementally.

A state file prevents previously processed events from being repeatedly investigated.

```text
New EVE Event
     ↓
Check State
     ↓
New Event?
   ↙     ↘
 YES      NO
  ↓       ↓
Process  Ignore
  ↓
Update State
```

This demonstrates a basic **stateful security automation workflow**.

---

## 3️⃣ IOC Extraction

The parser extracts important investigation fields:

<table>
<tr>
<th>Field</th>
<th>Purpose</th>
</tr>

<tr>
<td>Source IP</td>
<td>Identify originating network indicator</td>
</tr>

<tr>
<td>Destination IP</td>
<td>Identify affected host</td>
</tr>

<tr>
<td>Protocol</td>
<td>Understand network communication</td>
</tr>

<tr>
<td>Interface</td>
<td>Identify monitoring interface</td>
</tr>

<tr>
<td>Signature</td>
<td>Understand detection context</td>
</tr>

<tr>
<td>Severity</td>
<td>Determine alert priority</td>
</tr>

<tr>
<td>Timestamp</td>
<td>Track detection time</td>
</tr>
</table>

The system also distinguishes:

```text
Public IP
Private / Internal IP
```

Private/internal addresses are not unnecessarily submitted to public threat-intelligence platforms.

---

# 🌐 Threat Intelligence Enrichment

## AbuseIPDB

The automation retrieves:

- Abuse confidence score
- Country
- ISP
- Domain
- Usage type
- Total reports
- Last reported timestamp

## VirusTotal

The automation retrieves:

- Reputation
- Malicious detections
- Suspicious detections
- Harmless detections
- Undetected results
- Country
- ASN
- Autonomous system owner

### Multi-Source Investigation

```text
              Suspicious IP
                    ↓
        ┌───────────┴───────────┐
        ↓                       ↓
    AbuseIPDB               VirusTotal
        ↓                       ↓
 Abuse Confidence       Detection Results
        ↓                       ↓
        └───────────┬───────────┘
                    ↓
              Risk Engine
```

Using multiple intelligence sources provides additional investigation context.

---

# 🚦 Alert Priority

Suricata severity is converted into operational alert priority.

<table>
<tr>
<th>Suricata Severity</th>
<th>Alert Priority</th>
</tr>

<tr>
<td>1</td>
<td><strong>🔴 CRITICAL</strong></td>
</tr>

<tr>
<td>2</td>
<td><strong>🟠 HIGH</strong></td>
</tr>

<tr>
<td>3</td>
<td><strong>🟡 MEDIUM</strong></td>
</tr>

<tr>
<td>Other</td>
<td><strong>🟢 LOW</strong></td>
</tr>
</table>

### Important Design Decision

Alert priority and overall risk are **separate concepts**.

Example:

```text
Suricata Severity : 2
Alert Priority    : HIGH
```

The final risk assessment additionally considers threat-intelligence evidence.

---

# 🧠 Risk Assessment Engine

The risk engine combines:

```text
Suricata Severity
        +
AbuseIPDB Abuse Score
        +
VirusTotal Malicious Count
        ↓
    Risk Engine
        ↓
┌───────────────────────────┐
│ LOW                       │
│ MEDIUM                    │
│ HIGH                      │
│ CRITICAL                  │
└───────────────────────────┘
```

### Example

```text
Suricata Severity : 2
AbuseIPDB Score   : 100
VT Malicious      : 11

Risk Level        : CRITICAL
```

---

# 💡 Explainable Risk Decisions

The system doesn't simply output:

```text
Risk = CRITICAL
```

It also generates supporting reasons.

Example:

```text
Risk Level : CRITICAL

Risk Reasons:

• High AbuseIPDB score combined with high-severity Suricata alert
• VirusTotal reports multiple malicious detections
• AbuseIPDB abuse confidence score is elevated
• VirusTotal has multiple malicious engine detections
```

This makes the automation more useful for **analyst triage and investigation**.

---

# 🗺️ MITRE ATT&CK Integration

Detection signatures are mapped using:

```text
config/mitre_mapping.yaml
```

Each mapping contains:

- Tactic
- Technique ID
- Technique name
- Confidence
- Detection rationale

### Example

```text
ET SCAN Potential SSH Scan
            ↓
        Discovery
            ↓
T1046 - Network Service Scanning
```

The project uses confidence levels because an IDS signature does not automatically prove successful execution of an ATT&CK technique.

---

# 📄 Automated Incident Reporting

Each processed alert can generate a structured Markdown incident report.

Reports include:

- Detection time
- Alert signature
- Suricata severity
- Alert priority
- Risk level
- Risk reasons
- Source IP
- Destination IP
- Protocol
- AbuseIPDB intelligence
- VirusTotal intelligence
- MITRE ATT&CK mapping
- Analyst notes
- Investigation workflow
- Automation status

Example:

```text
incident_20260924_193524_404370_ET_DROP_Spamhaus_DROP_Listed_Traffic_Inb.md
```

Unique filenames prevent reports from being overwritten.

---

# 🧪 End-to-End Validation

During lab validation, the pipeline processed a Suricata alert associated with an external IP.

### Detection

```text
Signature       : ET DROP Spamhaus DROP Listed Traffic Inbound
Severity        : 2
Alert Priority  : HIGH

Source IP       : 178.20.210.151
Source Type     : Public IP

Destination IP  : 10.0.15.61
Destination Type: Private IP

Protocol        : TCP
Interface       : ens5
```

### Threat Intelligence

```text
AbuseIPDB Abuse Score : 100
VirusTotal Malicious  : 11
```

### Risk Assessment

```text
Risk Level : CRITICAL
```

### Automated Workflow

```text
Suricata Alert
      ↓
IOC Extraction
      ↓
AbuseIPDB Enrichment
      ↓
VirusTotal Enrichment
      ↓
Risk Calculation
      ↓
Risk Explanation
      ↓
MITRE ATT&CK Mapping
      ↓
Incident Report
```

> ⚠️ **Important:** This is laboratory validation evidence. It is not a claim that the source IP was attacking a production system. Threat-intelligence results and IDS alerts are investigation signals that require analyst validation and context.

---

# 📊 Project Validation

<table>
<tr>
<td>✅ Suricata configuration</td>
<td>✅ IDS service validation</td>
</tr>

<tr>
<td>✅ Custom detection rules</td>
<td>✅ EVE JSON processing</td>
</tr>

<tr>
<td>✅ Stateful processing</td>
<td>✅ IOC extraction</td>
</tr>

<tr>
<td>✅ AbuseIPDB enrichment</td>
<td>✅ VirusTotal enrichment</td>
</tr>

<tr>
<td>✅ Alert priority</td>
<td>✅ Risk engine</td>
</tr>

<tr>
<td>✅ Risk explanation</td>
<td>✅ MITRE mapping</td>
</tr>

<tr>
<td>✅ Incident reporting</td>
<td>✅ End-to-end validation</td>
</tr>

<tr>
<td>✅ Python compilation</td>
<td>✅ Git validation</td>
</tr>
</table>

---

# 📸 Project Evidence

All implementation evidence is available in:

```text
screenshots/
```

## Infrastructure

| Evidence | Screenshot |
|---|---|
| Suricata installation | [01-suricata-installed](screenshots/01-suricata-installed.png) |
| Network interface | [02-network-interface](screenshots/02-network-interface.png) |
| Suricata interface configuration | [03-suricata-interface-config](screenshots/03-suricata-interface-config.png) |
| Configuration validation | [04-suricata-config-test](screenshots/04-suricata-config-test.png) |
| Suricata running | [05-suricata-running](screenshots/05-suricata-running.png) |

## Detection & Parsing

| Evidence | Screenshot |
|---|---|
| Custom detection | [06-custom-rule-and-test](screenshots/06-custom-rule-and-test.png) |
| Python parser | [07-python-parser](screenshots/07-python-parser.png) |
| IOC extraction | [08-ioc-extraction](screenshots/08-ioc-extraction.png) |
| IOC parser | [09-python-ioc-parser](screenshots/09-python-ioc-parser.png) |

## Threat Intelligence

| Evidence | Screenshot |
|---|---|
| AbuseIPDB enrichment | [10-abuseipdb-enrichment](screenshots/10-abuseipdb-enrichment.png) |

## Risk Assessment

| Evidence | Screenshot |
|---|---|
| Risk engine | [11-risk-engine](screenshots/11-risk-engine.png) |
| Integrated risk assessment | [12-integrated-risk-assessment](screenshots/12-integrated-risk-assessment.png) |
| Alert priority | [21-alert-priority-in-pipeline](screenshots/21-alert-priority-in-pipeline.png) |
| Risk explanation | [22-risk-engine-explanation](screenshots/22-risk-engine-explanation.png) |
| Risk explanation in pipeline | [23-risk-explanation-in-pipeline](screenshots/23-risk-explanation-in-pipeline.png) |

## Incident Automation

| Evidence | Screenshot |
|---|---|
| Automated incident reports | [13-automated-incident-reports](screenshots/13-automated-incident-reports.png) |
| New alert processing | [14-new-alert-automated-processing](screenshots/14-new-alert-automated-processing.png) |
| Unique report filenames | [16-unique-incident-report-filenames](screenshots/16-unique-incident-report-filenames.png) |

## MITRE ATT&CK

| Evidence | Screenshot |
|---|---|
| MITRE integration | [15-mitre-attack-integrated-pipeline](screenshots/15-mitre-attack-integrated-pipeline.png) |
| MITRE mapping test | [18-mitre-mapping-test](screenshots/18-mitre-mapping-test.png) |
| SSH scan mapping | [20-mitre-ssh-scan-mapping](screenshots/20-mitre-ssh-scan-mapping.png) |

## End-to-End Validation

| Evidence | Screenshot |
|---|---|
| Full pipeline validation | [19-full-pipeline-validation](screenshots/19-full-pipeline-validation.png) |

---

# 📁 Project Structure

<pre>
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
│   ├── 01-...
│   ├── ...
│   └── 23-...
│
└── docs/
    └── architecture.md
</pre>

---

# 🛠️ Technology Stack

<table>
<tr>
<th>Technology</th>
<th>Purpose</th>
</tr>

<tr>
<td><strong>Suricata</strong></td>
<td>Network IDS and detection engine</td>
</tr>

<tr>
<td><strong>Python</strong></td>
<td>SOC automation and event processing</td>
</tr>

<tr>
<td><strong>AbuseIPDB</strong></td>
<td>IP reputation intelligence</td>
</tr>

<tr>
<td><strong>VirusTotal</strong></td>
<td>Multi-engine threat intelligence</td>
</tr>

<tr>
<td><strong>MITRE ATT&CK</strong></td>
<td>Adversary behavior mapping</td>
</tr>

<tr>
<td><strong>REST APIs</strong></td>
<td>Threat-intelligence integration</td>
</tr>

<tr>
<td><strong>JSON</strong></td>
<td>Security event processing</td>
</tr>

<tr>
<td><strong>YAML</strong></td>
<td>Configuration and mappings</td>
</tr>

<tr>
<td><strong>Markdown</strong></td>
<td>Incident reporting</td>
</tr>

<tr>
<td><strong>Linux</strong></td>
<td>SOC laboratory environment</td>
</tr>

<tr>
<td><strong>Git</strong></td>
<td>Version control</td>
</tr>
</table>

---

# ⚙️ Installation

## 1. Clone

```bash
git clone https://github.com/Sayanhakerz/soc-threat-enrichment-automation.git
cd soc-threat-enrichment-automation
```

## 2. Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🔐 API Configuration

Create a local `.env` file:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

Never commit `.env`.

Use:

```text
.env.example
```

as the configuration reference.

The repository excludes `.env` through `.gitignore`.

---

# ▶️ Running the Automation

Activate the environment:

```bash
source .venv/bin/activate
```

Run the parser:

```bash
python3 src/parser.py
```

The parser reads new Suricata EVE JSON events and performs the configured investigation workflow.

---

# 🔒 Security Design

### Credential Protection

API credentials are stored locally in:

```text
.env
```

and excluded from Git.

Only placeholders are committed through:

```text
.env.example
```

### Private IP Protection

Private/internal addresses are identified before public threat-intelligence queries.

### Analyst-in-the-Loop

Automated risk classification is treated as a **triage signal**, not an autonomous final incident verdict.

### MITRE Confidence

Mappings include confidence and rationale to avoid overstating what an IDS signature proves.

---

# 💼 Skills Demonstrated

## SOC Operations

- Alert monitoring
- Alert triage
- IOC investigation
- Threat-intelligence enrichment
- Risk prioritization
- Incident documentation

## Network Security

- IDS concepts
- Suricata
- Detection rules
- EVE JSON
- Network event analysis
- IP classification
- Protocol analysis

## Security Automation

- Python
- REST API integration
- JSON parsing
- Stateful processing
- Automation workflows
- Structured reporting

## Threat Intelligence

- AbuseIPDB
- VirusTotal
- IP reputation analysis
- IOC enrichment
- Multi-source investigation

## Detection Engineering

- Custom Suricata rules
- Signature processing
- Severity handling
- Alert prioritization
- Detection-to-framework mapping

## MITRE ATT&CK

- Tactic identification
- Technique mapping
- Confidence assessment
- Detection rationale

## Linux / DevOps

- Linux administration
- Service management
- Configuration management
- Virtual environments
- Git
- Repository management

---

# 🎓 Target Roles

<div align="center">

<table>
<tr>
<td>🛡️ SOC Analyst L1</td>
<td>🔐 Junior SOC Analyst</td>
</tr>

<tr>
<td>💻 Cybersecurity Intern</td>
<td>🛡️ Security Operations Intern</td>
</tr>

<tr>
<td>🔎 Security Monitoring Analyst</td>
<td>🔵 Blue Team Intern</td>
</tr>

<tr>
<td>🔐 Junior Security Analyst</td>
<td>🚨 Threat Monitoring Intern</td>
</tr>
</table>

</div>

---

# 🔮 Future Improvements

The following are planned extensions and are **not presented as implemented functionality**:

- Wazuh SIEM integration
- Elasticsearch / OpenSearch integratio
