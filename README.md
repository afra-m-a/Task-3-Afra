# ThreatScope // Malicious Email Analyzer

**Advanced Heuristic Threat Assessment & Triage Engine**

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

---

## Overview

**ThreatScope** is a standalone Python application built for security analysts to quickly triage suspicious messages, calculate precise risk metrics, and automate incident response path assignment. Combining rule-based psychological pattern extraction and a clean graphical interface, the toolkit turns complex message payloads into instant defensive actions.

---

## 🚀 Key Features

- **Live Payload Analysis** – Drop raw email body elements and headers into a dedicated verification zone for immediate signature parsing.
- **Psychological Vector Extraction** – Programmatically tags high-risk language identifiers tracking corporate urgency, coercion, and fear/greed exploits.
- **Dynamic Heuristic Scoring Matrix** – Computes a consolidated metric scale (0–100) using multi-weighted threat indicators.
- **Deterministic Action Routing** – Map alert values directly to standardized enterprise response playbooks:
  - **Score < 35** $\rightarrow$ `SAFE` $\rightarrow$ **CLOSE / ALLOW**
  - **35 ≤ Score ≤ 69** $\rightarrow$ `SUSPICIOUS` $\rightarrow$ **WARN USER & QUARANTINE**
  - **Score ≥ 70** $\rightarrow$ `MALICIOUS` $\rightarrow$ **ESCALATE TO SOC**
- **Threat Simulation Sandbox** – Features pre-configured, high-fidelity threat profiles (BEC "Lost Wallet," ChatGPT SaaS Billing Failure, TOAD Callback Phishing, and HR Policy Updates) for analyst training and platform validation.
- **Structured Log Export** – One-click copy engine to dump complete analytical triage logs directly to clipboard structures for case management systems.

---

## 📁 File Structure

```text
your-folder/
└── gui.py      # Standalone application file containing all parsing, scoring, and UI logic

```

---

## 🛠️ Environment Setup & Installation

### 1. Install Dependencies

```bash
pip install customtkinter

```

### 2. Launch the Application

```bash
python gui.py

```

---

## 🧪 Quick Start Workflow

1. Open the application interface.
2. Paste your raw email or text payload directly into the **Payload & Headers** capture text box.
3. Select **Analyze Payload** to run the underlying verification checks.
4. Evaluate findings via the color-coded **Risk Assessment** gauge, scrollable **Telemetry Flags**, and the primary **Automated Action** banner box.
5. Select **Copy Log Data** to export your structured forensic summary to your case documentation.

---

## 🧠 Heuristic Weighting Logic

| Indicator Category | Analytical Triggers | Points Added |
| --- | --- | --- |
| **High-Risk Keywords** | `wire transfer`, `password reset`, `verify account` | +35 |
| **Financial Inducements** | `bitcoin`, `paypal`, `gift card`, `western union` | +30 |
| **Urgency Parameters** | `urgent`, `within 24 hours`, `account suspended` | +20 |
| **Suspicious Call-to-Action** | `click here`, `verify now`, `update your payment` | +20 |
| **Security Impersonations** | `unusual login`, `suspicious activity`, `security alert` | +25 |
| **Payload Anomalies** | Unexpected financial/invoice attachment indicators | +15 |
| **Infrastructure Defects** | Flagged or deceptive external sender string patterns | +10 |
| **Baseline Filters** | Standard internal keywords (`meeting agenda`, `newsletter`) | -10 |

---

## 🔧 System Customization

### Modifying Keyword Taxonomy

Add target search expressions or specific infrastructure patterns inside `analyze_payload()`:

```python
if re.search(r"your-custom-token", text_lower):
    score += 15
    flags.append(("Description of flag", "critical"))

```

### Adjusting Threshold Boundaries

Tune defensive playbook routing profiles by shifting metric conditions:

```python
if score >= 70:
    risk_level = "MALICIOUS"
elif score >= 35:
    risk_level = "SUSPICIOUS"
else:
    risk_level = "SAFE"

```

---

## 📝 Forensic Log Output Profile Example

```text
=== PHISHING TRIAGE LOG ===
Risk Score: 55/100
Risk Level: SUSPICIOUS
Recommended Action: WARN USER & QUARANTINE
Telemetry Flags:
- High-risk keywords detected (wire transfer, password reset)
- Urgency / threat of suspension
Payload Preview:
From: "CFO John Harrison" <john.harrison@legit-bank-verify.com>...

```

---

## 📄 License & Disclaimer

Distributed under the **MIT License**. Free for educational training, defensive environment development, and authorized research testing.

> **⚠️ Operational Notice:** This tool is explicitly designed for authorized corporate security awareness monitoring, defensive lab training, and incident triage tracking. Never audit production records or inspect live payloads without explicit organizational authorization. The maintainer assumes zero liability for infrastructure engineering decisions or downstream response actions taken using this heuristic software framework.

---

**Stay vigilant. Stay secure.** *ThreatScope // Malicious Email Analyzer*