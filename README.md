Skip to content
shaunhacker
micro-soc-lab
Repository navigation
Code
Issues
Pull requests
Agents
Actions
Projects
Wiki
Security and quality
Insights
Settings
Files
Go to file
t
T
README.md
micro-soc-lab
/
README.md
in
main

Edit

Preview
Indent mode

Spaces
Indent size

2
Line wrap mode

Soft wrap
Editing README.md file contents
  2
  3
  4
  5
  6
  7
  8
  9
 10
 11
 12
 13
 14
 15
 16
 17
 18
 19
 20
 21
 22
 23
 24
 25
 26
 27
 28
 29
 30
 31
 32
 33
 34
 35
 36
 37
 38
 39
 40
 41
 42
 43
 44
 45
 46
 47
 48
 49
 50
 51
# 🛡️ Micro SIEM & SOAR Laboratory

An event-driven, lightweight Security Operations Center (SOC) lab built to demonstrate real-time log ingestion, detection engineering, and automated incident enrichment/containment within containerized, memory-constrained environments (<50 MB RAM footprint).

---

## 🏗️ Architecture Overview

                  ┌──────────────────────────────────────────┐
                  │          Public Webhook Ingest           │
                  │  (Simulated Firewall / Phishing Alert)   │
                  └────────────────────┬─────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐│                       FLASK SINGLE-CONTAINER ENGINE                         ││                                                                             ││   ┌───────────────────────────┐         ┌───────────────────────────────┐   ││   │         SIEM Core         │         │           SOAR Core           │   ││   │ - Log Ingestion & Parsing │         │ - Async Playbook Engine       │   ││   │ - Detection Rules         │────────>│ - Threat Intel APIs (VT)      │   ││   │ - SQLite Storage Engine   │         │ - Automated Triage Logic      │   ││   └─────────────┬─────────────┘         └───────────────┬───────────────┘   ││                 │                                       │                   ││                 └───────────────────┬───────────────────┘                   ││                                     ▼                                       ││                       ┌───────────────────────────┐                         ││                       │   Real-Time Web Dashboard │                         ││                       │   (HTML5 + Tailwind CSS)  │                         ││                       └───────────────────────────┘                         │└─────────────────────────────────────────────────────────────────────────────┘
---

## ✨ Features

* **SIEM Functionality:**
  * Endpoint REST API (`/api/ingest`) accepting JSON telemetry from firewalls, endpoints, and phishing simulation webhooks.
  * Real-time rule evaluation (parsing high-severity conditions such as brute force or malware execution).
  * Lightweight SQLite persistence store for log history and audit trails.

* **SOAR Functionality:**
  * Asynchronous execution engine that triggers automated playbooks on high-severity SIEM events without blocking log ingestion.
  * Direct Threat Intelligence enrichment via the VirusTotal v3 API.
  * Dynamic incident containment classification and triage summary generation.

* **Monitoring & Visibility:**
  * Live HTML5/Tailwind CSS dashboard displaying real-time SIEM alerts alongside SOAR playbook execution metrics side-by-side.

---

## 🚀 API Endpoint & Testing

To test the SIEM ingest and trigger an automated SOAR playbook workflow, send a `POST` request to the ingestion endpoint:

### Example Webhook Payload (`curl`)

```bash
curl -X POST [https://YOUR-APP-URL.onrender.com/api/ingest](https://YOUR-APP-URL.onrender.com/api/ingest) \
  -H "Content-Type: application/json" \
  -d '{
        "source": "PaloAltoFirewall",
        "event_type": "failed_login",
        "ip": "8.8.8.8",
        "details": "Multiple failed SSH authentication attempts detected."
      }'
⚙️ Environment VariablesVariableDescriptionRequired?VIRUSTOTAL_API_KEYVirusTotal API Key for real-time IP threat intelligence lookupsOptional (Fallback mode active if absent)PORTContainer binding port (Defaults to 5000)Optional

Use Control + Shift + m to toggle the tab key moving focus. Alternatively, use esc then tab to move to the next interactive element on the page.
No file chosen
Attach files by dragging & dropping, selecting or pasting them.
Editing micro-soc-lab/README.md at main · shaunhacker/micro-soc-lab 
