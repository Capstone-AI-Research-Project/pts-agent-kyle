# Agent Kyle: CyberAnalysis with Structured Agents

> Multi-agent cybersecurity investigation system: six specialized AI agents, nine investigation types, four security frameworks, one analyst-ready report.

## Project Overview

`PTS-CASA` (**P**roject **T**wilight **S**ynapse - **C**yber**A**nalysis with **S**tructured **A**gents) is a multi-agent cybersecurity investigation system built on the same local Docker / n8n / Ollama / Open WebUI stack established by [Project-Twilight-Synapse](https://github.com/Capstone-AI-Research-Project/Project-Twilight-Synapse). Six specialized AI agents - orchestrated through n8n workflows and powered entirely by local Ollama models - analyze security events across nine investigation types, match findings against four real security-framework datasets (MITRE ATT&CK, MITRE CAR, NIST CSF 2.0, CIS Controls v8.1.2), and produce NIST SP 800-92-aligned investigation reports.

An **Overseer** agent then cross-correlates all sub-reports into a unified, analyst-ready output. The pipeline is designed to run fully offline, no third-party LLM API calls and is deployable to either an AWS EC2 instance or a homelab Proxmox host.

## Architecture

**Master Workflow (v2 - 9 nodes, single-path pipeline):**
```
Analyst Query
    |
    v
Webhook Trigger
    |
    v
Router (casa-router) ──> Parse Router Output
    |
    v
Investigation Scanner ─── identifies 1+ investigation paths from Router + keyword analysis
    |
    v                     (one item per matched type — executes sequentially)
Dynamic Sub-Workflow Router ──> calls the matching sub-workflow(s)
    |
    v
Results Collector ─── deduplicates MITRE / NIST / CIS across all sub-reports
    |
    v
Overseer (casa-overseer) ─── cross-correlates, builds attack narrative, prioritizes
    |
    v
Final Report Formatter ──> Respond to Webhook ──> Open WebUI
```

**Each Sub-Workflow (11 nodes) — full analysis pipeline:**
```
Log Analyst ─┐
             ├─> Merge ─> MITRE ATT&CK Lookup ─> CAR Coverage Lookup
Net Analyst ─┘             ─> NIST CSF Mapper ─> CIS Controls Mapper
                           ─> PurpleTeamMapper ─> Synthesizer ─> Report Formatter
```

> Beaconing uses a single Network Analyst (no merge). All other types run Log + Network in parallel.

## Stack

| Service | Image | Purpose |
|---------|-------|---------|
| Ollama | `ollama/ollama:latest` | Local LLM inference (CPU or GPU) |
| Open WebUI | `ghcr.io/open-webui/open-webui:main` | Chat interface for analysts |
| n8n | `n8nio/n8n:latest` | Workflow orchestration |
| PostgreSQL | `pgvector/pgvector:pg16` | n8n database |
| Redis | `redis:7-alpine` | n8n queue |

## Agent Models

| Agent | Ollama Model | Base | Role |
|-------|-------------|------|------|
| Router | `casa-router` | phi3:3.8b | Fast query classification to investigation type |
| Log Analyst | `casa-log-analyst` | qwen2.5:14b | Morgan Chen - NIST SP 800-92 log analysis |
| Network Analyst | `casa-network-analyst` | qwen2.5:14b | Jordan Rivers - Traffic and beaconing detection |
| PurpleTeamMapper | `casa-purple-mapper` | phi3:3.8b | Alex Reyes - Validates framework mappings with evidence |
| Synthesizer | `casa-synthesizer` | qwen2.5:7b | Combines single-path findings into structured report |
| **Overseer** | **`casa-overseer`** | **qwen2.5:14b** | **Final synthesis - cross-correlates all sub-reports into unified analyst report** |

## Investigation Types

| Type | Triggers | Agents Used |
|------|----------|-------------|
| Auth Anomaly | Failed logins, credential stuffing, brute force | Log + Network |
| Beaconing | Periodic connections, C2 callbacks, DNS tunneling | Network |
| Exfiltration | Large transfers, data staging, after-hours access | Log + Network |
| Lateral Movement | East-west traffic, pass-the-hash, credential reuse | Log + Network |
| Privilege Escalation | Token manipulation, UAC bypass, sudo abuse | Log + Network |
| Persistence | Registry keys, scheduled tasks, services, cron jobs | Log + Network |
| Ransomware | File encryption, shadow copy deletion, ransom demands | Log + Network |
| Insider Threat | Policy violations, data hoarding, after-hours access | Log + Network |
| Vulnerability Exploitation | CVE exploitation, web shells, injection attacks | Log + Network |

When a query matches multiple types (e.g., logs showing both lateral movement and privilege escalation), the Investigation Scanner identifies all relevant paths and the Overseer merges the results.

## Framework Integration

The pipeline uses **deterministic lookups** against real framework data - LLMs provide reasoning, structured data provides facts:

| Framework | Asset | Coverage |
|-----------|-------|----------|
| **MITRE ATT&CK** | `mitre-attack-techniques.json` | 160 Enterprise techniques with keywords and detection guidance |
| **MITRE CAR Coverage** | `car-analytic-coverage.json` | 588 techniques with CAR / Sigma / ES SIEM / Splunk detection counts |
| **NIST CSF 2.0** | `nist-csf-2.0.json` | 6 functions, 22 categories, 106 subcategories |
| **CIS Controls v8.1.2** | `cis-controls-v8.1.2.json` | 18 controls, 153 safeguards with IG1/IG2/IG3 classification |
| **Technique-to-Controls Map** | `mitre-to-controls-map.json` | 160 techniques mapped to specific CIS safeguards + NIST CSF categories |

### What each framework contributes to the report

- **MITRE ATT&CK**: identifies the specific adversary techniques observed (T-codes)
- **MITRE CAR Coverage**: for each matched technique, shows how many community detections exist; flags zero-coverage techniques as highest-priority detection engineering gaps
- **NIST CSF 2.0**: maps findings to security function areas (Govern, Identify, Protect, Detect, Respond, Recover) for executive-level classification
- **CIS Controls v8.1.2**: produces prioritized, actionable safeguard recommendations; IG1 safeguards are surfaced as "quick wins"
- **Technique-to-Controls Map**: deterministic mapping from identified MITRE techniques to the specific CIS safeguards and NIST categories that address them (replaces keyword-only matching)

## Report Output

Each investigation produces a structured report with Overseer synthesis:

```
1. Executive Summary      — query, analysis mode, risk level, framework counts
2. Overseer Analysis      — cross-correlated findings, attack narrative, top 5 recommendations
3. MITRE ATT&CK Mapping   — combined techniques from all analysis paths with detection coverage
4. NIST CSF 2.0           — incident classification by security function
5. CIS Controls v8.1.2    — technique-mapped safeguard recommendations with IG1 quick wins
6. Evidence Chain         — investigation flow from query to report
```

---

## Quick Start

### Prerequisites
- Docker and Docker Compose
- 16GB+ RAM (64GB recommended - see [Memory Requirements](#memory-requirements))
- 4+ CPU cores (16 recommended)
- 100GB storage

### Step 1: Clone and configure

```bash
git clone https://github.com/Capstone-AI-Research-Project/pts-agent-kyle.git
cd pts-agent-kyle

cp .env.example .env
# Edit .env — set passwords, timezone, tune Ollama for your hardware
```

### Step 2: Start the stack

```bash
docker compose up --build -d

# Wait 2-3 minutes for all services to start
docker compose ps    # All services should show "running" or "healthy"
```

### Step 3: Build CASA agent models

```bash
bash scripts/build-models.sh
```

This script:
1. Pulls the 3 base models (phi3:3.8b, qwen2.5:7b, qwen2.5:14b)
2. Creates all 6 CASA agent models from Modelfiles
3. Verifies framework data assets are accessible in the n8n container

### Step 4: Verify models 
_*optional but recommended_
```bash
bash scripts/test-models.sh
```

Runs a quick smoke test against all 6 models to confirm they respond correctly.

### Step 5: Import workflows into n8n

Open n8n at `http://localhost:5678` (credentials from your `.env` file).

**Import the 9 sub-workflows first:**

1. Go to **Workflows > Import from File**
2. Import each `workflows/casa-*.json` file **except** `casa-master-v2.json`
3. For each imported sub-workflow:
   - Open the **Execute Workflow Trigger** node and ensure **Input data mode** is set to **Accept all data**
   - If the sub-workflow contains a **Merge** node, ensure its mode is set to **Append**
   - **Publish** the workflow and continue adding all sub-workflows
4. Note the workflow ID for each (visible in the URL: `http://localhost:5678/workflow/XXXXXX`)

**Import the master workflow:**

5. Import `workflows/casa-master-v2.json`
6. Open the **Dynamic Sub-Workflow Router** node
7. In the `workflowId` expression, replace each `REPLACE_WITH_ACTUAL_ID` with the real workflow IDs you noted:
   ```
   auth_anomaly: "your-auth-anomaly-id"
   beaconing: "your-beaconing-id"
   exfiltration: "your-exfiltration-id"
   lateral_movement: "your-lateral-movement-id"
   privilege_escalation: "your-privesc-id"
   persistence: "your-persistence-id"
   ransomware: "your-ransomware-id"
   insider_threat: "your-insider-threat-id"
   vulnerability_exploitation: "your-vuln-exploit-id"
   ```
8. **Activate** the master workflow

### Step 6: Install Open WebUI function

1. Open Open WebUI at `http://localhost:3000`
2. Go to **Workspace > Functions > "+" (Create)**
3. Paste the contents of `functions/casa_pipe.py`
4. Save and enable
5. Go to **Settings > Documents** > change **Top K** to **0** (default is 3); default RAG template is fine

### Step 7: Test the pipeline

```bash
# Quick test via curl
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "500 failed SSH logins from 192.168.1.100 targeting root in 5 minutes"}'
```

Or open Open WebUI, select **"CASA CyberAnalysis"** from the model dropdown, and type a query.

---

## Usage

### Via Open WebUI
1. Select **"CASA CyberAnalysis"** from the model dropdown
2. Type a security investigation query or upload a log file
3. Wait for the pipeline to complete (~2 min on AWS, ~10-30 min on homelab CPU)
4. Receive a formatted investigation report with framework mappings and prioritized recommendations

### Via curl
```bash
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "YOUR SECURITY INVESTIGATION QUERY HERE"}'
```

### Sample queries

Sample queries and log files are provided in the `logs/` directory. See `logs/SAMPLE-QUERIES.md` for 14 ready-to-use test scenarios covering all 9 investigation types plus 5 comprehensive multi-type tests.

```
# Auth Anomaly
"500 failed SSH logins from 192.168.1.100 targeting root in 5 minutes,
 followed by successful login and new user creation"

# Beaconing / C2
"Workstation at 10.0.5.42 making HTTPS connections every 60 seconds
 to a domain registered 3 days ago"

# Lateral Movement
"After phishing compromise on WORKSTATION-12, same credentials
 authenticating to 6 servers via SMB in 20 minutes"

# Ransomware
"Shadow copies deleted, boot recovery disabled, files renamed with
 .encrypted extension across network shares, README_TO_DECRYPT.txt appearing"
```

---

## File Structure

```
pts-agent-kyle/
├── assets/                                  # Framework data (auto-mounted into n8n)
│   ├── mitre-attack-techniques.json        # 160 MITRE ATT&CK Enterprise techniques
│   ├── mitre-to-controls-map.json          # Technique → CIS + NIST deterministic mappings
│   ├── car-analytic-coverage.json          # 588 techniques with detection counts
│   ├── nist-csf-2.0.json                   # NIST CSF 2.0 complete framework
│   ├── cis-controls-v8.1.2.json            # CIS Controls v8.1.2 — 153 safeguards
│   └── report-template.json                # Report section definitions
├── functions/
│   └── casa_pipe.py                        # Open WebUI Pipe function
├── modelfiles/                              # Ollama Modelfiles (6 agents)
│   ├── casa-router.Modelfile               # phi3:3.8b — query classifier
│   ├── casa-log-analyst.Modelfile          # qwen2.5:14b — log analysis
│   ├── casa-network-analyst.Modelfile      # qwen2.5:14b — network analysis
│   ├── casa-purple-mapper.Modelfile        # phi3:3.8b — framework validation
│   ├── casa-synthesizer.Modelfile          # qwen2.5:7b — single-path report synthesis
│   └── casa-overseer.Modelfile             # qwen2.5:14b — final cross-report synthesis
├── logs/                                    # Sample log files for testing
│   ├── SAMPLE-QUERIES.md                   # 14 ready-to-use test scenarios
│   ├── auth-anomaly-host.log               # Sample logs for each investigation type
│   ├── auth-anomaly-network.log
│   └── ...                                 # (18 log files total)
├── scripts/
│   ├── build-models.sh                     # Pull base models + create all 6 CASA agents
│   ├── test-models.sh                      # Smoke test all agents
│   ├── build-technique-controls-map.py     # Regenerate technique-to-controls mapping
│   ├── convert-car-coverage.js             # Regenerate CAR coverage from source CSV
│   └── convert-cis-controls.py             # Regenerate CIS controls from source Excel
├── workflows/                               # n8n workflow definitions
│   ├── casa-master-v2.json                 # Master v2 (9 nodes — single-path with Overseer)
│   ├── casa-auth-anomaly.json              # Sub-workflow (11 nodes each)
│   ├── casa-beaconing.json
│   ├── casa-exfiltration.json
│   ├── casa-lateral-movement.json
│   ├── casa-privilege-escalation.json
│   ├── casa-persistence.json
│   ├── casa-ransomware.json
│   ├── casa-insider-threat.json
│   └── casa-vulnerability-exploitation.json
├── docs/
│   ├── PTS-CASA-AWS-Provisioning-Guide.md  # AWS EC2 deployment guide
│   └── n8n-CyberAnalysis-Architecture.md   # Original design spec (historical)
├── docker-compose.yml                       # Full stack (Ollama, Open WebUI, n8n, PostgreSQL, Redis)
├── Dockerfile.runners                       # n8n task runners
├── .env.example                             # Environment configuration template
└── CHANGELOG.md                             # Version history
```

## Deployment Options

| Environment | Specs | Pipeline Time | Notes |
|-------------|-------|---------------|-------|
| **AWS EC2 m7i.4xlarge** | 16 vCPU, 64GB RAM | ~2-5 min | Recommended — all models pre-loaded |
| Homelab / Proxmox | 4-8 CPU, 16-32GB RAM | ~10-30 min | Functional — model swapping adds latency |

See [docs/PTS-CASA-AWS-Provisioning-Guide.md](docs/PTS-CASA-AWS-Provisioning-Guide.md) for full AWS setup instructions.

### Memory Requirements

| Component | RAM |
|-----------|-----|
| Docker + services | ~3GB |
| phi3:3.8b (Router + PurpleMapper) | ~2.5GB each |
| qwen2.5:14b (Log Analyst + Network Analyst + Overseer) | ~9GB each |
| qwen2.5:7b (Synthesizer) | ~5GB |
| **Minimum (model swapping)** | **16GB** |
| **Recommended (all loaded)** | **64GB** |

## Standards Compliance

| Standard | Usage |
|----------|-------|
| **NIST SP 800-92** | Report format and log analysis methodology |
| **NIST CSF 2.0** | Findings mapped to Govern, Identify, Protect, Detect, Respond, Recover |
| **MITRE ATT&CK** | Technique identification via deterministic lookup against Enterprise framework |
| **MITRE CAR** | Detection coverage from community analytic repositories |
| **CIS Controls v8.1.2** | Technique-mapped safeguard recommendations with Implementation Group prioritization |

## Authors

| Name | GitHub Profile |
|------|----------------|
| Kyle Versluis | [![GitHub](https://img.shields.io/badge/GitHub-ktalons-181717?style=for-the-badge&logo=github)](https://github.com/ktalons) |
| Spencer Nicol | [![GitHub](https://img.shields.io/badge/GitHub-snicol1-181717?style=for-the-badge&logo=github)](https://github.com/snicol1) |

## Related projects

- [Project-Twilight-Synapse](https://github.com/Capstone-AI-Research-Project/Project-Twilight-Synapse) - original foundation project that established the Docker / n8n / Ollama / Open WebUI stack PTS-CASA extends.
- [pts-agent-karen](https://github.com/Capstone-AI-Research-Project/pts-agent-karen) - sibling research agent under the same naming convention; focuses on log and PCAP behavior detection via Weaviate semantic search against MITRE ATT&CK.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.
