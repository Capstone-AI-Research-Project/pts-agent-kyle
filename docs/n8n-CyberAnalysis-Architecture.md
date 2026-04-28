# CASA CyberAnalysis — n8n Workflow Architecture (Historical Design Spec)

> **Note:** This is the original architecture design document from Feb 2026. It describes the planned architecture using Anthropic Claude API keys and cloud LLMs. The actual implementation uses local Ollama models (phi3:3.8b, qwen2.5:14b, qwen2.5:7b) on Docker. For current documentation, see the [README](../README.md) and other docs in this directory.

> Original: 2026-02-23 | Last reference update: 2026-04-01

---

## 1. Stack Overview

CASA runs entirely local on CPU. All LLM inference uses Ollama — no external API keys required.

| Service | Image | Purpose |
|---------|-------|---------|
| Ollama | `ollama/ollama:latest` | Local LLM inference (CPU) |
| Open WebUI | `ghcr.io/open-webui/open-webui:main` | Chat interface for analysts |
| n8n | `n8nio/n8n:latest` | Workflow orchestration |
| PostgreSQL | `pgvector/pgvector:pg16` | n8n operational database |
| Redis | `redis:7-alpine` | n8n queue (parallel execution) |

### Agent Models

| Agent | Ollama Model | Base | Role |
|-------|-------------|------|------|
| Router | `casa-router` | phi3:3.8b | Fast query classification to JSON |
| Log Analyst | `casa-log-analyst` | qwen2.5:7b | Morgan Chen — NIST SP 800-92 log analysis |
| Network Analyst | `casa-network-analyst` | qwen2.5:7b | Jordan Rivers — Traffic and beaconing detection |
| PurpleTeamMapper | `casa-purple-mapper` | qwen2.5:7b | Alex Reyes — Validates all framework mappings |
| Synthesizer | `casa-synthesizer` | qwen2.5:7b | Combines findings into structured report |

### Required Environment Variables

```env
# Core
N8N_HOST=0.0.0.0
N8N_PORT=5678
N8N_ENCRYPTION_KEY=<generate-a-strong-key>

# Queue mode for parallel agent execution
EXECUTIONS_MODE=queue
QUEUE_BULL_REDIS_HOST=redis

# Execution settings
EXECUTIONS_TIMEOUT=600          # 10 min for complex investigations
EXECUTIONS_DATA_SAVE_ON_SUCCESS=all  # Audit trail

# Ollama endpoint (from n8n container perspective)
OLLAMA_HOST=http://ollama:11434
```

---

## 2. Master Workflow Topology

```
┌─────────────────────────────────────────────────────────┐
│   Webhook Trigger                                        │
│   POST /webhook/casa-investigate                        │
│   { "query": "security investigation query" }           │
└──────────────────────┬──────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────────────┐
│  HTTP Node → casa-router (Ollama / phi3:3.8b)           │
│  Classifies: domain + investigation_type → JSON          │
└──────────────────────┬──────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────────────┐
│  Code Node: Parse Router Output                         │
│  Extracts structured JSON from model response           │
└──────────────────────┬──────────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────────────┐
│  Switch Node: Investigation Type                        │
│  Routes on investigation_type field                     │
└──────┬──────────┬──────────┬──────────┬─────────────────┘
       │          │          │          │
       ↓          ↓          ↓          ↓
  auth_anomaly  beaconing  exfiltration  lateral_movement
  Sub-Workflow  Sub-Workflow Sub-Workflow Sub-Workflow
       │          │          │          │
       └──────────┴──────────┴──────────┘
                            │
                            ↓ (general falls through to domain switch)
                   ┌────────────────┐
                   │  Domain Switch │
                   └──┬──────┬──────┘
                      │      │
                      ↓      ↓
                 Log Agent  Net Agent
                 (parallel for mixed)
                      │      │
                      └──┬───┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│  CODE: MITRE Lookup                                        │
│  assets/mitre-attack-techniques.json (160 techniques)     │
│  Keyword matching → matched T-codes + detection guidance  │
└────────────────────────┬───────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│  CODE: CAR Coverage Lookup  ← NEW in v2.0                 │
│  assets/car-analytic-coverage.json (588 techniques)       │
│  Enriches each technique with CAR/Sigma/ES SIEM/Splunk   │
│  Identifies coverage_gaps (total=0) and low_coverage (<5) │
└────────────────────────┬───────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│  CODE: NIST CSF Mapper                                     │
│  assets/nist-csf-2.0.json (6 functions, 22 categories)   │
│  Maps findings → function areas + relevant subcategories  │
└────────────────────────┬───────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│  CODE: CIS Controls Mapper  ← NEW in v2.0                 │
│  assets/cis-controls-v8.1.2.json (18 controls, 153 SGs)  │
│  Scores safeguards via keyword + MITRE tactic correlation │
│  Returns top safeguards grouped by control + IG1 wins    │
└────────────────────────┬───────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│  HTTP: PurpleTeamMapper (casa-purple-mapper / qwen2.5:7b) │
│  Alex Reyes — validates all 4 framework matches           │
│  Reviews CIS safeguards, flags zero-coverage techniques   │
└────────────────────────┬───────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│  HTTP: Synthesizer (casa-synthesizer / qwen2.5:7b)        │
│  Combines all findings into structured report input       │
└────────────────────────┬───────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│  CODE: Report Formatter (v2.0)                            │
│  Pulls from all 4 named nodes via $('Node Name').first()  │
│  Assembles 8-section NIST SP 800-92 investigation report  │
└────────────────────────┬───────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│  Respond to Webhook                                       │
│  Returns: investigation_report, risk_level, confidence,   │
│           mitre_techniques, nist_csf_functions,           │
│           cis_controls, coverage_gaps                     │
└────────────────────────────────────────────────────────────┘
```

---

## 3. Framework Data Nodes (Deterministic Lookups)

LLMs provide reasoning. Structured data provides facts. All four framework nodes use deterministic keyword/scoring logic — no LLM calls.

### MITRE Lookup

- **Type:** Code node (JavaScript)
- **Source:** `assets/mitre-attack-techniques.json` (160 Enterprise techniques)
- **Logic:** Split `analyst_findings` into tokens, match against `keywords[]` per technique, rank by score
- **Output:** `techniques[]` (matched T-codes with name, tactics, detection guidance)
- **Reference:** `scripts/n8n-nodes/mitre-lookup.js`

### CAR Coverage Lookup *(new in v2.0)*

- **Type:** Code node (JavaScript)
- **Source:** `assets/car-analytic-coverage.json` (588 techniques)
- **Logic:** Build `Map<techniqueId, coverage>`, enrich each matched technique with detection counts
- **Coverage fields:** `car`, `sigma`, `es_siem`, `splunk`, `total`
- **Gap detection:** `total === 0` → `coverage_gaps[]`; `total < 5` → `low_coverage[]`
- **Reference:** `scripts/n8n-nodes/car-coverage-lookup.js`

### NIST CSF Mapper

- **Type:** Code node (JavaScript)
- **Source:** `assets/nist-csf-2.0.json` (6 functions, 22 categories, 106 subcategories)
- **Logic:** Keyword scoring per subcategory, grouped by function; returns top 2-3 categories per function
- **Output:** `nist_csf_mappings[]` (function_id, function_name, categories with relevant_subcategories)
- **Reference:** `scripts/n8n-nodes/nist-csf-mapper.js`

### CIS Controls Mapper *(new in v2.0)*

- **Type:** Code node (JavaScript)
- **Source:** `assets/cis-controls-v8.1.2.json` (18 controls, 153 safeguards)
- **Scoring algorithm:**
  - +1 per keyword match in `analyst_findings`
  - +3 if safeguard title appears in findings
  - +0.5 per MITRE tactic → CIS security function alignment
  - +0.25 × `coverage_gaps.length` for Detect-function safeguards (when gaps exist)
- **Output:** `cis_mappings[]` (top 12 safeguards grouped by control), `cis_quick_wins[]` (IG1 safeguards only, top 6)
- **Reference:** `scripts/n8n-nodes/cis-controls-mapper.js`

---

## 4. Sub-Workflow Structure

Each of the 4 investigation types runs as an n8n sub-workflow with its own internal node chain.

| Sub-Workflow | Agents Used | Node Count |
|-------------|-------------|------------|
| `casa-auth-anomaly.json` | Log + Network (parallel) | 11 nodes |
| `casa-beaconing.json` | Network only | 9 nodes |
| `casa-exfiltration.json` | Log + Network (parallel) | 11 nodes |
| `casa-lateral-movement.json` | Log + Network (parallel) | 11 nodes |

**Internal node chain per sub-workflow:**
```
Execute Workflow Trigger
      ↓
Log Analyst + Network Analyst (parallel HTTP calls to Ollama)
      ↓
Merge (Append mode)
      ↓
MITRE Lookup → CAR Coverage Lookup → NIST CSF Mapper → CIS Controls Mapper
      ↓
PurpleTeamMapper → Synthesizer → Report Formatter
```

**Setup notes:**
- Set `Execute Workflow Trigger` to "Accept all data" mode
- Set all `Merge` nodes to "Append" mode
- Activate/publish all 4 sub-workflows before activating master
- After importing, update the 4 `Execute Sub-Workflow` nodes in master with real sub-workflow IDs

---

## 5. Report Output Structure (NIST SP 800-92)

The Report Formatter assembles an 8-section standardized report:

```
1. EXECUTIVE SUMMARY
   - Query, investigation type, risk level, confidence
   - MITRE technique count, NIST CSF functions count
   - CIS controls recommended, CIS quick wins count
   - Detection coverage gaps count

2. INCIDENT CLASSIFICATION (NIST CSF 2.0)
   - Mapped functions (GV/ID/PR/DE/RS/RC)
   - Relevant categories and subcategory IDs

3. TECHNICAL FINDINGS
   - Full synthesizer output

4. MITRE ATT&CK MAPPING
   - T-codes with tactic coverage
   - Per-technique CAR/Sigma/ES SIEM/Splunk counts

5. DETECTION GAPS & RECOMMENDATIONS
   - Technique-level detection guidance
   - ⚠️ ZERO-COVERAGE techniques (no community rules anywhere)
   - ⚠️ LOW-COVERAGE techniques (total < 5 rules)

5.5 ANALYTIC COVERAGE (MITRE CAR / Sigma / ES SIEM / Splunk)
   - Per-technique coverage matrix
   - Techniques flagged: ⚠️ NO DETECTIONS | ⚠️ LOW COVERAGE

5.6 CIS CONTROLS v8.1.2 RECOMMENDATIONS
   - Quick Wins (IG1 safeguards — applicable to all organizations)
   - Priority controls grouped by CIS Control number
   - Implementation Group tags [IG1/IG2/IG3] + security function

6. RECOMMENDED ACTIONS
   - Prioritized by risk level
   - References CIS Section 5.6 quick wins

7. CONFIDENCE ASSESSMENT
   - Overall confidence with reasoning
   - Technique match count, NIST functions covered
   - CIS controls matched, coverage gaps identified

8. EVIDENCE CHAIN
   - Investigation flow from query to report
   - Tracing through all 4 framework lookups
```

---

## 6. Agent Prompt Design

### Router (casa-router / phi3:3.8b)

Fast classifier. Returns only structured JSON.

```
Classify this cybersecurity query and return ONLY valid JSON:
{
  "domain": "log|network|mixed",
  "investigation_type": "auth_anomaly|beaconing|exfiltration|lateral_movement|general",
  "context_summary": "brief restatement",
  "priority_focus": "key question to answer"
}
```

### Log Analyst (casa-log-analyst / qwen2.5:7b) — Morgan Chen

NIST SP 800-92 methodology. Outputs structured findings with WHAT/WHY/CONFIDENCE/NEXT STEPS.
Key event IDs: 4624, 4625, 4648, 4672, 4768, 4771, 4776.

### Network Analyst (casa-network-analyst / qwen2.5:7b) — Jordan Rivers

Traffic analysis with periodicity scoring. Beaconing: jitter <15% of mean = HIGH score.
Common C2 intervals: 30s, 60s, 300s, 600s, 3600s.

### PurpleTeamMapper (casa-purple-mapper / qwen2.5:7b) — Alex Reyes

**Updated in v2.0.** Validates all 4 framework outputs:
1. Validate MITRE ATT&CK technique matches
2. Validate NIST CSF 2.0 category assignments
3. **Validate CIS Controls v8.1.2 recommendations** — confirm safeguard relevance, prioritize IG1
4. **Reference detection coverage** — flag zero-coverage techniques as highest-priority gaps

### Synthesizer (casa-synthesizer / qwen2.5:7b)

Combines agent findings and framework data into structured input for the Report Formatter.
Outputs natural language with risk level and confidence markers for formatter extraction.

---

## 7. Asset Files

All framework data is mounted into n8n at `/home/node/.n8n/assets/`:

| File | Source | Coverage |
|------|--------|----------|
| `mitre-attack-techniques.json` | MITRE ATT&CK Enterprise | 160 techniques, keywords, detection guidance |
| `car-analytic-coverage.json` | MITRE CAR (2024-01-08) | 588 techniques, detection counts per repository |
| `nist-csf-2.0.json` | NIST CSF 2.0 | 6 functions, 22 categories, 106 subcategories |
| `cis-controls-v8.1.2.json` | CIS Controls (March 2025) | 18 controls, 153 safeguards with IG classification |

**Regenerating assets from source files:**
```bash
# CAR coverage CSV → JSON (Node.js)
node scripts/convert-car-coverage.js

# CIS Controls Excel → JSON (Python + openpyxl)
pip install openpyxl && python3 scripts/convert-cis-controls.py

# Or run both via build script
bash scripts/build-models.sh  # Step [0/7] runs both conversions
```

---

## 8. n8n Settings Reference

| Setting | Value | Why |
|---------|-------|-----|
| `EXECUTIONS_MODE` | `queue` | Enables parallel agent execution |
| `EXECUTIONS_TIMEOUT` | `600` (seconds) | Complex investigations need time |
| `EXECUTIONS_DATA_SAVE_ON_SUCCESS` | `all` | Audit trail for investigations |
| `N8N_ENCRYPTION_KEY` | Strong random string | Encrypts stored credentials |
| HTTP node → Timeout | `300000` ms | 5 min per Ollama call (CPU inference is slow) |
| Merge node → Mode | `Append` | Collects parallel agent outputs |

### Security Considerations

- Run behind a reverse proxy (nginx/Caddy) with TLS
- Use n8n's built-in basic auth or IP allowlisting for webhook endpoint
- Never expose webhook URLs publicly — use VPN for external access
- All LLM inference stays local — no data leaves the host

---

## 9. Parallel Execution Flow

For investigation types using both Log + Network analysts:

```
Execute Workflow Trigger
        ↓
┌───────┴────────┐
│                │   (both branches fire simultaneously)
↓                ↓
HTTP: Log     HTTP: Network
Analyst       Analyst
(Ollama)      (Ollama)
│                │
└───────┬────────┘
        ↓
     Merge (Append)   ← waits for both to complete
        ↓
  Deterministic pipeline continues...
```

n8n handles branch parallelism natively in queue mode. Both Ollama calls run concurrently — peak RAM usage is ~8-9GB (two qwen2.5:7b instances).

---

## 10. Open WebUI Integration

CASA is exposed to analysts via the Open WebUI Pipe function (`functions/casa_pipe.py`).

**How it works:**
1. Analyst selects "CASA CyberAnalysis" from the model dropdown in Open WebUI
2. Query is sent to the Pipe function's `pipe()` method
3. Pipe POSTs to `http://n8n:5678/webhook/casa-investigate` (via Docker network)
4. Status events are emitted via `__event_emitter__` as pipeline progresses
5. `investigation_report` field from n8n response is returned as the assistant message

**Key Pipe function behaviors (v1.3.0):**
- Unwraps n8n array responses: `result[0]` if response is a list
- Unwraps nested `json` key: `result["json"]` if present
- Handles `content` as list (newer OpenWebUI versions): joins `text`-type parts
- Configurable via Valves: n8n endpoint URL, API key (if auth enabled), timeout

**Deployment:** Admin → Functions → Create → paste `functions/casa_pipe.py`
