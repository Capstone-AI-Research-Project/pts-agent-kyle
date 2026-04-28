# CASA Comprehensive Analysis Path — Architecture & Wiring

> **DEPRECATED (v2.2.0):** This guide describes the v1 master workflow architecture with the Investigation Type Switch and dual-path routing. In v2, the Switch was removed in favor of a single-path pipeline (Investigation Scanner → Dynamic Router → Results Collector → Overseer → Respond to Webhook). The concepts below are retained for historical reference only. See the main [README.md](../README.md) for the current architecture.

## Overview (v1 — Historical)

The master workflow routes queries through 5 paths based on the Router agent's classification:

- **9 targeted paths** — auth_anomaly, beaconing, exfiltration, lateral_movement, privilege_escalation, persistence, ransomware, insider_threat, vulnerability_exploitation each route directly to their specialized sub-workflow
- **1 comprehensive fallback** — general/unrecognized queries go through the Keyword Scanner, which dynamically routes to the appropriate sub-workflow(s) based on detected keywords

## Architecture

```
Webhook Trigger → Router → Parse Router Output → Investigation Type Switch
    ├── auth_anomaly ──────────────→ Sub-Workflow Auth Anomaly ──────→ Respond to Webhook
    ├── beaconing ─────────────────→ Sub-Workflow Beaconing ─────────→ Respond to Webhook
    ├── exfiltration ──────────────→ Sub-Workflow Exfiltration ──────→ Respond to Webhook
    ├── lateral_movement ──────────→ Sub-Workflow Lateral Movement ──→ Respond to Webhook
    ├── privilege_escalation ──────→ Sub-Workflow Privilege Esc ─────→ Respond to Webhook
    ├── persistence ───────────────→ Sub-Workflow Persistence ───────→ Respond to Webhook
    ├── ransomware ────────────────→ Sub-Workflow Ransomware ────────→ Respond to Webhook
    ├── insider_threat ────────────→ Sub-Workflow Insider Threat ────→ Respond to Webhook
    ├── vulnerability_exploitation → Sub-Workflow Vuln Exploitation ─→ Respond to Webhook
    └── fallback ──────────────────→ Keyword Scanner
                                         │
                                         ▼
                                    Comp Dynamic Router
                                    (selects sub-workflow by investigation_type)
                                         │
                                         ▼
                                    Comprehensive Report Merger
                                    (combines multi-path results)
                                         │
                                         ▼
                                    Respond to Webhook
```

**Total: 17 nodes.** 9 targeted paths + 1 comprehensive fallback (3 nodes).

## How the Comprehensive Path Works

### Keyword Scanner (Code Node)
- Receives the fallback query from the Investigation Type Switch
- Scans the query text for keywords associated with each investigation type
- Outputs **one item per matched type** — if a query matches both `auth_anomaly` and `lateral_movement`, two items are emitted
- If no keywords match, defaults to `auth_anomaly` (the most comprehensive sub-workflow)
- Source: `scripts/n8n-nodes/keyword-scanner-node.js`

### Comp Dynamic Router (Execute Sub-Workflow Node)
- Receives each item from the Keyword Scanner
- Uses an **expression-based workflow ID** to dynamically select the correct sub-workflow:
  ```
  {{ {"auth_anomaly": "YOUR-AUTH-ID", "beaconing": "YOUR-BEACON-ID", "exfiltration": "YOUR-EXFIL-ID", "lateral_movement": "YOUR-LATERAL-ID", "privilege_escalation": "YOUR-PRIVESC-ID", "persistence": "YOUR-PERSIST-ID", "ransomware": "YOUR-RANSOM-ID", "insider_threat": "YOUR-INSIDER-ID", "vulnerability_exploitation": "YOUR-VULNEXPLOIT-ID"}[$json.investigation_type] || "YOUR-AUTH-ID" }}
  ```
- Each item is processed sequentially through its matched sub-workflow
- Results accumulate for the Report Merger

### Comprehensive Report Merger (Code Node)
- Collects all sub-workflow results
- If only 1 report: passes it through unchanged
- If multiple reports: merges them into a unified comprehensive report with:
  - Combined MITRE technique inventory (deduplicated)
  - Aggregated NIST CSF function mappings
  - Combined CIS Controls recommendations
  - Cross-correlated findings across investigation paths
  - Highest-risk assessment across all paths
- Source: `scripts/n8n-nodes/comprehensive-report-merger.js`

## Updating Sub-Workflow IDs

If you re-import sub-workflows (new n8n instance, different IDs), update the Comp Dynamic Router expression:

1. Open each sub-workflow and copy the ID from the URL bar (`/workflow/XXXXX`)
2. Open the master workflow → Comp Dynamic Router node → Workflow ID field
3. Update the 4 IDs in the expression mapping + the fallback ID

Also update all 9 targeted Execute Sub-Workflow nodes with their new IDs.

## Testing

```bash
# Test targeted (should go through existing auth_anomaly path directly)
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "500 failed SSH logins from 192.168.1.100 targeting root in 5 minutes"}'

# Test comprehensive — should hit keyword scanner → dynamic router (auth + lateral)
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "Failed SSH logins followed by SMB connections to 6 internal servers"}'

# Test no-keyword fallback — should default to auth_anomaly via dynamic router
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "Analyze the attached log file and provide a detailed report"}'

# Test multi-type comprehensive — should trigger all 4 paths
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "Failed SSH logins followed by beacon-like HTTPS connections every 60 seconds, then large data upload to Google Drive, spreading to multiple hosts via pass-the-hash"}'
```

## Design Decisions

**Why a dynamic router instead of a switch + 4 duplicate sub-workflow nodes?**
The dynamic router uses a single Execute Sub-Workflow node with an expression-based ID. This is simpler (1 node vs 6+), easier to maintain, and naturally handles sequential execution which is better for memory-constrained environments.

**Why does the keyword scanner default to auth_anomaly?**
Auth anomaly is the most comprehensive sub-workflow — it runs both Log and Network analysts in parallel, giving the broadest coverage for unclassified queries.

**Why do sub-workflows contain the full pipeline?**
Each sub-workflow includes: analysts → MITRE Lookup → CAR Coverage → NIST CSF → CIS Controls → PurpleMapper → Synthesizer → Report Formatter. This means the master workflow doesn't need any framework nodes — it's purely a routing layer.
