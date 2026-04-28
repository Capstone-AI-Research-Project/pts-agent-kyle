# PTS-CASA: Bug Report & Recommended Fixes

**Date:** April 8, 2026  
**Source:** Analysis of 3 CASA-generated investigation reports  
**Environment:** Proxmox VM 110 (8 cores, 16 GiB RAM, Ollama CPU inference)

---

## Reports Analyzed

| Report | Input Type | Query / Description |
|--------|-----------|---------------------|
| 1.txt | File attachment (dhcp.pcap) | "Can you review the following pcap file and give me a summary report" |
| 2.txt | Text query | "Workstation at 10.0.5.42 making HTTPS connections every 60 seconds to a domain registered 3 days ago" |
| 3.txt | Text query | "500 failed SSH logins from 192.168.1.100 targeting root in 5 minutes, followed by successful login and new user creation" |

---

## BUG-001: Ollama Response Parsing — Agents Receive API Metadata Instead of Generated Text

**Severity:** CRITICAL  
**Affects:** All 3 reports  
**Component:** n8n workflow — HTTP Request / Ollama nodes

### Symptom

Every report's Technical Findings section contains analysis of Ollama's own inference performance metrics rather than the user's query or data:

> "The provided JSON data appears to be a performance or evaluation report for some kind of system, possibly related to machine learning or AI."
>
> References to `total_duration`, `load_duration`, `prompt_eval_count`, `eval_count`, `eval_duration`

These are fields from Ollama's API response envelope, not user-submitted content.

### Root Cause

The n8n workflow nodes that call Ollama's API are passing the **full JSON response object** to downstream agent nodes. Ollama's API returns a structure like:

```json
{
  "model": "casa-router",
  "response": "This is the actual generated analysis text...",
  "total_duration": 358816970253,
  "load_duration": 24430508910,
  "prompt_eval_count": 4096,
  "prompt_eval_duration": 287609406675,
  "eval_count": 512,
  "eval_duration": 68599690115
}
```

The next node in the workflow receives the entire object. When a downstream agent is prompted with this JSON, it "analyzes" the metadata fields instead of the actual content.

### Recommended Fix

In every n8n node that follows an Ollama API call, extract only the generated text before passing it downstream.

**For `/api/generate` endpoint:**
```javascript
// In the n8n expression field for the downstream node's input:
{{ $json.response }}
```

**For `/api/chat` endpoint:**
```javascript
{{ $json.message.content }}
```

**Where to check:** Open each of these n8n workflows and inspect the nodes immediately after every Ollama HTTP Request node:

- `casa-master.json` — router call output
- `casa-auth-anomaly.json` — analyst agent calls
- `casa-beaconing.json` — analyst agent calls
- `casa-exfiltration.json` — analyst agent calls
- `casa-lateral-movement.json` — analyst agent calls

Look for any **Set**, **Function**, or **Merge** node that passes data between the Ollama response and the next agent prompt. The expression should reference `$json.response` or `$json.message.content`, not `$json` (the whole object).

### Verification

After fixing, run the smoke test from the provisioning guide:

```bash
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "500 failed SSH logins from 192.168.1.100 targeting root in 5 minutes"}'
```

The Technical Findings section should now discuss SSH brute force attacks, not Ollama performance metrics.

---

## BUG-002: Router Agent Fails to Classify Queries — All Queries Route as "general"

**Severity:** HIGH  
**Affects:** All 3 reports  
**Component:** `casa-router` Modelfile + `casa-master.json` workflow

### Symptom

The Evidence Chain section of every report shows:

> "1. Query received and classified as: general"

All three queries should have been routed to specialized sub-workflows:

| Query | Expected Classification | Actual | Expected Sub-Workflow |
|-------|------------------------|--------|----------------------|
| DHCP pcap review | network (or general) | general | — |
| HTTPS beaconing every 60s to new domain | **beaconing** | general | `casa-beaconing.json` |
| 500 failed SSH logins + successful login + new user | **auth-anomaly** | general | `casa-auth-anomaly.json` |

### Root Cause

Two possible causes (likely both contributing):

1. **BUG-001 cascade** — If the router agent receives Ollama metadata instead of the user's query text, it cannot classify the query at all and falls back to "general."
2. **Router Modelfile prompt** — The `casa-router` Modelfile may not define the classification categories clearly enough, or the output format instructions may be ambiguous, causing `phi3:3.8b` to produce unparseable responses that the workflow treats as "general."

### Recommended Fix

**Step 1:** Fix BUG-001 first. The router can't classify what it can't see.

**Step 2:** Verify the router receives the raw query. In `casa-master.json`, find the first Ollama HTTP Request node (the router call). Confirm the prompt template includes the user's original query, for example:

```
Classify the following security query into exactly one category:
- auth-anomaly
- beaconing
- exfiltration
- lateral-movement

Query: {{ $json.query }}

Respond with only the category name, nothing else.
```

**Step 3:** Check the node that parses the router's output. There should be a **Switch** or **IF** node that reads the classification and routes to the correct Execute Sub-Workflow node. Verify it handles the router's output format correctly — `phi3:3.8b` may pad its response with whitespace, quotes, or explanation text. Add a trim/lowercase step:

```javascript
// In a Function node after the router response:
const raw = $json.response || $json.message.content || "";
const classification = raw.trim().toLowerCase().replace(/[^a-z-]/g, "");

const validCategories = ["auth-anomaly", "beaconing", "exfiltration", "lateral-movement"];
return {
  category: validCategories.includes(classification) ? classification : "general"
};
```

**Step 4:** Test each classification category individually:

```bash
# Should route to auth-anomaly
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "500 failed SSH logins from 192.168.1.100 targeting root"}'

# Should route to beaconing
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "Workstation beaconing every 60 seconds to newly registered domain"}'

# Should route to lateral-movement
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "RDP connections from server A to workstations B, C, D using admin credentials"}'

# Should route to exfiltration
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "Large DNS TXT responses to external domain with base64 encoded payloads"}'
```

Check the Evidence Chain in each report to confirm proper routing.

---

## BUG-003: Risk Level Is Static — Always Returns MEDIUM

**Severity:** MEDIUM  
**Affects:** All 3 reports  
**Component:** `casa-synthesizer` Modelfile or report template in `casa_pipe.py` / n8n workflow

### Symptom

All three reports show `Risk Level: MEDIUM` regardless of the scenario's severity:

- A DHCP pcap review (low/informational) → MEDIUM
- A C2 beaconing pattern (high) → MEDIUM
- A successful brute force with account creation (critical) → MEDIUM

### Root Cause

The risk level is either hardcoded in the report template or the synthesizer agent's risk assessment output is being ignored in favor of a default value.

### Recommended Fix

**Option A — Check the report template.** Search for "MEDIUM" in `functions/casa_pipe.py` and the n8n workflow nodes that assemble the final report. If risk level is a static string, replace it with the synthesizer agent's output:

```bash
grep -rn "MEDIUM" functions/casa_pipe.py
grep -rn "Risk Level" functions/casa_pipe.py
```

**Option B — Fix the synthesizer prompt.** If the synthesizer is supposed to determine risk level, verify its Modelfile includes explicit instructions:

```
Based on your analysis, assign a risk level using this scale:
- CRITICAL: Active compromise confirmed, attacker has persistence or is exfiltrating data
- HIGH: Strong indicators of compromise, successful unauthorized access detected
- MEDIUM: Suspicious activity requiring investigation, no confirmed compromise
- LOW: Minor anomalies, likely benign but worth monitoring
- INFORMATIONAL: Routine activity, no indicators of concern

Respond with the risk level on its own line in the format: RISK_LEVEL: <level>
```

**Option C — Implement rule-based risk scoring in the workflow.** Add a Function node before report assembly that scores based on the identified MITRE techniques:

```javascript
const techniques = $json.techniques || [];
const techniqueIds = techniques.map(t => t.id);

let risk = "LOW";
if (techniqueIds.some(id => ["T1136", "T1098", "T1543"].includes(id))) risk = "HIGH";
if (techniqueIds.some(id => ["T1110", "T1078"].includes(id)) &&
    techniqueIds.some(id => ["T1136"].includes(id))) risk = "CRITICAL";
if (techniqueIds.some(id => ["T1071", "T1573", "T1041"].includes(id))) risk = "HIGH";

return { risk_level: risk };
```

---

## BUG-004: No File Attachment Processing Pipeline

**Severity:** MEDIUM  
**Affects:** Report 1 (pcap file input)  
**Component:** Webhook intake + pre-processing stage (missing)

### Symptom

The DHCP pcap file was submitted but the report contains zero references to DHCP, packets, MAC addresses, IP leases, or any network protocol data. The file was effectively ignored.

### Root Cause

The pipeline has no mechanism to decode binary file formats before passing them to LLM agents. PCAP files are binary and cannot be read directly by an LLM — they require tools like `tshark` or `tcpdump` to convert to human-readable text or JSON.

### Recommended Fix

Add a pre-processing stage in the n8n workflow between the webhook intake and the router agent. This stage should detect file attachments and convert them to text before passing to agents.

**Step 1:** Add file type detection to the webhook handler:

```javascript
const query = $json.query || "";
const fileAttachment = $json.file || null; // however Open WebUI passes files

if (fileAttachment) {
  const extension = fileAttachment.name.split('.').pop().toLowerCase();
  return { query, fileType: extension, filePath: fileAttachment.path };
}
return { query, fileType: null, filePath: null };
```

**Step 2:** Add an Execute Command node for pcap processing:

```bash
# Convert pcap to readable text summary
tshark -r /path/to/uploaded/file.pcap -q -z conv,ip -z io,stat,1 > /tmp/pcap_summary.txt

# Or for detailed packet-level output:
tshark -r /path/to/uploaded/file.pcap -T fields \
  -e frame.number -e frame.time -e ip.src -e ip.dst \
  -e _ws.col.Protocol -e _ws.col.Info \
  -E header=y -E separator=, > /tmp/pcap_detail.csv
```

**Step 3:** Install `tshark` on the host:

```bash
sudo apt install -y tshark
```

**Step 4:** Prepend the converted file content to the query before sending to the router:

```javascript
const fileContent = $json.pcapSummary || "";
const originalQuery = $json.query || "";

return {
  query: `${originalQuery}\n\n--- PARSED FILE DATA ---\n${fileContent}`
};
```

**Supported file types to consider adding:**

| Format | Conversion Tool | Command |
|--------|----------------|---------|
| .pcap / .pcapng | tshark | `tshark -r file.pcap -T json` |
| .evtx (Windows Event Log) | python-evtx | `evtx_dump.py file.evtx` |
| .log (plaintext) | cat | `cat file.log` (direct pass-through) |
| .csv | cat | `cat file.csv` (direct pass-through) |
| .json | jq | `jq . file.json` (pretty-print and pass) |

---

## BUG-005: NIST CSF and CIS Controls Sections Are Not Tailored to Findings

**Severity:** LOW  
**Affects:** All 3 reports  
**Component:** Report template / synthesizer agent / `casa-purple-mapper` Modelfile

### Symptom

The NIST CSF 2.0 and CIS Controls v8.1.2 sections are structurally identical across all three reports despite covering very different scenarios. The framework mappings appear to be pulled from the reference data assets in bulk rather than selected based on the specific techniques and findings identified.

Examples of irrelevant mappings:

- Report 1 (DHCP pcap): Recommends CIS 5.2 (Use Unique Passwords) — not relevant to DHCP analysis
- Report 2 (beaconing): Missing CIS 13.3 (Deploy Network Intrusion Detection) — directly relevant to C2 detection
- Report 3 (SSH brute force): Recommends CIS 16.12 (Code-Level Security Checks) — not relevant to SSH brute force

### Root Cause

The `casa-purple-mapper` agent or the synthesizer is likely pulling a broad set of framework mappings based on keyword overlap rather than using the identified MITRE ATT&CK techniques to drive targeted framework recommendations.

### Recommended Fix

Use the MITRE ATT&CK technique IDs as the lookup key into NIST CSF and CIS Controls mappings rather than doing free-text matching.

**Step 1:** Create a mapping file (`data/attack-to-controls.json`) that maps ATT&CK technique IDs to specific NIST CSF subcategories and CIS Controls:

```json
{
  "T1110": {
    "nist_csf": ["PR.AA-01", "PR.AA-03", "DE.CM-01", "DE.AE-02"],
    "cis_controls": ["5.2", "4.1", "8.5", "8.11"]
  },
  "T1136": {
    "nist_csf": ["PR.AA-01", "PR.AA-02", "DE.CM-03"],
    "cis_controls": ["5.3", "5.4", "8.5"]
  },
  "T1071.001": {
    "nist_csf": ["DE.CM-01", "DE.AE-03", "PR.IR-01"],
    "cis_controls": ["13.3", "13.6", "9.2"]
  }
}
```

**Step 2:** In the report assembly stage, look up controls based only on the identified technique IDs rather than passing the full reference datasets to an LLM for free-form matching.

---

## BUG-006: MITRE ATT&CK Technique Selection Includes Irrelevant Techniques

**Severity:** LOW  
**Affects:** Reports 1 and 2  
**Component:** `casa-purple-mapper` or `casa-synthesizer` Modelfile

### Symptom

Reports include MITRE ATT&CK techniques unrelated to the investigated scenario:

- **Report 1** (DHCP pcap): Includes T1558 (Kerberos Tickets), T1550.003 (Pass the Ticket) — no relevance to DHCP
- **Report 2** (HTTPS beaconing): Includes T1110 (Brute Force), T1558 (Kerberos Tickets) — no relevance to C2 beaconing. Missing T1071.001 (Web Protocols), T1573 (Encrypted Channel), T1568 (Dynamic Resolution)
- **Report 3** (SSH brute force): Mostly correct, but includes T1071.004 (DNS C2) without justification

### Root Cause

Likely a combination of BUG-001 (agents can't see the actual query) and the technique selection being too broad — the agents may default to a common set of techniques when they lack clear input data.

### Recommended Fix

This should largely self-correct once BUG-001 and BUG-002 are fixed, since agents will be able to read the actual scenario and select relevant techniques. Additionally, update the `casa-purple-mapper` Modelfile to include:

```
IMPORTANT: Only map techniques that are DIRECTLY evidenced by the findings.
Do not include techniques speculatively. Each technique you list must be
justified by specific evidence from the analyst findings.

For each technique, provide:
- Technique ID and name
- The specific evidence from the findings that supports this mapping
- Confidence level (HIGH / MEDIUM / LOW)

If fewer than 5 techniques are clearly evidenced, list fewer than 5.
Do not pad the list to reach a quota.
```

---

## Fix Priority Order

| Priority | Bug | Impact | Effort |
|----------|-----|--------|--------|
| 1 | BUG-001 (Ollama response parsing) | Fixes the core analysis in all reports | Low — expression change in n8n nodes |
| 2 | BUG-002 (Router classification) | Enables specialized sub-workflow routing | Low–Medium — Modelfile + workflow node fix |
| 3 | BUG-003 (Static risk level) | Accurate severity reporting | Low — template or prompt fix |
| 4 | BUG-004 (File attachment processing) | Enables pcap/evtx/log file analysis | Medium — new n8n pre-processing stage |
| 5 | BUG-005 (Framework mapping relevance) | More useful recommendations | Medium — mapping data + logic change |
| 6 | BUG-006 (Irrelevant ATT&CK techniques) | Cleaner reports | Low — likely auto-fixes with BUG-001 |

Fixing BUG-001 alone will likely have a cascading positive effect on BUG-002, BUG-003, and BUG-006 since the agents will finally be able to read the actual input data. Start there.

---

## Regression Test Queries

After applying fixes, re-run these three test cases and verify:

**Test 1 — Auth Anomaly:**
```
Query: "500 failed SSH logins from 192.168.1.100 targeting root in 5 minutes, followed by successful login and new user creation"
Expected: Classification = auth-anomaly | Risk = HIGH or CRITICAL | Techniques include T1110, T1021.004, T1078, T1136
```

**Test 2 — Beaconing:**
```
Query: "Workstation at 10.0.5.42 making HTTPS connections every 60 seconds to a domain registered 3 days ago"
Expected: Classification = beaconing | Risk = HIGH | Techniques include T1071.001, T1573, T1568
```

**Test 3 — Lateral Movement:**
```
Query: "Admin account used to RDP from server 10.1.1.5 to workstations 10.1.2.10, 10.1.2.11, 10.1.2.12 in sequence over 4 minutes"
Expected: Classification = lateral-movement | Risk = HIGH | Techniques include T1021.001, T1078
```

**Test 4 — Exfiltration:**
```
Query: "DNS TXT queries to subdomain.evil.com with base64-encoded payloads averaging 200 bytes every 30 seconds"
Expected: Classification = exfiltration | Risk = HIGH | Techniques include T1048.001, T1071.004
```
