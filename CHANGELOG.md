# Changelog

All notable changes to PTS-CASA are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Planned
- File attachment processing pipeline (pcap, evtx, log file pre-processing via tshark)

---

## [2.2.3] - 2026-04-20

### Fixed
- **BUG-014 (CRITICAL):** All dataset types route to `auth_anomaly` sub-workflow regardless of log
  content — the query reaching n8n contained only the user's text message
  (`"Investigate and produce triage framework report"`), never the log file JSON. Two causes:

  1. **Router LLM context overflow:** The Router (phi3:3.8b, 4096-token window) received the raw
     multi-MB JSON but could only see the first ~16KB, missing all attack indicator strings.
  2. **Pipe file extraction guard bug:** Sources 2 and 3 (message-level files, content list parts)
     were gated on `files_found == 0`. When Source 1 found file metadata objects with no inline
     content, `files_found` was incremented and Sources 2/3 were skipped — leaving
     `files_extracted == 0` with no fallback attempted.

- **BUG-015 (HIGH):** Open WebUI file uploads not reaching the pipe in `casa_pipe.py` — two
  missing extraction formats and a missing system-message source:
  - Format 5 added: `file_obj["data"]["content"]` (Open WebUI 0.4.x+ common format)
  - Format 6 added: `file_obj["file"]["content"]` (nested file without data wrapper)
  - Source 4 added: scans system messages for JSON log content injected by Open WebUI when
    RAG is disabled (detects `"capture_summary"`, `"flagged_flows"`, `"indicators"` signatures)
  - Guard conditions on Sources 2 and 3 changed from `files_found == 0` to
    `files_extracted == 0` — ensures all delivery formats are tried before giving up

### Added
- **Log Preprocessor node (`casa-master-v2.json`):** New Code node inserted between Webhook
  Trigger and Router. Detects JSON network log data in the query (from `filter_casa.py` output)
  and extracts attack indicator strings by direct substring search — safe for multi-MB inputs
  where `JSON.parse` would be prohibitive.

  Recognized indicators and their routing targets:
  | Indicator | Investigation Type |
  |-----------|-------------------|
  | `PORT_SCAN_SOURCE` | lateral_movement |
  | `MANY_RESETS` | lateral_movement |
  | `BEACONING_PATTERN` | beaconing |
  | `HIGH_VOLUME`, `SYN_FLOOD_PATTERN`, `TTL_VARIANCE`, `SLOW_DOS_PATTERN`, `EPHEMERAL_SRC` | vulnerability_exploitation |
  | `LARGE_TRANSFER` | exfiltration |

  Outputs `attack_indicators[]` and `log_summary` passed to Router and Investigation Scanner.
  Also truncates the raw query to ≤300 chars before appending the concise indicator summary,
  preventing the Router's 4096-token context from being consumed by raw JSON.

### Changed
- **Router LLM prompt updated:** Added explicit indicator-to-type mapping hints
  (`PORT_SCAN_SOURCE→lateral_movement`, `BEACONING_PATTERN→beaconing`, etc.) so the LLM
  classifies correctly when indicator names appear in the (now-truncated) query.

- **Investigation Scanner keyword scan uses `searchText` instead of `query`:**
  `searchText = query + ' ' + attackIndicators.join(' ')` — the extracted indicator
  keywords are appended before scanning, ensuring `port_scan_source` matches `lateral_movement`,
  `beaconing_pattern` matches `beaconing`, etc. even when the raw query has no attack vocabulary.

- **Parse Router Output propagates `attack_indicators`, `has_log_data`, `log_summary`** from
  Log Preprocessor to Investigation Scanner via the results object.

- **Connections updated** in `casa-master-v2.json`:
  `Webhook Trigger → Log Preprocessor → Router` (was `Webhook Trigger → Router`)

### Expected routing with dataset testing (post-fix)
| Dataset | Investigation paths |
|---------|-------------------|
| `botnet_ares_filtered.json` | beaconing, exfiltration, lateral_movement, vulnerability_exploitation |
| `ddos_dns_filtered.json` | beaconing, exfiltration, lateral_movement, vulnerability_exploitation |
| `ddos_ldap_filtered.json` | exfiltration, lateral_movement, vulnerability_exploitation |

### Upgrade Notes
Re-import `casa-master-v2.json` into n8n (Log Preprocessor node is new — cannot be patched
in-place). Update sub-workflow IDs in Dynamic Sub-Workflow Router after import.
Update `functions/casa_pipe.py` in Open WebUI.

For immediate dataset testing without waiting for pipe fix, use `filter_casa.py --query` flag
to send log data directly in the webhook body — Log Preprocessor will extract indicators from
the JSON and route correctly.

---

## [2.2.2] - 2026-04-17

### Fixed
- **BUG-012 (HIGH):** MITRE ATT&CK `Description` and `Detection` fields blank in Overseer report —
  all 9 sub-workflow Report Formatters were stripping `description` and `detection` from the
  `mitre_techniques` structured output returned to the Results Collector:
  ```js
  // before — description/detection dropped
  mitre_techniques: techniques.map(t => ({ id, name, tactics, coverage }))
  // after — fields preserved
  mitre_techniques: techniques.map(t => ({ id, name, tactics, description, detection, coverage }))
  ```
  The Final Report Formatter in `casa-master-v2.json` then rendered `t.description || ''` as an
  empty string. Fix applied to all 9 sub-workflow Report Formatter nodes.

- **BUG-013 (MEDIUM):** CIS Controls safeguard descriptions in report truncated mid-sentence with
  `...` — `formatCisControls()` in all 9 sub-workflow Report Formatters applied a hard
  `sg.description.slice(0, 120)` cut before appending ellipsis. Description lines removed from the
  formatter entirely; safeguard ID, title, implementation groups, and security function remain.

### Changed
- **Investigation Scanner keyword expansion (172 keywords added across all 9 types):**
  All investigation type keyword lists expanded to improve sub-workflow routing accuracy.
  Key additions by type:
  - `auth_anomaly` (+19): `4740`, `4720`, `4726`, `4728`, `4732`, `account locked`, `impossible travel`,
    `credential dump`, `golden ticket`, `dcsync`, `ntlm hash`, `pass the hash`
  - `beaconing` (+19): `beaconing_pattern`, `avg_interval`, `base64`, `anydesk`, `teamviewer`,
    `fast flux`, `domain fronting`, `http beacon`, `protocol tunnel`, `keepalive`
  - `exfiltration` (+20): `large_transfer`, `ftp`, `sftp`, `smtp`, `data staging`, `keylogger`,
    `dns exfiltration`, `mail forwarding`, `encrypted archive`, `mapped drive`
  - `lateral_movement` (+22): `port_scan_source`, `many_resets`, `mimikatz`, `bloodhound`,
    `impacket`, `crackmapexec`, `dcom`, `ntlm hash`, `overpass the hash`, `3389`, `445`, `5985`
  - `privilege_escalation` (+21): `kernel exploit`, `gpo`, `process injection`, `kerberoast`,
    `asreproast`, `fodhelper`, `eventvwr`, `relay attack`, `silver ticket`, `elevation`
  - `persistence` (+21): `rootkit`, `dll hijacking`, `dll side-loading`, `launchd`, `mbr`, `uefi`,
    `bits job`, `lnk file`, `path interception`, `add user`, `event triggered`
  - `ransomware` (+15): `lockbit`, `ryuk`, `conti`, `revil`, `blackcat`, `alphv`, `wiper`,
    `double extortion`, `restore point`, `backup deletion`, `data leak site`
  - `insider_threat` (+15): `forwarding rule`, `inbox rule`, `classified`, `terminated`,
    `anomalous access`, `email forwarding`, `vdi`, `solicitation`
  - `vulnerability_exploitation` (+20): `ttl_variance`, `ephemeral_src`, `slow_dos_pattern`,
    `shellcode`, `meterpreter`, `log4j`, `log4shell`, `proxyshell`, `nikto`, `gobuster`,
    `xxe`, `ssti`, `csrf`, `memory corruption`

  filter_casa.py indicator names (`beaconing_pattern`, `large_transfer`, `port_scan_source`,
  `many_resets`, `ttl_variance`, `ephemeral_src`, `slow_dos_pattern`, `high_volume`,
  `syn_flood_pattern`) are now direct keyword matches in the relevant investigation types —
  filtered network captures route to the correct sub-workflow without relying solely on the
  Router LLM's classification.

- **Router Modelfile (`casa-router`):** `vulnerability_exploitation` description expanded to include
  DoS/DDoS attack types
  Previously the Router had no DoS vocabulary, causing slow-HTTP and flood captures to be
  misclassified as `auth_anomaly` or `beaconing`.

- **`casa-master-v2.json` added to version control:** Previously gitignored during development;
  now tracked alongside the sub-workflow JSONs. `.gitignore` entry removed.

### Docs
- **README Quick Start (Steps 5–6) corrected for n8n v2 UI:**
  - Step 5: replaced "verify shows 'When called by another workflow'" with accurate instructions —
    set **Input data mode** to **Accept all data**, set Merge node mode to **Append**, then
    **Publish** each sub-workflow
  - Step 6: added instruction to set Open WebUI **Settings → Documents → Top K = 0**
    (default of 3 was causing RAG interference with analyst queries)

### Upgrade Notes
Re-import all 9 updated sub-workflow JSONs and `casa-master-v2.json` into n8n for the report
and routing fixes to take effect. Rebuild the Router model to apply the updated Modelfile:
```bash
ollama create casa-router -f modelfiles/casa-router.Modelfile
```

---

## [2.2.1] - 2026-04-14

### Fixed
- **BUG-011 (HIGH):** `build-models.sh` hangs indefinitely at step 2 "Verifying assets inside n8n
  container..." — `docker exec n8n-main ls /home/node/.n8n/assets/*.json` had two compounding issues:
  (1) glob `*.json` is not expanded inside the container because `docker exec` does not invoke a shell,
  so `ls` received a literal filename and stalled on the bind-mount filesystem while n8n was still
  initializing its database; (2) no timeout, so any stall blocked the script permanently.
  Fixed by replacing the bare `ls` with `timeout 10 docker exec n8n-main sh -c 'find /home/node/assets
  -name "*.json" 2>/dev/null | wc -l'` plus a `|| echo "0"` fallback — the script now continues
  regardless of container readiness state.

### Changed
- **Asset volume path updated:** `./assets:/home/node/.n8n/assets` → `./assets:/home/node/assets`
  in `docker-compose.yml` for both `n8n-main` and `n8n-runners` services. The previous path mounted
  a bind-mount as a subdirectory of the `n8n_data` named volume, which caused Docker volume layering
  ambiguity on some hosts. New path is a clean, top-level bind mount under `/home/node/` — within the
  existing `N8N_RESTRICT_FILE_ACCESS_TO=/home/node/` boundary, no other env changes required.
- Updated asset path from `/home/node/.n8n/assets/` → `/home/node/assets/` across all affected files:
  - All 9 sub-workflow JSONs (Code nodes: MITRE Lookup, CAR Coverage Lookup, NIST CSF Mapper,
    CIS Controls Mapper)
  - `scripts/n8n-nodes/mitre-lookup.js`
  - `scripts/n8n-nodes/car-coverage-lookup.js`
  - `scripts/n8n-nodes/nist-csf-mapper.js`
  - `scripts/n8n-nodes/cis-controls-mapper.js`
  - `scripts/update-workflows.js`
  - `scripts/update-cis-mapper.py`
  - `scripts/build-models.sh` (verification step)

### Upgrade Notes
After pulling this release on the deployment host:
```bash
docker compose up --build -d   # rebuild required — volume mount changed
bash scripts/build-models.sh   # re-verify assets are accessible at new path
```
Re-import all 9 updated sub-workflow JSONs into n8n (Code nodes now reference `/home/node/assets/`).

---

## [2.2.0] - 2026-04-09

### Added
- **casa-overseer Modelfile (qwen2.5:14b):** New final-stage synthesis model that cross-correlates
  all sub-workflow reports into a unified analyst-facing report with attack narrative, prioritized
  recommendations, and confidence assessment. 4096 ctx, 1024 num_predict.
- **Technique-to-controls mapping data file (`assets/mitre-to-controls-map.json`):** Deterministic
  MITRE ATT&CK → CIS Controls v8.1.2 + NIST CSF 2.0 mappings for all 160 techniques. Replaces
  keyword-only matching with technique-specific control recommendations.
- **Master workflow v2 architecture:** Single-path pipeline eliminates dual-path race condition.
  New nodes: Investigation Scanner, Dynamic Sub-Workflow Router, Results Collector, Overseer,
  Final Report Formatter. Only one path to Respond to Webhook.
- `scripts/build-technique-controls-map.py` — generates the mapping data file
- `scripts/apply-fixes.py` — applies sub-workflow code fixes
- `scripts/update-cis-mapper.py` — updates CIS mapper with technique mapping support
- `docs/SUB-WORKFLOW-FIXES.md` — documents all sub-workflow code changes

### Fixed
- **BUG-007 (CRITICAL):** Report returned to Open WebUI before all sub-workflows complete — race
  condition caused by multiple sub-workflow outputs connecting directly to Respond to Webhook.
  Fixed by restructuring to single-path pipeline with Overseer synthesis.
- **BUG-008 (CRITICAL):** `investigation_type` always defaults to 'general' — Ollama analyst
  responses strip metadata, causing MITRE Lookup to lose the type. Fixed by reading from
  `$('Execute Workflow Trigger')` in all 9 sub-workflows.
- **BUG-009 (CRITICAL):** Query shows "N/A" in reports — Report Formatter's `$('Webhook Trigger')`
  reference crashes in sub-workflows where that node doesn't exist. Fixed by removing the reference
  and using separate try/catch for `$('Execute Workflow Trigger')`.
- **BUG-010 (MEDIUM):** Report Formatter missing display names for 5 investigation types
  (privilege_escalation, persistence, ransomware, insider_threat, vulnerability_exploitation).

### Changed
- CIS Controls Mapper in all 9 sub-workflows now uses deterministic technique-to-controls mapping
  as primary source, with keyword matching as supplement (was keyword-only)
- Master workflow reduced from 17 nodes to 9 (eliminated Switch node and direct sub-workflow connections)
- Investigation Scanner replaces Switch + Keyword Scanner with unified classification that always
  includes the Router LLM's classification plus keyword-matched types
- `build-models.sh` updated to build casa-overseer (9 steps, was 8)
- CIS mapper now returns top 15 safeguards (was 12) with technique-map match source tracking

---

## [2.1.0] - 2026-04-08

### Fixed
- **BUG-001 (CRITICAL):** Synthesizer nodes in all sub-workflows were serializing full Ollama API envelope (`total_duration`, `eval_count`, etc.) into prompts — agents analyzed API metadata instead of security findings. Fixed to extract `$json.response` first.
- **BUG-002 (HIGH):** Parse Router Output now handles malformed phi3:3.8b JSON with markdown fence stripping, pre/post-JSON text removal, type validation, and keyword-based fallback classification from original query.
- **BUG-003 (MEDIUM):** Risk level no longer stuck at MEDIUM — auto-resolved by BUG-001 fix (Report Formatter's dynamic risk extraction now receives clean Synthesizer output).
- **BUG-005/006:** PurpleMapper Modelfile now requires evidence-based technique mapping — no speculative padding, each technique must cite specific findings with confidence level.

### Changed
- Updated all documentation to reflect current 9-type architecture
- Moved `n8n-CyberAnalysis-Architecture.md` to `docs/` with historical disclaimer
- Wiring guide updated for 9 targeted paths + 17 master workflow nodes

---

## [2.0.0] - 2026-04-08

### Added
- **5 new investigation types:** privilege_escalation, persistence, ransomware, insider_threat, vulnerability_exploitation
- 5 new sub-workflow JSONs (11 nodes each, following existing pipeline pattern)
- Type-specific analyst prompts for all 5 new types (log + network focus areas)
- Keyword scanner expanded with 5 new keyword lists for comprehensive fallback
- MITRE lookup tactic boosting for all 9 investigation types

### Changed
- **Analyst models upgraded from qwen2.5:7b to qwen2.5:14b** — significantly better reasoning quality for report generation (requires 64GB RAM for all models loaded)
- Log Analyst Modelfile enhanced: added Sysmon events (1, 3, 7, 8, 11, 12, 13, 22), additional Windows Event IDs (4698, 7045, 4688, 1102, 4697, 4720, 4726), Linux audit indicators (auditd, SELinux, AppArmor)
- Network Analyst Modelfile enhanced: added JA3/JA3S TLS fingerprinting, DNS tunneling detection scoring, HTTP anomaly detection patterns
- Router Modelfile updated to classify all 9 investigation types
- Master workflow expanded to 17 nodes (9 targeted paths + comprehensive fallback)
- `build-models.sh` updated to pull qwen2.5:14b base model

---

## [1.5.0] - 2026-04-07

### Added
- **Comprehensive analysis mode:** Keyword Scanner + Comp Dynamic Router + Comprehensive Report Merger for general/ambiguous queries
- AWS EC2 provisioning guide (`docs/PTS-CASA-AWS-Provisioning-Guide.md`)
- Comprehensive analysis wiring guide (`docs/comprehensive-analysis-wiring-guide.md`)
- `scripts/n8n-nodes/keyword-scanner-node.js` — keyword-based investigation type detection
- `scripts/n8n-nodes/comprehensive-report-merger.js` — merges parallel sub-workflow reports

### Changed
- Master workflow cleaned from 23 nodes to 12 (then expanded in v2.0.0): replaced 14-node Domain Switch chain with 3-node comprehensive fallback path
- Docker-compose Ollama settings tuned for AWS (16 threads, 4 models loaded, 30m keep-alive)
- Docker-compose timezone corrected to America/Phoenix
- `.env.example` expanded with Ollama performance tuning variables
- All sub-workflow IDs updated to AWS n8n instance values

### Fixed
- PurpleMapper and Synthesizer generation timeout: reduced `num_predict` from 1024 to 512, added `options: { num_predict: 512 }` override in workflow HTTP bodies
- n8n HTTP timeout for PurpleMapper/Synthesizer nodes increased from 600000ms to 1800000ms

---

## [1.4.0] - 2026-04-01

### Added
- **CIS Controls v8.1.2 framework:** 18 controls, 153 safeguards with IG1/IG2/IG3 classification
- **MITRE CAR analytic coverage:** 588 techniques with CAR/Sigma/ES SIEM/Splunk detection counts
- `scripts/n8n-nodes/car-coverage-lookup.js` — CAR analytic coverage enrichment
- `scripts/n8n-nodes/cis-controls-mapper.js` — CIS Controls v8.1.2 safeguard mapper
- `scripts/convert-car-coverage.js` — CSV to JSON converter for CAR data
- `scripts/convert-cis-controls.py` — Excel to JSON converter for CIS Controls
- Report sections 5.5 (Analytic Coverage) and 5.6 (CIS Controls) added to report formatter

### Fixed
- Open WebUI pipe file upload: added 3-source file delivery check (body-level, message-level, content list)
- OpenWebUI internal task request interception (title/tag/emoji generation no longer triggers pipeline)

---

## [1.3.0] - 2026-03-03

### Added
- MITRE ATT&CK deterministic lookup (`scripts/n8n-nodes/mitre-lookup.js`) — 160 techniques with keyword matching and tactic boosting
- NIST CSF 2.0 mapper (`scripts/n8n-nodes/nist-csf-mapper.js`) — 6 functions, 22 categories, 106 subcategories
- NIST SP 800-92 report formatter (`scripts/n8n-nodes/report-formatter.js`) — 8-section standardized output
- Framework data assets: `mitre-attack-techniques.json`, `nist-csf-2.0.json`, `report-template.json`
- PurpleMapper role shifted from "generate from scratch" to "validate and refine" pre-matched techniques

### Changed
- All 5 workflow JSONs updated with 3 Code nodes each (MITRE Lookup, NIST CSF Mapper, Report Formatter)
- Docker-compose: added `fs` to `NODE_FUNCTION_ALLOW_BUILTIN=path,fs`

### Fixed
- Ollama CPU timeout: increased n8n HTTP Request timeouts, reduced `num_ctx` from 8192 to 2048 in analyst Modelfiles
- Added `OLLAMA_KEEP_ALIVE=10m` to prevent premature model unloading

---

## [1.0.0] - 2026-02-26

### Added
- Initial CASA multi-agent investigation system
- 5 Ollama Modelfiles: casa-router (phi3:3.8b), casa-log-analyst, casa-network-analyst, casa-purple-mapper, casa-synthesizer (all qwen2.5:7b)
- 5 n8n workflows: master router + 4 sub-workflows (auth-anomaly, beaconing, exfiltration, lateral-movement)
- Open WebUI pipe function (`functions/casa_pipe.py`) for chat-based investigation
- Docker stack: Ollama, Open WebUI, n8n, PostgreSQL, Redis
- Agent personas: Morgan Chen (Log), Jordan Rivers (Network), Alex Reyes (Purple)
- `scripts/build-models.sh` and `scripts/test-models.sh`
