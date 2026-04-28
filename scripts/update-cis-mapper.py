#!/usr/bin/env python3
"""
Update the CIS Controls Mapper code node in all 9 sub-workflows to use
the new technique-to-controls deterministic mapping file.

The new mapper uses technique-to-controls mappings as PRIMARY source,
supplemented by keyword matching for additional coverage.
"""

import json
import os

WORKFLOWS_DIR = "/Users/tnexus/Projects/pts-casa/workflows"

SUB_WORKFLOW_FILES = [
    "casa-auth-anomaly.json",
    "casa-beaconing.json",
    "casa-exfiltration.json",
    "casa-lateral-movement.json",
    "casa-privilege-escalation.json",
    "casa-persistence.json",
    "casa-ransomware.json",
    "casa-insider-threat.json",
    "casa-vulnerability-exploitation.json",
]

NEW_CIS_MAPPER_CODE = r"""const fs = require('fs');

// Load CIS Controls data
const cisData = JSON.parse(
  fs.readFileSync('/home/node/assets/cis-controls-v8.1.2.json', 'utf8')
);

// Load technique-to-controls deterministic mapping
let techniqueMap = {};
try {
  const mapData = JSON.parse(
    fs.readFileSync('/home/node/assets/mitre-to-controls-map.json', 'utf8')
  );
  for (const m of mapData.mappings) {
    techniqueMap[m.technique_id] = {
      cis_safeguards: m.cis_safeguards,
      nist_csf_categories: m.nist_csf_categories
    };
  }
} catch (e) {
  // Mapping file not available — fall back to keyword-only matching
}

const inputData = $input.first().json;
const findings     = inputData.analyst_findings  || JSON.stringify(inputData);
const techniques   = inputData.techniques        || [];
const nistMappings = inputData.nist_csf_mappings || [];
const coverageGaps = inputData.coverage_gaps     || [];
const lowCoverage  = inputData.low_coverage      || [];

// ── Step 1: Deterministic mapping from identified techniques ──
// This is the PRIMARY source — directly maps MITRE techniques to CIS safeguards
const techniqueMatchedSafeguards = new Set();

for (const tech of techniques) {
  const mapping = techniqueMap[tech.id];
  if (mapping) {
    for (const sgId of mapping.cis_safeguards) {
      techniqueMatchedSafeguards.add(sgId);
    }
  }
}

// ── Step 2: Keyword supplement for additional coverage ──
const normalizedFindings = findings.toLowerCase()
  .replace(/[^a-z0-9\s\-\.]/g, ' ').replace(/\s+/g, ' ').trim();

const tacticToCisFunction = {
  'Initial Access': ['Protect'], 'Execution': ['Protect', 'Detect'],
  'Persistence': ['Protect', 'Detect'], 'Privilege Escalation': ['Protect', 'Identify'],
  'Defense Evasion': ['Detect', 'Protect'], 'Credential Access': ['Protect', 'Identify'],
  'Discovery': ['Identify', 'Detect'], 'Lateral Movement': ['Protect', 'Detect'],
  'Collection': ['Protect', 'Detect'], 'Command and Control': ['Detect', 'Respond'],
  'Exfiltration': ['Detect', 'Respond', 'Protect'], 'Impact': ['Respond', 'Recover'],
};
const observedTactics = new Set();
for (const tech of techniques) for (const tactic of (tech.tactics || [])) observedTactics.add(tactic);

// ── Step 3: Score safeguards ──
const safeguardScores = [];
for (const control of cisData.controls) {
  for (const sg of control.safeguards) {
    let score = 0;
    let matchSource = [];

    // Deterministic technique mapping (highest weight)
    if (techniqueMatchedSafeguards.has(sg.id)) {
      score += 5;
      matchSource.push('technique-map');
    }

    // Keyword matching (supplement)
    for (const kw of (sg.keywords || [])) {
      if (normalizedFindings.includes(kw.toLowerCase())) score += 1;
    }
    if (normalizedFindings.includes(sg.title.toLowerCase())) score += 2;

    // Tactic-function correlation
    const secFunc = sg.security_function || '';
    for (const tactic of observedTactics) {
      const fns = tacticToCisFunction[tactic] || [];
      if (fns.some(f => f.toLowerCase() === secFunc.toLowerCase())) score += 0.5;
    }

    // Coverage gap boost
    if (coverageGaps.length > 0 && secFunc.toLowerCase() === 'detect') {
      score += coverageGaps.length * 0.25;
    }

    if (score > 0) {
      safeguardScores.push({
        control_id: control.id, control_title: control.title,
        safeguard_id: sg.id, safeguard_title: sg.title, description: sg.description,
        asset_type: sg.asset_type, security_function: sg.security_function,
        nist_csf_function: sg.nist_csf_function, implementation_groups: sg.implementation_groups,
        score, match_source: matchSource,
      });
    }
  }
}

safeguardScores.sort((a, b) => b.score - a.score);
const topSafeguards = safeguardScores.slice(0, 15);
const byControl = {};
for (const sg of topSafeguards) {
  if (!byControl[sg.control_id]) {
    byControl[sg.control_id] = {
      control_id: sg.control_id, control_title: sg.control_title, safeguards: []
    };
  }
  byControl[sg.control_id].safeguards.push({
    id: sg.safeguard_id, title: sg.safeguard_title,
    description: sg.description, asset_type: sg.asset_type,
    security_function: sg.security_function,
    nist_csf_function: sg.nist_csf_function,
    implementation_groups: sg.implementation_groups
  });
}
const cisMappings = Object.values(byControl).sort((a, b) => a.control_id - b.control_id);
const quickWins = topSafeguards
  .filter(sg => sg.implementation_groups.includes('IG1'))
  .slice(0, 6)
  .map(sg => ({
    id: sg.safeguard_id, title: sg.safeguard_title,
    control_id: sg.control_id, control_title: sg.control_title,
    security_function: sg.security_function,
    implementation_groups: sg.implementation_groups
  }));

return [{ json: {
  cis_mappings: cisMappings,
  cis_quick_wins: quickWins,
  cis_safeguard_count: topSafeguards.length,
  technique_mapped_count: techniqueMatchedSafeguards.size,
  techniques, nist_csf_mappings: nistMappings,
  analyst_findings: findings,
  coverage_gaps: coverageGaps, low_coverage: lowCoverage,
}}];"""


def main():
    print("Updating CIS Controls Mapper in all 9 sub-workflows")
    print("=" * 60)

    for filename in SUB_WORKFLOW_FILES:
        filepath = os.path.join(WORKFLOWS_DIR, filename)
        if not os.path.exists(filepath):
            print(f"  SKIP: {filename} — not found")
            continue

        with open(filepath) as f:
            data = json.load(f)

        updated = False
        for node in data["nodes"]:
            if node.get("name") == "CIS Controls Mapper":
                node["parameters"]["jsCode"] = NEW_CIS_MAPPER_CODE
                updated = True

        if updated:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
            print(f"  OK: {filename}")
        else:
            print(f"  WARN: {filename} — CIS Controls Mapper node not found")

    print("\nDone.")


if __name__ == "__main__":
    main()
