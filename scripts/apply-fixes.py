#!/usr/bin/env python3
"""
Apply CASA sub-workflow fixes to all 9 workflow JSON files.

Fixes:
1. MITRE Lookup: Read investigation_type from Execute Workflow Trigger
2. Report Formatter: Fix query retrieval (remove $('Webhook Trigger') reference)
3. Report Formatter: Add investigation_type fallback from trigger
4. Report Formatter: Add all 9 investigation type display names
"""

import json
import os
import sys

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

# ── Fix 1: MITRE Lookup — investigation_type from trigger ─────────────────────

MITRE_OLD = (
    "const investigationType = $input.first().json.investigation_type || 'general';"
)

MITRE_NEW = (
    "// Get investigation_type from the workflow trigger (not from Ollama response, which strips it)\n"
    "let investigationType = 'general';\n"
    "try {\n"
    "  investigationType = $('Execute Workflow Trigger').first().json.investigation_type || 'general';\n"
    "} catch (e) {\n"
    "  // Fallback: check immediate input (works if data was passed through)\n"
    "  investigationType = $input.first().json.investigation_type || 'general';\n"
    "}"
)

# ── Fix 2: Report Formatter — query retrieval ─────────────────────────────────

QUERY_OLD = (
    "try {\n"
    "  originalQuery = $('Execute Workflow Trigger').first().json.query ||\n"
    "                  $('Webhook Trigger').first().json.body.query || '';\n"
    "} catch (e) {\n"
    "  originalQuery = synthesizerOutput.query || 'N/A';\n"
    "}"
)

QUERY_NEW = (
    "// Get query from the workflow trigger — DO NOT reference $('Webhook Trigger')\n"
    "// which doesn't exist in sub-workflows and causes the entire try to throw\n"
    "try {\n"
    "  originalQuery = $('Execute Workflow Trigger').first().json.query || '';\n"
    "} catch (e) {\n"
    "  originalQuery = '';\n"
    "}\n"
    "if (!originalQuery) {\n"
    "  originalQuery = synthesizerOutput.query || 'N/A';\n"
    "}"
)

# ── Fix 3: Report Formatter — investigation_type fallback ─────────────────────

# We insert this AFTER the MITRE Lookup try/catch block in the Report Formatter.
# The anchor is the closing of the first try/catch block.
INVEST_TYPE_ANCHOR = (
    "} catch (e) {\n"
    "  techniques = synthesizerOutput.techniques || [];\n"
    "}"
)

INVEST_TYPE_INSERT = (
    "} catch (e) {\n"
    "  techniques = synthesizerOutput.techniques || [];\n"
    "}\n"
    "\n"
    "// Safety: if MITRE Lookup still says 'general', check the workflow trigger directly\n"
    "if (investigationType === 'general') {\n"
    "  try {\n"
    "    const triggerType = $('Execute Workflow Trigger').first().json.investigation_type;\n"
    "    if (triggerType && triggerType !== 'general') {\n"
    "      investigationType = triggerType;\n"
    "    }\n"
    "  } catch (e) {\n"
    "    // Trigger reference failed — keep 'general'\n"
    "  }\n"
    "}"
)

# ── Fix 4: Report Formatter — display names ──────────────────────────────────

DISPLAY_OLD = (
    "const typeDisplayNames = {\n"
    "  'auth_anomaly':    'Authentication Anomaly Investigation',\n"
    "  'beaconing':       'Beaconing / C2 Communication Investigation',\n"
    "  'exfiltration':    'Data Exfiltration Investigation',\n"
    "  'lateral_movement':'Lateral Movement Investigation',\n"
    "  'general':         'General Security Investigation',\n"
    "};"
)

DISPLAY_NEW = (
    "const typeDisplayNames = {\n"
    "  'auth_anomaly':              'Authentication Anomaly Investigation',\n"
    "  'beaconing':                 'Beaconing / C2 Communication Investigation',\n"
    "  'exfiltration':              'Data Exfiltration Investigation',\n"
    "  'lateral_movement':          'Lateral Movement Investigation',\n"
    "  'privilege_escalation':      'Privilege Escalation Investigation',\n"
    "  'persistence':               'Persistence Mechanism Investigation',\n"
    "  'ransomware':                'Ransomware Incident Investigation',\n"
    "  'insider_threat':            'Insider Threat Investigation',\n"
    "  'vulnerability_exploitation':'Vulnerability Exploitation Investigation',\n"
    "  'general':                   'General Security Investigation',\n"
    "};"
)


def apply_fix_to_code(code: str, old: str, new: str, fix_name: str) -> tuple[str, bool]:
    """Replace old pattern with new in a jsCode string. Returns (new_code, was_applied)."""
    # In JSON jsCode fields, newlines are \\n. We need to handle both forms.
    # The code is stored with literal \\n in the JSON string.

    # Try direct replacement first (for in-memory decoded strings)
    if old in code:
        return code.replace(old, new, 1), True

    # Try with JSON-escaped newlines
    old_escaped = old.replace("\n", "\\n")
    new_escaped = new.replace("\n", "\\n")
    if old_escaped in code:
        return code.replace(old_escaped, new_escaped, 1), True

    return code, False


def process_workflow(filepath: str) -> dict:
    """Apply all fixes to a single workflow file. Returns summary of changes."""
    with open(filepath, "r") as f:
        data = json.load(f)

    filename = os.path.basename(filepath)
    results = {"file": filename, "fixes": []}

    for node in data["nodes"]:
        node_name = node.get("name", "")
        js_code = node.get("parameters", {}).get("jsCode", "")

        if not js_code:
            continue

        if node_name == "MITRE Lookup":
            # Fix 1: investigation_type from trigger
            new_code, applied = apply_fix_to_code(js_code, MITRE_OLD, MITRE_NEW, "Fix 1")
            if applied:
                node["parameters"]["jsCode"] = new_code
                results["fixes"].append(f"Fix 1: MITRE Lookup investigation_type ✓")
            else:
                results["fixes"].append(f"Fix 1: MITRE Lookup — pattern not found (may already be fixed)")

        elif node_name == "Report Formatter":
            modified = False

            # Fix 2: query retrieval
            new_code, applied = apply_fix_to_code(js_code, QUERY_OLD, QUERY_NEW, "Fix 2")
            if applied:
                js_code = new_code
                modified = True
                results["fixes"].append(f"Fix 2: Report Formatter query retrieval ✓")
            else:
                results["fixes"].append(f"Fix 2: Report Formatter query — pattern not found")

            # Fix 3: investigation_type fallback
            new_code, applied = apply_fix_to_code(js_code, INVEST_TYPE_ANCHOR, INVEST_TYPE_INSERT, "Fix 3")
            if applied:
                js_code = new_code
                modified = True
                results["fixes"].append(f"Fix 3: Report Formatter investigation_type fallback ✓")
            else:
                results["fixes"].append(f"Fix 3: Report Formatter type fallback — pattern not found")

            # Fix 4: display names
            new_code, applied = apply_fix_to_code(js_code, DISPLAY_OLD, DISPLAY_NEW, "Fix 4")
            if applied:
                js_code = new_code
                modified = True
                results["fixes"].append(f"Fix 4: Report Formatter display names ✓")
            else:
                results["fixes"].append(f"Fix 4: Report Formatter display names — pattern not found")

            if modified:
                node["parameters"]["jsCode"] = js_code

    # Write the updated workflow
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

    return results


def main():
    print("CASA Sub-Workflow Fix Script")
    print("=" * 60)

    all_results = []
    for filename in SUB_WORKFLOW_FILES:
        filepath = os.path.join(WORKFLOWS_DIR, filename)
        if not os.path.exists(filepath):
            print(f"  SKIP: {filename} — file not found")
            continue

        result = process_workflow(filepath)
        all_results.append(result)

        print(f"\n{result['file']}:")
        for fix in result["fixes"]:
            print(f"  {fix}")

    # Summary
    print("\n" + "=" * 60)
    total_applied = sum(1 for r in all_results for f in r["fixes"] if "✓" in f)
    total_skipped = sum(1 for r in all_results for f in r["fixes"] if "not found" in f)
    print(f"Total fixes applied: {total_applied}")
    print(f"Patterns not found: {total_skipped}")

    return 0 if total_skipped == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
