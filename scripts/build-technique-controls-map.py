#!/usr/bin/env python3
"""
Build the MITRE ATT&CK → CIS Controls + NIST CSF mapping data file.

This creates deterministic mappings from each MITRE technique to:
  - CIS Controls v8.1.2 safeguards that mitigate/detect the technique
  - NIST CSF 2.0 categories relevant to the technique

Mappings are based on:
  - CIS Controls v8 ATT&CK Mappings (official CIS publication)
  - NIST CSF to ATT&CK Navigator mappings
  - MITRE ATT&CK Mitigations cross-references

Output: assets/mitre-to-controls-map.json
"""

import json
import os

# ── Tactic-level CIS Control mappings ────────────────────────────────────────
# Each tactic maps to CIS safeguard IDs that are broadly relevant.
# Technique-specific overrides are applied after.

TACTIC_TO_CIS = {
    "Initial Access": [
        "4.1", "4.4", "4.5",     # Secure configuration, firewall
        "7.1", "7.2", "7.4",     # Vulnerability management
        "9.1", "9.2", "9.3",     # Email/web protections
        "12.1",                   # Network infrastructure
        "13.1", "13.3",          # Network monitoring
    ],
    "Execution": [
        "2.5", "2.6", "2.7",     # Software allowlisting
        "4.1", "4.8",            # Secure configuration
        "8.2", "8.5", "8.8",     # Audit logging, command-line
        "10.1", "10.2", "10.5",  # Malware defenses
    ],
    "Persistence": [
        "4.1", "4.8",            # Secure configuration
        "5.3", "5.4",            # Account management
        "8.2", "8.5",            # Audit logging
        "10.1", "10.2",          # Malware defenses
    ],
    "Privilege Escalation": [
        "4.1", "4.7",            # Secure configuration
        "5.1", "5.3", "5.4",     # Account management
        "6.1", "6.2", "6.8",     # Access control
        "8.2", "8.5",            # Audit logging
    ],
    "Defense Evasion": [
        "2.5", "2.6",            # Software allowlisting
        "8.2", "8.5", "8.11",    # Audit logging, log review
        "10.1", "10.2", "10.5",  # Malware defenses
        "13.6",                   # Network monitoring (IDS)
    ],
    "Credential Access": [
        "5.1", "5.2", "5.3", "5.4",  # Account management
        "6.3", "6.4", "6.5",         # Access control, MFA
        "8.2", "8.5",                 # Audit logging
        "11.4",                        # Data recovery (credential stores)
    ],
    "Discovery": [
        "1.1", "1.2",            # Asset inventory
        "8.2", "8.5",            # Audit logging
        "13.1", "13.3",          # Network monitoring
    ],
    "Lateral Movement": [
        "4.1", "4.2",            # Secure configuration
        "6.1", "6.3", "6.4",     # Access control
        "12.1", "12.2", "12.7",  # Network infrastructure, VPN
        "13.1", "13.3", "13.4",  # Network monitoring, segmentation
    ],
    "Collection": [
        "3.1", "3.2", "3.3",     # Data protection
        "8.2", "8.5",            # Audit logging
        "13.1",                   # Network monitoring
    ],
    "Command and Control": [
        "4.5",                    # Firewall
        "9.2", "9.3",            # Web protections
        "12.1", "12.3",          # Network infrastructure
        "13.1", "13.3", "13.6",  # Network monitoring, IDS
    ],
    "Exfiltration": [
        "3.1", "3.2", "3.3",     # Data protection
        "4.5",                    # Firewall
        "12.1",                   # Network infrastructure
        "13.1", "13.3", "13.8",  # Network monitoring, DLP
    ],
    "Impact": [
        "3.1", "3.2",            # Data protection
        "11.1", "11.2", "11.3", "11.4", "11.5",  # Data recovery
        "17.1", "17.4", "17.7",  # Incident response
    ],
}

# ── Tactic-level NIST CSF mappings ───────────────────────────────────────────

TACTIC_TO_NIST = {
    "Initial Access":       ["PR.AA", "PR.IR", "DE.CM", "DE.AE"],
    "Execution":            ["PR.PS", "DE.CM", "DE.AE"],
    "Persistence":          ["PR.PS", "PR.AA", "DE.CM", "DE.AE"],
    "Privilege Escalation": ["PR.AA", "PR.PS", "DE.CM", "DE.AE", "GV.OV"],
    "Defense Evasion":      ["PR.PS", "DE.CM", "DE.AE"],
    "Credential Access":    ["PR.AA", "PR.DS", "DE.CM", "ID.AM"],
    "Discovery":            ["DE.CM", "DE.AE", "ID.AM"],
    "Lateral Movement":     ["PR.IR", "PR.AA", "DE.CM", "DE.AE"],
    "Collection":           ["PR.DS", "DE.CM", "DE.AE"],
    "Command and Control":  ["PR.IR", "DE.CM", "DE.AE", "RS.AN"],
    "Exfiltration":         ["PR.DS", "PR.IR", "DE.CM", "DE.AE", "RS.AN"],
    "Impact":               ["PR.DS", "PR.IR", "RS.AN", "RS.MI", "RC.RP"],
}

# ── Technique-specific overrides / additions ─────────────────────────────────
# These add precision beyond tactic-level mapping.

TECHNIQUE_CIS_OVERRIDES = {
    # Credential Access specifics
    "T1110":     ["5.1", "5.2", "5.3", "5.4", "6.3", "6.4", "6.5", "8.2", "8.5", "8.11", "4.1"],
    "T1110.001": ["5.1", "5.2", "5.3", "6.3", "6.4", "8.2", "8.11"],
    "T1110.002": ["5.2", "5.3", "5.4", "6.5"],
    "T1110.003": ["5.1", "5.2", "5.3", "6.3", "6.4", "6.5", "8.2", "8.11"],
    "T1110.004": ["5.1", "5.2", "5.3", "6.3", "6.4", "6.5", "8.2", "8.11"],
    "T1003":     ["5.2", "5.4", "6.1", "6.2", "6.8", "8.2", "8.5", "10.5"],
    "T1003.001": ["5.2", "5.4", "6.1", "6.8", "8.2", "10.5"],
    "T1003.002": ["4.1", "5.2", "6.1", "8.2"],
    "T1003.003": ["5.2", "5.4", "6.1", "6.2", "8.2"],
    "T1003.006": ["5.3", "5.4", "6.1", "6.2", "8.2", "8.5"],
    "T1558":     ["5.2", "5.4", "6.3", "6.4", "8.2", "8.5"],
    "T1558.003": ["5.2", "5.4", "6.3", "8.2", "8.5"],
    "T1558.001": ["5.2", "5.4", "6.3", "6.4", "8.2", "8.5"],
    "T1555":     ["5.2", "3.3", "4.1", "8.2"],
    "T1555.003": ["5.2", "4.1", "9.1"],
    "T1552":     ["3.3", "3.12", "5.2", "8.2"],
    "T1552.001": ["3.3", "3.12", "5.2"],
    "T1557":     ["12.1", "12.6", "13.1", "13.6", "6.3"],
    "T1539":     ["5.2", "9.1", "9.2", "16.11"],
    "T1528":     ["5.2", "6.1", "6.3", "16.11"],

    # Phishing specifics
    "T1566":     ["9.1", "9.2", "9.6", "9.7", "14.1", "14.2", "14.3"],
    "T1566.001": ["9.1", "9.6", "9.7", "10.1", "14.1", "14.3"],
    "T1566.002": ["9.1", "9.2", "9.6", "14.1", "14.3"],

    # Supply chain
    "T1195":     ["2.1", "2.2", "2.5", "15.1", "15.2", "16.4"],
    "T1199":     ["6.1", "6.3", "6.4", "15.1", "15.2", "12.7"],

    # Exploitation
    "T1190":     ["7.1", "7.2", "7.4", "7.7", "16.1", "16.6", "16.12", "16.14", "13.1"],
    "T1189":     ["9.1", "9.2", "9.5", "7.1", "7.4"],
    "T1068":     ["7.1", "7.2", "7.4", "4.1", "4.7", "18.3"],

    # Execution specifics
    "T1059":     ["2.5", "2.6", "2.7", "8.8", "10.1", "10.5"],
    "T1059.001": ["2.5", "2.7", "8.8", "10.1", "10.5"],
    "T1059.003": ["2.5", "8.8", "10.1"],
    "T1059.004": ["2.5", "2.7", "8.8", "10.1"],
    "T1059.005": ["2.5", "2.7", "8.8", "9.6", "10.1"],
    "T1059.006": ["2.5", "2.7", "8.8", "10.1"],
    "T1059.007": ["2.5", "2.7", "8.8", "9.2", "10.1"],
    "T1204":     ["9.1", "9.2", "14.1", "14.2", "14.3", "10.1"],
    "T1047":     ["4.1", "4.8", "8.8", "8.5", "6.1"],
    "T1569":     ["4.1", "6.1", "8.5"],
    "T1569.002": ["4.1", "6.1", "8.5", "8.2"],

    # Persistence specifics
    "T1053":     ["4.1", "4.8", "5.3", "8.2", "8.5"],
    "T1053.005": ["4.1", "4.8", "5.3", "8.2", "8.5"],
    "T1053.003": ["4.1", "5.3", "8.2", "8.5"],
    "T1098":     ["5.1", "5.3", "5.4", "6.1", "6.2", "8.2", "8.5"],
    "T1136":     ["5.1", "5.3", "6.1", "8.2"],
    "T1136.001": ["5.1", "5.3", "6.1", "8.2"],
    "T1136.002": ["5.1", "5.3", "5.4", "6.1", "6.2", "8.2"],
    "T1543":     ["4.1", "8.2", "8.5", "10.1"],
    "T1543.003": ["4.1", "8.2", "8.5", "10.1"],
    "T1547":     ["4.1", "8.2", "10.1", "10.5"],
    "T1547.001": ["4.1", "8.2", "10.1", "10.5"],
    "T1547.009": ["4.1", "8.2", "10.1"],
    "T1546":     ["4.1", "8.2", "8.5", "10.1"],
    "T1556":     ["5.2", "5.4", "4.1", "8.2", "8.5"],
    "T1574":     ["2.5", "2.6", "4.1", "8.2", "10.1"],
    "T1542":     ["4.1", "8.2", "10.5"],
    "T1197":     ["2.5", "4.1", "8.2"],

    # Privilege escalation specifics
    "T1548":     ["4.1", "4.7", "5.4", "6.1", "6.8", "8.2"],
    "T1548.002": ["4.1", "4.7", "6.1", "6.8", "8.2"],
    "T1134":     ["5.4", "6.1", "6.8", "8.2", "8.5"],
    "T1484":     ["5.4", "6.1", "6.2", "8.2", "8.5"],

    # Defense evasion specifics
    "T1070":     ["8.2", "8.5", "8.9", "8.11"],
    "T1070.001": ["8.2", "8.5", "8.9", "8.11"],
    "T1070.004": ["8.2", "8.5"],
    "T1036":     ["2.5", "2.6", "8.2", "10.1", "10.5"],
    "T1036.005": ["2.5", "2.6", "8.2", "10.1"],
    "T1562":     ["8.2", "8.5", "10.1", "10.2", "13.1"],
    "T1562.001": ["8.2", "10.1", "10.2"],
    "T1562.004": ["4.5", "8.2", "12.1"],
    "T1027":     ["10.1", "10.5", "13.6"],
    "T1055":     ["8.2", "8.5", "10.1", "10.5", "10.7"],
    "T1140":     ["10.1", "10.5", "13.6"],
    "T1218":     ["2.5", "2.6", "8.2", "8.8"],
    "T1218.011": ["2.5", "2.6", "8.2", "8.8"],
    "T1218.005": ["2.5", "2.6", "8.2", "9.2"],
    "T1553":     ["2.5", "4.1", "10.5"],
    "T1112":     ["4.1", "8.2", "8.5"],
    "T1497":     ["10.1", "10.5"],
    "T1564":     ["8.2", "8.5", "10.1"],

    # Lateral movement specifics
    "T1021":     ["4.1", "4.2", "6.1", "6.3", "6.4", "12.1", "12.7", "13.1", "13.4"],
    "T1021.001": ["4.1", "6.1", "6.3", "6.4", "12.7", "13.1"],
    "T1021.002": ["4.1", "4.2", "6.1", "6.3", "12.1", "13.1", "13.4"],
    "T1021.003": ["4.1", "6.1", "8.2"],
    "T1021.004": ["4.1", "6.1", "6.3", "6.5", "12.7", "13.1"],
    "T1021.006": ["4.1", "6.1", "6.3", "8.2", "8.8"],
    "T1570":     ["2.5", "6.1", "12.1", "13.1"],
    "T1080":     ["3.3", "6.1", "13.1"],
    "T1550":     ["5.2", "6.3", "6.4", "8.2", "13.1"],
    "T1550.002": ["5.2", "6.3", "6.4", "8.2", "13.1"],
    "T1550.003": ["5.2", "6.3", "6.4", "8.2", "13.1"],
    "T1563":     ["6.1", "6.3", "8.2", "13.1"],

    # Collection specifics
    "T1560":     ["3.1", "3.3", "8.2", "13.1"],
    "T1074":     ["3.1", "3.3", "8.2"],
    "T1005":     ["3.1", "3.3", "6.1", "8.2"],
    "T1039":     ["3.3", "6.1", "8.2", "13.1"],
    "T1025":     ["3.1", "3.3", "8.2", "10.3"],
    "T1114":     ["3.1", "3.3", "8.2", "9.1"],
    "T1113":     ["8.2", "10.1"],
    "T1056":     ["5.2", "8.2", "10.1", "10.5"],
    "T1119":     ["3.3", "8.2", "13.1"],

    # C2 specifics
    "T1071":     ["9.2", "12.1", "13.1", "13.3", "13.6"],
    "T1071.001": ["9.2", "12.1", "13.1", "13.3", "13.6"],
    "T1071.002": ["12.1", "13.1", "13.3", "13.6"],
    "T1071.003": ["9.1", "12.1", "13.1", "13.3"],
    "T1071.004": ["9.2", "12.1", "13.1", "13.3", "13.6"],
    "T1573":     ["12.1", "13.1", "13.3", "13.6"],
    "T1095":     ["12.1", "13.1", "13.6", "4.5"],
    "T1572":     ["12.1", "13.1", "13.3", "13.6"],
    "T1090":     ["12.1", "13.1", "13.3"],
    "T1090.001": ["12.1", "13.1", "13.4"],
    "T1090.002": ["12.1", "13.1", "13.3"],
    "T1105":     ["2.5", "10.1", "13.1", "13.6"],
    "T1568":     ["9.2", "13.1", "13.3", "13.6"],
    "T1568.002": ["9.2", "13.1", "13.3", "13.6"],
    "T1571":     ["4.5", "12.1", "13.1", "13.3"],
    "T1132":     ["13.1", "13.3", "13.6"],
    "T1001":     ["13.1", "13.3", "13.6"],
    "T1219":     ["2.5", "4.5", "9.2", "13.1"],
    "T1102":     ["9.2", "13.1", "13.3"],

    # Exfiltration specifics
    "T1041":     ["3.1", "3.2", "13.1", "13.3", "13.8"],
    "T1048":     ["3.1", "4.5", "12.1", "13.1", "13.3", "13.8"],
    "T1048.001": ["3.1", "4.5", "12.1", "13.1", "13.3"],
    "T1048.003": ["3.1", "4.5", "12.1", "13.1", "13.3", "13.8"],
    "T1567":     ["3.1", "9.2", "13.1", "13.3", "13.8"],
    "T1567.002": ["3.1", "9.2", "13.1", "13.3", "13.8"],
    "T1029":     ["3.1", "13.1", "13.3"],
    "T1030":     ["3.1", "13.1", "13.3"],
    "T1537":     ["3.1", "6.1", "13.1"],
    "T1020":     ["3.1", "13.1", "13.3", "13.8"],
    "T1011":     ["3.1", "12.1", "13.1"],

    # Impact specifics
    "T1486":     ["3.1", "11.1", "11.2", "11.3", "11.4", "11.5", "17.1", "17.4"],
    "T1490":     ["4.1", "11.1", "11.2", "11.3", "11.4", "8.2"],
    "T1489":     ["4.1", "8.2", "17.1"],
    "T1485":     ["3.1", "11.1", "11.2", "11.3", "11.4", "11.5", "8.2"],
    "T1491":     ["7.1", "11.1", "16.1"],
    "T1499":     ["12.1", "13.1", "13.10"],
    "T1498":     ["12.1", "13.1", "13.10"],
    "T1531":     ["5.1", "5.3", "6.1", "8.2", "17.1"],
    "T1565":     ["3.1", "3.2", "8.2", "11.1"],
    "T1561":     ["3.1", "11.1", "11.2", "11.3", "11.4", "11.5"],
    "T1529":     ["4.1", "8.2", "17.1"],

    # Valid Accounts specifics
    "T1078":     ["5.1", "5.2", "5.3", "5.4", "6.1", "6.3", "6.4", "6.5", "8.2", "8.5", "8.11"],
    "T1078.001": ["4.1", "5.1", "5.2", "6.1", "8.2"],
    "T1078.002": ["5.1", "5.2", "5.3", "5.4", "6.1", "6.3", "6.4", "8.2"],
    "T1078.003": ["5.1", "5.2", "5.3", "6.1", "6.3", "8.2"],
    "T1078.004": ["5.1", "5.2", "5.3", "6.1", "6.3", "6.5", "8.2"],

    # External Remote Services / Valid Accounts
    "T1133":     ["4.1", "4.5", "6.3", "6.4", "12.1", "12.7", "13.1"],

    # Discovery specifics
    "T1087":     ["5.3", "6.1", "8.2", "8.5"],
    "T1082":     ["8.2", "8.5"],
    "T1083":     ["3.3", "8.2", "8.5"],
    "T1046":     ["1.1", "12.1", "13.1", "13.3"],
    "T1135":     ["3.3", "6.1", "8.2", "13.1"],
    "T1040":     ["6.3", "12.1", "12.6", "13.1"],
    "T1049":     ["8.2", "13.1"],
    "T1016":     ["8.2"],
    "T1018":     ["1.1", "8.2", "13.1"],
    "T1057":     ["8.2", "8.5"],
    "T1069":     ["5.3", "6.1", "8.2"],
    "T1012":     ["8.2", "8.5"],
    "T1518":     ["2.1", "2.2", "8.2"],
    "T1518.001": ["2.1", "2.2", "8.2", "10.1"],
}

TECHNIQUE_NIST_OVERRIDES = {
    # Credential access needs ID (identify compromised creds)
    "T1110":     ["PR.AA", "DE.CM", "DE.AE", "RS.AN"],
    "T1003":     ["PR.AA", "PR.DS", "DE.CM", "DE.AE"],
    "T1558":     ["PR.AA", "DE.CM", "DE.AE"],

    # Phishing needs awareness
    "T1566":     ["PR.AA", "PR.AT", "DE.CM", "DE.AE"],
    "T1566.001": ["PR.AT", "DE.CM", "DE.AE"],
    "T1566.002": ["PR.AT", "PR.IR", "DE.CM"],

    # Impact needs response and recovery
    "T1486":     ["PR.DS", "PR.IR", "RS.AN", "RS.MI", "RC.RP"],
    "T1490":     ["PR.DS", "PR.IR", "RS.MI", "RC.RP"],
    "T1485":     ["PR.DS", "RS.AN", "RS.MI", "RC.RP"],
    "T1489":     ["PR.IR", "RS.MI", "RC.RP"],

    # Lateral movement
    "T1021":     ["PR.AA", "PR.IR", "DE.CM", "DE.AE"],
    "T1550":     ["PR.AA", "DE.CM", "DE.AE"],

    # Log clearing
    "T1070":     ["PR.PS", "DE.CM", "RS.AN"],
    "T1070.001": ["PR.PS", "DE.CM", "RS.AN"],
}


def build_mapping():
    """Build the complete technique-to-controls mapping."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    techniques_path = os.path.join(base_dir, "assets", "mitre-attack-techniques.json")

    with open(techniques_path) as f:
        techniques = json.load(f)

    mappings = []

    for tech in techniques:
        tid = tech["id"]
        tactics = tech["tactics"]

        # ── CIS Controls ──
        if tid in TECHNIQUE_CIS_OVERRIDES:
            cis = sorted(set(TECHNIQUE_CIS_OVERRIDES[tid]))
        else:
            # Aggregate from tactic-level mappings
            cis = set()
            for tactic in tactics:
                cis.update(TACTIC_TO_CIS.get(tactic, []))
            cis = sorted(cis)

        # ── NIST CSF ──
        if tid in TECHNIQUE_NIST_OVERRIDES:
            nist = sorted(set(TECHNIQUE_NIST_OVERRIDES[tid]))
        else:
            nist = set()
            for tactic in tactics:
                nist.update(TACTIC_TO_NIST.get(tactic, []))
            nist = sorted(nist)

        mappings.append({
            "technique_id": tid,
            "technique_name": tech["name"],
            "tactics": tactics,
            "cis_safeguards": cis,
            "nist_csf_categories": nist,
        })

    output = {
        "version": "1.0.0",
        "description": "MITRE ATT&CK to CIS Controls v8.1.2 + NIST CSF 2.0 deterministic mappings",
        "technique_count": len(mappings),
        "sources": [
            "CIS Controls v8 ATT&CK Mappings",
            "NIST CSF to ATT&CK Navigator",
            "MITRE ATT&CK Mitigations cross-references"
        ],
        "mappings": mappings
    }

    output_path = os.path.join(base_dir, "assets", "mitre-to-controls-map.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Generated {len(mappings)} technique mappings")
    print(f"Output: {output_path}")

    # Stats
    cis_counts = [len(m["cis_safeguards"]) for m in mappings]
    nist_counts = [len(m["nist_csf_categories"]) for m in mappings]
    print(f"CIS safeguards per technique: min={min(cis_counts)}, max={max(cis_counts)}, avg={sum(cis_counts)/len(cis_counts):.1f}")
    print(f"NIST categories per technique: min={min(nist_counts)}, max={max(nist_counts)}, avg={sum(nist_counts)/len(nist_counts):.1f}")


if __name__ == "__main__":
    build_mapping()
