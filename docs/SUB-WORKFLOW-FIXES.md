# CASA Sub-Workflow Code Fixes

Apply these fixes to ALL 9 sub-workflows:
- casa-auth-anomaly
- casa-beaconing
- casa-exfiltration
- casa-lateral-movement
- casa-privilege-escalation
- casa-persistence
- casa-ransomware
- casa-insider-threat
- casa-vulnerability-exploitation

---

## Fix 1: MITRE Lookup Node — investigation_type propagation

**Problem:** The MITRE Lookup reads `investigation_type` from its immediate input (the Ollama
analyst response), which doesn't contain it. Always defaults to `'general'`, disabling
tactic boosting for the specific investigation type.

**Find this line** (near the top of the MITRE Lookup code):
```javascript
const investigationType = $input.first().json.investigation_type || 'general';
```

**Replace with:**
```javascript
// Get investigation_type from the workflow trigger (not from Ollama response, which strips it)
let investigationType = 'general';
try {
  investigationType = $('Execute Workflow Trigger').first().json.investigation_type || 'general';
} catch (e) {
  // Fallback: check immediate input (works if data was passed through)
  investigationType = $input.first().json.investigation_type || 'general';
}
```

---

## Fix 2: Report Formatter Node — query retrieval crash

**Problem:** The query retrieval uses `||` chaining with `$('Webhook Trigger')`, which
doesn't exist in sub-workflows. When the first operand is falsy, JavaScript evaluates
the second operand, which throws, and the catch block returns `'N/A'`.

**Find this block** (in the Report Formatter):
```javascript
try {
  originalQuery = $('Execute Workflow Trigger').first().json.query ||
                  $('Webhook Trigger').first().json.body.query || '';
} catch (e) {
  originalQuery = synthesizerOutput.query || 'N/A';
}
```

**Replace with:**
```javascript
// Get query from the workflow trigger — DO NOT reference $('Webhook Trigger')
// which doesn't exist in sub-workflows and causes the entire try to throw
try {
  originalQuery = $('Execute Workflow Trigger').first().json.query || '';
} catch (e) {
  originalQuery = '';
}
if (!originalQuery) {
  originalQuery = synthesizerOutput.query || 'N/A';
}
```

---

## Fix 3: Report Formatter Node — investigation_type fallback

**Problem:** The Report Formatter gets `investigationType` from MITRE Lookup, which
(before Fix 1) defaults to 'general'. Even after Fix 1, add a safety fallback.

**Find this block** (after the MITRE Lookup try/catch in Report Formatter):
```javascript
try {
  const mitreData     = $('MITRE Lookup').first().json;
  techniques          = mitreData.techniques        || [];
  analystFindings     = mitreData.analyst_findings  || '';
  investigationType   = mitreData.investigation_type || 'general';
} catch (e) {
  techniques = synthesizerOutput.techniques || [];
}
```

**Add immediately after that block:**
```javascript
// Safety: if MITRE Lookup still says 'general', check the workflow trigger directly
if (investigationType === 'general') {
  try {
    const triggerType = $('Execute Workflow Trigger').first().json.investigation_type;
    if (triggerType && triggerType !== 'general') {
      investigationType = triggerType;
    }
  } catch (e) {
    // Trigger reference failed — keep 'general'
  }
}
```

---

## Fix 4: Report Formatter — Add missing display names

**Find the `typeDisplayNames` object:**
```javascript
const typeDisplayNames = {
  'auth_anomaly':    'Authentication Anomaly Investigation',
  'beaconing':       'Beaconing / C2 Communication Investigation',
  'exfiltration':    'Data Exfiltration Investigation',
  'lateral_movement':'Lateral Movement Investigation',
  'general':         'General Security Investigation',
};
```

**Replace with (add all 9 types):**
```javascript
const typeDisplayNames = {
  'auth_anomaly':              'Authentication Anomaly Investigation',
  'beaconing':                 'Beaconing / C2 Communication Investigation',
  'exfiltration':              'Data Exfiltration Investigation',
  'lateral_movement':          'Lateral Movement Investigation',
  'privilege_escalation':      'Privilege Escalation Investigation',
  'persistence':               'Persistence Mechanism Investigation',
  'ransomware':                'Ransomware Incident Investigation',
  'insider_threat':            'Insider Threat Investigation',
  'vulnerability_exploitation':'Vulnerability Exploitation Investigation',
  'general':                   'General Security Investigation',
};
```
