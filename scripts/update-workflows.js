#!/usr/bin/env node
// Update all CASA n8n workflows to add CAR Coverage Lookup and CIS Controls Mapper nodes
// Run: node scripts/update-workflows.js
//
// What this does:
// 1. Reads each workflow JSON file
// 2. Inserts CAR Coverage Lookup node (between MITRE Lookup and NIST CSF Mapper)
// 3. Inserts CIS Controls Mapper node (between NIST CSF Mapper and PurpleTeamMapper/Synthesizer)
// 4. Updates connection chains accordingly
// 5. Writes updated JSON back

const fs   = require('fs');
const path = require('path');

const WORKFLOWS_DIR = path.join(__dirname, '..', 'workflows');

// ── Inline JS for CAR Coverage Lookup node ───────────────────────────────────

const CAR_LOOKUP_JS = `
const fs = require('fs');
const coverageData = JSON.parse(
  fs.readFileSync('/home/node/assets/car-analytic-coverage.json', 'utf8')
);
const coverageMap = new Map();
for (const tech of coverageData.techniques) {
  coverageMap.set(tech.id, tech.coverage);
}
const inputData = $input.first().json;
const techniques        = inputData.techniques        || [];
const investigationType = inputData.investigation_type || 'general';
const analystFindings   = inputData.analyst_findings   || '';

const enrichedTechniques = techniques.map(t => {
  const coverage = coverageMap.get(t.id) || { car: 0, sigma: 0, es_siem: 0, splunk: 0, total: 0 };
  return { ...t, coverage };
});

const coverageGaps = enrichedTechniques.filter(t => t.coverage.total === 0).map(t => ({
  id: t.id, name: t.name, tactics: t.tactics, coverage: t.coverage,
}));

const lowCoverage = enrichedTechniques.filter(t => t.coverage.total > 0 && t.coverage.total < 5).map(t => ({
  id: t.id, name: t.name, tactics: t.tactics, coverage: t.coverage,
}));

return [{
  json: {
    techniques: enrichedTechniques,
    coverage_gaps: coverageGaps,
    low_coverage: lowCoverage,
    coverage_db_version: coverageData.version,
    investigation_type: investigationType,
    analyst_findings: analystFindings,
    technique_count: techniques.length,
  }
}];
`.trim();

// ── Inline JS for CIS Controls Mapper node ───────────────────────────────────

const CIS_MAPPER_JS = `
const fs = require('fs');
const cisData = JSON.parse(
  fs.readFileSync('/home/node/assets/cis-controls-v8.1.2.json', 'utf8')
);
const inputData = $input.first().json;
const findings     = inputData.analyst_findings  || JSON.stringify(inputData);
const techniques   = inputData.techniques        || [];
const nistMappings = inputData.nist_csf_mappings || [];
const coverageGaps = inputData.coverage_gaps     || [];
const lowCoverage  = inputData.low_coverage      || [];

const normalizedFindings = findings.toLowerCase()
  .replace(/[^a-z0-9\\s\\-\\.]/g, ' ').replace(/\\s+/g, ' ').trim();

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

const safeguardScores = [];
for (const control of cisData.controls) {
  for (const sg of control.safeguards) {
    let score = 0;
    for (const kw of (sg.keywords || [])) if (normalizedFindings.includes(kw.toLowerCase())) score += 1;
    if (normalizedFindings.includes(sg.title.toLowerCase())) score += 3;
    const secFunc = sg.security_function || '';
    for (const tactic of observedTactics) {
      const fns = tacticToCisFunction[tactic] || [];
      if (fns.some(f => f.toLowerCase() === secFunc.toLowerCase())) score += 0.5;
    }
    if (coverageGaps.length > 0 && secFunc.toLowerCase() === 'detect') score += coverageGaps.length * 0.25;
    if (score > 0) safeguardScores.push({
      control_id: control.id, control_title: control.title,
      safeguard_id: sg.id, safeguard_title: sg.title, description: sg.description,
      asset_type: sg.asset_type, security_function: sg.security_function,
      nist_csf_function: sg.nist_csf_function, implementation_groups: sg.implementation_groups, score,
    });
  }
}

safeguardScores.sort((a, b) => b.score - a.score);
const topSafeguards = safeguardScores.slice(0, 12);
const byControl = {};
for (const sg of topSafeguards) {
  if (!byControl[sg.control_id]) byControl[sg.control_id] = { control_id: sg.control_id, control_title: sg.control_title, safeguards: [] };
  byControl[sg.control_id].safeguards.push({ id: sg.safeguard_id, title: sg.safeguard_title,
    description: sg.description, asset_type: sg.asset_type, security_function: sg.security_function,
    nist_csf_function: sg.nist_csf_function, implementation_groups: sg.implementation_groups });
}
const cisMappings = Object.values(byControl).sort((a, b) => a.control_id - b.control_id);
const quickWins = topSafeguards.filter(sg => sg.implementation_groups.includes('IG1')).slice(0, 6)
  .map(sg => ({ id: sg.safeguard_id, title: sg.safeguard_title, control_id: sg.control_id,
    control_title: sg.control_title, security_function: sg.security_function, implementation_groups: sg.implementation_groups }));

return [{ json: {
  cis_mappings: cisMappings, cis_quick_wins: quickWins, cis_safeguard_count: topSafeguards.length,
  techniques, nist_csf_mappings: nistMappings, analyst_findings: findings,
  coverage_gaps: coverageGaps, low_coverage: lowCoverage,
}}];
`.trim();

// ── Node template factories ───────────────────────────────────────────────────

function makeCarNode(idSuffix, x, y) {
  return {
    id: `casa-car-lookup-${idSuffix}`,
    name: 'CAR Coverage Lookup',
    type: 'n8n-nodes-base.code',
    typeVersion: 2,
    position: [x, y],
    parameters: { jsCode: CAR_LOOKUP_JS },
  };
}

function makeCisNode(idSuffix, x, y) {
  return {
    id: `casa-cis-mapper-${idSuffix}`,
    name: 'CIS Controls Mapper',
    type: 'n8n-nodes-base.code',
    typeVersion: 2,
    position: [x, y],
    parameters: { jsCode: CIS_MAPPER_JS },
  };
}

function makeConn(targetNode) {
  return { node: targetNode, type: 'main', index: 0 };
}

// ── Workflow updater ──────────────────────────────────────────────────────────

function updateWorkflow(workflow, isMaster) {
  const nodes       = workflow.nodes;
  const connections = workflow.connections;

  // Find existing node names present in this workflow
  const nodeNames = new Set(nodes.map(n => n.name));

  // Skip if already updated
  if (nodeNames.has('CAR Coverage Lookup') && nodeNames.has('CIS Controls Mapper')) {
    console.log('  Already updated — skipping');
    return workflow;
  }

  // Find MITRE Lookup position to place new nodes nearby
  const mitreLookup = nodes.find(n => n.name === 'MITRE Lookup');
  const nistMapper  = nodes.find(n => n.name === 'NIST CSF Mapper');

  if (!mitreLookup || !nistMapper) {
    console.warn('  WARNING: MITRE Lookup or NIST CSF Mapper not found — skipping');
    return workflow;
  }

  const [mx, my] = mitreLookup.position;
  const [nx, ny] = nistMapper.position;

  // For the CAR node: place between MITRE Lookup and NIST CSF Mapper
  const carX = mx + Math.round((nx - mx) * 0.4);
  const carY = my;

  // For CIS node: place after NIST CSF Mapper
  const cisX = nx + (nx - mx);
  const cisY = ny;

  const idSuffix = isMaster ? 'master' : workflow.name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '').slice(-20);

  const carNode = makeCarNode(idSuffix, carX, carY);
  const cisNode = makeCisNode(idSuffix, cisX, cisY);

  // Add new nodes
  nodes.push(carNode);
  nodes.push(cisNode);

  // Find what NIST CSF Mapper currently connects TO (downstream node)
  const nistDownstream = connections['NIST CSF Mapper']?.main?.[0]?.[0]?.node;

  // Rewire connections:
  // Old: MITRE Lookup → NIST CSF Mapper → [downstream]
  // New: MITRE Lookup → CAR Coverage Lookup → NIST CSF Mapper → CIS Controls Mapper → [downstream]

  // MITRE Lookup now points to CAR Coverage Lookup
  connections['MITRE Lookup'] = { main: [[makeConn('CAR Coverage Lookup')]] };

  // CAR Coverage Lookup → NIST CSF Mapper
  connections['CAR Coverage Lookup'] = { main: [[makeConn('NIST CSF Mapper')]] };

  // NIST CSF Mapper → CIS Controls Mapper (was → downstream)
  connections['NIST CSF Mapper'] = { main: [[makeConn('CIS Controls Mapper')]] };

  // CIS Controls Mapper → original downstream node
  if (nistDownstream) {
    connections['CIS Controls Mapper'] = { main: [[makeConn(nistDownstream)]] };
  }

  // Update PurpleTeamMapper prompt to reference CIS Controls and CAR data (in sub-workflows)
  const purpleMapper = nodes.find(n => n.name === 'PurpleTeamMapper' || n.name === 'PurpleTeamMapper Auth' ||
    n.name === 'PurpleTeamMapper Beaconing' || n.name === 'PurpleTeamMapper Exfil' ||
    n.name === 'PurpleTeamMapper Lateral' || n.name === 'PurpleTeamMapper Improvement');

  if (purpleMapper && purpleMapper.parameters && purpleMapper.parameters.jsonBody) {
    const oldBody = purpleMapper.parameters.jsonBody;
    if (!oldBody.includes('CIS Controls') && oldBody.includes('casa-purple-mapper')) {
      // Append CIS and CAR data to the prompt
      purpleMapper.parameters.jsonBody = oldBody.replace(
        /prompt: '([^']*?)Analysis findings:/,
        "prompt: '$1CIS Controls recommendations: ' + JSON.stringify($('CIS Controls Mapper').item.json.cis_mappings) + ' Detection coverage gaps: ' + JSON.stringify($('CAR Coverage Lookup').item.json.coverage_gaps) + ' Analysis findings:"
      );
    }
  }

  return workflow;
}

// ── Process all workflow files ────────────────────────────────────────────────

const workflowFiles = fs.readdirSync(WORKFLOWS_DIR)
  .filter(f => f.endsWith('.json'))
  .map(f => path.join(WORKFLOWS_DIR, f));

for (const filePath of workflowFiles) {
  const fileName = path.basename(filePath);
  console.log(`\nProcessing: ${fileName}`);

  let workflow;
  try {
    workflow = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    console.error(`  ERROR parsing JSON: ${e.message}`);
    continue;
  }

  const isMaster = fileName.includes('master');
  const updated  = updateWorkflow(workflow, isMaster);

  fs.writeFileSync(filePath, JSON.stringify(updated, null, 2), 'utf8');
  const nodeCount = updated.nodes.length;
  console.log(`  ✓ Saved (${nodeCount} nodes)`);
}

console.log('\n✓ All workflows updated.');
console.log('\nIMPORTANT: Re-import updated workflow JSON files into n8n UI to apply changes.');
console.log('  1. Open n8n → Workflows');
console.log('  2. Delete the existing workflow');
console.log('  3. Import the updated JSON file');
console.log('  4. Activate the workflow');
