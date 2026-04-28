// MITRE ATT&CK Lookup Node for n8n
// Paste this code into an n8n Code node
// Reads MITRE ATT&CK techniques from JSON and matches against analyst findings

const fs = require('fs');

// Read the MITRE ATT&CK techniques database
const techniquesData = JSON.parse(
  fs.readFileSync('/home/node/assets/mitre-attack-techniques.json', 'utf8')
);

// Get analyst findings from upstream nodes
const inputData = $input.all();
const findings = inputData.map(item => {
  // Handle both direct response text and structured objects
  if (typeof item.json === 'string') return item.json;
  if (item.json.response) return item.json.response;
  return JSON.stringify(item.json);
}).join(' ');

// Get investigation type if available (for boosting relevant tactics)
const investigationType = $('Parse Router Output')?.item?.json?.investigation_type || 'general';

// Investigation-type-specific tactic boosting
const tacticBoosts = {
  'auth_anomaly': ['Credential Access', 'Initial Access', 'Privilege Escalation', 'Persistence'],
  'beaconing': ['Command and Control', 'Exfiltration', 'Defense Evasion'],
  'exfiltration': ['Exfiltration', 'Collection', 'Command and Control'],
  'lateral_movement': ['Lateral Movement', 'Discovery', 'Credential Access', 'Execution'],
  'privilege_escalation': ['Privilege Escalation', 'Credential Access', 'Execution', 'Defense Evasion'],
  'persistence': ['Persistence', 'Defense Evasion', 'Execution', 'Privilege Escalation'],
  'ransomware': ['Impact', 'Execution', 'Defense Evasion', 'Command and Control', 'Lateral Movement'],
  'insider_threat': ['Collection', 'Exfiltration', 'Credential Access', 'Discovery'],
  'vulnerability_exploitation': ['Initial Access', 'Execution', 'Privilege Escalation', 'Defense Evasion'],
  'general': []
};

const boostedTactics = tacticBoosts[investigationType] || [];

// Normalize text for keyword matching
function normalizeText(text) {
  return text.toLowerCase()
    .replace(/[^a-z0-9\s\-\.]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// Extract meaningful terms from findings
const normalizedFindings = normalizeText(findings);
const findingsTerms = normalizedFindings.split(' ').filter(t => t.length > 2);

// Score each technique against the findings
const scoredTechniques = techniquesData.map(technique => {
  let score = 0;

  // Keyword matching
  for (const keyword of technique.keywords) {
    const normalizedKeyword = keyword.toLowerCase();
    // Check if the keyword (which may be multi-word) appears in findings
    if (normalizedFindings.includes(normalizedKeyword)) {
      score += normalizedKeyword.split(' ').length; // Multi-word matches score higher
    }
  }

  // Tactic boosting for investigation type
  if (boostedTactics.length > 0) {
    const tacticOverlap = technique.tactics.filter(t => boostedTactics.includes(t));
    score += tacticOverlap.length * 0.5; // Boost by 0.5 per matching tactic
  }

  // Name matching (technique name appears in findings)
  if (normalizedFindings.includes(technique.name.toLowerCase())) {
    score += 3;
  }

  // ID matching (technique ID explicitly mentioned)
  if (normalizedFindings.includes(technique.id.toLowerCase())) {
    score += 5;
  }

  return {
    id: technique.id,
    name: technique.name,
    tactics: technique.tactics,
    description: technique.description,
    detection: technique.detection,
    score: score
  };
}).filter(t => t.score > 0);

// Sort by score descending, take top 10
scoredTechniques.sort((a, b) => b.score - a.score);
const topTechniques = scoredTechniques.slice(0, 10);

// Build output
return [{
  json: {
    techniques: topTechniques,
    technique_count: topTechniques.length,
    investigation_type: investigationType,
    total_techniques_scanned: techniquesData.length,
    // Pass through the original findings for downstream nodes
    analyst_findings: findings
  }
}];
