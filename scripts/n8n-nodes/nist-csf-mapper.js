// NIST CSF 2.0 Mapping Node for n8n
// Paste this code into an n8n Code node
// Maps analyst findings to NIST CSF 2.0 functions and categories

const fs = require('fs');

// Read the NIST CSF 2.0 framework data
const csfData = JSON.parse(
  fs.readFileSync('/home/node/assets/nist-csf-2.0.json', 'utf8')
);

// Get findings from upstream (MITRE Lookup node passes analyst_findings through)
const inputData = $input.first().json;
const findings = inputData.analyst_findings || JSON.stringify(inputData);
const techniques = inputData.techniques || [];

// Normalize text for matching
const normalizedFindings = findings.toLowerCase()
  .replace(/[^a-z0-9\s\-\.]/g, ' ')
  .replace(/\s+/g, ' ')
  .trim();

// Score each CSF category against findings
const mappings = [];

for (const func of csfData.functions) {
  for (const category of func.categories) {
    let score = 0;

    // Keyword matching against findings
    for (const keyword of (category.keywords || [])) {
      if (normalizedFindings.includes(keyword.toLowerCase())) {
        score += 1;
      }
    }

    // Category name matching
    if (normalizedFindings.includes(category.name.toLowerCase())) {
      score += 2;
    }

    // Boost based on MITRE technique tactics → CSF function correlation
    // DE (Detect) correlates with Discovery, Initial Access detection
    // RS (Respond) correlates with incident-related findings
    // PR (Protect) correlates with prevention-related findings
    const tacticToCsf = {
      'Initial Access': ['DE', 'PR'],
      'Execution': ['DE', 'PR'],
      'Persistence': ['DE', 'PR'],
      'Privilege Escalation': ['DE', 'PR', 'GV'],
      'Defense Evasion': ['DE'],
      'Credential Access': ['DE', 'PR', 'ID'],
      'Discovery': ['DE'],
      'Lateral Movement': ['DE', 'RS'],
      'Collection': ['DE', 'PR'],
      'Command and Control': ['DE', 'RS'],
      'Exfiltration': ['DE', 'RS', 'RC'],
      'Impact': ['RS', 'RC']
    };

    for (const technique of techniques) {
      for (const tactic of technique.tactics) {
        const correlatedFunctions = tacticToCsf[tactic] || [];
        if (correlatedFunctions.includes(func.id)) {
          score += 0.5;
        }
      }
    }

    if (score > 0) {
      mappings.push({
        function_id: func.id,
        function_name: func.name,
        category_id: category.id,
        category_name: category.name,
        description: category.description,
        score: score,
        relevant_subcategories: (category.subcategories || [])
          .map(sc => ({ id: sc.id, description: sc.description }))
      });
    }
  }
}

// Sort by score, take top matches
mappings.sort((a, b) => b.score - a.score);
const topMappings = mappings.slice(0, 8);

// Group by function for cleaner output
const byFunction = {};
for (const m of topMappings) {
  if (!byFunction[m.function_id]) {
    byFunction[m.function_id] = {
      function_id: m.function_id,
      function_name: m.function_name,
      categories: []
    };
  }
  byFunction[m.function_id].categories.push({
    category_id: m.category_id,
    category_name: m.category_name,
    description: m.description,
    relevant_subcategories: m.relevant_subcategories.slice(0, 3)
  });
}

return [{
  json: {
    nist_csf_mappings: Object.values(byFunction),
    total_mappings: topMappings.length,
    // Pass through upstream data for downstream nodes
    techniques: techniques,
    analyst_findings: findings
  }
}];
