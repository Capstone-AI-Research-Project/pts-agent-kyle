// MITRE CAR Analytic Coverage Lookup Node for n8n
// Paste this code into an n8n Code node
// Enriches MITRE ATT&CK technique matches with detection rule coverage data
// (CAR, Sigma, ES SIEM, Splunk counts) from the MITRE analytic coverage dataset
//
// Position: Insert AFTER "MITRE Lookup" node, BEFORE "NIST CSF Mapper" node

const fs = require('fs');

// Read the CAR analytic coverage database
const coverageData = JSON.parse(
  fs.readFileSync('/home/node/assets/car-analytic-coverage.json', 'utf8')
);

// Build a fast O(1) lookup map by technique ID
const coverageMap = new Map();
for (const tech of coverageData.techniques) {
  coverageMap.set(tech.id, tech.coverage);
}

// Get data from upstream MITRE Lookup node
const inputData = $input.first().json;
const techniques        = inputData.techniques        || [];
const investigationType = inputData.investigation_type || 'general';
const analystFindings   = inputData.analyst_findings   || '';

// Enrich each matched technique with coverage data
const enrichedTechniques = techniques.map(t => {
  const coverage = coverageMap.get(t.id) || { car: 0, sigma: 0, es_siem: 0, splunk: 0, total: 0 };
  return { ...t, coverage };
});

// Identify techniques with no detection rules anywhere
const coverageGaps = enrichedTechniques.filter(t => t.coverage.total === 0).map(t => ({
  id: t.id,
  name: t.name,
  tactics: t.tactics,
  coverage: t.coverage,
}));

// Identify techniques with very few detections (total < 5)
const lowCoverage = enrichedTechniques.filter(t => t.coverage.total > 0 && t.coverage.total < 5).map(t => ({
  id: t.id,
  name: t.name,
  tactics: t.tactics,
  coverage: t.coverage,
}));

// Sort enriched techniques by descending total coverage (most-detectable first)
// within the existing relevance ordering from MITRE Lookup
const sortedByScore = [...enrichedTechniques].sort((a, b) => b.score - a.score);

return [{
  json: {
    // Enriched techniques with coverage data appended
    techniques: sortedByScore,

    // Techniques with zero detection rules — highest priority gaps
    coverage_gaps: coverageGaps,

    // Techniques with very low detection coverage
    low_coverage: lowCoverage,

    // Coverage dataset metadata
    coverage_db_version: coverageData.version,
    coverage_db_techniques: coverageData.technique_count,

    // Pass-through for downstream nodes
    investigation_type:  investigationType,
    analyst_findings:    analystFindings,
    technique_count:     techniques.length,
  }
}];
