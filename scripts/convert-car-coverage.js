#!/usr/bin/env node
// Convert MITRE CAR Analytic Coverage CSV to JSON
// Input:  assets/analytic_coverage_01_08_2024.csv
// Output: assets/car-analytic-coverage.json
//
// Run: node scripts/convert-car-coverage.js

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const ASSETS_DIR = path.join(__dirname, '..', 'assets');
const INPUT_FILE = path.join(ASSETS_DIR, 'analytic_coverage_01_08_2024.csv');
const OUTPUT_FILE = path.join(ASSETS_DIR, 'car-analytic-coverage.json');

async function convertCarCoverage() {
  if (!fs.existsSync(INPUT_FILE)) {
    console.error(`ERROR: Input file not found: ${INPUT_FILE}`);
    process.exit(1);
  }

  const fileStream = fs.createReadStream(INPUT_FILE);
  const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

  const techniques = [];
  let isHeader = true;
  let lineNum = 0;

  for await (const line of rl) {
    lineNum++;
    if (isHeader) {
      isHeader = false;
      // Verify expected header
      if (!line.includes('Technique') || !line.includes('CAR')) {
        console.warn(`Warning: Unexpected header at line 1: ${line}`);
      }
      continue;
    }

    const trimmed = line.trim();
    if (!trimmed) continue;

    // CSV format: Technique (ID), Technique (Name), Sub-technique (Name),
    //             Num. CAR, Num. Sigma, Num. ES SIEM, Num. Splunk, Total
    const cols = trimmed.split(',');
    if (cols.length < 8) continue;

    const id      = cols[0].trim();
    const name    = cols[1].trim();
    const subName = cols[2].trim();
    const car     = parseInt(cols[3].trim(), 10) || 0;
    const sigma   = parseInt(cols[4].trim(), 10) || 0;
    const esSiem  = parseInt(cols[5].trim(), 10) || 0;
    const splunk  = parseInt(cols[6].trim(), 10) || 0;
    const total   = parseInt(cols[7].trim(), 10) || 0;

    // Only include rows with valid technique IDs (T1234 or T1234.001 format)
    if (!id || !/^T\d{4}(\.\d{3})?$/.test(id)) continue;

    techniques.push({
      id,
      name,
      subtechnique: (subName === 'n/a' || !subName) ? null : subName,
      coverage: { car, sigma, es_siem: esSiem, splunk, total }
    });
  }

  // Coverage statistics
  const gapCount  = techniques.filter(t => t.coverage.total === 0).length;
  const lowCount  = techniques.filter(t => t.coverage.total > 0 && t.coverage.total < 5).length;
  const goodCount = techniques.length - gapCount - lowCount;

  const output = {
    version: '2024-01-08',
    description: 'MITRE ATT&CK Analytic Coverage — detection rule counts across CAR, Sigma, ES SIEM, and Splunk',
    source: 'analytic_coverage_01_08_2024.csv',
    technique_count: techniques.length,
    coverage_stats: {
      no_coverage:  gapCount,
      low_coverage: lowCount,
      good_coverage: goodCount
    },
    techniques
  };

  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2), 'utf8');
  console.log(`\n✓ Converted ${techniques.length} techniques → ${path.relative(process.cwd(), OUTPUT_FILE)}`);
  console.log(`  Coverage gaps (total=0):  ${gapCount}`);
  console.log(`  Low coverage (total<5):   ${lowCount}`);
  console.log(`  Good coverage (total≥5):  ${goodCount}`);
}

convertCarCoverage().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
