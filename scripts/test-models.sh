#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "  CASA CyberAnalysis - Model Test Suite"
echo "============================================"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

test_model() {
  local model="$1"
  local prompt="$2"
  local label="$3"

  echo "--- Testing: ${label} (${model}) ---"
  output=$(docker exec ollama ollama run "${model}" "${prompt}" 2>&1) || true

  if [[ -n "${output}" && "${output}" != *"error"* && "${output}" != *"not found"* ]]; then
    echo "RESULT: ${output:0:200}..."
    echo ">>> PASS: ${label}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo ">>> FAIL: ${label} — no valid output received"
    echo "OUTPUT: ${output}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
  echo ""
}

# Test 1: Router
test_model "casa-router" \
  "500 failed SSH logins from 192.168.1.100 in 5 minutes" \
  "casa-router (query classification)"

# Test 2: Log Analyst
test_model "casa-log-analyst" \
  "Analyze these Windows Event ID 4625 failures from a single source IP" \
  "casa-log-analyst (log analysis)"

# Test 3: Network Analyst
test_model "casa-network-analyst" \
  "Host 10.0.0.50 connecting to external IP every 60 seconds with 2% jitter" \
  "casa-network-analyst (network analysis)"

# Test 4: Purple Mapper
test_model "casa-purple-mapper" \
  "Multiple failed logins followed by successful login and lateral movement" \
  "casa-purple-mapper (purple team mapping)"

# Test 5: Synthesizer
test_model "casa-synthesizer" \
  "Summarize: Found brute force attack from 192.168.1.100, 500 failed logins, one success, followed by east-west scanning" \
  "casa-synthesizer (synthesis)"

# Test 6: Overseer
test_model "casa-overseer" \
  "Cross-correlate these findings: Report 1 (auth_anomaly): 500 failed logins from 192.168.1.100, one success at 03:14 UTC. Report 2 (lateral_movement): Same IP moved to 3 internal servers via SMB within 20 minutes of initial access. Identify the attack narrative and top 3 recommendations." \
  "casa-overseer (cross-report synthesis)"

echo "============================================"
echo "  Test Results: ${PASS_COUNT} PASS / ${FAIL_COUNT} FAIL"
echo "============================================"

if [[ ${FAIL_COUNT} -gt 0 ]]; then
  exit 1
fi
