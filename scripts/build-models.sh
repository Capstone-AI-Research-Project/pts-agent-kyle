#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "  CASA CyberAnalysis - Model Builder v2"
echo "============================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Step 0: Verify Docker containers are running ─────────────────────────────
echo "[0/10] Checking Docker containers..."
if ! docker ps --format '{{.Names}}' | grep -q '^ollama$'; then
  echo "  ERROR: 'ollama' container is not running."
  echo "  Run: docker compose up -d"
  exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q '^n8n-main$'; then
  echo "  WARNING: 'n8n-main' container is not running. Assets won't be verified."
fi
echo "  ✓ Containers OK"
echo ""

# ── Step 1: Convert framework data files (idempotent) ────────────────────────
echo "[1/10] Converting framework data files (if source files present)..."

# CAR coverage CSV → JSON
if [ -f "${PROJECT_DIR}/data/car-analytic-coverage.csv" ] && command -v node &>/dev/null; then
  echo "  Converting MITRE CAR coverage CSV to JSON..."
  if node "${SCRIPT_DIR}/convert-car-coverage.js" 2>/dev/null; then
    echo "  ✓ car-analytic-coverage.json regenerated"
  else
    echo "  SKIP: Conversion failed (pre-built JSON will be used)"
  fi
else
  echo "  SKIP: CAR source CSV not found or Node.js not available (using pre-built JSON)"
fi

# CIS Controls Excel → JSON
if [ -f "${PROJECT_DIR}/data/cis-controls-v8.1.2.xlsx" ] && command -v python3 &>/dev/null; then
  echo "  Converting CIS Controls Excel to JSON..."
  if python3 -m venv /tmp/casa-build-venv 2>/dev/null && \
     /tmp/casa-build-venv/bin/pip install openpyxl -q 2>/dev/null && \
     /tmp/casa-build-venv/bin/python "${SCRIPT_DIR}/convert-cis-controls.py" 2>/dev/null; then
    echo "  ✓ cis-controls-v8.1.2.json regenerated"
  else
    echo "  SKIP: Conversion failed (pre-built JSON will be used)"
  fi
else
  echo "  SKIP: CIS source Excel not found or Python not available (using pre-built JSON)"
fi

# Technique-to-controls mapping (always regenerate — fast, no dependencies)
if command -v python3 &>/dev/null && [ -f "${SCRIPT_DIR}/build-technique-controls-map.py" ]; then
  echo "  Building technique-to-controls mapping..."
  if python3 "${SCRIPT_DIR}/build-technique-controls-map.py" 2>/dev/null; then
    echo "  ✓ mitre-to-controls-map.json generated"
  else
    echo "  SKIP: Generation failed (pre-built JSON will be used)"
  fi
fi
echo ""

# ── Step 2: Verify framework data assets ─────────────────────────────────────
echo "[2/10] Verifying framework data assets..."
ASSETS_DIR="${PROJECT_DIR}/assets"
REQUIRED_ASSETS=(
  "mitre-attack-techniques.json"
  "car-analytic-coverage.json"
  "nist-csf-2.0.json"
  "cis-controls-v8.1.2.json"
  "mitre-to-controls-map.json"
)
MISSING=0
for asset in "${REQUIRED_ASSETS[@]}"; do
  if [ -f "${ASSETS_DIR}/${asset}" ]; then
    SIZE=$(wc -c < "${ASSETS_DIR}/${asset}" | tr -d ' ')
    echo "  ✓ ${asset} (${SIZE} bytes)"
  else
    echo "  ✗ ${asset} — MISSING"
    MISSING=$((MISSING + 1))
  fi
done

if [ $MISSING -gt 0 ]; then
  echo ""
  echo "  WARNING: ${MISSING} asset(s) missing. The pipeline may produce incomplete reports."
  echo "  Assets are mounted from ./assets/ into the n8n container via docker-compose."
fi

# Verify assets are accessible inside the n8n container
if docker ps --format '{{.Names}}' | grep -q '^n8n-main$'; then
  echo ""
  echo "  Verifying assets inside n8n container..."
  N8N_ASSET_COUNT=$(timeout 10 docker exec n8n-main sh -c 'find /home/node/assets -name "*.json" 2>/dev/null | wc -l' 2>/dev/null | tr -d ' ' || echo "0")
  echo "  ✓ ${N8N_ASSET_COUNT} JSON files accessible in n8n at /home/node/assets/"
fi
echo ""

# ── Steps 3-5: Pull base models ──────────────────────────────────────────────
echo "[3/10] Pulling phi3:3.8b base model..."
docker exec ollama ollama pull phi3:3.8b

echo "[4/10] Pulling qwen2.5:14b base model (analysts + overseer)..."
docker exec ollama ollama pull qwen2.5:14b

echo "[5/10] Pulling qwen2.5:7b base model (synthesizer)..."
docker exec ollama ollama pull qwen2.5:7b

echo ""
echo "Base models pulled. Creating CASA agent models..."
echo ""

# ── Steps 6-10: Create CASA agent models ─────────────────────────────────────
echo "[6/10] Creating casa-router (phi3:3.8b)..."
docker exec ollama ollama create casa-router -f /modelfiles/casa-router.Modelfile

echo "[7/10] Creating casa-log-analyst (qwen2.5:14b)..."
docker exec ollama ollama create casa-log-analyst -f /modelfiles/casa-log-analyst.Modelfile

echo "[8/10] Creating casa-network-analyst (qwen2.5:14b)..."
docker exec ollama ollama create casa-network-analyst -f /modelfiles/casa-network-analyst.Modelfile

echo "[9/10] Creating casa-purple-mapper (phi3:3.8b)..."
docker exec ollama ollama create casa-purple-mapper -f /modelfiles/casa-purple-mapper.Modelfile

echo "[10a/10] Creating casa-synthesizer (qwen2.5:7b)..."
docker exec ollama ollama create casa-synthesizer -f /modelfiles/casa-synthesizer.Modelfile

echo "[10b/10] Creating casa-overseer (qwen2.5:14b)..."
docker exec ollama ollama create casa-overseer -f /modelfiles/casa-overseer.Modelfile

echo ""
echo "============================================"
echo "  All CASA models created successfully!"
echo "============================================"
echo ""
echo "Available models:"
docker exec ollama ollama list
echo ""
echo "Next steps:"
echo "  1. Run: bash scripts/test-models.sh     (verify all models respond)"
echo "  2. Import sub-workflows into n8n         (all casa-*.json except master)"
echo "  3. Import casa-master.json into n8n      (update workflow IDs in Dynamic Sub-Workflow Router)"
echo "  4. Add casa_pipe.py as a Function in Open WebUI"
echo "  5. Test: curl -X POST http://localhost:5678/webhook/casa-investigate \\"
echo '     -H "Content-Type: application/json" \\'
echo '     -d '"'"'{"query": "500 failed SSH logins from 192.168.1.100 in 5 minutes"}'"'"
