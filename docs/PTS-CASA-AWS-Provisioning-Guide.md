# PTS-CASA: AWS VM Provisioning Guide

**Instance:** m7i.4xlarge · 16 vCPUs · 64 GiB RAM · Ubuntu 24.04 LTS  
**Budget:** ~$100 AWS Credits · ~123 hours runtime  
**Purpose:** Demo & Presentation Environment  
**Prepared:** April 2026

---

## 1. Why m7i.4xlarge?

Your current Proxmox VM (VM 110) runs on 8 x86-64 cores, 16 GiB RAM, and 180GB ZFS storage. While that meets CASA's minimum specs, qwen2.5:7b doing CPU inference on 8 cores makes every multi-agent investigation painfully slow. The m7i.4xlarge is the sweet spot for your demo needs.

### 1.1 Current vs. Recommended Comparison

| Spec | Current (Proxmox VM 110) | Recommended (m7i.4xlarge) |
|------|--------------------------|---------------------------|
| vCPUs | 8 (x86-64-v2-AES) | **16 (Intel Sapphire Rapids)** |
| RAM | 16 GiB | **64 GiB** |
| Storage | 180 GB (ZFS) | 100 GB gp3 EBS |
| Network | virtio bridge | Up to 12.5 Gbps |
| Cost | Homelab (free) | ~$0.81/hr on-demand |

### 1.2 Why This Makes CASA Faster

- **2x CPU cores:** Ollama's CPU inference scales nearly linearly with core count. 16 cores vs 8 means roughly 1.8–2x faster token generation for each agent.
- **4x RAM:** 64 GiB lets Ollama keep all CASA models loaded simultaneously (phi3:3.8b router/mapper + qwen2.5:14b analysts + qwen2.5:7b synthesizer). On your current 16GB setup, Ollama constantly swaps models in/out of memory, adding 15–30 seconds per agent handoff.
- **Sapphire Rapids AVX-512 + AMX:** Intel's 4th Gen Xeon includes Advanced Matrix Extensions that accelerate the matrix multiplications underlying LLM inference, giving an additional performance boost beyond raw core count.
- **Faster I/O:** gp3 EBS provides 3,000 baseline IOPS and 125 MB/s throughput. Docker image pulls and Elasticsearch indexing will be snappier.

### 1.3 Budget Breakdown

| Item | Cost | Notes |
|------|------|-------|
| m7i.4xlarge on-demand | $0.8064/hr | ~123 hours on $100 |
| 100GB gp3 EBS volume | ~$8/month | Persistent across stop/start |
| Data transfer (first 100GB) | Free | AWS free tier outbound |
| **Estimated total for 5 days** | **~$100** | **Enough for setup + multiple demos** |

> ✅ **TIP:** Always STOP your instance when not actively using it. You only pay for EBS storage (~$0.01/hr) while stopped, not the $0.81/hr compute cost. This can easily double your effective runtime.

---

## 2. Alternatives Considered

| Instance | vCPUs | RAM | Hourly Cost | Runtime on $100 | Why Not Chosen |
|----------|-------|-----|-------------|-----------------|----------------|
| m7i.2xlarge | 8 | 32 GiB | ~$0.40 | ~250 hrs | Same core count as your Proxmox — won't feel faster |
| m7i.4xlarge | 16 | 64 GiB | ~$0.81 | ~123 hrs | **← RECOMMENDED** |
| m7i.8xlarge | 32 | 128 GiB | ~$1.61 | ~62 hrs | Diminishing returns — CASA doesn't saturate 32 cores |
| g5.xlarge | 4 | 16 GiB | ~$1.01 | ~99 hrs | GPU is fast for inference but only 4 vCPUs hurts n8n/Docker |
| m8gd.metal-48xl | 192 | 768 GiB | ~$11.07 | ~9 hrs | 50x more machine than needed; burns budget in half a day |

> The m7i.4xlarge hits the sweet spot: noticeably faster than your current VM, enough RAM to eliminate model swapping, and enough budget for days of work.

---

## 3. Prerequisites

Before you begin, make sure you have:

1. An AWS account with ~$100 in credits
2. AWS CLI installed locally (optional but helpful): https://aws.amazon.com/cli/
3. An SSH key pair (you'll create one in AWS if you don't have one)
4. Your PTS-CASA repository: https://github.com/ktalons/pts-casa.git

---

## 4. Step-by-Step: Launch the Instance

### Step 1 — Sign in to AWS Console

Navigate to https://console.aws.amazon.com and sign in. Select **US East (N. Virginia) / us-east-1** as your region (top-right dropdown) — this region typically has the best pricing and availability.

### Step 2 — Create a Key Pair

1. Go to **EC2 → Network & Security → Key Pairs**
2. Click **Create key pair**
3. Name: `pts-casa-key`
4. Key pair type: **RSA**
5. Private key file format: **.pem** (Linux/Mac) or **.ppk** (Windows/PuTTY)
6. Click **Create key pair** — the `.pem` file downloads automatically
7. On your local machine, secure the key:

```bash
chmod 400 ~/Downloads/pts-casa-key.pem
mv ~/Downloads/pts-casa-key.pem ~/.ssh/
```

### Step 3 — Create a Security Group

1. Go to **EC2 → Network & Security → Security Groups**
2. Click **Create security group**
3. Name: `pts-casa-sg`
4. Description: `PTS-CASA demo environment`
5. VPC: leave default

**Inbound rules — add the following:**

| Type | Port Range | Source | Purpose |
|------|-----------|--------|---------|
| SSH | 22 | My IP | SSH access |
| Custom TCP | 5678 | My IP | n8n workflow UI |
| Custom TCP | 3000 | My IP | Open WebUI |
| Custom TCP | 11434 | My IP | Ollama API (optional) |

> ⚠️ **WARNING:** Never set source to `0.0.0.0/0` (anywhere) for these ports. Always restrict to "My IP" to prevent unauthorized access to your CASA environment.

6. Outbound rules: leave default (all traffic allowed)
7. Click **Create security group**

### Step 4 — Launch the EC2 Instance

1. Go to **EC2 → Instances → Launch instances**
2. Configure as follows:

**Name and tags:**
- Name: `PTS-CASA-Demo`

**Application and OS Images (AMI):**
- Quick Start → **Ubuntu**
- AMI: **Ubuntu Server 24.04 LTS (HVM), SSD Volume Type**
- Architecture: **64-bit (x86)**

**Instance type:**
- Search for and select: **m7i.4xlarge**

**Key pair:**
- Select: `pts-casa-key`

**Network settings:**
- Click **Edit**
- Auto-assign public IP: **Enable**
- Select existing security group: `pts-casa-sg`

**Configure storage:**
- Change root volume to: **100 GiB**
- Volume type: **gp3**
- IOPS: 3000 (default)
- Throughput: 125 MB/s (default)

3. Click **Launch instance**
4. Wait for the instance state to show **Running** and Status checks to show **2/2 checks passed**

### Step 5 — Connect via SSH

Find your instance's **Public IPv4 address** in the EC2 console, then:

```bash
ssh -i ~/.ssh/pts-casa-key.pem ubuntu@<YOUR-PUBLIC-IP>
```

> ✅ **TIP:** Add this to your `~/.ssh/config` for easier access:
> ```
> Host casa
>     HostName <YOUR-PUBLIC-IP>
>     User ubuntu
>     IdentityFile ~/.ssh/pts-casa-key.pem
> ```
> Then you can just run: `ssh casa`

---

## 5. Step-by-Step: Install the CASA Stack

### Step 1 — System Update & Docker Installation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Docker using the official convenience script
curl -fsSL https://get.docker.com | sudo sh

# Add your user to the docker group (no sudo needed for docker commands)
sudo usermod -aG docker $USER

# Install Docker Compose plugin
sudo apt install -y docker-compose-plugin

# Apply group changes (or log out and back in)
newgrp docker

# Verify installation
docker --version
docker compose version
```

### Step 2 — Install Additional Dependencies

```bash
# Install Node.js (for CAR coverage conversion script)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install Python dependencies (for CIS Controls conversion)
sudo apt install -y python3-pip python3-openpyxl

# Install git
sudo apt install -y git
```

### Step 3 — Clone and Configure PTS-CASA

```bash
# Clone the repository
cd ~
git clone https://github.com/ktalons/pts-casa.git
cd pts-casa

# Create your environment file
cp .env.example .env

# Edit the .env file — set your passwords and preferences
nano .env
```

**Key `.env` settings to configure:**

```bash
# Set strong passwords (change these!)
POSTGRES_PASSWORD=your_secure_password_here
N8N_BASIC_AUTH_PASSWORD=your_n8n_password_here

# Set your timezone
TZ=America/Phoenix

# Ports (defaults should be fine)
N8N_PORT=5678
OPEN_WEBUI_PORT=3000
OLLAMA_PORT=11434
```

### Step 4 — Launch the Docker Stack

```bash
# Start all services
docker compose up --build -d

# Wait 2-3 minutes for all services to initialize
sleep 180

# Verify all containers are healthy
docker compose ps
```

You should see all 5 services running: Ollama, Open WebUI, n8n, PostgreSQL, and Redis.

### Step 5 — Build Framework Data Assets

```bash
# Convert CAR coverage CSV to JSON (if regenerating from source)
node scripts/convert-car-coverage.js

# Convert CIS Controls Excel to JSON (if regenerating from source)
python3 scripts/convert-cis-controls.py

# Note: Pre-built JSON assets are included in the repo
# This step is only needed if you want to regenerate from updated source files
```

### Step 6 — Build CASA Agent Models

This is the most time-consuming step — Ollama needs to pull the base models and create each CASA agent.

```bash
# Pull base models and build all CASA agents
bash scripts/build-models.sh
```

**Expected download sizes:**
| Model | Size | Purpose |
|-------|------|---------|
| phi3:3.8b | ~2.3 GB | Router + PurpleMapper base |
| qwen2.5:14b | ~9.0 GB | Log Analyst + Network Analyst base |
| qwen2.5:7b | ~4.7 GB | Synthesizer base |

> ✅ **TIP:** On the m7i.4xlarge with 12.5 Gbps networking, these downloads should complete in 1-2 minutes. On your Proxmox homelab this probably took much longer.

**Verify all models are built:**

```bash
# Check all CASA models exist
docker exec -it ollama ollama list
```

You should see: `casa-router`, `casa-log-analyst`, `casa-network-analyst`, `casa-purple-mapper`, and `casa-synthesizer`.

### Step 7 — Configure n8n Workflows

1. Open n8n in your browser: `http://<YOUR-PUBLIC-IP>:5678`
2. Create your account or sign in

**Import workflows in this order:**

1. Import all 4 sub-workflows first:
   - `workflows/casa-auth-anomaly.json`
   - `workflows/casa-beaconing.json`
   - `workflows/casa-exfiltration.json`
   - `workflows/casa-lateral-movement.json`

2. For each sub-workflow:
   - Set **Execute Workflow Trigger** to "Accept all data"
   - Set all **Merge nodes** to "Append" mode
   - **Publish/activate** the sub-workflow

3. Import the master workflow:
   - `workflows/casa-master.json`

4. Update the 4 **Execute Sub-Workflow** nodes with the real sub-workflow IDs (visible in each sub-workflow's URL)

5. **Publish/activate** the master workflow

### Step 8 — Configure Open WebUI

1. Open WebUI in your browser: `http://<YOUR-PUBLIC-IP>:3000`
2. Create your admin account
3. Go to **Admin → Functions → Create**
4. Paste the contents of `functions/casa_pipe.py`
5. Save and enable the function

### Step 9 — Test the Pipeline

```bash
# Quick smoke test via curl
curl -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "500 failed SSH logins from 192.168.1.100 targeting root in 5 minutes"}'
```

Or use Open WebUI:
1. Select **"CASA CyberAnalysis"** from the model dropdown
2. Enter a test query
3. Wait for the full pipeline (should complete in 1-2 minutes on this instance vs. several minutes on your Proxmox)

---

## 6. Ollama Performance Tuning for 64GB RAM

With 64 GiB of RAM, you can optimize Ollama to keep models loaded and avoid the cold-start penalty that slows down your Proxmox setup.

```bash
# Create/edit the Ollama environment override
# If using Docker, add these to your docker-compose.yml under ollama environment:

# Keep models loaded for 30 minutes (default is 5 min)
OLLAMA_KEEP_ALIVE=30m

# Allow up to 4 models loaded simultaneously (you have the RAM for it)
OLLAMA_MAX_LOADED_MODELS=4

# Use all 16 CPU threads for inference
OLLAMA_NUM_THREAD=16
```

After updating `docker-compose.yml`, restart the Ollama container:

```bash
docker compose restart ollama
```

**Expected RAM usage with all models loaded:**

| Component | RAM Usage |
|-----------|-----------|
| Docker + n8n + PostgreSQL + Redis | ~3 GB |
| Open WebUI | ~0.5 GB |
| phi3:3.8b (router + PurpleMapper) | ~2.5 GB x2 |
| qwen2.5:14b (Log Analyst) | ~9 GB |
| qwen2.5:14b (Network Analyst) | ~9 GB |
| qwen2.5:7b (Synthesizer) | ~5 GB |
| OS + buffers | ~3 GB |
| **Total** | **~34 GB** |
| **Remaining free** | **~30 GB** |

> ✅ **TIP:** With ~30 GB of spare RAM, you have headroom for future model additions or experimenting with even larger models for specific agents.

---

## 7. Cost Management — Stretch Your $100

### 7.1 Start/Stop Discipline

The single most important thing: **stop the instance when you're not using it.**

```bash
# From your local machine — stop the instance via CLI
aws ec2 stop-instances --instance-ids <YOUR-INSTANCE-ID>

# Start it back up when ready
aws ec2 start-instances --instance-ids <YOUR-INSTANCE-ID>
```

Or use the EC2 Console: select your instance → Instance state → Stop instance.

> ⚠️ **WARNING:** Your Public IP address changes every time you stop/start. Consider allocating an **Elastic IP** (free while attached to a running instance) if you want a stable address for bookmarks and SSH config.

### 7.2 Cost Tracking

```bash
# Check your remaining credits
# AWS Console → Billing → Credits
```

**Rough cost scenarios:**

| Usage Pattern | Daily Cost | Days on $100 |
|---------------|-----------|--------------|
| 24/7 running (don't do this) | $19.35 | ~5 days |
| 8 hrs/day active | $6.45 | ~15 days |
| 4 hrs/day focused sessions | $3.23 | ~31 days |
| 2 hrs/day demo prep | $1.61 | ~62 days |

### 7.3 When You're Done

When your demo/presentation is complete:

```bash
# 1. Export any data you want to keep
docker compose exec n8n n8n export:workflow --all --output=/tmp/workflows/
docker cp pts-casa-n8n-1:/tmp/workflows/ ~/casa-workflow-backup/

# 2. Stop the instance
# EC2 Console → Instance state → Stop instance

# 3. If completely done, TERMINATE to stop all charges
# EC2 Console → Instance state → Terminate instance
# WARNING: This deletes the EBS volume — make sure you've backed up
```

> 🛑 **CRITICAL:** A stopped instance still incurs EBS storage charges (~$8/month for 100GB gp3). If you're completely finished, terminate the instance to stop all charges. Make sure to back up your workflows and any custom Modelfiles first.

---

## 8. Verifying the Performance Improvement

After setup, run this benchmark to compare against your Proxmox experience:

```bash
# Time a single agent inference
time docker exec -it ollama ollama run casa-router \
  "500 failed SSH logins from 192.168.1.100 targeting root in 5 minutes"

# Time a full pipeline investigation
time curl -s -X POST http://localhost:5678/webhook/casa-investigate \
  -H "Content-Type: application/json" \
  -d '{"query": "500 failed SSH logins from 192.168.1.100 targeting root in 5 minutes"}' \
  > /dev/null
```

**Expected performance on m7i.4xlarge vs. your Proxmox VM:**

| Metric | Proxmox (8 cores, 16GB) | m7i.4xlarge (16 cores, 64GB) |
|--------|-------------------------|------------------------------|
| Router classification | 3-5 sec | 1-2 sec |
| Single agent response | 30-60 sec | 15-25 sec |
| Model swap penalty | 15-30 sec | ~0 sec (all models loaded) |
| Full investigation pipeline | 4-8+ min | **1-2 min** |

The biggest win isn't just raw CPU speed — it's eliminating model swap overhead. With 64GB RAM and `OLLAMA_MAX_LOADED_MODELS=4`, every agent is pre-loaded and ready to respond immediately.

---

## 9. Quick Reference Card

### SSH Access
```bash
ssh -i ~/.ssh/pts-casa-key.pem ubuntu@<YOUR-PUBLIC-IP>
```

### Service URLs
| Service | URL |
|---------|-----|
| n8n | `http://<YOUR-PUBLIC-IP>:5678` |
| Open WebUI | `http://<YOUR-PUBLIC-IP>:3000` |
| Ollama API | `http://<YOUR-PUBLIC-IP>:11434` |

### Common Commands
```bash
# Check all services
docker compose ps

# View logs for a specific service
docker compose logs -f ollama
docker compose logs -f n8n

# Restart everything
docker compose restart

# Rebuild after changes
docker compose up --build -d

# Check Ollama models
docker exec -it ollama ollama list

# Monitor resource usage
htop
docker stats
```

### Emergency: Running Low on Credits
```bash
# Check how long you've been running
uptime

# Stop immediately to preserve credits
sudo shutdown -h now
# (or use AWS Console to stop)
```

---

## 10. Troubleshooting

**Instance won't start / capacity error:**  
Try a different availability zone. In the launch wizard, under Network settings, select a different subnet (e.g., us-east-1b instead of us-east-1a). If m7i.4xlarge is unavailable, m7i-flex.4xlarge is a slightly cheaper alternative with the same specs.

**Ollama models fail to build:**  
Check available disk space with `df -h`. The base models need ~7GB of downloads plus space for the built agents. 100GB should be more than sufficient, but check that Docker isn't consuming excessive space with `docker system df`.

**n8n workflows fail / timeout:**  
With 64GB RAM, memory shouldn't be the issue. Check that Ollama is responding: `curl http://localhost:11434/api/tags`. If agents are slow, verify `OLLAMA_NUM_THREADS=16` is set.

**Can't access web UIs from browser:**  
Verify your security group inbound rules include your current IP. Your IP may have changed since you created the rules — update "My IP" in the security group.

**Public IP changed after stop/start:**  
This is normal. Either update your SSH config and bookmarks, or allocate an Elastic IP: EC2 → Elastic IPs → Allocate → Associate with your instance.

---

## Appendix A: Instance Comparison Reference

For future reference, if your needs change:

| Need | Instance | Cost/hr | Runtime on $100 |
|------|----------|---------|-----------------|
| Maximum runtime (budget-first) | m7i.xlarge (4 vCPU, 16GB) | $0.20 | ~500 hrs |
| **Balanced demo (recommended)** | **m7i.4xlarge (16 vCPU, 64GB)** | **$0.81** | **~123 hrs** |
| Faster inference (CPU) | m7i.8xlarge (32 vCPU, 128GB) | $1.61 | ~62 hrs |
| GPU-accelerated inference | g5.xlarge (4 vCPU, 16GB, A10G) | $1.01 | ~99 hrs |
| GPU + more system RAM | g5.2xlarge (8 vCPU, 32GB, A10G) | $1.21 | ~82 hrs |

## Appendix B: Future GPU Upgrade Path

If you decide to explore GPU acceleration later, the process is straightforward:

1. Stop your m7i.4xlarge instance
2. Create a snapshot of your EBS volume (EC2 → Volumes → Create snapshot)
3. Launch a new g5.xlarge instance using that snapshot as the root volume
4. Ollama automatically detects the NVIDIA A10G GPU — no driver installation needed on Ubuntu 24.04 with the standard NVIDIA AMI
5. Your CASA models, workflows, and configuration carry over unchanged

The A10G's 24GB VRAM can run qwen2.5:7b entirely on GPU, reducing per-agent inference from ~20 seconds to ~2-3 seconds. The tradeoff is only 4 vCPUs for running Docker/n8n, which may create a bottleneck during parallel agent execution.
