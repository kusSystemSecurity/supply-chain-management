# SecureChain AI - Development Guide for Claude Code

## Project Overview
AI-powered software supply chain security analysis platform that scans multiple sources (Git repos, containers, VMs, K8s, SBOM), enriches CVE data, and uses AI agents to prioritize threats and generate remediation plans.

## Tech Stack
- **Backend**: Python 3.11+, FastAPI, PostgreSQL, Redis, Celery
- **Frontend**: React 18, TypeScript, Tailwind CSS, D3.js
- **Security**: Trivy scanner
- **AI**: Claude API (Anthropic)
- **ML**: XGBoost (EPSS prediction)
- **Infra**: Docker, Docker Compose

## Architecture
```
Trivy Scan → CVE Enrichment → AI Agents → Web Dashboard
     ↓              ↓              ↓            ↓
  (Multiple    (CVEDetails   (3 Agents:    (React UI)
   Sources)     + EPSS)      Priority/
                             Analysis/
                             Remediation)
```

## Core Components

### 1. Backend Structure
```
backend/
├── app/
│   ├── api/
│   │   ├── scans.py          # Scan management endpoints
│   │   ├── vulnerabilities.py # CVE detail endpoints
│   │   └── ai_analysis.py     # AI agent endpoints
│   ├── agents/
│   │   ├── prioritization.py  # Agent 1: Risk scoring
│   │   ├── supply_chain.py    # Agent 2: Dependency analysis
│   │   └── remediation.py     # Agent 3: Fix generation
│   ├── integrations/
│   │   ├── trivy.py           # Trivy CLI wrapper
│   │   ├── cvedetails.py      # CVEDetails API client
│   │   └── epss_predictor.py  # ML model for EPSS
│   ├── models/
│   │   └── database.py        # SQLAlchemy models
│   └── main.py                # FastAPI app
├── models/
│   └── epss_predictor.json    # Pre-trained XGBoost model
└── requirements.txt
```

### 2. Database Schema
```sql
-- Scans table
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    scan_type VARCHAR(50), -- 'git_repo'|'container'|'vm'|'sbom'|'k8s'
    target VARCHAR(500),
    status VARCHAR(20),    -- 'pending'|'running'|'completed'|'failed'
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    result_json JSONB
);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),
    cve_id VARCHAR(20),
    package_name VARCHAR(200),
    package_version VARCHAR(100),
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    epss_score DECIMAL(5,5),
    epss_predicted BOOLEAN,
    cve_details JSONB  -- Full CVEDetails API response
);

CREATE INDEX idx_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_scan_id ON vulnerabilities(scan_id);

-- AI analyses table
CREATE TABLE ai_analyses (
    id UUID PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),
    agent_type VARCHAR(50), -- 'prioritization'|'supply_chain'|'remediation'
    input_data JSONB,
    output_data JSONB,
    tokens_used INTEGER,
    processing_time_ms INTEGER
);
```

### 3. Trivy Integration
```python
# app/integrations/trivy.py
import subprocess
import json

class TrivyScanner:
    def scan_repository(self, repo_path: str) -> dict:
        """Scan Git repository for vulnerabilities"""
        cmd = [
            'trivy', 'fs',
            '--format', 'json',
            '--scanners', 'vuln',
            repo_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return json.loads(result.stdout)
    
    def scan_image(self, image_name: str) -> dict:
        """Scan container image"""
        cmd = ['trivy', 'image', '--format', 'json', image_name]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return json.loads(result.stdout)
    
    def scan_k8s_cluster(self) -> dict:
        """Scan Kubernetes cluster"""
        cmd = ['trivy', 'k8s', '--report', 'summary', 'cluster']
        result = subprocess.run(cmd, capture_output=True, text=True)
        return json.loads(result.stdout)
    
    def scan_sbom(self, sbom_path: str) -> dict:
        """Analyze SBOM file"""
        cmd = ['trivy', 'sbom', '--format', 'json', sbom_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return json.loads(result.stdout)
```

### 4. CVE Enrichment
```python
# app/integrations/cvedetails.py
import requests
from typing import Optional

class CVEDetailsClient:
    BASE_URL = "https://www.cvedetails.com/api/v1"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"Authorization": f"Bearer {api_key}"}
    
    def get_cve_details(self, cve_id: str) -> dict:
        """Fetch detailed CVE information"""
        url = f"{self.BASE_URL}/cve/{cve_id}"
        response = requests.get(url, headers=self.headers, timeout=10)
        response.raise_for_status()
        return response.json()
    
    def batch_get_cves(self, cve_ids: list[str]) -> list[dict]:
        """Fetch multiple CVEs (implement based on API limits)"""
        return [self.get_cve_details(cve_id) for cve_id in cve_ids]

# app/integrations/epss_predictor.py
import xgboost as xgb
import numpy as np

class EPSSPredictor:
    def __init__(self, model_path: str = "models/epss_predictor.json"):
        self.model = xgb.Booster()
        self.model.load_model(model_path)
    
    def predict(self, cve_data: dict) -> float:
        """Predict EPSS score for CVE without existing EPSS"""
        features = self._extract_features(cve_data)
        epss_score = self.model.predict(xgb.DMatrix(features))[0]
        return float(np.clip(epss_score, 0, 1))
    
    def _extract_features(self, cve_data: dict) -> np.ndarray:
        """Feature engineering from CVE data"""
        # Extract CVSS metrics, CWE, publish date, etc.
        features = [
            float(cve_data.get('maxCvssBaseScore', 0)),
            float(cve_data.get('maxCvssExploitabilityScore', 0)),
            float(cve_data.get('maxCvssImpactScore', 0)),
            # Add more features based on training
        ]
        return np.array(features).reshape(1, -1)
```

### 5. AI Agent System

#### Agent 1: Threat Prioritization
```python
# app/agents/prioritization.py
import anthropic
import json

PRIORITIZATION_PROMPT = """
You are a cybersecurity analyst. Evaluate this vulnerability's real-world risk.

CVE: {cve_id}
CVSS: {cvss_score}
EPSS: {epss_score} (top {epss_percentile}%)
Risk Score: {risk_score}
Code Execution: {is_code_exec}
Exploit Exists: {exploit_exists}
CISA KEV: {in_cisa_kev}

System Context:
- Internet-facing: {is_internet_facing}
- Authentication required: {has_auth}
- Data sensitivity: {data_classification}

Provide:
1. Priority Score (1-10)
2. Likelihood (Low/Medium/High/Critical)
3. Business Impact (2 sentences)
4. Recommendation (Immediate/Scheduled/Monitor)
5. Rationale (3 sentences)

Output as JSON only:
{{
  "priorityScore": <1-10>,
  "likelihood": "...",
  "businessImpact": "...",
  "recommendation": "...",
  "rationale": "..."
}}
"""

async def prioritize_vulnerability(cve_data: dict, context: dict) -> dict:
    client = anthropic.Anthropic()
    
    prompt = PRIORITIZATION_PROMPT.format(
        cve_id=cve_data['cveId'],
        cvss_score=cve_data['maxCvssBaseScore'],
        epss_score=cve_data['epssScore'],
        epss_percentile=float(cve_data['epssPercentile']) * 100,
        risk_score=cve_data['riskScore']['riskScore'],
        is_code_exec='Yes' if cve_data['isCodeExecution'] else 'No',
        exploit_exists='Yes' if cve_data['exploitExists'] else 'No',
        in_cisa_kev='Yes' if cve_data['isInCISAKEV'] else 'No',
        **context
    )
    
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    
    # Parse JSON from response
    response_text = message.content[0].text
    # Strip markdown code blocks if present
    response_text = response_text.replace('```json', '').replace('```', '').strip()
    return json.loads(response_text)
```

#### Agent 2: Supply Chain Analysis
```python
# app/agents/supply_chain.py
SUPPLY_CHAIN_PROMPT = """
Analyze these multi-source scan results for supply chain risks.

Scan Results:
{scan_data}

Identify:
1. Overlapping vulnerabilities across layers
2. Dependency chains propagating vulnerabilities
3. Root causes and blast radius
4. Consolidated remediation strategies

Output in Markdown format with sections:
## Critical Findings
## Dependency Analysis
## Root Causes
## Consolidated Remediation
## Risk Metrics
"""

async def analyze_supply_chain(scans: list[dict]) -> str:
    client = anthropic.Anthropic()
    
    prompt = SUPPLY_CHAIN_PROMPT.format(
        scan_data=json.dumps(scans, indent=2)
    )
    
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}]
    )
    
    return message.content[0].text
```

#### Agent 3: Remediation Advisor
```python
# app/agents/remediation.py
REMEDIATION_PROMPT = """
Create a detailed remediation plan for:

CVE: {cve_id}
Package: {package} version {current_version}
Fixed in: {fixed_version}

Tech Stack: {tech_stack}
Deployment: {deployment_type}

Provide:
1. Pre-Flight Checklist
2. Patch Commands (copy-paste ready)
3. Configuration Changes (diffs)
4. Breaking Changes
5. Testing Checklist
6. Rollback Plan
7. Alternative Mitigations

Use Markdown with code blocks.
"""

async def generate_remediation(vuln: dict, context: dict) -> str:
    client = anthropic.Anthropic()
    
    prompt = REMEDIATION_PROMPT.format(**vuln, **context)
    
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=3072,
        messages=[{"role": "user", "content": prompt}]
    )
    
    return message.content[0].text
```

### 6. API Endpoints
```python
# app/api/scans.py
from fastapi import APIRouter, BackgroundTasks
from app.integrations.trivy import TrivyScanner
from app.models.database import Scan, Vulnerability

router = APIRouter(prefix="/api/scans")

@router.post("/trigger")
async def trigger_scan(
    scan_type: str,
    target: str,
    background_tasks: BackgroundTasks
):
    """Start a new scan asynchronously"""
    scan = Scan(scan_type=scan_type, target=target, status="pending")
    db.add(scan)
    db.commit()
    
    background_tasks.add_task(run_scan_task, scan.id, scan_type, target)
    return {"scanId": scan.id, "status": "pending"}

@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan results"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    vulnerabilities = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id
    ).all()
    
    return {
        "id": scan.id,
        "status": scan.status,
        "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        "summary": {
            "critical": sum(1 for v in vulnerabilities if v.severity == "CRITICAL"),
            "high": sum(1 for v in vulnerabilities if v.severity == "HIGH"),
            # ... etc
        }
    }
```

### 7. Frontend Structure
```
frontend/
├── src/
│   ├── components/
│   │   ├── Dashboard.tsx          # Main dashboard
│   │   ├── ScanTrigger.tsx        # Initiate scans
│   │   ├── VulnerabilityList.tsx  # CVE table
│   │   ├── CVEDetail.tsx          # Individual CVE view
│   │   ├── DependencyGraph.tsx    # D3.js visualization
│   │   ├── AIReport.tsx           # AI analysis display
│   │   └── RemediationPlan.tsx    # Fix instructions
│   ├── api/
│   │   └── client.ts              # API client
│   ├── types/
│   │   └── index.ts               # TypeScript interfaces
│   └── App.tsx
├── package.json
└── vite.config.ts
```

### 8. Key TypeScript Interfaces
```typescript
// frontend/src/types/index.ts
interface CVEDetail {
  cveId: string;
  title: string;
  summary: string;
  maxCvssBaseScore: number;
  epssScore: number;
  epssPercentile: number;
  riskScore: {
    riskScore: number;
    productThreatOverview: number;
  };
  affects: AffectedProduct[];
  aiAnalysis?: {
    priorityScore: number;
    likelihood: string;
    businessImpact: string;
    recommendation: string;
    rationale: string;
  };
}

interface Scan {
  id: string;
  scanType: 'git_repo' | 'container' | 'vm' | 'sbom' | 'k8s';
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt: string;
  completedAt?: string;
}
```

## Development Priorities

### Phase 1: Core Infrastructure (Week 1-2)
1. Set up FastAPI project with PostgreSQL
2. Implement Trivy wrapper for all scan types
3. Create CVEDetails API client with caching
4. Build database models and migrations
5. Set up Celery for async scanning

### Phase 2: AI Agents (Week 3-4)
1. Implement 3 AI agents with proper prompts
2. Add error handling and retries
3. Implement JSON parsing from LLM responses
4. Add validation layer to prevent hallucinations
5. Test agents with sample CVE data

### Phase 3: Frontend (Week 5-6)
1. Create React app with Tailwind
2. Build dashboard with charts (Recharts)
3. Implement CVE detail view
4. Add D3.js dependency graph
5. Create AI report renderer

### Phase 4: Integration (Week 7-8)
1. Connect frontend to backend
2. Add WebSocket for real-time scan updates
3. Implement PDF export
4. End-to-end testing
5. Docker Compose setup

## Important Implementation Notes

### Trivy Scan Results Format
Trivy outputs JSON with structure:
```json
{
  "Results": [
    {
      "Target": "package.json",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-31449",
          "PkgName": "redis",
          "InstalledVersion": "7.2.5",
          "Severity": "HIGH",
          "Title": "...",
          "Description": "..."
        }
      ]
    }
  ]
}
```

### CVE Enrichment Flow
1. Extract unique CVE IDs from Trivy results
2. Check Redis cache for each CVE
3. For cache miss: call CVEDetails API
4. If no EPSS in response: use ML model to predict
5. Store enriched data in PostgreSQL
6. Cache in Redis for 24 hours

### AI Agent Error Handling
```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10)
)
async def call_ai_agent(prompt: str) -> dict:
    try:
        response = await anthropic_client.messages.create(...)
        # Parse JSON, handle markdown code blocks
        return parse_json_response(response)
    except json.JSONDecodeError:
        # Log and return error
        return {"error": "Failed to parse AI response"}
    except anthropic.APIError as e:
        # Handle rate limits, timeouts
        raise
```

### Security Considerations
- Never store API keys in code (use environment variables)
- Validate all user inputs (scan targets, file uploads)
- Sanitize Trivy output before storing
- Rate limit API endpoints
- Use CORS properly for frontend
- Implement authentication for production

## Testing Strategy

### Unit Tests
- Test each Trivy scanner method
- Test CVE enrichment logic
- Test EPSS prediction model
- Test AI agent prompt formatting

### Integration Tests
- Test full scan → enrichment → AI analysis flow
- Test API endpoints
- Test database operations

### E2E Tests
- Scan a known vulnerable repo (e.g., DVWA)
- Verify CVE detection
- Check AI analysis quality
- Test export features

## Environment Variables
```bash
# .env
DATABASE_URL=postgresql://user:pass@localhost/securechain
REDIS_URL=redis://localhost:6379
CVEDETAILS_API_KEY=your_api_key
ANTHROPIC_API_KEY=your_claude_key
CELERY_BROKER_URL=redis://localhost:6379/1
```

## Docker Compose Setup
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: securechain
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    ports:
      - "5432:5432"
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
  
  backend:
    build: ./backend
    depends_on:
      - postgres
      - redis
    environment:
      DATABASE_URL: postgresql://user:pass@postgres/securechain
      REDIS_URL: redis://redis:6379
    ports:
      - "8000:8000"
  
  frontend:
    build: ./frontend
    ports:
      - "5173:5173"
```

## Quick Start Commands
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev

# Docker
docker-compose up -d
```

## Success Metrics
- [ ] Successfully scan 4+ source types with Trivy
- [ ] Enrich CVEs with CVEDetails API + EPSS prediction
- [ ] Generate meaningful AI analysis for top 10 CVEs
- [ ] Display results in responsive web dashboard
- [ ] Complete scan-to-report flow in <5 minutes
- [ ] Export PDF reports

## Common Issues & Solutions

**Issue**: Trivy scan timeout on large repos
**Solution**: Use `--timeout 15m` flag, implement caching

**Issue**: CVEDetails API rate limit
**Solution**: Implement Redis caching, batch requests

**Issue**: AI hallucinating package versions
**Solution**: Add post-processing validation against package registries

**Issue**: EPSS model accuracy low for new CVEs
**Solution**: Use conservative (high) estimates, retrain monthly

## Reference Documentation
- Trivy: https://aquasecurity.github.io/trivy/
- CVEDetails API: https://www.cvedetails.com/api-documentation
- Anthropic Claude: https://docs.anthropic.com/
- FastAPI: https://fastapi.tiangolo.com/
- React + D3: https://www.react-graph-gallery.com/

---

**Next Steps**: Start with Phase 1 by setting up the FastAPI backend and Trivy integration. Create a simple `/health` endpoint and a single scan function for Git repos first, then expand to other sources.
