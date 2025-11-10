# AI 기반 Supply Chain 보안 플랫폼 - PRD & 기획안

# 프로젝트 개요

## 프로젝트명

**SecureChain AI** - AI Agent 기반 소프트웨어 공급망 보안 분석 플랫폼

## 목적

소프트웨어 공급망의 다층적 보안 위협을 자동으로 탐지하고, AI를 활용하여 취약점의 실제 위험도를 평가하며, 실행 가능한 수정 방안을 제시하는 통합 플랫폼 개발

## 핵심 가치

- **자동화**: Trivy를 활용한 다중 소스(Git, Container, VM, SBOM) 자동 스캔
- **지능화**: CVEDetails API + 자체 EPSS 예측 모델로 취약점 데이터 보강
- **실용화**: AI Agent가 우선순위화 및 구체적 remediation 제안
- **가시화**: 웹 대시보드를 통한 Supply Chain 전체 위협 지형 시각화

---

# 시스템 아키텍처

## 전체 구조

```
┌──────────────────────────────────────────────────┐
│           Scan Layer (Trivy)                     │
│  ┌─────────┬─────────┬─────────┬─────────┐      │
│  │ Git Repo│Container│   VM    │  SBOM   │      │
│  └─────────┴─────────┴─────────┴─────────┘      │
└──────────────────┬───────────────────────────────┘
                   │ CVE IDs
                   ▼
┌──────────────────────────────────────────────────┐
│      Data Enrichment Layer                       │
│  ┌──────────────────┬─────────────────────┐     │
│  │ CVEDetails API   │ EPSS Predictor      │     │
│  │ (CVE 상세 정보)  │ (Missing EPSS 예측) │     │
│  └──────────────────┴─────────────────────┘     │
└──────────────────┬───────────────────────────────┘
                   │ Enriched CVE Data
                   ▼
┌──────────────────────────────────────────────────┐
│          AI Agent Layer                          │
│  ┌─────────────────────────────────────────┐    │
│  │ Agent 1: Threat Prioritization          │    │
│  │ Agent 2: Supply Chain Impact Analysis   │    │
│  │ Agent 3: Remediation Advisor            │    │
│  └─────────────────────────────────────────┘    │
└──────────────────┬───────────────────────────────┘
                   │ Analysis Results
                   ▼
┌──────────────────────────────────────────────────┐
│      Presentation Layer (Web Dashboard)          │
│  ┌──────────────┬──────────────┬──────────┐     │
│  │ Risk Board   │ Dependency   │ AI Report│     │
│  │              │ Graph        │          │     │
│  └──────────────┴──────────────┴──────────┘     │
└──────────────────────────────────────────────────┘
```

## 데이터 플로우

1. **Input**: GitHub URL, Container Image, VM 접근 정보, SBOM 파일
2. **Scanning**: Trivy가 각 소스를 병렬 스캔 → CVE ID 목록 추출
3. **Enrichment**:
    - CVE ID → CVEDetails API 호출 → 상세 정보 획득
    - EPSS 없는 경우 → 자체 ML 모델로 예측
4. **AI Analysis**: 3개 Agent가 순차/병렬 처리
5. **Output**: 웹 대시보드에 결과 렌더링 + JSON/PDF 리포트

---

# 기술 스택

## Backend

- **Language**: Python 3.11+
- **Framework**: FastAPI
- **Scan Engine**: Trivy (Aqua Security)
- **AI/LLM**: Claude API (Anthropic) 또는 GPT-4
- **Agent Framework**: LangGraph 또는 Custom Multi-Agent
- **ML Model**: scikit-learn/XGBoost (EPSS 예측)
- **Database**: PostgreSQL (스캔 이력), Redis (캐시)
- **Task Queue**: Celery + RabbitMQ

## Frontend

- **Framework**: React 18 + TypeScript
- **UI Library**: Tailwind CSS + shadcn/ui
- **Visualization**: Recharts, D3.js (dependency graph)
- **State Management**: Zustand

## Infrastructure

- **Containerization**: Docker + Docker Compose
- **API Integration**: [CVEDetails.com](http://CVEDetails.com) REST API
- **File Storage**: MinIO (S3-compatible)

---

# 핵심 기능 명세

## 1. Multi-Source Vulnerability Scanning

### 1.1 Git Repository 스캔

```bash
trivy fs --format json --output repo-scan.json /path/to/repo
```

- **대상**: 소스코드, 의존성 파일 (package.json, requirements.txt 등)
- **탐지**: 직접 의존성 + 간접 의존성 취약점

### 1.2 Container Image 스캔

```bash
trivy image --format json --output container-scan.json nginx:latest
```

- **대상**: OS 패키지 + 애플리케이션 라이브러리
- **Layer 분석**: 각 Docker layer별 취약점 추적

### 1.3 VM/서버 스캔

```bash
trivy rootfs --format json --output vm-scan.json /
```

- **대상**: 시스템 패키지, 설치된 소프트웨어

### 1.4 SBOM 분석

```bash
trivy sbom --format json sbom.cdx.json
```

- **지원 형식**: CycloneDX, SPDX
- **분석**: 전체 SBOM에 대한 취약점 매핑

### 1.5 Kubernetes Cluster 스캔 (추가 권장)

```bash
trivy k8s --report summary cluster
trivy k8s --report all namespace/podname
```

- **대상**: 실행 중인 클러스터의 모든 워크로드
- **탐지 항목**:
    - Pod 이미지 취약점
    - Kubernetes Misconfiguration (보안 설정 오류)
    - RBAC 권한 문제
    - Secret/ConfigMap 노출
- **AI 활용**: 클러스터 전체 위험도 맵, Pod 간 취약점 전파 경로 분석

### 1.6 IaC (Infrastructure as Code) 스캔 (선택)

```bash
trivy config ./terraform
trivy config ./kubernetes-manifests
trivy config ./cloudformation
```

- **대상**: Terraform, CloudFormation, Kubernetes YAML, Dockerfile
- **탐지**: 배포 전 설정 오류 및 보안 위험
- **AI 활용**: 잘못된 설정이 런타임에 미치는 영향 예측, 보안 Best Practice 제안

### 1.7 License Compliance 검사 (선택)

```bash
trivy fs --scanners license ./repo
```

- **대상**: 오픈소스 라이선스 검증
- **탐지**: GPL, MIT, Apache 등 라이선스 충돌
- **AI 활용**: 라이선스 호환성 분석 및 대체 패키지 제안

## 권장 스캔 조합

### 기본 구성 (MVP)

- Git Repository
- Container Image
- SBOM

### 확장 구성 (추천)

- **기본 구성** + **Kubernetes Cluster**
- 이유: 개발(Git) → 빌드(Container) → 배포(K8s) 전체 파이프라인 커버

### 완전 구성 (실무급)

- 기본 구성 + K8s + IaC + License
- 이유: DevSecOps 전체 라이프사이클 보안 검증

## 2. CVE Data Enrichment

### 2.1 CVEDetails API 통합

```python
def enrich_cve(cve_id: str) -> dict:
    url = f"[https://www.cvedetails.com/api/v1/cve/{cve_id}](https://www.cvedetails.com/api/v1/cve/{cve_id})"
    response = requests.get(url, headers={"Authorization": f"Bearer {API_KEY}"})
    return response.json()
```

**획득 데이터**:

- CVSS Score (Base, Exploitability, Impact)
- EPSS Score & Percentile
- Risk Score (CVEDetails 자체 알고리즘)
- 취약점 카테고리 (Overflow, Code Execution 등)
- 영향받는 제품 버전 범위
- Exploit 존재 여부
- CISA KEV 포함 여부

### 2.2 EPSS 예측 모델

```python
class EPSSPredictor:
    def predict(self, cve_data: dict) -> float:
        features = self.extract_features(cve_data)
        # CVSS vector, CWE, publish date, vendor 등 feature 엔지니어링
        epss_score = self.model.predict(features)
        return epss_score
```

**Training Data**: NVD + EPSS 공개 데이터셋

**Features**: CVSS 메트릭, CWE ID, 제품 카테고리, 발표 후 경과 시간

## 3. AI Agent System

### Agent 1: Threat Prioritization Agent

**역할**: 취약점의 실제 위험도 계산 및 우선순위 결정

**Input**:

```json
{
  "cveId": "CVE-2024-31449",
  "maxCvssBaseScore": "8.8",
  "epssScore": "0.35598",
  "epssPercentile": "0.96874",
  "isCodeExecution": 1,
  "exploitExists": 0,
  "isInCISAKEV": 0,
  "riskScore": {
    "riskScore": 20,
    "productThreatOverview": 5,
    "vulnCategoryScoreLabel": "Very high risk vulnerability category"
  },
  "context": {
    "isInternetFacing": true,
    "hasAuthentication": true,
    "dataClassification": "confidential"
  }
}
```

**AI Prompt**:

```python
prompt = f"""
당신은 사이버 보안 전문가입니다. 다음 취약점의 실제 위험도를 평가하세요.

## 취약점 정보
CVE ID: {data['cveId']}
CVSS Score: {data['maxCvssBaseScore']} (High)
EPSS: {data['epssScore']} (상위 {float(data['epssPercentile'])*100:.1f}%)
Risk Score: {data['riskScore']['riskScore']}

## 취약점 특성
- Remote Code Execution 가능: {'예' if data['isCodeExecution'] else '아니오'}
- 공개된 Exploit: {'존재' if data['exploitExists'] else '없음'}
- CISA KEV 등재: {'예' if data['isInCISAKEV'] else '아니오'}
- 취약점 카테고리: {data['riskScore']['vulnCategoryScoreLabel']}

## 시스템 컨텍스트
- 인터넷 노출: {'예' if data['context']['isInternetFacing'] else '아니오'}
- 인증 필요: {'예' if data['context']['hasAuthentication'] else '아니오'}
- 데이터 민감도: {data['context']['dataClassification']}

## 요청사항
1. **Priority Score** (1-10): 즉시 패치 필요도
2. **Likelihood**: 실제 공격 가능성 (Low/Medium/High/Critical)
3. **Business Impact**: 공격 성공 시 비즈니스 영향
4. **Recommendation**: 즉각 조치 또는 계획된 패치 여부
5. **Rationale**: 평가 근거 (2-3문장)

JSON 형식으로 답변하세요.
"""
```

**Output**:

```json
{
  "priorityScore": 9,
  "likelihood": "High",
  "businessImpact": "Critical - RCE 취약점으로 전체 시스템 장악 가능",
  "recommendation": "즉각 패치 필요 (24시간 내)",
  "rationale": "EPSS 상위 3%로 활발히 악용되는 취약점이며, 인증된 사용자로도 RCE가 가능합니다. Redis가 인터넷에 노출되어 있어 공격 표면이 넓습니다."
}
```

### Agent 2: Supply Chain Impact Analyzer

**역할**: 여러 스캔 소스에서 발견된 취약점 간 관계 분석

**Input**:

```json
{
  "scans": [
    {
      "source": "git_repo",
      "vulnerabilities": [
        {"cveId": "CVE-2024-31449", "package": "redis-py", "version": "4.5.0"}
      ]
    },
    {
      "source": "container",
      "vulnerabilities": [
        {"cveId": "CVE-2024-31449", "package": "redis-server", "version": "7.2.5"}
      ]
    },
    {
      "source": "sbom",
      "vulnerabilities": [
        {"cveId": "CVE-2024-31449", "package": "redis", "version": "7.2.5"}
      ]
    }
  ]
}
```

**AI Prompt**:

```python
prompt = f"""
다음은 공급망의 여러 레이어에서 발견된 취약점 목록입니다.

{json.dumps(data['scans'], indent=2)}

## 분석 요청
1. **Overlap Analysis**: 여러 레이어에 공통으로 나타나는 CVE 식별
2. **Dependency Chain**: 취약점이 전파되는 경로 추적
3. **Root Cause**: 가장 상위 원인이 되는 취약 컴포넌트
4. **Blast Radius**: 하나의 취약점이 영향을 미치는 범위
5. **Consolidated Remediation**: 여러 레이어를 한 번에 해결할 수 있는 방법

Markdown 형식으로 답변하세요.
"""
```

**Output**:

```markdown
## Supply Chain 영향 분석

### 중복 취약점 (Critical)
CVE-2024-31449가 3개 레이어에서 모두 발견됨:
- Git Repo: redis-py 클라이언트 라이브러리
- Container: redis-server 런타임
- SBOM: 전체 의존성 트리

### 의존성 체인
redis-py (애플리케이션) → redis-server (컨테이너) → Lua scripting library (시스템)

### Root Cause
Redis 7.2.5의 Lua bit library에 stack overflow 취약점

### 영향 범위
- 3개의 마이크로서비스가 영향받음
- 총 12개 컨테이너 인스턴스
- 프로덕션 환경 포함

### 통합 수정 방안
**단일 액션으로 해결 가능**:
1. 베이스 이미지를 Redis 7.2.6으로 업데이트
2. requirements.txt에서 redis-py ≥ 5.0.0 명시
3. 컨테이너 재빌드 → 모든 레이어 동시 해결
```

### Agent 3: Remediation Advisor

**역할**: 실행 가능한 구체적 수정 방안 제시

**AI Prompt**:

```python
prompt = f"""
다음 취약점에 대한 상세한 remediation plan을 작성하세요.

## 취약점
CVE: {cve_id}
영향받는 패키지: {package}
현재 버전: {current_version}
수정 버전: {fixed_version}

## 시스템 환경
- 언어/프레임워크: {tech_stack}
- 배포 방식: {deployment_type}
- CI/CD: {cicd_tool}

## 요청사항
다음을 포함한 실행 플랜을 작성하세요:

1. **Pre-Flight Check**: 패치 전 확인사항
2. **Patch Commands**: 실제 실행할 명령어 (복사 가능한 형태)
3. **Configuration Changes**: 설정 파일 수정사항 (diff 형식)
4. **Breaking Changes**: 주의해야 할 호환성 문제
5. **Testing Checklist**: 패치 후 테스트 항목
6. **Rollback Plan**: 문제 발생 시 복구 방법
7. **Alternative Solutions**: 즉시 패치가 불가능한 경우 임시 완화책

Markdown 코드 블록을 적극 활용하세요.
"""
```

**Output 예시**:

```markdown
# Remediation Plan: CVE-2024-31449 (Redis)

## ✅ Pre-Flight Check
- [ ] 현재 Redis 버전 확인: `redis-cli INFO server | grep redis_version`
- [ ] 백업 수행: `redis-cli BGSAVE`
- [ ] 다운타임 공지 (예상 5분)

## 🔧 Patch Commands

### Dockerfile 수정
```

- FROM redis:7.2.5-alpine
- FROM redis:7.2.6-alpine

```

### Docker Compose 업데이트
```

docker-compose pull redis

docker-compose up -d redis

```

### Python 의존성 업데이트
```

pip install redis>=5.0.0 --upgrade

pip freeze > requirements.txt

```

## ⚠️ Breaking Changes
없음 (Patch 레벨 업데이트)

## 🧪 Testing Checklist
- [ ] Redis 연결 테스트: `redis-cli PING` → PONG 응답 확인
- [ ] Lua 스크립트 동작 확인
- [ ] 성능 테스트 (응답 시간 ≤ 기존 수준)
- [ ] 애플리케이션 통합 테스트

## 🔙 Rollback Plan
```

docker-compose down redis

git checkout HEAD~1 docker-compose.yml

docker-compose up -d redis

```

## 🛡️ Alternative Solutions (즉시 패치 불가 시)
1. **Network Segmentation**: Redis를 private subnet으로 격리
2. **Access Control**: `requirepass` 설정 강화
3. **Lua 스크립트 비활성화**: `rename-command EVAL ""` (극단적 조치)
```

## 4. Web Dashboard

### 4.1 메인 대시보드

**Components**:

- **Risk Overview Panel**:
    - Critical/High/Medium/Low 취약점 개수
    - EPSS 상위 10% CVE 카운트
    - CISA KEV 포함 취약점 강조
- **Priority Queue**: AI가 선정한 상위 10개 즉시 조치 항목
- **Timeline Chart**: 최근 30일 취약점 발견 추이
- **Supply Chain Health Score**: 전체 공급망 안전도 (0-100)

### 4.2 Vulnerability Detail View

**CVE 상세 페이지** (업로드된 JSON 구조 활용):

```tsx
interface CVEDetail {
  // Basic Info
  cveId: string;
  title: string;
  summary: string;
  publishDate: string;
  
  // Scores
  maxCvssBaseScore: number;
  epssScore: number;
  epssPercentile: number;
  riskScore: RiskScore;
  
  // AI Analysis
  aiPriority: {
    score: number;
    likelihood: string;
    businessImpact: string;
    recommendation: string;
  };
  
  // Affected Products
  affects: AffectedProduct[];
  
  // Remediation
  remediationPlan: string; // Markdown
}
```

**UI 요소**:

- CVSS Vector 시각화 (Attack Vector, Complexity 등)
- EPSS Percentile 게이지
- Risk Score 히트맵
- "Affects" 테이블 (버전 범위)
- AI 생성 remediation 아코디언

### 4.3 Dependency Graph

**기술**: D3.js Force-Directed Graph

**노드**:

- 원형: 패키지/라이브러리
- 색상: 취약점 심각도 (빨강=Critical, 주황=High, 노랑=Medium, 초록=Safe)
- 크기: 의존하는 패키지 수

**엣지**:

- 의존성 관계 (A → B: A가 B에 의존)
- 취약점 전파 경로 강조 (점선)

**인터랙션**:

- 노드 클릭 → 패키지 상세 정보 사이드바
- 취약 경로 하이라이트 → Root cause까지 추적

### 4.4 AI Report 페이지

**섹션 구성**:

1. **Executive Summary** (AI 생성)
    - 전체 취약점 통계
    - 가장 위험한 3개 취약점
    - 권장 조치 타임라인
2. **Supply Chain Analysis** (Agent 2 결과)
    - 레이어별 취약점 분포
    - 중복 CVE 분석
    - 의존성 체인 다이어그램
3. **Action Items** (Agent 3 결과)
    - 우선순위별 remediation 플랜
    - 복사 가능한 코드 블록
    - 예상 작업 시간
4. **Export Options**:
    - PDF 리포트 다운로드
    - JSON 데이터 익스포트
    - JIRA/GitHub Issue 자동 생성

---

# 구현 계획

## Phase 1: Core Infrastructure (Week 1-2)

### Week 1: Backend Setup

- [ ]  FastAPI 프로젝트 구조 설정
- [ ]  Trivy CLI wrapper 구현
    
    ```python
    class TrivyScanner:
        def scan_repository(self, repo_path: str) -> dict
        def scan_image(self, image_name: str) -> dict
        def scan_sbom(self, sbom_path: str) -> dict
    ```
    
- [ ]  PostgreSQL schema 설계 (scans, vulnerabilities, reports)
- [ ]  CVEDetails API client 구현

### Week 2: Data Pipeline

- [ ]  CVE enrichment 파이프라인
- [ ]  EPSS 예측 모델 통합 (학습된 모델 로드)
- [ ]  Celery task 정의 (비동기 스캔)
- [ ]  Redis 캐싱 전략 (CVE 데이터 24시간 캐시)

## Phase 2: AI Agent Development (Week 3-4)

### Week 3: Agent Implementation

- [ ]  LangGraph 또는 Custom Agent 프레임워크 구축
- [ ]  Agent 1: Prioritization 프롬프트 엔지니어링
- [ ]  Agent 2: Supply Chain Analyzer 구현
- [ ]  Agent 3: Remediation Generator
- [ ]  Agent 체인 연결 및 테스트

### Week 4: Agent Optimization

- [ ]  프롬프트 튜닝 (Few-shot examples 추가)
- [ ]  응답 파싱 로직 (JSON extraction)
- [ ]  Error handling (API rate limit, timeout)
- [ ]  결과 검증 로직 (hallucination 방지)

## Phase 3: Frontend Development (Week 5-6)

### Week 5: UI Components

- [ ]  React 프로젝트 setup (Vite + TypeScript)
- [ ]  레이아웃 구조 (Dashboard, CVE Detail, Reports)
- [ ]  차트 컴포넌트 (Recharts 통합)
- [ ]  테이블 컴포넌트 (Tanstack Table)

### Week 6: Advanced Features

- [ ]  D3.js Dependency Graph 구현
- [ ]  AI Report 렌더링 (Markdown → HTML)
- [ ]  Export 기능 (PDF, JSON)
- [ ]  다크모드 지원

## Phase 4: Integration & Testing (Week 7-8)

### Week 7: End-to-End Integration

- [ ]  Frontend ↔ Backend API 연결
- [ ]  실제 GitHub repo로 E2E 테스트
- [ ]  Docker Compose로 전체 스택 구동
- [ ]  성능 최적화 (스캔 시간 단축)

### Week 8: Demo Preparation

- [ ]  샘플 데이터 준비 (취약한 오픈소스 프로젝트)
- [ ]  데모 시나리오 작성
- [ ]  발표 자료 제작
- [ ]  버그 수정 및 폴리싱

---

# 데이터 모델

## Database Schema

### scans 테이블

```sql
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    scan_type VARCHAR(50) NOT NULL, -- 'git_repo', 'container', 'vm', 'sbom'
    target VARCHAR(500) NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'pending', 'running', 'completed', 'failed'
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    result_json JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### vulnerabilities 테이블

```sql
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),
    cve_id VARCHAR(20) NOT NULL,
    package_name VARCHAR(200),
    package_version VARCHAR(100),
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    epss_score DECIMAL(5,5),
    epss_predicted BOOLEAN DEFAULT FALSE,
    cve_details JSONB, -- CVEDetails API 응답 전체
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_scan_id ON vulnerabilities(scan_id);
```

### ai_analyses 테이블

```sql
CREATE TABLE ai_analyses (
    id UUID PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),
    agent_type VARCHAR(50), -- 'prioritization', 'supply_chain', 'remediation'
    input_data JSONB,
    output_data JSONB,
    tokens_used INTEGER,
    processing_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## API Endpoints

### Scan Management

```
POST   /api/scans/trigger
  Body: {
    "scanType": "git_repo" | "container" | "vm" | "sbom",
    "target": "[https://github.com/user/repo](https://github.com/user/repo)" | "nginx:latest",
    "options": { ... }
  }
  Response: { "scanId": "uuid", "status": "pending" }

GET    /api/scans/{scanId}
  Response: {
    "id": "uuid",
    "status": "completed",
    "vulnerabilities": [...],
    "summary": { "critical": 2, "high": 5, ... }
  }

GET    /api/scans
  Query: ?page=1&limit=20&status=completed
  Response: { "scans": [...], "total": 150 }
```

### Vulnerability Details

```
GET    /api/vulnerabilities/{cveId}
  Response: {
    "cveId": "CVE-2024-31449",
    "details": { ...CVEDetails API data... },
    "aiAnalysis": {
      "priorityScore": 9,
      "likelihood": "High",
      ...
    },
    "affectedScans": ["scan-1", "scan-2"]
  }

GET    /api/vulnerabilities
  Query: ?scanId=uuid&severity=CRITICAL&sort=epss_desc
  Response: { "vulnerabilities": [...], "total": 42 }
```

### AI Analysis

```
POST   /api/ai/analyze
  Body: {
    "scanId": "uuid",
    "agents": ["prioritization", "supply_chain", "remediation"]
  }
  Response: {
    "analysisId": "uuid",
    "status": "processing"
  }

GET    /api/ai/analysis/{analysisId}
  Response: {
    "results": {
      "prioritization": { ... },
      "supply_chain": { ... },
      "remediation": { ... }
    }
  }
```

### Reports

```
GET    /api/reports/generate
  Query: ?scanId=uuid&format=pdf|json|markdown
  Response: File download or JSON data
```

---

# AI Agent 상세 설계

## Agent Orchestration

```python
from langgraph.graph import StateGraph, END

class SupplyChainAnalysisState(TypedDict):
    scan_results: dict
    enriched_cves: list[dict]
    prioritization: dict
    supply_chain_analysis: dict
    remediation_plans: list[dict]
    final_report: str

def build_agent_graph():
    workflow = StateGraph(SupplyChainAnalysisState)
    
    # Nodes
    workflow.add_node("enrich_cves", enrich_cves_node)
    workflow.add_node("prioritize", prioritization_agent)
    workflow.add_node("analyze_supply_chain", supply_chain_agent)
    workflow.add_node("generate_remediation", remediation_agent)
    workflow.add_node("compile_report", report_generator)
    
    # Edges
    workflow.set_entry_point("enrich_cves")
    workflow.add_edge("enrich_cves", "prioritize")
    workflow.add_edge("enrich_cves", "analyze_supply_chain")  # 병렬
    workflow.add_edge("prioritize", "generate_remediation")
    workflow.add_edge("analyze_supply_chain", "generate_remediation")
    workflow.add_edge("generate_remediation", "compile_report")
    workflow.add_edge("compile_report", END)
    
    return workflow.compile()
```

## Prompt Templates

### Prioritization Agent Prompt

```python
PRIORITIZATION_PROMPT = """
You are a cybersecurity analyst specializing in vulnerability risk assessment.

Given the following vulnerability data, calculate a priority score (1-10) and provide actionable recommendations.

# Vulnerability Data
{cve_data}

# Scoring Criteria
- CVSS Score (weight: 30%)
- EPSS Score (weight: 25%)
- Exploit availability (weight: 20%)
- System context (internet-facing, data sensitivity) (weight: 15%)
- CISA KEV status (weight: 10%)

# Output Format (JSON)
{{
  "priorityScore": <1-10>,
  "likelihood": "Low|Medium|High|Critical",
  "businessImpact": "<2 sentences>",
  "recommendation": "Immediate|Scheduled|Monitor",
  "rationale": "<3 sentences explaining the score>",
  "estimatedRemediationTime": "<hours>"
}}

Provide ONLY the JSON output, no additional text.
"""
```

### Supply Chain Agent Prompt

```python
SUPPLY_CHAIN_PROMPT = """
You are a software supply chain security expert.

Analyze the following multi-source scan results to identify:
1. Overlapping vulnerabilities across layers
2. Dependency chains that propagate vulnerabilities
3. Root causes and blast radius
4. Consolidated remediation strategies

# Scan Results
{scan_data}

# Output Format (Markdown)
## Critical Findings
- List the top 3 most concerning supply chain risks

## Dependency Analysis
- Trace how vulnerabilities propagate through the stack

## Root Causes
- Identify the upstream packages causing multiple downstream issues

## Consolidated Remediation
- Suggest fixes that address multiple layers simultaneously

## Risk Metrics
- Total unique CVEs: X
- Overlapping CVEs: Y
- Affected components: Z
"""
```

### Remediation Agent Prompt

```python
REMEDIATION_PROMPT = """
You are a DevOps engineer creating detailed remediation plans.

For CVE {cve_id} affecting {package} version {current_version}:

Provide a comprehensive, copy-paste ready remediation plan.

# Tech Stack Context
- Language: {language}
- Package Manager: {package_manager}
- Deployment: {deployment_type}
- CI/CD: {cicd_tool}

# Required Sections
1. Pre-Flight Checklist (bullet points)
2. Patch Commands (code blocks with exact commands)
3. Configuration Changes (diffs)
4. Breaking Changes & Compatibility Notes
5. Testing Procedure (step-by-step)
6. Rollback Plan
7. Alternative Mitigations (if patching not immediately possible)

Use Markdown formatting with code blocks.
Be specific and actionable - avoid generic advice.
"""
```

## Error Handling & Retries

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10)
)
async def call_ai_agent(prompt: str) -> dict:
    try:
        response = await anthropic.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        
        # JSON 추출 (markdown code block 제거)
        content = response.content[0].text
        json_match = [re.search](http://re.search)(r'```json\s*({.*?})\s*```', content, re.DOTALL)
        if json_match:
            return json.loads(json_[match.group](http://match.group)(1))
        return json.loads(content)  # Raw JSON인 경우
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI response: {e}")
        # Fallback: 텍스트 응답 그대로 반환
        return {"raw_response": content, "parse_error": str(e)}
    except Exception as e:
        logger.error(f"AI agent error: {e}")
        raise
```

---

# EPSS 예측 모델

## 모델 아키텍처

```python
import xgboost as xgb
from sklearn.preprocessing import StandardScaler

class EPSSPredictor:
    def __init__(self, model_path: str):
        self.model = xgb.Booster()
        self.model.load_model(model_path)
        self.scaler = StandardScaler()
        
    def extract_features(self, cve_data: dict) -> np.ndarray:
        """
        Feature Engineering:
        - CVSS Base Score, Exploitability, Impact
        - Attack Vector (Network=4, Adjacent=3, Local=2, Physical=1)
        - Attack Complexity (Low=2, High=1)
        - Privileges Required (None=3, Low=2, High=1)
        - CWE category (one-hot encoded top 50 CWEs)
        - Vendor popularity (GitHub stars, downloads)
        - Days since publication
        - Weekday of publication (0-6)
        """
        features = [
            float(cve_data.get('maxCvssBaseScore', 0)),
            float(cve_data.get('maxCvssExploitabilityScore', 0)),
            float(cve_data.get('maxCvssImpactScore', 0)),
            self._encode_attack_vector(cve_data),
            self._encode_complexity(cve_data),
            self._encode_privileges(cve_data),
            self._days_since_publication(cve_data['publishDate']),
            # ... CWE one-hot encoding
            # ... Vendor features
        ]
        return np.array(features).reshape(1, -1)
    
    def predict(self, cve_data: dict) -> float:
        features = self.extract_features(cve_data)
        features_scaled = self.scaler.transform(features)
        epss_score = self.model.predict(xgb.DMatrix(features_scaled))[0]
        return float(np.clip(epss_score, 0, 1))  # 0-1 범위로 클리핑
```

## Training Pipeline (Reference)

```python
# 학습 데이터 준비 (과제 제출 시 포함하지 않아도 됨)
def train_epss_model():
    # NVD + EPSS 공개 데이터셋 로드
    df = [pd.read](http://pd.read)_csv('nvd_epss_training_data.csv')
    
    X = df[feature_columns]
    y = df['epss_score']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    
    model = xgb.XGBRegressor(
        objective='reg:squarederror',
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05
    )
    
    [model.fit](http://model.fit)(X_train, y_train)
    
    # 평가
    y_pred = model.predict(X_test)
    mae = mean_absolute_error(y_test, y_pred)
    print(f"MAE: {mae:.4f}")  # Target: < 0.05
    
    [model.save](http://model.save)_model('epss_predictor.json')
```

---

# 데모 시나리오

## 시나리오 1: 실제 오픈소스 프로젝트 스캔

**Target**: [`https://github.com/example/vulnerable-app`](https://github.com/example/vulnerable-app) (의도적으로 구버전 의존성 사용)

**Steps**:

1. 웹 UI에서 GitHub URL 입력
2. "Start Scan" 버튼 클릭
3. 실시간 스캔 진행 상황 표시 (WebSocket)
4. 완료 후 대시보드 자동 업데이트
    - **발견**: 15개 취약점 (Critical: 2, High: 5, Medium: 8)
    - **AI 우선순위**: CVE-2024-31449 (Redis) - Priority Score 9
5. CVE 상세 페이지 진입
    - CVEDetails 데이터 표시
    - AI 분석 결과 확장
    - Remediation plan 복사
6. Dependency Graph 확인
    - Redis가 3개 마이크로서비스에 영향
    - 빨간색 노드로 하이라이트
7. AI Report 생성 및 PDF 다운로드

## 시나리오 2: Container Image 스캔

**Target**: `nginx:1.21.0` (알려진 취약점 존재)

**Steps**:

1. "Scan Container" 탭 선택
2. Image name 입력: `nginx:1.21.0`
3. 스캔 실행 → 8개 취약점 발견
4. AI가 OS 레벨 취약점 vs 애플리케이션 레벨 구분
5. Remediation: `nginx:1.21.6`으로 업그레이드 제안
6. Dockerfile diff 자동 생성

## 시나리오 3: Multi-Source 통합 분석

**Setup**:

- Git Repo 스캔 완료 (10개 CVE)
- Container 스캔 완료 (8개 CVE)
- SBOM 업로드 (12개 CVE)

**AI Supply Chain Analysis**:

- **중복 발견**: CVE-2024-31449가 3곳 모두에서 발견
- **Root Cause**: Redis 7.2.5
- **통합 수정**: 베이스 이미지 업데이트 1번으로 모든 레이어 해결
- **예상 시간**: 30분

---

# 평가 기준 (과제용)

## 기술 구현 (40%)

- [ ]  Trivy 통합 및 다중 소스 스캔 (10%)
- [ ]  CVEDetails API 연동 및 EPSS 예측 (10%)
- [ ]  AI Agent 구현 (3개 Agent 모두 동작) (15%)
- [ ]  웹 대시보드 완성도 (5%)

## 기능 완성도 (30%)

- [ ]  취약점 우선순위화의 정확성 (10%)
- [ ]  Supply Chain 분석의 유의미성 (10%)
- [ ]  Remediation plan의 실용성 (10%)

## 문서화 (15%)

- [ ]  코드 주석 및 README
- [ ]  아키텍처 다이어그램
- [ ]  API 문서 (Swagger/OpenAPI)

## 데모 & 발표 (15%)

- [ ]  실제 동작 시연
- [ ]  문제 해결 과정 설명
- [ ]  향후 개선 방향 제시

---

# 기술적 도전 과제 & 해결 방안

## Challenge 1: Trivy 스캔 속도

**문제**: 대형 레포지토리 스캔 시 10분+ 소요

**해결**:

- Celery로 백그라운드 작업 처리
- 캐싱: 같은 패키지 버전은 재스캔 생략
- 병렬 스캔: 여러 소스 동시 실행

## Challenge 2: CVEDetails API Rate Limit

**문제**: 무료 플랜 시간당 100 요청 제한

**해결**:

- Redis에 CVE 데이터 24시간 캐싱
- Batch 요청: 한 번에 여러 CVE 조회
- Fallback: NVD API 사용

## Challenge 3: AI Hallucination

**문제**: LLM이 존재하지 않는 패치 버전 제안

**해결**:

- Structured output (JSON mode 강제)
- Post-processing: 실제 패키지 레지스트리에서 버전 검증
- Few-shot examples로 정확도 향상

## Challenge 4: EPSS 예측 정확도

**문제**: 신규 CVE는 히스토리 데이터 부족

**해결**:

- Transfer learning: 유사 CWE 카테고리 데이터 활용
- Conservative estimation: 불확실하면 높은 점수 부여 (false positive 선호)
- 주기적 재학습: 실제 EPSS 발표 후 모델 업데이트

---

# 확장 가능성 (Future Work)

## v2.0 Features

1. **CI/CD 통합**
    - GitHub Actions/GitLab CI 플러그인
    - PR에 자동 취약점 코멘트
2. **자동 패치 PR 생성**
    - AI가 생성한 Dockerfile/requirements.txt를 자동으로 PR 생성
    - 개발자는 리뷰만 수행
3. **Compliance Reporting**
    - NIST, ISO 27001 기준 보고서
    - 라이선스 컴플라이언스 검사
4. **Threat Intelligence Feed**
    - 실시간 Exploit 공개 알림
    - Zero-day 취약점 모니터링
5. **Multi-Tenant SaaS**
    - 팀별 워크스페이스
    - RBAC (Role-Based Access Control)
    - 스캔 히스토리 관리

---

# 참고 자료

## 오픈소스 도구

- **Trivy**: [https://github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy)
- **LangGraph**: [https://github.com/langchain-ai/langgraph](https://github.com/langchain-ai/langgraph)
- **CVEDetails**: [https://www.cvedetails.com/api-documentation](https://www.cvedetails.com/api-documentation)

## 데이터셋

- **NVD (National Vulnerability Database)**: [https://nvd.nist.gov/](https://nvd.nist.gov/)
- **EPSS (Exploit Prediction Scoring System)**: [https://www.first.org/epss/](https://www.first.org/epss/)
- **CISA KEV Catalog**: [https://www.cisa.gov/known-exploited-vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities)

## 논문/표준

- CVSS v3.1 Specification
- EPSS Whitepaper ([FIRST.org](http://FIRST.org))
- SBOM Standards: CycloneDX, SPDX

---

# 프로젝트 구조

```
securechain-ai/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── [scans.py](http://scans.py)
│   │   │   ├── [vulnerabilities.py](http://vulnerabilities.py)
│   │   │   └── ai_[analysis.py](http://analysis.py)
│   │   ├── agents/
│   │   │   ├── [prioritization.py](http://prioritization.py)
│   │   │   ├── supply_[chain.py](http://chain.py)
│   │   │   └── [remediation.py](http://remediation.py)
│   │   ├── integrations/
│   │   │   ├── [trivy.py](http://trivy.py)
│   │   │   ├── [cvedetails.py](http://cvedetails.py)
│   │   │   └── epss_[predictor.py](http://predictor.py)
│   │   ├── models/
│   │   │   └── [database.py](http://database.py)
│   │   └── [main.py](http://main.py)
│   ├── models/
│   │   └── epss_predictor.json
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── CVEDetail.tsx
│   │   │   ├── DependencyGraph.tsx
│   │   │   └── AIReport.tsx
│   │   ├── api/
│   │   │   └── client.ts
│   │   └── App.tsx
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
├── [README.md](http://README.md)
└── docs/
    ├── [architecture.md](http://architecture.md)
    └── api-spec.yaml
```

---

# 결론

이 프로젝트는 소프트웨어 공급망 보안의 3가지 핵심 문제를 해결합니다:

1. **가시성 부족** → Trivy로 다층적 스캔
2. **우선순위 혼란** → AI가 맥락 기반 평가
3. **실행 장벽** → 복사 가능한 구체적 해결책 제시

학교 과제로 적합한 이유:

- **명확한 범위**: 8주 내 MVP 구현 가능
- **최신 기술**: LLM Agent, Supply Chain Security 트렌드 반영
- **실용성**: 실제 오픈소스 프로젝트에 적용 가능한 결과물
- **학습 가치**: DevSecOps, AI 통합, Full-stack 개발 경험

**Next Steps**: Phase 1 구현부터 시작하며, 질문이나 막히는 부분이 있으면 언제든지 문의하세요!