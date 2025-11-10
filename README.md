# SecureChain AI - Supply Chain Security Platform

AI-powered software supply chain security analysis platform with comprehensive vulnerability scanning, ML-based EPSS prediction, intelligent remediation assistance, and a modern web interface.

![Version](https://img.shields.io/badge/version-0.1.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![Next.js](https://img.shields.io/badge/next.js-15-black)
![License](https://img.shields.io/badge/license-MIT-purple)

## Overview

SecureChain AI is a comprehensive platform for securing software supply chains through:

- **Multi-format Vulnerability Scanning**: Git repositories, containers, VMs, SBOMs, Kubernetes
- **ML-based EPSS Prediction**: Predict exploitation probability when data is unavailable
- **AI-Powered Analysis**: Three specialized AI agents for prioritization, supply chain impact, and remediation
- **Modern Web UI**: Beautiful, responsive Next.js interface with real-time updates
- **Database Persistence**: PostgreSQL for reliable data storage

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (Next.js 15)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │Dashboard │  │  Scans   │  │  Vulns   │  │    AI    │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                            │ REST API
┌───────────────────────────┴─────────────────────────────────┐
│                    Backend (FastAPI)                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Scan Orchestration                       │  │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌─────────┐  │  │
│  │  │Git Repo │ │Container │ │   VM    │ │   K8s   │  │  │
│  │  └─────────┘ └──────────┘ └─────────┘ └─────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │          CVE Enrichment + EPSS Prediction             │  │
│  │  ┌────────────────┐  ┌─────────────────────────┐    │  │
│  │  │ CVEDetails API │  │ ML EPSS Predictor       │    │  │
│  │  │ (Real EPSS)    │  │ (Gradient Boosting)     │    │  │
│  │  └────────────────┘  └─────────────────────────┘    │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              AI Agents (Claude API)                   │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐│  │
│  │  │Prioritization│ │Supply Chain  │ │ Remediation  ││  │
│  │  └──────────────┘ └──────────────┘ └──────────────┘│  │
│  └──────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────┴─────────────────────────────────┐
│                   PostgreSQL Database                        │
│  ┌──────────┐  ┌────────────────┐  ┌──────────────┐       │
│  │  Scans   │  │Vulnerabilities │  │ AI Analyses  │       │
│  └──────────┘  └────────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

## Features

### 🔍 Comprehensive Scanning

- **Git Repositories**: Source code analysis
- **Container Images**: Docker/OCI image scanning
- **Virtual Machines**: VM image security assessment
- **SBOM Files**: Software Bill of Materials analysis
- **Kubernetes**: Manifest and cluster scanning
- **Powered by Trivy**: Industry-leading vulnerability scanner

### 🤖 AI-Powered Analysis

#### Prioritization Agent

- Risk-based vulnerability scoring
- EPSS score integration
- Business impact assessment
- Contextual recommendations

#### Supply Chain Agent

- Cross-scan vulnerability correlation
- Dependency chain analysis
- Common vulnerability patterns
- Consolidated remediation strategies

#### Remediation Agent

- Step-by-step remediation plans
- Upgrade commands and configurations
- Testing and validation procedures
- Rollback strategies

### 📊 ML-based EPSS Prediction

When EPSS scores are unavailable from CVEDetails API:

- **Gradient Boosting Model**: Trained on historical CVE data
- **13 Feature Engineering**: CVSS metrics, attack vectors, CWE patterns
- **Automatic Fallback**: Seamlessly predicts when API data is missing
- **Continuous Learning**: Model can be retrained with new data

### 🎨 Modern Web Interface

- **Real-time Dashboard**: Security metrics and recent scans
- **Interactive Vulnerability Tables**: Search, filter, and sort
- **Scan Management**: Create, monitor, and manage scans
- **AI Analysis Interface**: Run and view AI agent results
- **Responsive Design**: Works on all devices
- **Auto-refresh**: Real-time updates for running scans

## Quick Start

### Prerequisites

- Docker & Docker Compose (recommended)
- OR: Python 3.11+, Node.js 20+, PostgreSQL 16+
- Anthropic API key (for AI features)
- CVEDetails API key (optional, for real EPSS data)

### Option 1: Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/your-org/supply-chain-management.git
cd supply-chain-management

# Configure environment
cp backend/.env.example backend/.env
# Edit backend/.env with your API keys

# Start all services
docker compose up -d

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Option 2: Manual Setup

#### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys and database URL

# Run database migrations
alembic upgrade head

# Start backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Configure environment
echo "NEXT_PUBLIC_API_URL=http://localhost:8000/api" > .env.local

# Start development server
npm run dev
```

## Environment Configuration

### Backend (.env)

```bash
# Database
DATABASE_URL=postgresql://securechain:password@localhost:5432/securechain

# API Keys
ANTHROPIC_API_KEY=your_anthropic_api_key
CVEDETAILS_API_KEY=your_cvedetails_api_key  # Optional

# Server
DEBUG=true
API_HOST=0.0.0.0
API_PORT=8000

# Security
SECRET_KEY=your_secret_key_here
```

### Frontend (.env.local)

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000/api
```

## Usage Examples

### 1. Create a Scan

**Via UI:**

1. Navigate to http://localhost:3000/scans
2. Click "New Scan"
3. Select scan type and enter target
4. Click "Start Scan"

**Via API:**

```bash
curl -X POST "http://localhost:8000/api/scans/trigger" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "container",
    "target": "nginx:latest",
    "options": {}
  }'
```

### 2. View Scan Results

**Via UI:**

- Visit http://localhost:3000/scans
- Click on any scan to view details
- Filter vulnerabilities by severity
- Search by CVE ID or package name

**Via API:**

```bash
# Get scan details
curl "http://localhost:8000/api/scans/{scan_id}"

# Get vulnerabilities
curl "http://localhost:8000/api/scans/{scan_id}/vulnerabilities?severity=CRITICAL"
```

### 3. Run AI Analysis

**Via UI:**

- Navigate to http://localhost:3000/analysis
- Select a completed scan
- Choose an AI agent
- Click "Run AI Analysis"

**Via API:**

```bash
curl -X POST "http://localhost:8000/api/ai/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "{scan_id}",
    "agents": ["prioritization", "remediation"],
    "context": {}
  }'
```

## Documentation

- **[Backend README](backend/README.md)**: API documentation, architecture, deployment
- **[Frontend README](frontend/README.md)**: UI components, features, development
- **[Database Guide](DATABASE_GUIDE.md)**: Schema, migrations, administration
- **[EPSS Model Guide](backend/EPSS_MODEL_GUIDE.md)**: ML model details, training
- **[Implementation Summary](backend/IMPLEMENTATION_SUMMARY.md)**: Complete feature list

## API Documentation

Interactive API documentation available at:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

| Endpoint                          | Method | Description               |
| --------------------------------- | ------ | ------------------------- |
| `/api/scans/trigger`              | POST   | Create new scan           |
| `/api/scans`                      | GET    | List all scans            |
| `/api/scans/{id}`                 | GET    | Get scan details          |
| `/api/scans/{id}/vulnerabilities` | GET    | Get vulnerabilities       |
| `/api/ai/analyze`                 | POST   | Run AI analysis           |
| `/api/ai/prioritize`              | POST   | Prioritize vulnerability  |
| `/api/ai/remediation`             | POST   | Generate remediation plan |

## Development

### Backend Development

```bash
cd backend

# Install dev dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio black flake8

# Run tests
pytest

# Format code
black app/

# Lint
flake8 app/
```

### Frontend Development

```bash
cd frontend

# Start dev server with hot reload
npm run dev

# Build for production
npm run build

# Run linter
npm run lint

# Type check
npx tsc --noEmit
```

### Database Migrations

```bash
cd backend

# Create new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback one version
alembic downgrade -1

# View migration history
alembic history
```

## Project Structure

```
supply-chain-management/
├── backend/                      # FastAPI backend
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── config.py            # Configuration
│   │   ├── database.py          # Database connection
│   │   ├── crud.py              # CRUD operations
│   │   ├── models/              # Database models
│   │   ├── api/                 # API endpoints
│   │   ├── agents/              # AI agents
│   │   ├── scanners/            # Vulnerability scanners
│   │   └── integrations/        # External APIs
│   ├── alembic/                 # Database migrations
│   ├── requirements.txt
│   └── README.md
├── frontend/                     # Next.js frontend
│   ├── app/                     # Next.js pages
│   ├── components/              # React components
│   ├── lib/                     # Utilities
│   ├── package.json
│   └── README.md
├── docker-compose.yml           # Docker orchestration
├── DATABASE_GUIDE.md            # Database documentation
└── README.md                    # This file
```

## Technology Stack

### Backend

- **Framework**: FastAPI
- **Language**: Python 3.11+
- **Database**: PostgreSQL 16
- **ORM**: SQLAlchemy
- **Migrations**: Alembic
- **Scanner**: Trivy
- **ML**: scikit-learn, pandas, numpy
- **AI**: Anthropic Claude API

### Frontend

- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **UI**: shadcn/ui + Radix UI
- **Data Fetching**: TanStack Query
- **Icons**: Lucide React

### Infrastructure

- **Container**: Docker
- **Orchestration**: Docker Compose
- **Database**: PostgreSQL
- **Reverse Proxy**: Nginx (production)

## Deployment

### Docker Production Deployment

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Scale services
docker-compose up -d --scale backend=3
```

### Manual Production Deployment

See individual READMEs:

- [Backend Deployment](backend/README.md#deployment)
- [Frontend Deployment](frontend/README.md#deployment)

## Monitoring & Maintenance

### Database Backup

```bash
# Backup
docker-compose exec postgres pg_dump -U securechain securechain > backup.sql

# Restore
docker-compose exec -T postgres psql -U securechain securechain < backup.sql
```

### Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f postgres
```

### Health Checks

```bash
# Backend health
curl http://localhost:8000/health

# Frontend (browser)
open http://localhost:3000

# Database connection
docker-compose exec postgres psql -U securechain -d securechain -c "SELECT 1"
```

## Troubleshooting

### Backend Issues

```bash
# Check backend logs
docker-compose logs backend

# Restart backend
docker-compose restart backend

# Run migrations
docker-compose exec backend alembic upgrade head
```

### Frontend Issues

```bash
# Check frontend logs
docker-compose logs frontend

# Rebuild frontend
docker-compose build frontend
docker-compose up -d frontend

# Clear Next.js cache
cd frontend && rm -rf .next && npm run dev
```

### Database Issues

```bash
# Check PostgreSQL status
docker-compose ps postgres

# Access PostgreSQL shell
docker-compose exec postgres psql -U securechain -d securechain

# Reset database
docker-compose exec backend python -c "from app.database import reset_database; reset_database()"
```

## Performance

- **Scan Speed**: 1-5 minutes for typical containers
- **API Response**: < 100ms for most endpoints
- **Database Queries**: Optimized with indexes
- **Frontend Load**: < 2s initial load
- **Concurrent Scans**: Supports multiple parallel scans

## Security

- **API Authentication**: JWT tokens (planned for production)
- **Database**: Encrypted connections
- **Secrets**: Environment variables only
- **CORS**: Configured for production
- **Input Validation**: Pydantic models
- **SQL Injection**: Protected by ORM

## What's New in This Version

✅ **Complete Frontend**: React/Next.js UI with shadcn/ui
✅ **Database Persistence**: PostgreSQL integration with Alembic migrations
✅ **EPSS ML Model**: Gradient Boosting for exploitation prediction
✅ **AI Agents**: Three specialized Claude-powered agents
✅ **Real-time Updates**: Auto-polling for scan status
✅ **Comprehensive Docs**: Full documentation for all components

## Roadmap

- [ ] User authentication and multi-tenancy
- [ ] Advanced RBAC (Role-Based Access Control)
- [ ] Webhook integrations
- [ ] Scheduled scans
- [ ] Report generation (PDF/Excel)
- [ ] JIRA/GitHub Issues integration
- [ ] Slack/Teams notifications
- [ ] Custom AI agent training
- [ ] Advanced analytics dashboard
- [ ] Vulnerability trends and metrics

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is part of a thesis and is provided as-is for educational purposes.

## Acknowledgments

- **Trivy**: Vulnerability scanner by Aqua Security
- **CVEDetails**: CVE information database
- **Anthropic**: Claude AI for intelligent analysis
- **shadcn/ui**: Beautiful UI component library
- **FastAPI**: High-performance Python web framework
- **Next.js**: React framework by Vercel

---

Built with ❤️ for supply chain security
