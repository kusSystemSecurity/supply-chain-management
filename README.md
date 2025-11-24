# SecureChain AI - Supply Chain Security Platform

AI-powered software supply chain security analysis platform with comprehensive vulnerability scanning, ML-based EPSS prediction, intelligent remediation assistance, and a modern web interface.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React + Vite)                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │Dashboard │  │  Scans   │  │  Vulns   │  │    AI    │     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
└───────────────────────────┬─────────────────────────────────┘
                            │ REST API
┌───────────────────────────┴─────────────────────────────────┐
│                  Backend (FastAPI)                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Scan Orchestration                      │   │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌─────────┐    │   │
│  │  │Git Repo │ │Container │ │   VM    │ │   K8s   │    │   │
│  │  └─────────┘ └──────────┘ └─────────┘ └─────────┘    │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │          CVE Enrichment + EPSS Prediction            │   │
│  │  ┌────────────────┐  ┌─────────────────────────┐     │   │
│  │  │ CVEDetails API │  │ ML EPSS Predictor       │     │   │
│  │  │ (Real EPSS)    │  │                         │     │   │
│  │  └────────────────┘  └─────────────────────────┘     │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              AI Agents Team (OpenRouter API)         │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────┴─────────────────────────────────┐
│                      In-Memory Storage                      │
│  ┌──────────┐  ┌────────────────┐  ┌──────────────┐         │
│  │  Scans   │  │Vulnerabilities │  │ AI Analyses  │         │
│  └──────────┘  └────────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## Setup

### Database Setup

#### Using Docker
```bash
docker run -d \
  --name agno-postgres \
  -e POSTGRES_DB=ai \
  -e POSTGRES_USER=ai \
  -e POSTGRES_PASSWORD=ai \
  -p 5532:5432 \
  pgvector/pgvector:pg17
```

### Backend Setup

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure environment variables:
   - Copy `.env.example` to `.env`
   - Set your API keys:
     - `CVEDETAILS_API_KEY=your_api_key_here`
     - `OPENROUTER_API_KEY=your_openrouter_api_key_here`

3. Run FastAPI server:
   ```bash
   python run_api.py
   ```
   The API will be available at `http://localhost:8000`

### Frontend Setup

1. Navigate to frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   - Create `.env` file in `frontend/` directory
   - Set `VITE_API_BASE_URL=http://localhost:8000`

4. Run development server:
   ```bash
   npm run dev
   ```
   The frontend will be available at `http://localhost:5173`

## Features

- **Multi-format Vulnerability Scanning**: Git repositories, containers, VMs, SBOMs, Kubernetes
- **ML-based EPSS Prediction**: Predict exploitation probability when data is unavailable
- **AI-Powered Analysis**: Three specialized AI agents for prioritization, supply chain impact, and remediation
- **Modern Web UI**: Beautiful, responsive React interface with dark mode support
- **Project Management**: Organize scans into projects for better analysis
- **Real-time Updates**: Live scan status updates and results
- **Scan Management**: Create, view, and manage security scans
- **Vulnerability Details**: Detailed view of vulnerabilities with CVE information
- **Interactive Dashboard**: Visual charts and statistics for security insights

## API Documentation

When the FastAPI server is running, visit `http://localhost:8000/docs` for interactive API documentation.

## Project Structure

```
supply-chain-management/
├── backend/              # Backend modules
│   ├── api/             # FastAPI application
│   ├── schemas/         # Pydantic schemas
│   └── ...              # Other backend modules
├── frontend/            # React frontend
│   ├── src/
│   │   ├── components/  # React components
│   │   ├── pages/       # Page components
│   │   ├── services/    # API client
│   │   └── types/       # TypeScript types
│   └── ...
├── gradio_app.py        # Gradio interface (legacy)
└── run_api.py           # FastAPI server entry point
```

## Pages

- **Dashboard** (`/`): Overview of all scans, statistics, and charts
- **Create Scan** (`/create-scan`): Create new security scans
- **Scan Detail** (`/scan/:scanId`): View detailed scan information and vulnerabilities
- **AI Analysis** (`/ai-analysis`): Run AI-powered analysis on projects
