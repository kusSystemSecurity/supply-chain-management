# SecureChain AI - Supply Chain Security Platform

AI-powered software supply chain security analysis platform with comprehensive vulnerability scanning, ML-based EPSS prediction, intelligent remediation assistance, and a modern web interface.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure environment variables:
   - Copy `.env.example` to `.env`
   - Set your CVE Details API key: `CVEDETAILS_API_KEY=your_api_key_here`
   - Get your API key from: https://www.cvedetails.com/

## Overview

SecureChain AI is a comprehensive platform for securing software supply chains through:

- **Multi-format Vulnerability Scanning**: Git repositories, containers, VMs, SBOMs, Kubernetes
- **ML-based EPSS Prediction**: Predict exploitation probability when data is unavailable
- **AI-Powered Analysis**: Specialized AI agents for supply chain security analysis
- **Modern Web UI**: Beautiful, responsive Next.js interface with real-time updates
- **Database Persistence**: PostgreSQL for reliable data storage

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Frontend                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │Dashboard │  │  Scans   │  │  Vulns   │  │    AI    │     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
└───────────────────────────┬─────────────────────────────────┘
                            │ REST API
┌───────────────────────────┴─────────────────────────────────┐
│                    Backend (FastAPI)                        │
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
│  │  │ (Real EPSS)    │  │ (Gradient Boosting)     │     │   │
│  │  └────────────────┘  └─────────────────────────┘     │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              AI Agents (LLM API)                     │   │
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
