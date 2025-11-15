# SecureChain AI - Supply Chain Security Platform

AI-powered software supply chain security analysis platform with comprehensive vulnerability scanning, ML-based EPSS prediction, intelligent remediation assistance, and a modern web interface.

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
│                    Frontend (Next.js 15)                    │
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
│  │              AI Agents (Claude API)                  │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐  │   │
│  │  │Prioritization│ │Supply Chain  │ │ Remediation  │  │   │
│  │  └──────────────┘ └──────────────┘ └──────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────┴─────────────────────────────────┐
│                   PostgreSQL Database                       │
│  ┌──────────┐  ┌────────────────┐  ┌──────────────┐         │
│  │  Scans   │  │Vulnerabilities │  │ AI Analyses  │         │
│  └──────────┘  └────────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────┘
```
