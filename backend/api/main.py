"""
FastAPI application entry point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
import agentops
from .routers import scans, vulnerabilities, projects, ai_analysis, cve

# Load environment variables
load_dotenv()

AGENTOPS_API_KEY = os.getenv("AGENTOPS_API_KEY")

if AGENTOPS_API_KEY:
    agentops.init(api_key=AGENTOPS_API_KEY)
    print("AgentOps initialized")
else:
    print("AgentOps not initialized")

# Create FastAPI app
app = FastAPI(
    title="SecureChain AI API",
    description="Supply Chain Security Platform API",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173",
                   "http://localhost:3000"],  # Vite default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(vulnerabilities.router,
                   prefix="/api/vulnerabilities", tags=["vulnerabilities"])
app.include_router(projects.router, prefix="/api/projects", tags=["projects"])
app.include_router(ai_analysis.router,
                   prefix="/api/ai-analysis", tags=["ai-analysis"])
app.include_router(cve.router, prefix="/api/cve", tags=["cve"])


@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "SecureChain AI API", "version": "1.0.0"}


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}
