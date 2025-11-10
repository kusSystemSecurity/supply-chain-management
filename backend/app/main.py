"""Main FastAPI application"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from app.api import scans, ai_analysis
from app.config import settings
from app.database import init_db, test_connection

# Configure logging
logging.basicConfig(
    level=logging.INFO if settings.debug else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events"""
    logger.info("SecureChain AI API starting up...")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"Database URL: {settings.database_url.split('@')[1] if '@' in settings.database_url else settings.database_url}")

    # Test database connection
    if test_connection():
        logger.info("✅ Database connection successful")

        # Initialize database (create tables if they don't exist)
        try:
            init_db()
            logger.info("✅ Database initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize database: {e}")
            logger.warning("API will start but database operations may fail")
    else:
        logger.error("❌ Database connection failed")
        logger.warning("API will start but database operations will fail")

    logger.info(f"API will be available at http://{settings.api_host}:{settings.api_port}")

    yield

    logger.info("SecureChain AI API shutting down...")


# Create FastAPI app
app = FastAPI(
    title="SecureChain AI API",
    description="AI-powered software supply chain security analysis platform",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scans.router)
app.include_router(ai_analysis.router)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "SecureChain AI API",
        "version": "0.1.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "securechain-ai",
        "version": "0.1.0"
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )
