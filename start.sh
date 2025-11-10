#!/bin/bash

# SecureChain AI - Quick Start Script

echo "==================================="
echo "SecureChain AI - Quick Start"
echo "==================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "✅ Docker is running"
echo ""

# Check if .env file exists
if [ ! -f "backend/.env" ]; then
    echo "⚠️  .env file not found. Creating from example..."
    cp backend/.env.example backend/.env
    echo "✅ Created backend/.env file"
    echo "⚠️  Please edit backend/.env and add your API keys:"
    echo "   - ANTHROPIC_API_KEY"
    echo "   - CVEDETAILS_API_KEY"
    echo ""
fi

# Start the application
echo "🚀 Starting SecureChain AI..."
echo ""

docker-compose up -d

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check service status
echo ""
echo "📊 Service Status:"
docker-compose ps

echo ""
echo "==================================="
echo "✅ SecureChain AI is running!"
echo "==================================="
echo ""
echo "📡 API Documentation: http://localhost:8000/docs"
echo "📡 ReDoc: http://localhost:8000/redoc"
echo "🏥 Health Check: http://localhost:8000/health"
echo ""
echo "To view logs:"
echo "  docker-compose logs -f backend"
echo ""
echo "To stop:"
echo "  docker-compose down"
echo ""
