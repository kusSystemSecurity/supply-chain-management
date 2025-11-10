# Database Persistence Guide - SecureChain AI

## Overview

The SecureChain AI platform now uses **PostgreSQL** for persistent storage, replacing the previous in-memory mock database. All scans, vulnerabilities, and AI analyses are now permanently stored.

## Database Schema

### Tables

#### 1. `scans`
Stores scan metadata and status.

```sql
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    scan_type VARCHAR(50) NOT NULL,      -- git_repo, container, vm, sbom, k8s
    target VARCHAR(500) NOT NULL,         -- URL, image name, or path
    status VARCHAR(20) NOT NULL,          -- pending, running, completed, failed
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    result_json JSON,                     -- Full scan results
    error_message VARCHAR(1000),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_started_at ON scans(started_at);
```

#### 2. `vulnerabilities`
Stores discovered vulnerabilities.

```sql
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id VARCHAR(20) NOT NULL,
    package_name VARCHAR(200),
    package_version VARCHAR(100),
    severity VARCHAR(20),                 -- CRITICAL, HIGH, MEDIUM, LOW
    cvss_score FLOAT,
    epss_score FLOAT,
    epss_predicted BOOLEAN DEFAULT FALSE,
    cve_details JSON,                     -- Full CVE information
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
```

#### 3. `ai_analyses`
Stores AI agent analysis results.

```sql
CREATE TABLE ai_analyses (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    agent_type VARCHAR(50) NOT NULL,      -- prioritization, supply_chain, remediation
    input_data JSON,
    output_data JSON,
    tokens_used INTEGER,
    processing_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_ai_analyses_scan_id ON ai_analyses(scan_id);
CREATE INDEX idx_ai_analyses_agent_type ON ai_analyses(agent_type);
```

## Database Setup

### Using Docker Compose (Recommended)

The easiest way to use the database is with Docker Compose:

```bash
# Start all services including PostgreSQL
docker-compose up -d

# Check database status
docker-compose logs postgres

# Connect to PostgreSQL shell
docker-compose exec postgres psql -U securechain -d securechain
```

**Database URL** (automatically configured):
```
postgresql://securechain:securechain_password@postgres:5432/securechain
```

### Manual PostgreSQL Setup

If you prefer to run PostgreSQL manually:

```bash
# 1. Install PostgreSQL
# macOS
brew install postgresql@16
brew services start postgresql@16

# Ubuntu/Debian
sudo apt update
sudo apt install postgresql-16

# 2. Create database and user
sudo -u postgres psql
```

```sql
CREATE DATABASE securechain;
CREATE USER securechain WITH PASSWORD 'securechain_password';
GRANT ALL PRIVILEGES ON DATABASE securechain TO securechain;
\q
```

```bash
# 3. Update .env file
echo "DATABASE_URL=postgresql://securechain:securechain_password@localhost:5432/securechain" >> backend/.env

# 4. Initialize database
cd backend
python -c "from app.database import init_db; init_db()"
```

## Database Migrations with Alembic

### Initial Setup

Alembic is configured and ready to use:

```bash
cd backend

# Create initial migration (already done)
# alembic revision --autogenerate -m "initial schema"

# Apply migrations
alembic upgrade head

# Check current migration version
alembic current

# View migration history
alembic history
```

### Creating New Migrations

When you modify database models:

```bash
# 1. Edit models in app/models/database.py

# 2. Generate migration automatically
alembic revision --autogenerate -m "description of changes"

# 3. Review the generated migration in alembic/versions/

# 4. Apply the migration
alembic upgrade head
```

### Migration Commands

```bash
# Upgrade to latest
alembic upgrade head

# Upgrade one version
alembic upgrade +1

# Downgrade one version
alembic downgrade -1

# Downgrade to base (empty database)
alembic downgrade base

# Show current version
alembic current

# Show history
alembic history --verbose
```

## CRUD Operations

### Using CRUD Functions

The `app/crud.py` module provides database operations:

```python
from app.database import get_db_context
from app import crud

# Create a scan
with get_db_context() as db:
    scan = crud.create_scan(
        db=db,
        scan_type="container",
        target="nginx:latest"
    )
    print(f"Created scan: {scan.id}")

# Get scan details
with get_db_context() as db:
    scan = crud.get_scan(db, scan_id)
    print(f"Status: {scan.status}")

# Get vulnerabilities
with get_db_context() as db:
    vulns = crud.get_vulnerabilities_by_scan(db, scan_id)
    print(f"Found {len(vulns)} vulnerabilities")

# Search vulnerabilities
with get_db_context() as db:
    critical_vulns = crud.search_vulnerabilities(
        db=db,
        severity="CRITICAL",
        min_cvss=9.0
    )
```

### FastAPI Dependency Injection

In API endpoints, use `Depends(get_db)`:

```python
from fastapi import Depends
from sqlalchemy.orm import Session
from app.database import get_db

@router.get("/scans")
async def list_scans(db: Session = Depends(get_db)):
    scans = crud.get_scans(db, limit=10)
    return scans
```

## API Examples with Database

### 1. Create a Scan

```bash
curl -X POST "http://localhost:8000/api/scans/trigger" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "container",
    "target": "nginx:latest",
    "options": {}
  }'
```

Response:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "message": "Scan initiated for nginx:latest"
}
```

**Database Effect**: New row in `scans` table with status `pending`.

### 2. Get Scan Details

```bash
curl "http://localhost:8000/api/scans/550e8400-e29b-41d4-a716-446655440000"
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "scan_type": "container",
  "target": "nginx:latest",
  "status": "completed",
  "started_at": "2025-01-10T12:00:00",
  "completed_at": "2025-01-10T12:05:00",
  "vulnerability_count": 15,
  "critical_count": 2,
  "high_count": 5,
  "medium_count": 6,
  "low_count": 2
}
```

### 3. List All Scans

```bash
# All scans
curl "http://localhost:8000/api/scans"

# Filter by status
curl "http://localhost:8000/api/scans?status=completed&limit=10"

# Filter by type
curl "http://localhost:8000/api/scans?scan_type=container"
```

### 4. Get Vulnerabilities

```bash
curl "http://localhost:8000/api/scans/550e8400-e29b-41d4-a716-446655440000/vulnerabilities"
```

### 5. Delete a Scan

```bash
curl -X DELETE "http://localhost:8000/api/scans/550e8400-e29b-41d4-a716-446655440000"
```

**Database Effect**: Cascade delete removes scan, vulnerabilities, and AI analyses.

## Database Administration

### Backup Database

```bash
# Using Docker Compose
docker-compose exec postgres pg_dump -U securechain securechain > backup.sql

# Manual PostgreSQL
pg_dump -U securechain -d securechain -F c -f backup.dump
```

### Restore Database

```bash
# Using Docker Compose
docker-compose exec -T postgres psql -U securechain securechain < backup.sql

# Manual PostgreSQL
pg_restore -U securechain -d securechain backup.dump
```

### Reset Database

```bash
# Using Python
cd backend
python -c "from app.database import reset_database; reset_database()"

# Or using Alembic
alembic downgrade base
alembic upgrade head
```

### Connect to Database

```bash
# Using Docker Compose
docker-compose exec postgres psql -U securechain -d securechain

# Direct connection
psql postgresql://securechain:securechain_password@localhost:5432/securechain
```

### Useful SQL Queries

```sql
-- Count scans by status
SELECT status, COUNT(*) FROM scans GROUP BY status;

-- Count vulnerabilities by severity
SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity;

-- Recent scans
SELECT id, scan_type, target, status, started_at
FROM scans
ORDER BY started_at DESC
LIMIT 10;

-- Scans with most vulnerabilities
SELECT s.id, s.target, COUNT(v.id) as vuln_count
FROM scans s
LEFT JOIN vulnerabilities v ON s.id = v.scan_id
GROUP BY s.id, s.target
ORDER BY vuln_count DESC;

-- CVEs by frequency
SELECT cve_id, COUNT(*) as occurrence_count
FROM vulnerabilities
GROUP BY cve_id
ORDER BY occurrence_count DESC
LIMIT 20;

-- Average EPSS scores
SELECT
    AVG(epss_score) as avg_epss,
    AVG(CASE WHEN epss_predicted = true THEN epss_score END) as avg_predicted,
    AVG(CASE WHEN epss_predicted = false THEN epss_score END) as avg_actual
FROM vulnerabilities;
```

## Environment Configuration

### Database URL Format

```
postgresql://[user]:[password]@[host]:[port]/[database]
```

Examples:
```bash
# Local PostgreSQL
DATABASE_URL=postgresql://securechain:password@localhost:5432/securechain

# Docker Compose
DATABASE_URL=postgresql://securechain:password@postgres:5432/securechain

# Cloud PostgreSQL (e.g., AWS RDS)
DATABASE_URL=postgresql://user:pass@mydb.abc123.us-east-1.rds.amazonaws.com:5432/securechain

# SQLite (for testing only)
DATABASE_URL=sqlite:///./securechain.db
```

### Connection Pooling

Configure in `app/database.py`:

```python
engine = create_engine(
    settings.database_url,
    pool_size=20,           # Number of permanent connections
    max_overflow=10,        # Additional connections allowed
    pool_pre_ping=True,     # Check connections before use
    echo=False              # Set True to log SQL queries
)
```

## Troubleshooting

### Issue: "relation does not exist"
**Solution**: Run migrations
```bash
cd backend
alembic upgrade head
```

### Issue: "could not connect to server"
**Solution**: Check PostgreSQL is running
```bash
# Docker Compose
docker-compose ps postgres

# Manual
sudo systemctl status postgresql
```

### Issue: "password authentication failed"
**Solution**: Verify credentials in .env
```bash
# Check DATABASE_URL in backend/.env
cat backend/.env | grep DATABASE_URL
```

### Issue: "database locks" or "deadlock detected"
**Solution**: Check for long-running transactions
```sql
-- Show active connections
SELECT * FROM pg_stat_activity WHERE datname = 'securechain';

-- Kill problematic connection
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
WHERE datname = 'securechain' AND pid != pg_backend_pid();
```

### Issue: "too many connections"
**Solution**: Increase max_connections or reduce pool_size
```sql
-- Check current connections
SELECT count(*) FROM pg_stat_activity;

-- Show max connections
SHOW max_connections;
```

## Performance Tips

### 1. Add Indexes
```sql
-- For frequently queried columns
CREATE INDEX idx_vulnerabilities_package ON vulnerabilities(package_name);
CREATE INDEX idx_scans_target ON scans(target);
```

### 2. Use Bulk Operations
```python
# Efficient: Bulk insert
crud.bulk_create_vulnerabilities(db, scan_id, vulnerabilities)

# Inefficient: Individual inserts
for vuln in vulnerabilities:
    crud.create_vulnerability(db, scan_id, **vuln)
```

### 3. Use Eager Loading
```python
from sqlalchemy.orm import joinedload

# Load scan with vulnerabilities in one query
scan = db.query(Scan).options(
    joinedload(Scan.vulnerabilities)
).filter(Scan.id == scan_id).first()
```

### 4. Regular Maintenance
```sql
-- Vacuum database (reclaim space)
VACUUM ANALYZE;

-- Reindex tables
REINDEX TABLE vulnerabilities;
```

## Production Considerations

### Security
- ✅ Use strong passwords
- ✅ Enable SSL/TLS for connections
- ✅ Restrict network access
- ✅ Regular backups
- ✅ Monitor for slow queries

### Scaling
- Use connection pooling
- Add read replicas for read-heavy workloads
- Partition large tables by date
- Archive old scans to separate database

### Monitoring
```sql
-- Slow queries
SELECT query, calls, mean_exec_time, max_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Table sizes
SELECT
    relname as table_name,
    pg_size_pretty(pg_total_relation_size(relid)) as size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
```

## Migration from Mock Database

No data migration needed! The platform now starts fresh with PostgreSQL. All new scans will be stored persistently.

## Summary

✅ **PostgreSQL integration complete**
✅ **Alembic migrations configured**
✅ **CRUD operations implemented**
✅ **API endpoints updated**
✅ **Database automatically initialized on startup**

The database persistence layer is production-ready!
