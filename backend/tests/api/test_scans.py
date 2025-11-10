import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from sqlalchemy.orm import Session
from uuid import UUID, uuid4
from datetime import datetime

from app.api.scans import ScanTypeEnum
from app.models.database import Scan, Vulnerability, ScanStatus


@pytest.fixture(scope="function")
def scans_in_db(db_session: Session):
    """Fixture to create a set of scans for testing list endpoints."""
    scans_data = [
        {"id": uuid4(), "scan_type": "git_repo", "status": "completed", "target": "repo1"},
        {"id": uuid4(), "scan_type": "container", "status": "completed", "target": "image1"},
        {"id": uuid4(), "scan_type": "git_repo", "status": "pending", "target": "repo2"},
        {"id": uuid4(), "scan_type": "sbom", "status": "failed", "target": "sbom1"},
        {"id": uuid4(), "scan_type": "git_repo", "status": "completed", "target": "repo3"},
    ]

    scans = [Scan(started_at=datetime.utcnow(), **d) for d in scans_data]
    db_session.bulk_save_objects(scans)
    db_session.commit()
    return scans


@pytest.fixture(scope="function")
def scan_with_vulnerabilities(db_session: Session):
    """Fixture to create a scan with vulnerabilities."""
    scan_id = uuid4()
    scan = Scan(
        id=scan_id,
        scan_type="container",
        status="completed",
        target="test-image:latest",
        started_at=datetime.utcnow()
    )
    db_session.add(scan)
    db_session.commit()

    vulnerabilities_data = [
        {"scan_id": scan_id, "cve_id": "CVE-2023-0001", "severity": "CRITICAL"},
        {"scan_id": scan_id, "cve_id": "CVE-2023-0002", "severity": "HIGH"},
        {"scan_id": scan_id, "cve_id": "CVE-2023-0003", "severity": "MEDIUM"},
        {"scan_id": scan_id, "cve_id": "CVE-2023-0004", "severity": "HIGH"},
    ]
    vulnerabilities = [Vulnerability(**d) for d in vulnerabilities_data]
    db_session.bulk_save_objects(vulnerabilities)
    db_session.commit()
    return scan, vulnerabilities


def test_trigger_scan_success(client: TestClient, db_session: Session):
    """
    Test successful triggering of a new scan.
    """
    # GIVEN a valid scan request
    scan_request = {
        "scan_type": ScanTypeEnum.GIT_REPO.value,
        "target": "https://github.com/test/repo",
        "options": {"branch": "main"}
    }

    # WHEN the /api/scans/trigger endpoint is called
    response = client.post("/api/scans/trigger", json=scan_request)

    # THEN the response should be successful
    assert response.status_code == 200
    response_data = response.json()
    assert "scan_id" in response_data
    assert response_data["status"] == "pending"
    assert "Scan initiated" in response_data["message"]

    # AND a new scan record should be created in the database
    scan_id = UUID(response_data["scan_id"])
    db_scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
    assert db_scan is not None
    assert db_scan.scan_type == scan_request["scan_type"]
    assert db_scan.target == scan_request["target"]
    assert db_scan.status == "pending"
    assert db_scan.options == scan_request["options"]


@patch("app.crud.create_scan")
def test_trigger_scan_db_error(mock_create_scan, client: TestClient):
    """
    Test error handling when the database fails to create a scan.
    """
    # GIVEN the crud.create_scan function will raise an exception
    mock_create_scan.side_effect = Exception("Database connection failed")
    scan_request = {
        "scan_type": ScanTypeEnum.GIT_REPO.value,
        "target": "https://github.com/test/repo",
    }

    # WHEN the /api/scans/trigger endpoint is called
    response = client.post("/api/scans/trigger", json=scan_request)

    # THEN the response should be a 500 Internal Server Error
    assert response.status_code == 500
    assert "Database connection failed" in response.json()["detail"]


def test_get_scan_success(client: TestClient, db_session: Session):
    """
    Test successful retrieval of scan details.
    """
    # GIVEN a scan with vulnerabilities in the database
    scan_id = uuid4()
    scan = Scan(
        id=scan_id,
        scan_type="git_repo",
        target="https://github.com/test/repo",
        status="completed",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
    )
    db_session.add(scan)
    db_session.commit()

    vulnerabilities = [
        Vulnerability(scan_id=scan_id, cve_id="CVE-2023-1001", severity="CRITICAL"),
        Vulnerability(scan_id=scan_id, cve_id="CVE-2023-1002", severity="HIGH"),
        Vulnerability(scan_id=scan_id, cve_id="CVE-2023-1003", severity="HIGH"),
        Vulnerability(scan_id=scan_id, cve_id="CVE-2023-1004", severity="MEDIUM"),
    ]
    db_session.bulk_save_objects(vulnerabilities)
    db_session.commit()

    # WHEN the /api/scans/{scan_id} endpoint is called
    response = client.get(f"/api/scans/{scan_id}")

    # THEN the response should be successful and contain the correct data
    assert response.status_code == 200
    scan_details = response.json()
    assert scan_details["id"] == str(scan_id)
    assert scan_details["scan_type"] == "git_repo"
    assert scan_details["target"] == "https://github.com/test/repo"
    assert scan_details["status"] == "completed"
    assert scan_details["vulnerability_count"] == 4
    assert scan_details["critical_count"] == 1
    assert scan_details["high_count"] == 2
    assert scan_details["medium_count"] == 1
    assert scan_details["low_count"] == 0


def test_get_scan_not_found(client: TestClient, db_session: Session):
    """
    Test that a 404 is returned for a non-existent scan.
    """
    # GIVEN a random scan ID that does not exist
    non_existent_scan_id = uuid4()

    # WHEN the /api/scans/{scan_id} endpoint is called
    response = client.get(f"/api/scans/{non_existent_scan_id}")

    # THEN the response should be 404 Not Found
    assert response.status_code == 404
    assert "Scan not found" in response.json()["detail"]


def test_get_scan_invalid_uuid(client: TestClient):
    """
    Test that a 400 is returned for an invalid scan ID.
    """
    # GIVEN an invalid scan ID
    invalid_scan_id = "not-a-uuid"

    # WHEN the /api/scans/{scan_id} endpoint is called
    response = client.get(f"/api/scans/{invalid_scan_id}")

    # THEN the response should be 400 Bad Request
    assert response.status_code == 400
    assert "Invalid scan ID format" in response.json()["detail"]


def test_list_scans_no_filters(client: TestClient, scans_in_db):
    """Test listing all scans without any filters."""
    response = client.get("/api/scans/")
    assert response.status_code == 200
    assert len(response.json()) == 5


def test_list_scans_filter_by_status(client: TestClient, scans_in_db):
    """Test filtering scans by status."""
    response = client.get(f"/api/scans/?status={ScanStatus.COMPLETED.value}")
    assert response.status_code == 200
    scans = response.json()
    assert len(scans) == 3
    assert all(s["status"] == ScanStatus.COMPLETED.value for s in scans)


def test_list_scans_filter_by_scan_type(client: TestClient, scans_in_db):
    """Test filtering scans by scan_type."""
    response = client.get(f"/api/scans/?scan_type={ScanTypeEnum.GIT_REPO.value}")
    assert response.status_code == 200
    scans = response.json()
    assert len(scans) == 3
    assert all(s["scan_type"] == ScanTypeEnum.GIT_REPO.value for s in scans)


def test_list_scans_filter_by_status_and_type(client: TestClient, scans_in_db):
    """Test filtering scans by both status and scan_type."""
    response = client.get(f"/api/scans/?status={ScanStatus.COMPLETED.value}&scan_type={ScanTypeEnum.GIT_REPO.value}")
    assert response.status_code == 200
    scans = response.json()
    assert len(scans) == 2
    assert all(s["status"] == ScanStatus.COMPLETED.value and s["scan_type"] == ScanTypeEnum.GIT_REPO.value for s in scans)


def test_list_scans_pagination(client: TestClient, scans_in_db):
    """Test pagination of the scans list."""
    response = client.get("/api/scans/?limit=2&offset=1")
    assert response.status_code == 200
    scans = response.json()
    assert len(scans) == 2
    # Add more specific assertions based on ordering if it's deterministic


def test_get_scan_vulnerabilities_success(client: TestClient, scan_with_vulnerabilities):
    """Test retrieving all vulnerabilities for a scan."""
    scan, _ = scan_with_vulnerabilities
    response = client.get(f"/api/scans/{scan.id}/vulnerabilities")
    assert response.status_code == 200
    assert len(response.json()) == 4


def test_get_scan_vulnerabilities_filter_by_severity(client: TestClient, scan_with_vulnerabilities):
    """Test filtering vulnerabilities by severity."""
    scan, _ = scan_with_vulnerabilities
    response = client.get(f"/api/scans/{scan.id}/vulnerabilities?severity=HIGH")
    assert response.status_code == 200
    vulnerabilities = response.json()
    assert len(vulnerabilities) == 2
    assert all(v["severity"] == "HIGH" for v in vulnerabilities)


def test_get_scan_vulnerabilities_scan_not_found(client: TestClient, db_session: Session):
    """Test 404 for a non-existent scan."""
    non_existent_scan_id = uuid4()
    response = client.get(f"/api/scans/{non_existent_scan_id}/vulnerabilities")
    assert response.status_code == 404
    assert "Scan not found" in response.json()["detail"]


def test_delete_scan_success(client: TestClient, db_session: Session, scans_in_db):
    """Test successful deletion of a scan."""
    # GIVEN a scan to be deleted
    scan_to_delete = scans_in_db[0]
    scan_id = scan_to_delete.id

    # WHEN the /api/scans/{scan_id} endpoint is called
    response = client.delete(f"/api/scans/{scan_id}")

    # THEN the response should be successful
    assert response.status_code == 200
    assert "deleted successfully" in response.json()["message"]

    # AND the scan should be removed from the database
    db_scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
    assert db_scan is None


def test_delete_scan_not_found(client: TestClient, db_session: Session):
    """Test that a 404 is returned for a non-existent scan."""
    # GIVEN a random scan ID that does not exist
    non_existent_scan_id = uuid4()

    # WHEN the /api/scans/{scan_id} endpoint is called
    response = client.delete(f"/api/scans/{non_existent_scan_id}")

    # THEN the response should be 404 Not Found
    assert response.status_code == 404
    assert "Scan not found" in response.json()["detail"]
