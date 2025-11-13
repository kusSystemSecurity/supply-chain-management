"""
Simple Gradio App for Supply Chain Security Scanning
A simplified Python-only interface for the SecureChain AI platform.
"""
import gradio as gr
from datetime import datetime
from typing import List, Dict, Optional
import uuid
from enum import Enum
import subprocess
import json
import logging
import os
import requests
from typing import Tuple


# ============= Data Models =============

class ScanType(str, Enum):
    """Scan type enumeration"""
    GIT_REPO = "git_repo"
    CONTAINER = "container"
    VM = "vm"
    SBOM = "sbom"
    K8S = "k8s"


class ScanStatus(str, Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ============= In-Memory Storage =============

# Simple in-memory storage (replace with database in production)
scans_storage: List[Dict] = []
vulnerabilities_storage: List[Dict] = []


# ============= Helper Functions =============

def fetch_cve_details(cve_id: str) -> Dict:
    """
    Fetch CVE details from CVEDetails API

    Args:
        cve_id: CVE ID (e.g., "CVE-2025-38664")

    Returns:
        Dictionary with CVE details or error info
    """
    # NOTE: In production, store API key securely (environment variable, etc.)
    
    # api_key = os.getenv("CVEDETAILS_API_KEY", "")
    api_key = "240d57348ca2c0538d5268b25e125fa0034d5b86.eyJzdWIiOjE0OTQ0LCJpYXQiOjE3NjE2MzQ4MjgsImV4cCI6MTc2NzEzOTIwMCwia2lkIjoxLCJjIjoiemZvR0pOQUhkS3FqVHA4cjk3YWo3d0lLT282VFB5OHFuenVoQlwvaUV2OTJIMFZNN0pHWGpSeEVCQUw1ZlpzbHJHeXQ0NUNXS3FRPT0ifQ=="
    if not api_key:
        return {
            "success": False,
            "error": "CVEDetails API key not configured. Set CVEDETAILS_API_KEY environment variable."
        }

    try:
        url = "https://www.cvedetails.com/api/v1/vulnerability/info"
        params = {
            "cveId": cve_id,
            "returnAffectedCPEs": "true",
            "returnRiskScore": "true",
            "returnAlternativeIds": "true"
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "accept": "*/*"
        }

        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        return {"success": True, "data": data}

    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"API request failed: {str(e)}"}
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Invalid JSON response: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, Dict]:
    """
    Fetch EPSS scores for multiple CVEs from FIRST.org API

    Args:
        cve_ids: List of CVE IDs

    Returns:
        Dictionary mapping CVE IDs to their EPSS data
    """
    if not cve_ids:
        return {}

    try:
        # EPSS API allows up to 100 CVEs per request
        # Split into batches if needed
        batch_size = 50
        epss_data = {}

        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            cve_param = ",".join(batch)

            url = "https://api.first.org/data/v1/epss"
            params = {
                "cve": cve_param,
                "pretty": "false"  # We don't need pretty formatting
            }

            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()

            if data.get("status") == "OK" and "data" in data:
                for item in data["data"]:
                    cve_id = item.get("cve")
                    if cve_id:
                        epss_data[cve_id] = {
                            "epss_score": float(item.get("epss", 0)),
                            "epss_percentile": float(item.get("percentile", 0)),
                            "epss_date": item.get("date")
                        }

        return epss_data

    except requests.exceptions.RequestException as e:
        print(f"Error fetching EPSS scores: {e}")
        return {}
    except Exception as e:
        print(f"Unexpected error fetching EPSS scores: {e}")
        return {}


def update_vulnerability_with_cve_details(cve_id: str, cve_api_details: dict):
    """
    Update existing vulnerability with CVE API details

    Args:
        cve_id: CVE ID to update
        cve_api_details: Raw CVE API response data
    """
    for vuln in vulnerabilities_storage:
        if vuln.get("cve_id") == cve_id:
            vuln["cve_api_details"] = cve_api_details
            print(f"Updated vulnerability {cve_id} with API details")
            break




def check_trivy_installed() -> bool:
    """Check if Trivy is installed"""
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "aquasec/trivy", "--version"],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode == 0
    except Exception:
        return False


def install_trivy() -> bool:
    """Install Trivy via Docker (pull the image)"""
    try:
        print("Installing Trivy via Docker...")
        result = subprocess.run(
            ["docker", "pull", "aquasec/trivy"],
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Error installing Trivy: {e}")
        return False


def run_trivy_scan(scan_type: str, target: str) -> Dict:
    """
    Run actual Trivy scan and return results

    Args:
        scan_type: Type of scan (container, git_repo, etc.)
        target: Target to scan

    Returns:
        Dictionary with scan results
    """
    try:
        cmd = ["docker", "run", "--rm", "aquasec/trivy"]

        # Configure scan based on type
        if scan_type == "container":
            cmd.extend(["image", "--format", "json", target])
        elif scan_type == "git_repo":
            cmd.extend(["repo", "--format", "json", target])
        elif scan_type == "vm":
            cmd.extend(["vm", "--format", "json", target])
        elif scan_type == "sbom":
            cmd.extend(["sbom", "--format", "json", target])
        elif scan_type == "k8s":
            cmd.extend(["k8s", "--format", "json", target])
        else:
            raise ValueError(f"Unsupported scan type: {scan_type}")

        print(f"Running Trivy command: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes timeout
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            raise Exception(f"Trivy scan failed: {error_msg}")

        # Parse JSON output
        try:
            trivy_output = json.loads(result.stdout)
            return {"success": True, "data": trivy_output}
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Failed to parse Trivy output: {e}"}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Scan timed out after 10 minutes"}
    except Exception as e:
        return {"success": False, "error": f"Scan failed: {str(e)}"}


def parse_trivy_vulnerabilities(trivy_data: Dict, scan_id: str) -> List[Dict]:
    """
    Parse Trivy vulnerability data and return standardized format with EPSS scores

    Args:
        trivy_data: Raw Trivy JSON output
        scan_id: Scan ID to associate vulnerabilities with

    Returns:
        List of vulnerability dictionaries with EPSS data
    """
    vulnerabilities = []
    cve_ids = []

    try:
        # First pass: collect all CVE IDs and create vulnerability objects
        if "Results" in trivy_data:
            # Container/image scan format
            for result in trivy_data.get("Results", []):
                if "Vulnerabilities" in result:
                    for vuln in result["Vulnerabilities"]:
                        cve_id = vuln.get("VulnerabilityID", "Unknown")
                        if cve_id.startswith("CVE-"):
                            cve_ids.append(cve_id)

                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "scan_id": scan_id,
                            "cve_id": cve_id,
                            "package_name": vuln.get("PkgName", "Unknown"),
                            "package_version": vuln.get("InstalledVersion", "Unknown"),
                            "severity": vuln.get("Severity", "UNKNOWN"),
                            "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score") or
                                         vuln.get("CVSS", {}).get("nvd", {}).get("V2Score"),
                            "epss_score": None,
                            "epss_percentile": None,
                            "epss_date": None,
                            "epss_predicted": False,
                            "cve_details": vuln
                        })

        elif "Vulnerabilities" in trivy_data:
            # Direct vulnerability list format
            for vuln in trivy_data["Vulnerabilities"]:
                cve_id = vuln.get("VulnerabilityID", "Unknown")
                if cve_id.startswith("CVE-"):
                    cve_ids.append(cve_id)

                vulnerabilities.append({
                    "id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "cve_id": cve_id,
                    "package_name": vuln.get("PkgName", "Unknown"),
                    "package_version": vuln.get("InstalledVersion", "Unknown"),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score") or
                                 vuln.get("CVSS", {}).get("nvd", {}).get("V2Score"),
                    "epss_score": None,
                    "epss_percentile": None,
                    "epss_date": None,
                    "epss_predicted": False,
                    "cve_details": vuln
                })

        elif isinstance(trivy_data, list):
            # Some formats return list directly
            for item in trivy_data:
                if "Vulnerabilities" in item:
                    for vuln in item["Vulnerabilities"]:
                        cve_id = vuln.get("VulnerabilityID", "Unknown")
                        if cve_id.startswith("CVE-"):
                            cve_ids.append(cve_id)

                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "scan_id": scan_id,
                            "cve_id": cve_id,
                            "package_name": vuln.get("PkgName", "Unknown"),
                            "package_version": vuln.get("InstalledVersion", "Unknown"),
                            "severity": vuln.get("Severity", "UNKNOWN"),
                            "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score") or
                                         vuln.get("CVSS", {}).get("nvd", {}).get("V2Score"),
                            "epss_score": None,
                            "epss_percentile": None,
                            "epss_date": None,
                            "epss_predicted": False,
                            "cve_details": vuln
                        })

        # Fetch EPSS scores for all collected CVE IDs
        if cve_ids:
            print(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
            epss_data = fetch_epss_scores(cve_ids)

            # Update vulnerabilities with EPSS data
            for vuln in vulnerabilities:
                cve_id = vuln.get("cve_id")
                if cve_id in epss_data:
                    vuln["epss_score"] = epss_data[cve_id]["epss_score"]
                    vuln["epss_percentile"] = epss_data[cve_id]["epss_percentile"]
                    vuln["epss_date"] = epss_data[cve_id]["epss_date"]
                    vuln["epss_predicted"] = True  # Mark as having real EPSS data
                    print(f"Updated {cve_id} with EPSS: {epss_data[cve_id]['epss_score']}")

    except Exception as e:
        print(f"Error parsing Trivy vulnerabilities: {e}")
        # Return empty list on parse error
        pass

    return vulnerabilities


def create_scan(scan_type: str, target: str) -> Dict:
    """Create a new scan"""
    scan_id = str(uuid.uuid4())
    scan = {
        "id": scan_id,
        "scan_type": scan_type,
        "target": target,
        "status": ScanStatus.PENDING.value,
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "vulnerability_count": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "result_json": None,  # Store original Trivy JSON output
    }
    scans_storage.append(scan)
    return scan


def get_scan(scan_id: str) -> Optional[Dict]:
    """Get scan by ID"""
    for scan in scans_storage:
        if scan["id"] == scan_id:
            return scan
    return None


def get_all_scans() -> List[Dict]:
    """Get all scans"""
    return scans_storage.copy()


def update_scan_status(scan_id: str, status: str, vulnerability_count: int = 0, result_json: dict = None):
    """Update scan status"""
    scan = get_scan(scan_id)
    if scan:
        scan["status"] = status
        if status == ScanStatus.COMPLETED.value:
            scan["completed_at"] = datetime.now().isoformat()
            scan["vulnerability_count"] = vulnerability_count
        if result_json is not None:
            scan["result_json"] = result_json


def add_vulnerability(scan_id: str, cve_id: str, package_name: str = None,
                     package_version: str = None, severity: str = None,
                     cvss_score: float = None, epss_score: float = None,
                     cve_api_details: dict = None):
    """Add vulnerability to storage"""
    vuln = {
        "id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "cve_id": cve_id,
        "package_name": package_name,
        "package_version": package_version,
        "severity": severity or "UNKNOWN",
        "cvss_score": cvss_score,
        "epss_score": epss_score,
        "epss_predicted": False,
        "cve_api_details": cve_api_details,  # Store raw CVEDetails API response
    }
    vulnerabilities_storage.append(vuln)
    return vuln


def get_vulnerabilities_by_scan(scan_id: str) -> List[Dict]:
    """Get all vulnerabilities for a scan"""
    return [v for v in vulnerabilities_storage if v["scan_id"] == scan_id]


# ============= Gradio Interface Functions =============

def trigger_scan(scan_type: str, target: str) -> str:
    """
    Trigger a new scan using actual Trivy

    Returns:
        status_message
    """
    if not scan_type:
        return "❌ Error: Please select a scan type."

    if not target or not target.strip():
        return "❌ Error: Please provide a target (repository URL, container image, file path, etc.)"

    try:
        # Validate scan type
        valid_types = ["git_repo", "container", "vm", "sbom", "k8s"]
        if scan_type not in valid_types:
            return f"❌ Error: Invalid scan type '{scan_type}'. Must be one of: {', '.join(valid_types)}"

        # Check if Trivy is available
        print("Checking Trivy installation...")
        if not check_trivy_installed():
            print("Trivy not found, installing...")
            if not install_trivy():
                return "❌ Error: Failed to install Trivy. Please ensure Docker is running and you have internet access."

        # Create scan record
        scan = create_scan(scan_type, target.strip())

        try:
            # Update scan status to running
            update_scan_status(scan["id"], ScanStatus.RUNNING.value)

            # Run actual Trivy scan
            print(f"Starting Trivy scan for {scan_type}: {target}")
            scan_result = run_trivy_scan(scan_type, target.strip())

            if not scan_result["success"]:
                update_scan_status(scan["id"], ScanStatus.FAILED.value)
                return f"❌ Scan failed: {scan_result['error']}\n\nScan ID: {scan['id']}\nStatus: Failed"

            # Parse vulnerabilities from Trivy output
            trivy_data = scan_result["data"]
            vulnerabilities = parse_trivy_vulnerabilities(trivy_data, scan["id"])

            # Store vulnerabilities
            for vuln in vulnerabilities:
                vulnerabilities_storage.append(vuln)

            # Update severity counts
            scan["critical_count"] = sum(1 for v in vulnerabilities if v["severity"] == "CRITICAL")
            scan["high_count"] = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
            scan["medium_count"] = sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM")
            scan["low_count"] = sum(1 for v in vulnerabilities if v["severity"] == "LOW")
            scan["vulnerability_count"] = len(vulnerabilities)

            # Mark scan as completed and store original Trivy JSON
            update_scan_status(scan["id"], ScanStatus.COMPLETED.value, scan["vulnerability_count"], trivy_data)

            # Build success message
            message = f"✅ Scan completed successfully!\n\n"
            message += f"Scan ID: {scan['id']}\n"
            message += f"Type: {scan['scan_type']}\n"
            message += f"Target: {scan['target']}\n"
            message += f"Status: {scan['status']}\n"
            message += f"Vulnerabilities found: {scan['vulnerability_count']}\n"
            message += f"  - Critical: {scan['critical_count']}\n"
            message += f"  - High: {scan['high_count']}\n"
            message += f"  - Medium: {scan['medium_count']}\n"
            message += f"  - Low: {scan['low_count']}"

            if scan["vulnerability_count"] == 0:
                message += "\n\nℹ️ No vulnerabilities found in this scan."

            print(f"Scan completed successfully: {scan['id']}")
            return message

        except Exception as e:
            # Mark scan as failed
            update_scan_status(scan["id"], ScanStatus.FAILED.value)
            print(f"Error during scan processing: {e}")
            return f"❌ Error during scan processing: {str(e)}\n\nScan ID: {scan['id']}\nStatus: Failed"

    except Exception as e:
        print(f"Error creating scan: {e}")
        return f"❌ Error creating scan: {str(e)}\n\nPlease check your inputs and try again."


def refresh_scan_list() -> List[List]:
    """
    Refresh and return scan list as table data
    
    Returns:
        List of lists for Gradio Dataframe
    """
    try:
        scans = get_all_scans()
        if not scans:
            return [["No scans yet", "", "", "", "", ""]]
        
        # Sort by started_at (newest first)
        try:
            scans_sorted = sorted(scans, key=lambda x: x.get("started_at", ""), reverse=True)
        except Exception:
            scans_sorted = scans
        
        table_data = []
        for scan in scans_sorted:
            try:
                scan_id = scan.get("id", "Unknown")
                scan_type = scan.get("scan_type", "Unknown")
                target = scan.get("target", "Unknown")
                status = scan.get("status", "Unknown")
                vuln_count = scan.get("vulnerability_count", 0)
                started_at = scan.get("started_at", "")
                
                # Format display values safely
                short_id = (scan_id[:8] + "...") if len(scan_id) > 8 else scan_id
                truncated_target = (target[:50] + "...") if len(target) > 50 else target
                formatted_time = started_at[:19] if started_at and len(started_at) >= 19 else (started_at or "N/A")
                
                table_data.append([
                    short_id,
                    scan_type,
                    truncated_target,
                    status,
                    str(vuln_count),
                    formatted_time
                ])
            except Exception as e:
                # Skip malformed scans
                continue
        
        if not table_data:
            return [["No valid scans found", "", "", "", "", ""]]
        
        return table_data
        
    except Exception as e:
        return [[f"Error loading scans: {str(e)}", "", "", "", "", ""]]


def get_scan_vulnerabilities(scan_id: str) -> tuple:
    """
    Get vulnerabilities for a selected scan

    Returns:
        (vulnerability_table_data, info_message)
    """
    if not scan_id or not scan_id.strip():
        return [], "⚠️ Please select a scan from the dropdown above."

    try:
        # Find full scan ID if short ID was provided
        full_scan_id = None
        for scan in scans_storage:
            scan_id_str = scan.get("id", "")
            if scan_id_str == scan_id or scan_id_str.startswith(scan_id):
                full_scan_id = scan_id_str
                break

        if not full_scan_id:
            return [], f"❌ Scan not found: {scan_id}\n\nPlease make sure the scan exists and try refreshing the dropdown."

        vulnerabilities = get_vulnerabilities_by_scan(full_scan_id)

        if not vulnerabilities:
            scan = get_scan(full_scan_id)
            if scan:
                status = scan.get("status", "Unknown")
                result_json = scan.get("result_json")
                has_raw_data = "Yes" if result_json else "No"
                return [], f"ℹ️ No vulnerabilities found for scan {scan_id[:8]}...\nStatus: {status}\nRaw JSON available: {has_raw_data}\n\nThis scan may still be in progress or completed with no vulnerabilities."
            return [], f"❌ Scan not found: {scan_id}"

        # Format for table display
        table_data = []
        for vuln in vulnerabilities:
            try:
                cve_id = vuln.get("cve_id", "Unknown")
                pkg_name = vuln.get("package_name") or "N/A"
                pkg_version = vuln.get("package_version") or "N/A"
                severity = vuln.get("severity", "UNKNOWN")

                # Format scores safely
                cvss = vuln.get("cvss_score")
                cvss_str = f"{cvss:.2f}" if cvss is not None else "N/A"

                epss = vuln.get("epss_score")
                epss_str = f"{epss:.3f}" if epss is not None else "N/A"

                epss_percentile = vuln.get("epss_percentile")
                epss_percentile_str = f"{epss_percentile:.3f}" if epss_percentile is not None else "N/A"

                epss_date = vuln.get("epss_date") or "N/A"

                table_data.append([
                    cve_id,
                    pkg_name,
                    pkg_version,
                    severity,
                    cvss_str,
                    epss_str,
                    epss_percentile_str,
                    epss_date
                ])
            except Exception as e:
                # Skip malformed vulnerabilities
                continue

        if not table_data:
            return [], f"⚠️ Error formatting vulnerabilities for scan {scan_id[:8]}..."

        scan = get_scan(full_scan_id)
        info = f"✅ Found {len(vulnerabilities)} vulnerability/vulnerabilities"

        # Check if any vulnerabilities have CVE API details
        cve_details_count = sum(1 for v in vulnerabilities if v.get("cve_api_details"))

        if scan:
            target = scan.get("target", "Unknown")
            scan_type = scan.get("scan_type", "Unknown")
            result_json = scan.get("result_json")
            has_raw_data = "Yes" if result_json else "No"
            info += f"\n\nScan Details:\n- Target: {target}\n- Type: {scan_type}\n- Raw JSON available: {has_raw_data}\n- CVE API details: {cve_details_count} CVEs"

        return table_data, info

    except Exception as e:
        return [], f"❌ Error retrieving vulnerabilities: {str(e)}\n\nPlease try again or select a different scan."


def get_scan_dropdown_options() -> List[str]:
    """Get list of scan IDs for dropdown"""
    try:
        scans = get_all_scans()
        if not scans:
            return []

        # Sort by started_at (newest first), handle missing dates
        try:
            sorted_scans = sorted(scans, key=lambda x: x.get("started_at", ""), reverse=True)
        except Exception:
            sorted_scans = scans

        return [scan.get("id", "") for scan in sorted_scans if scan.get("id")]
    except Exception:
        return []


def get_raw_json_dropdown_options() -> List[str]:
    """Get list of scan IDs and CVE IDs with API details for raw JSON dropdown"""
    try:
        options = []

        # Add scan IDs
        scans = get_all_scans()
        if scans:
            try:
                sorted_scans = sorted(scans, key=lambda x: x.get("started_at", ""), reverse=True)
            except Exception:
                sorted_scans = scans

            for scan in sorted_scans:
                scan_id = scan.get("id")
                if scan_id:
                    options.append(f"Scan: {scan_id[:8]}...")

        # Add CVE IDs that have API details
        cve_ids = []
        for vuln in vulnerabilities_storage:
            cve_id = vuln.get("cve_id")
            if cve_id and vuln.get("cve_api_details") and cve_id not in cve_ids:
                cve_ids.append(cve_id)

        if cve_ids:
            options.append("--- CVE IDs ---")
            options.extend(cve_ids)

        return options if options else []
    except Exception:
        return []


def get_scan_raw_json(selected_option: str) -> str:
    """
    Get the raw Trivy JSON output for a scan or CVE API details

    Returns:
        JSON string or error message
    """
    if not selected_option or not selected_option.strip():
        return "⚠️ Please select an option from the dropdown above."

    try:
        # Check if it's a CVE ID
        if selected_option.upper().startswith("CVE"):
            # Look for CVE API details in vulnerabilities
            cve_id = selected_option.strip().upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"

            for vuln in vulnerabilities_storage:
                if vuln.get("cve_id") == cve_id and vuln.get("cve_api_details"):
                    # Pretty-print the CVE API JSON
                    try:
                        import json
                        formatted_json = json.dumps(vuln["cve_api_details"], indent=2, ensure_ascii=False)
                        return f"🔍 Raw CVE API JSON for {cve_id}...\n\n{formatted_json}"
                    except Exception:
                        return f"🔍 Raw CVE API JSON for {cve_id}...\n\n{vuln['cve_api_details']}"

            return f"ℹ️ No CVE API details available for {cve_id}.\n\nTry fetching CVE details first using the 'Get CVE Details' button in the Vulnerabilities tab."

        # Check if it's a scan option (starts with "Scan: ")
        elif selected_option.startswith("Scan: "):
            # Extract scan ID from "Scan: abc123..."
            scan_display = selected_option[6:]  # Remove "Scan: " prefix
            scan_id = scan_display.replace("...", "")  # Remove "..." if present

            # Find full scan ID
            full_scan_id = None
            for scan in scans_storage:
                scan_id_str = scan.get("id", "")
                if scan_id_str.startswith(scan_id):
                    full_scan_id = scan_id_str
                    break

            if not full_scan_id:
                return f"❌ Scan not found: {scan_id}"

            scan = get_scan(full_scan_id)
            if not scan:
                return f"❌ Scan not found: {scan_id}"

            result_json = scan.get("result_json")
            if not result_json:
                status = scan.get("status", "Unknown")
                return f"ℹ️ No raw JSON data available for scan {scan_id}...\n\nStatus: {status}\n\nRaw JSON data is only available for completed scans."

            # Pretty-print the JSON
            try:
                import json
                formatted_json = json.dumps(result_json, indent=2, ensure_ascii=False)
                return f"✅ Raw Trivy JSON for scan {scan_id}...\n\n{formatted_json}"
            except Exception:
                return f"✅ Raw Trivy JSON for scan {scan_id}...\n\n{result_json}"

        else:
            return f"❌ Invalid selection: {selected_option}"

    except Exception as e:
        return f"❌ Error retrieving raw JSON: {str(e)}"


# ============= Gradio UI Components =============

def create_scan_tab():
    """Create the scan creation tab"""
    with gr.Column():
        gr.Markdown("## Create New Scan")
        gr.Markdown("Select a scan type and provide the target to scan for vulnerabilities.")
        
        scan_type = gr.Dropdown(
            choices=["git_repo", "container", "vm", "sbom", "k8s"],
            label="Scan Type",
            value="container",
            info="Select the type of target to scan"
        )
        
        target_input = gr.Textbox(
            label="Target",
            placeholder="e.g., nginx:latest, https://github.com/user/repo, /path/to/sbom.json",
            info="Repository URL, container image name, file path, or Kubernetes cluster"
        )
        
        submit_btn = gr.Button("Start Scan", variant="primary")
        
        status_output = gr.Textbox(
            label="Status",
            lines=10,
            interactive=False,
            placeholder="Scan results will appear here..."
        )
        
        submit_btn.click(
            fn=trigger_scan,
            inputs=[scan_type, target_input],
            outputs=status_output
        )


def create_scan_list_tab():
    """Create the scan list tab"""
    with gr.Column():
        gr.Markdown("## All Scans")
        gr.Markdown("View all security scans that have been performed.")
        
        refresh_btn = gr.Button("Refresh List", variant="secondary")
        
        scan_table = gr.Dataframe(
            headers=["Scan ID", "Type", "Target", "Status", "Vulns", "Started At"],
            label="Scans",
            interactive=False,
            wrap=True,
            value=refresh_scan_list()  # Initial load
        )
        
        refresh_btn.click(
            fn=refresh_scan_list,
            outputs=scan_table
        )


def create_vulnerability_tab():
    """Create the vulnerability viewing tab"""
    with gr.Column():
        gr.Markdown("## View Vulnerabilities")
        gr.Markdown("Select a scan to view its discovered vulnerabilities. Click on CVE IDs to see detailed information.")

        scan_dropdown = gr.Dropdown(
            choices=get_scan_dropdown_options(),
            label="Select Scan",
            info="Choose a scan to view its vulnerabilities"
        )

        refresh_dropdown_btn = gr.Button("Refresh Scan List", variant="secondary", size="sm")

        view_btn = gr.Button("View Vulnerabilities", variant="primary")

        info_output = gr.Textbox(
            label="Scan Information",
            lines=3,
            interactive=False
        )

        vuln_table = gr.Dataframe(
            headers=["CVE ID", "Package", "Version", "Severity", "CVSS Score", "EPSS Score", "EPSS Percentile", "EPSS Date"],
            label="Vulnerabilities",
            interactive=False,
            wrap=True
        )

        # CVE Details Section
        with gr.Row():
            cve_input = gr.Textbox(
                label="CVE ID for Details",
                placeholder="e.g., CVE-2025-38664",
                info="Enter CVE ID to fetch detailed information"
            )
            fetch_cve_btn = gr.Button("Get CVE Details", variant="secondary")

        cve_details_output = gr.Textbox(
            label="CVE Details",
            lines=15,
            interactive=False,
            placeholder="CVE details will appear here..."
        )

        def update_dropdown():
            """Update dropdown choices"""
            try:
                choices = get_scan_dropdown_options()
                return gr.Dropdown(choices=choices, value=choices[0] if choices else None)
            except Exception:
                return gr.Dropdown(choices=[])

        def view_vulns(scan_id):
            """View vulnerabilities and update dropdown"""
            try:
                table_data, info = get_scan_vulnerabilities(scan_id)
                choices = get_scan_dropdown_options()
                return table_data, info, gr.Dropdown(choices=choices, value=scan_id if scan_id in choices else (choices[0] if choices else None))
            except Exception as e:
                return [], f"❌ Error: {str(e)}", gr.Dropdown(choices=get_scan_dropdown_options())

        def fetch_cve_info(cve_id: str):
            """Fetch CVE details and store raw data"""
            if not cve_id or not cve_id.strip():
                return "⚠️ Please enter a valid CVE ID (e.g., CVE-2025-38664)"

            try:
                # Clean up CVE ID
                cve_id = cve_id.strip().upper()
                if not cve_id.startswith("CVE-"):
                    cve_id = f"CVE-{cve_id}"

                result = fetch_cve_details(cve_id)

                if result["success"]:
                    # Store raw CVE API data in vulnerabilities
                    update_vulnerability_with_cve_details(cve_id, result["data"])

                    # Return success message
                    return f"✅ CVE details fetched and stored successfully for {cve_id}.\n\nRaw JSON data is now available in the 'Raw JSON' tab."
                else:
                    return f"❌ Failed to fetch CVE details:\n\n{result['error']}\n\n💡 Make sure CVEDETAILS_API_KEY environment variable is set with your API key."

            except Exception as e:
                return f"❌ Error fetching CVE details: {str(e)}"

        refresh_dropdown_btn.click(
            fn=update_dropdown,
            outputs=scan_dropdown
        )

        view_btn.click(
            fn=view_vulns,
            inputs=scan_dropdown,
            outputs=[vuln_table, info_output, scan_dropdown]
        )

        fetch_cve_btn.click(
            fn=fetch_cve_info,
            inputs=cve_input,
            outputs=cve_details_output
        )


def create_raw_json_tab():
    """Create the raw JSON tab"""
    with gr.Column():
        gr.Markdown("## Raw Trivy JSON")
        gr.Markdown("View the original JSON output from Trivy scans. This contains the complete scan results including all metadata.")

        raw_json_dropdown = gr.Dropdown(
            choices=get_raw_json_dropdown_options(),
            label="Select Scan or CVE",
            info="Choose a scan to view Trivy JSON or CVE ID to view API details"
        )

        refresh_raw_dropdown_btn = gr.Button("Refresh Scan List", variant="secondary", size="sm")

        view_raw_btn = gr.Button("View Raw JSON", variant="primary")

        raw_json_output = gr.Textbox(
            label="Raw Trivy JSON",
            lines=20,
            interactive=False,
            placeholder="Raw JSON output will appear here..."
        )

        copy_json_btn = gr.Button("Copy JSON to Clipboard", variant="secondary", visible=False)

        def update_raw_dropdown():
            """Update dropdown choices"""
            try:
                choices = get_raw_json_dropdown_options()
                return gr.Dropdown(choices=choices, value=choices[0] if choices else None)
            except Exception:
                return gr.Dropdown(choices=[])

        def view_raw_json(scan_id):
            """View raw JSON for selected scan"""
            try:
                json_content = get_scan_raw_json(scan_id)
                choices = get_scan_dropdown_options()
                # Show copy button if we have valid JSON
                show_copy = "✅ Raw Trivy JSON" in json_content
                return json_content, gr.Dropdown(choices=choices, value=scan_id if scan_id in choices else (choices[0] if choices else None)), gr.Button(visible=show_copy)
            except Exception as e:
                return f"❌ Error: {str(e)}", gr.Dropdown(choices=get_scan_dropdown_options()), gr.Button(visible=False)

        def copy_json_to_clipboard(scan_id):
            """Return JSON content for copying (Gradio will handle clipboard)"""
            try:
                json_content = get_scan_raw_json(scan_id)
                if "✅ Raw Trivy JSON" in json_content:
                    # Extract just the JSON part
                    json_start = json_content.find("\n\n")
                    if json_start != -1:
                        json_data = json_content[json_start + 2:]
                        return json_data
                return "No JSON data available"
            except Exception:
                return "Error retrieving JSON data"

        refresh_raw_dropdown_btn.click(
            fn=update_raw_dropdown,
            outputs=raw_json_dropdown
        )

        view_raw_btn.click(
            fn=view_raw_json,
            inputs=raw_json_dropdown,
            outputs=[raw_json_output, raw_json_dropdown, copy_json_btn]
        )

        copy_json_btn.click(
            fn=copy_json_to_clipboard,
            inputs=raw_json_dropdown,
            outputs=None  # Gradio handles clipboard copy
        )

        # Dropdown is initialized with choices above, no need for load event


def create_ai_analysis_tab():
    """Create the AI analysis tab (stub)"""
    with gr.Column():
        gr.Markdown("## AI Analysis")
        gr.Markdown("### AI Agent Functionality")
        gr.Markdown(
            """
            **Coming Soon**

            This section will provide AI-powered analysis capabilities:

            - **Prioritization Agent**: Risk-based vulnerability scoring and prioritization
            - **Supply Chain Agent**: Cross-scan vulnerability correlation and dependency analysis
            - **Remediation Agent**: Step-by-step remediation plans and upgrade guidance

            The AI agent functionality is currently under development and will be available in a future update.
            """
        )


# ============= Main App =============

def create_app():
    """Create and launch the Gradio app"""
    with gr.Blocks(title="SecureChain AI - Supply Chain Security", theme=gr.themes.Soft()) as app:
        gr.Markdown(
            """
            # 🔒 SecureChain AI - Supply Chain Security Platform
            
            AI-powered software supply chain security analysis platform with comprehensive vulnerability scanning.
            """
        )
        
        with gr.Tabs():
            with gr.Tab("Create Scan"):
                create_scan_tab()

            with gr.Tab("Scan List"):
                create_scan_list_tab()

            with gr.Tab("Vulnerabilities"):
                create_vulnerability_tab()

            with gr.Tab("Raw JSON"):
                create_raw_json_tab()

            with gr.Tab("AI Analysis"):
                create_ai_analysis_tab()
        
        gr.Markdown(
            """
            ---
            **Note**: This is a simplified Gradio interface. For production use, connect to the full FastAPI backend.
            """
        )
    
    return app


if __name__ == "__main__":
    app = create_app()
    app.launch(server_name="0.0.0.0", server_port=7860, share=False)

