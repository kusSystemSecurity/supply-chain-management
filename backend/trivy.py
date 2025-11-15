"""
Trivy scan-related functions
"""

import subprocess
import json
import uuid
from typing import List, Dict

from .cve import fetch_epss_scores


def check_trivy_installed() -> bool:
    """Check if Trivy is installed"""
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "aquasec/trivy", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
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
            timeout=300,  # 5 minutes timeout
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
            cmd, capture_output=True, text=True, timeout=600  # 10 minutes timeout
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

                        vulnerabilities.append(
                            {
                                "id": str(uuid.uuid4()),
                                "scan_id": scan_id,
                                "cve_id": cve_id,
                                "package_name": vuln.get("PkgName", "Unknown"),
                                "package_version": vuln.get(
                                    "InstalledVersion", "Unknown"
                                ),
                                "severity": vuln.get("Severity", "UNKNOWN"),
                                "cvss_score": vuln.get("CVSS", {})
                                .get("nvd", {})
                                .get("V3Score")
                                or vuln.get("CVSS", {}).get("nvd", {}).get("V2Score"),
                                "epss_score": None,
                                "epss_percentile": None,
                                "epss_date": None,
                                "epss_predicted": False,
                                "cve_details": vuln,
                            }
                        )

        elif "Vulnerabilities" in trivy_data:
            # Direct vulnerability list format
            for vuln in trivy_data["Vulnerabilities"]:
                cve_id = vuln.get("VulnerabilityID", "Unknown")
                if cve_id.startswith("CVE-"):
                    cve_ids.append(cve_id)

                vulnerabilities.append(
                    {
                        "id": str(uuid.uuid4()),
                        "scan_id": scan_id,
                        "cve_id": cve_id,
                        "package_name": vuln.get("PkgName", "Unknown"),
                        "package_version": vuln.get("InstalledVersion", "Unknown"),
                        "severity": vuln.get("Severity", "UNKNOWN"),
                        "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score")
                        or vuln.get("CVSS", {}).get("nvd", {}).get("V2Score"),
                        "epss_score": None,
                        "epss_percentile": None,
                        "epss_date": None,
                        "epss_predicted": False,
                        "cve_details": vuln,
                    }
                )

        elif isinstance(trivy_data, list):
            # Some formats return list directly
            for item in trivy_data:
                if "Vulnerabilities" in item:
                    for vuln in item["Vulnerabilities"]:
                        cve_id = vuln.get("VulnerabilityID", "Unknown")
                        if cve_id.startswith("CVE-"):
                            cve_ids.append(cve_id)

                        vulnerabilities.append(
                            {
                                "id": str(uuid.uuid4()),
                                "scan_id": scan_id,
                                "cve_id": cve_id,
                                "package_name": vuln.get("PkgName", "Unknown"),
                                "package_version": vuln.get(
                                    "InstalledVersion", "Unknown"
                                ),
                                "severity": vuln.get("Severity", "UNKNOWN"),
                                "cvss_score": vuln.get("CVSS", {})
                                .get("nvd", {})
                                .get("V3Score")
                                or vuln.get("CVSS", {}).get("nvd", {}).get("V2Score"),
                                "epss_score": None,
                                "epss_percentile": None,
                                "epss_date": None,
                                "epss_predicted": False,
                                "cve_details": vuln,
                            }
                        )

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
                    # Mark as having real EPSS data
                    vuln["epss_predicted"] = True
                    print(
                        f"Updated {cve_id} with EPSS: {epss_data[cve_id]['epss_score']}"
                    )

    except Exception as e:
        print(f"Error parsing Trivy vulnerabilities: {e}")
        # Return empty list on parse error
        pass

    return vulnerabilities

