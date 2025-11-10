"""Trivy scanner integration"""
import subprocess
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class TrivyScanner:
    """Wrapper for Trivy CLI scanner"""

    def __init__(self):
        self._check_trivy_installed()

    def _check_trivy_installed(self) -> bool:
        """Check if Trivy is installed"""
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Trivy version: {result.stdout.strip()}")
                return True
            else:
                logger.warning("Trivy is not installed or not in PATH")
                return False
        except Exception as e:
            logger.error(f"Error checking Trivy installation: {e}")
            return False

    def scan_repository(self, repo_path: str) -> Dict:
        """
        Scan Git repository for vulnerabilities

        Args:
            repo_path: Path to the repository directory

        Returns:
            Dictionary containing scan results
        """
        try:
            cmd = [
                "trivy",
                "fs",
                "--format", "json",
                "--scanners", "vuln",
                "--quiet",
                repo_path
            ]

            logger.info(f"Scanning repository: {repo_path}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout
            )

            if result.returncode != 0:
                logger.error(f"Trivy scan failed: {result.stderr}")
                return {"error": result.stderr, "Results": []}

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timed out")
            return {"error": "Scan timeout", "Results": []}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Trivy output: {e}")
            return {"error": "Invalid JSON output", "Results": []}
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            return {"error": str(e), "Results": []}

    def scan_image(self, image_name: str) -> Dict:
        """
        Scan container image for vulnerabilities

        Args:
            image_name: Container image name (e.g., "nginx:latest")

        Returns:
            Dictionary containing scan results
        """
        try:
            cmd = [
                "trivy",
                "image",
                "--format", "json",
                "--quiet",
                image_name
            ]

            logger.info(f"Scanning container image: {image_name}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode != 0:
                logger.error(f"Trivy image scan failed: {result.stderr}")
                return {"error": result.stderr, "Results": []}

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error("Trivy image scan timed out")
            return {"error": "Scan timeout", "Results": []}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Trivy output: {e}")
            return {"error": "Invalid JSON output", "Results": []}
        except Exception as e:
            logger.error(f"Unexpected error during image scan: {e}")
            return {"error": str(e), "Results": []}

    def scan_k8s_cluster(self) -> Dict:
        """
        Scan Kubernetes cluster for vulnerabilities

        Returns:
            Dictionary containing scan results
        """
        try:
            cmd = [
                "trivy",
                "k8s",
                "--format", "json",
                "--report", "summary",
                "cluster"
            ]

            logger.info("Scanning Kubernetes cluster")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode != 0:
                logger.error(f"Trivy k8s scan failed: {result.stderr}")
                return {"error": result.stderr, "Results": []}

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error("Trivy k8s scan timed out")
            return {"error": "Scan timeout", "Results": []}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Trivy output: {e}")
            return {"error": "Invalid JSON output", "Results": []}
        except Exception as e:
            logger.error(f"Unexpected error during k8s scan: {e}")
            return {"error": str(e), "Results": []}

    def scan_sbom(self, sbom_path: str) -> Dict:
        """
        Analyze SBOM file for vulnerabilities

        Args:
            sbom_path: Path to SBOM file (CycloneDX or SPDX)

        Returns:
            Dictionary containing scan results
        """
        try:
            cmd = [
                "trivy",
                "sbom",
                "--format", "json",
                sbom_path
            ]

            logger.info(f"Analyzing SBOM: {sbom_path}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                logger.error(f"Trivy SBOM scan failed: {result.stderr}")
                return {"error": result.stderr, "Results": []}

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error("Trivy SBOM scan timed out")
            return {"error": "Scan timeout", "Results": []}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Trivy output: {e}")
            return {"error": "Invalid JSON output", "Results": []}
        except Exception as e:
            logger.error(f"Unexpected error during SBOM scan: {e}")
            return {"error": str(e), "Results": []}

    def extract_vulnerabilities(self, scan_result: Dict) -> List[Dict]:
        """
        Extract vulnerability information from Trivy scan results

        Args:
            scan_result: Raw Trivy scan result

        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []

        try:
            results = scan_result.get("Results", [])

            for result in results:
                target = result.get("Target", "")
                vulns = result.get("Vulnerabilities", [])

                for vuln in vulns:
                    vulnerabilities.append({
                        "target": target,
                        "cve_id": vuln.get("VulnerabilityID"),
                        "package_name": vuln.get("PkgName"),
                        "package_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title"),
                        "description": vuln.get("Description"),
                        "references": vuln.get("References", []),
                        "cvss": vuln.get("CVSS", {})
                    })

            logger.info(f"Extracted {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except Exception as e:
            logger.error(f"Error extracting vulnerabilities: {e}")
            return []
