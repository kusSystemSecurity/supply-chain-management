"""
CVE-related functions for fetching CVE details and EPSS scores
"""

import os
import json
import requests
from typing import List, Dict


def fetch_cve_details(cve_id: str) -> Dict:
    """
    Fetch CVE details from CVEDetails API

    Args:
        cve_id: CVE ID (e.g., "CVE-2025-38664")

    Returns:
        Dictionary with CVE details or error info
    """
    api_key = os.getenv("CVEDETAILS_API_KEY", "")
    if not api_key:
        return {
            "success": False,
            "error": "CVEDetails API key not configured. Set CVEDETAILS_API_KEY in .env file.",
        }

    try:
        url = "https://www.cvedetails.com/api/v1/vulnerability/info"
        params = {
            "cveId": cve_id,
            "returnAffectedCPEs": "true",
            "returnRiskScore": "true",
            "returnAlternativeIds": "true",
        }
        headers = {"Authorization": f"Bearer {api_key}", "accept": "*/*"}

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
            batch = cve_ids[i : i + batch_size]
            cve_param = ",".join(batch)

            url = "https://api.first.org/data/v1/epss"
            params = {
                "cve": cve_param,
                "pretty": "false",  # We don't need pretty formatting
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
                            "epss_date": item.get("date"),
                        }

        return epss_data

    except requests.exceptions.RequestException as e:
        print(f"Error fetching EPSS scores: {e}")
        return {}
    except Exception as e:
        print(f"Unexpected error fetching EPSS scores: {e}")
        return {}

