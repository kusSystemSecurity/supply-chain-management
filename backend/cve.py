"""
CVE-related functions for fetching CVE details and EPSS scores
"""

import os
import json
import requests
import time
from typing import List, Dict
from tqdm import tqdm


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
    
    epss_data = {}
    max_retries = 3
    # EPSS API allows up to 100 CVEs per request
    # Split into batches if needed
    batch_size = 50

    for i in tqdm(
        range(0, len(cve_ids), batch_size),
        desc="Fetching EPSS Scores",
        unit="batch",
    ):
        batch = cve_ids[i : i + batch_size]
        cve_param = ",".join(batch)

        url = "https://api.first.org/data/v1/epss"
        params = {
            "cve": cve_param,
            "pretty": "false",  # We don't need pretty formatting
        }

        for attempt in range(max_retries):
            try:
                response = requests.get(url, params=params, timeout=30)
                
                # 200 OK일 때
                if response.status_code == 200:
                    try:
                        data = response.json() # 여기서 JSON 에러가 날 수 있음
                        if data.get("status") == "OK" and "data" in data:
                            for item in data["data"]:
                                cve_id = item.get("cve")
                                if cve_id:
                                    epss_data[cve_id] = {
                                        "epss_score": float(item.get("epss", 0)),
                                        "epss_percentile": float(item.get("percentile", 0)),
                                        "epss_date": item.get("date"),
                                    }
                        break # 성공하면 재시도 루프 탈출
                    except json.JSONDecodeError:
                        # JSON 변환 실패 (HTML 에러 페이지 등이 왔을 때)
                        print(f"\n[Error] Non-JSON response at batch {i}. Server raw text: {response.text[:100]}...")
                        time.sleep(2) # 잠깐 대기 후 재시도
                        continue 

                elif response.status_code in [429, 502, 503, 504]:
                    # 서버 과부하/차단 -> 대기 후 재시도
                    print(f"\nServer busy ({response.status_code}). Retrying... ({attempt+1}/{max_retries})")
                    time.sleep(5)
                    continue
                
                else:
                    # 404 등 기타 에러 -> 건너뜀
                    print(f"\nFailed batch {i} with status {response.status_code}. Skipping.")
                    break

            except requests.exceptions.RequestException as e:
                print(f"\nNetwork error at batch {i}: {e}. Retrying... ({attempt+1}/{max_retries})")
                time.sleep(5)
        
        # 재시도 루프가 끝난 후에도 데이터를 못 가져왔으면 그냥 다음 배치로 넘어감 (함수 종료 X)

    print(f"Fetch completed. Collected {len(epss_data)} scores.")
    return epss_data # 에러가 났더라도 모인 만큼 반환
