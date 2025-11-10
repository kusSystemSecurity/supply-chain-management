"""CVEDetails API client"""
import requests
import logging
from typing import Dict, List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential
import time

logger = logging.getLogger(__name__)


class CVEDetailsClient:
    """Client for CVEDetails.com API"""

    BASE_URL = "https://www.cvedetails.com/api/v1"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize CVEDetails client

        Args:
            api_key: CVEDetails API key
        """
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch detailed CVE information

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-31449")

        Returns:
            Dictionary containing CVE details or None if not found
        """
        try:
            url = f"{self.BASE_URL}/cve/{cve_id}"
            logger.info(f"Fetching CVE details: {cve_id}")

            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Successfully fetched details for {cve_id}")
                return data
            elif response.status_code == 404:
                logger.warning(f"CVE not found: {cve_id}")
                return None
            elif response.status_code == 429:
                logger.warning(f"Rate limit exceeded for {cve_id}")
                time.sleep(5)
                raise Exception("Rate limit exceeded")
            else:
                logger.error(f"Error fetching {cve_id}: {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            logger.error(f"Timeout fetching {cve_id}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {cve_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching {cve_id}: {e}")
            return None

    def batch_get_cves(self, cve_ids: List[str], delay: float = 1.0) -> Dict[str, Optional[Dict]]:
        """
        Fetch multiple CVEs with rate limiting

        Args:
            cve_ids: List of CVE identifiers
            delay: Delay between requests in seconds

        Returns:
            Dictionary mapping CVE IDs to their details
        """
        results = {}

        for i, cve_id in enumerate(cve_ids):
            logger.info(f"Fetching CVE {i+1}/{len(cve_ids)}: {cve_id}")
            results[cve_id] = self.get_cve_details(cve_id)

            # Rate limiting
            if i < len(cve_ids) - 1:
                time.sleep(delay)

        logger.info(f"Fetched details for {len(results)} CVEs")
        return results

    def enrich_vulnerability(self, vulnerability: Dict) -> Dict:
        """
        Enrich vulnerability data with CVEDetails information

        Args:
            vulnerability: Basic vulnerability info from Trivy

        Returns:
            Enriched vulnerability dictionary
        """
        cve_id = vulnerability.get("cve_id")

        if not cve_id:
            logger.warning("No CVE ID provided for enrichment")
            return vulnerability

        # Fetch CVE details
        cve_details = self.get_cve_details(cve_id)

        if cve_details:
            vulnerability["cve_details"] = cve_details
            vulnerability["cvss_score"] = cve_details.get("maxCvssBaseScore")
            vulnerability["epss_score"] = cve_details.get("epssScore")
            vulnerability["epss_percentile"] = cve_details.get("epssPercentile")
            vulnerability["risk_score"] = cve_details.get("riskScore", {}).get("riskScore")
            vulnerability["is_code_execution"] = cve_details.get("isCodeExecution", 0) == 1
            vulnerability["exploit_exists"] = cve_details.get("exploitExists", 0) == 1
            vulnerability["is_in_cisa_kev"] = cve_details.get("isInCISAKEV", 0) == 1

            logger.info(f"Successfully enriched {cve_id}")

            # If EPSS score is missing, use prediction model
            if vulnerability["epss_score"] is None:
                logger.info(f"EPSS score not available for {cve_id}, using prediction")
                vulnerability = self.enrich_with_epss_prediction(vulnerability)
            else:
                vulnerability["epss_predicted"] = False

        else:
            logger.warning(f"Could not enrich {cve_id}")
            # Use EPSS prediction model
            vulnerability = self.enrich_with_epss_prediction(vulnerability)

        return vulnerability


    def enrich_with_epss_prediction(self, vulnerability: Dict) -> Dict:
        """
        Enrich vulnerability with EPSS prediction when not available from API

        Args:
            vulnerability: Vulnerability dict with basic CVE info

        Returns:
            Enriched vulnerability with predicted EPSS
        """
        try:
            from .epss_predictor import EPSSPredictor

            # Check if EPSS is already available
            if vulnerability.get('epss_score') is not None:
                return vulnerability

            cve_id = vulnerability.get("cve_id")
            logger.info(f"Predicting EPSS for {cve_id}")

            # Initialize predictor
            predictor = EPSSPredictor()

            # Predict EPSS score
            epss_score, metadata = predictor.predict(vulnerability)

            # Add to vulnerability data
            vulnerability["epss_score"] = epss_score
            vulnerability["epss_predicted"] = True
            vulnerability["epss_prediction_method"] = metadata.get("method", "unknown")

            logger.info(f"Predicted EPSS {epss_score:.4f} for {cve_id}")

            return vulnerability

        except Exception as e:
            logger.error(f"Error predicting EPSS: {e}")
            # Set conservative default
            vulnerability["epss_score"] = 0.05
            vulnerability["epss_predicted"] = True
            vulnerability["epss_prediction_method"] = "default"
            return vulnerability


class MockCVEDetailsClient(CVEDetailsClient):
    """Mock client for testing without API key"""

    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Return mock CVE data for testing

        Args:
            cve_id: CVE identifier

        Returns:
            Mock CVE details
        """
        logger.info(f"Using mock data for {cve_id}")

        return {
            "cveId": cve_id,
            "title": f"Mock vulnerability for {cve_id}",
            "summary": "This is mock data for testing purposes",
            "maxCvssBaseScore": 7.5,
            "epssScore": None,  # No EPSS to trigger prediction
            "epssPercentile": None,
            "riskScore": {
                "riskScore": 15,
                "productThreatOverview": 3,
                "vulnCategoryScoreLabel": "High risk vulnerability"
            },
            "isCodeExecution": 0,
            "exploitExists": 0,
            "isInCISAKEV": 0,
            "publishDate": "2024-01-01"
        }
