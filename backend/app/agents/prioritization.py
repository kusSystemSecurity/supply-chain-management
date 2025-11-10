"""Threat Prioritization Agent"""
import anthropic
import json
import logging
import time
from typing import Dict, Optional
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


PRIORITIZATION_PROMPT = """
You are a cybersecurity analyst specializing in vulnerability risk assessment.

Given the following vulnerability data, calculate a priority score (1-10) and provide actionable recommendations.

# Vulnerability Data
CVE ID: {cve_id}
CVSS Score: {cvss_score}
EPSS Score: {epss_score} (top {epss_percentile}%)
Risk Score: {risk_score}

# Vulnerability Characteristics
- Remote Code Execution: {is_code_exec}
- Public Exploit Available: {exploit_exists}
- CISA KEV Listed: {in_cisa_kev}
- Severity: {severity}

# System Context
- Internet-facing: {is_internet_facing}
- Authentication required: {has_auth}
- Data classification: {data_classification}

# Scoring Criteria
- CVSS Score (weight: 30%)
- EPSS Score (weight: 25%)
- Exploit availability (weight: 20%)
- System context (internet-facing, data sensitivity) (weight: 15%)
- CISA KEV status (weight: 10%)

# Output Format (JSON only, no additional text)
{{
  "priorityScore": <1-10>,
  "likelihood": "Low|Medium|High|Critical",
  "businessImpact": "<2 sentences describing potential business impact>",
  "recommendation": "Immediate|Scheduled|Monitor",
  "rationale": "<3 sentences explaining the score>",
  "estimatedRemediationTime": "<estimated hours>"
}}

Provide ONLY the JSON output, no additional text or markdown formatting.
"""


class PrioritizationAgent:
    """AI Agent for threat prioritization"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize prioritization agent

        Args:
            api_key: Anthropic API key
        """
        if api_key:
            self.client = anthropic.Anthropic(api_key=api_key)
        else:
            logger.warning("No Anthropic API key provided, agent will not function")
            self.client = None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def prioritize_vulnerability(
        self,
        cve_data: Dict,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze vulnerability and provide prioritization

        Args:
            cve_data: CVE details from enrichment
            context: System context (internet-facing, auth, data classification)

        Returns:
            Dictionary containing prioritization analysis
        """
        if not self.client:
            return self._mock_prioritization(cve_data)

        start_time = time.time()

        try:
            # Set default context if not provided
            if context is None:
                context = {
                    "is_internet_facing": "Unknown",
                    "has_auth": "Unknown",
                    "data_classification": "Unknown"
                }

            # Format prompt
            prompt = PRIORITIZATION_PROMPT.format(
                cve_id=cve_data.get("cve_id", "Unknown"),
                cvss_score=cve_data.get("cvss_score", 0),
                epss_score=cve_data.get("epss_score", 0),
                epss_percentile=float(cve_data.get("epss_percentile", 0)) * 100,
                risk_score=cve_data.get("risk_score", 0),
                is_code_exec="Yes" if cve_data.get("is_code_execution") else "No",
                exploit_exists="Yes" if cve_data.get("exploit_exists") else "No",
                in_cisa_kev="Yes" if cve_data.get("is_in_cisa_kev") else "No",
                severity=cve_data.get("severity", "Unknown"),
                is_internet_facing=context.get("is_internet_facing", "Unknown"),
                has_auth=context.get("has_auth", "Unknown"),
                data_classification=context.get("data_classification", "Unknown")
            )

            logger.info(f"Analyzing CVE {cve_data.get('cve_id')}")

            # Call Claude API
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}]
            )

            # Extract response
            response_text = message.content[0].text

            # Remove markdown code blocks if present
            response_text = response_text.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()

            # Parse JSON
            result = json.loads(response_text)

            # Calculate metrics
            processing_time = int((time.time() - start_time) * 1000)
            tokens_used = message.usage.input_tokens + message.usage.output_tokens

            result["tokens_used"] = tokens_used
            result["processing_time_ms"] = processing_time

            logger.info(f"Successfully prioritized {cve_data.get('cve_id')}")
            return result

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response: {e}")
            return {
                "error": "Failed to parse AI response",
                "raw_response": response_text,
                "priorityScore": 5,
                "likelihood": "Medium",
                "businessImpact": "Unable to assess - please review manually",
                "recommendation": "Scheduled",
                "rationale": "Automated analysis failed"
            }
        except anthropic.APIError as e:
            logger.error(f"Anthropic API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during prioritization: {e}")
            return {
                "error": str(e),
                "priorityScore": 5,
                "likelihood": "Medium",
                "businessImpact": "Analysis error occurred",
                "recommendation": "Scheduled",
                "rationale": "Error during analysis"
            }

    def _mock_prioritization(self, cve_data: Dict) -> Dict:
        """
        Generate mock prioritization for testing

        Args:
            cve_data: CVE details

        Returns:
            Mock prioritization result
        """
        cvss = cve_data.get("cvss_score", 0)

        if cvss >= 9:
            priority = 9
            likelihood = "Critical"
            recommendation = "Immediate"
        elif cvss >= 7:
            priority = 7
            likelihood = "High"
            recommendation = "Immediate"
        elif cvss >= 4:
            priority = 5
            likelihood = "Medium"
            recommendation = "Scheduled"
        else:
            priority = 3
            likelihood = "Low"
            recommendation = "Monitor"

        return {
            "priorityScore": priority,
            "likelihood": likelihood,
            "businessImpact": f"Mock assessment based on CVSS {cvss}",
            "recommendation": recommendation,
            "rationale": "This is a mock prioritization for testing purposes",
            "estimatedRemediationTime": "2-4 hours",
            "mock": True
        }
