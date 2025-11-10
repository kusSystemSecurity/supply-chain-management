"""Supply Chain Impact Analysis Agent"""
import anthropic
import json
import logging
import time
from typing import Dict, List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


SUPPLY_CHAIN_PROMPT = """
You are a software supply chain security expert.

Analyze the following multi-source scan results to identify supply chain risks.

# Scan Results
{scan_data}

# Analysis Requirements
1. **Overlapping Vulnerabilities**: Identify CVEs that appear across multiple layers (git, container, SBOM, etc.)
2. **Dependency Chains**: Trace how vulnerabilities propagate through the stack
3. **Root Causes**: Identify upstream packages causing multiple downstream issues
4. **Blast Radius**: Determine the scope of impact for each vulnerability
5. **Consolidated Remediation**: Suggest fixes that address multiple layers simultaneously

# Output Format (Markdown)
Provide a detailed analysis with the following sections:

## Critical Findings
- List the top 3 most concerning supply chain risks

## Overlapping Vulnerabilities
- CVEs found in multiple layers with their locations

## Dependency Analysis
- How vulnerabilities propagate through the dependency tree

## Root Causes
- Upstream packages causing cascading issues

## Blast Radius
- Total affected components, services, or containers

## Consolidated Remediation
- Single actions that can fix multiple layers
- Priority order for fixes

## Risk Metrics
- Total unique CVEs
- Overlapping CVEs across layers
- Number of affected components

Use clear, technical language suitable for security engineers.
"""


class SupplyChainAgent:
    """AI Agent for supply chain impact analysis"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize supply chain agent

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
    async def analyze_supply_chain(self, scans: List[Dict]) -> Dict:
        """
        Analyze supply chain impact across multiple scans

        Args:
            scans: List of scan results with vulnerabilities

        Returns:
            Dictionary containing supply chain analysis
        """
        if not self.client:
            return self._mock_supply_chain_analysis(scans)

        start_time = time.time()

        try:
            # Prepare scan data
            scan_summary = []
            for scan in scans:
                scan_summary.append({
                    "source": scan.get("scan_type"),
                    "target": scan.get("target"),
                    "vulnerability_count": len(scan.get("vulnerabilities", [])),
                    "vulnerabilities": [
                        {
                            "cve_id": v.get("cve_id"),
                            "package": v.get("package_name"),
                            "version": v.get("package_version"),
                            "severity": v.get("severity")
                        }
                        for v in scan.get("vulnerabilities", [])[:10]  # Limit to top 10
                    ]
                })

            # Format prompt
            prompt = SUPPLY_CHAIN_PROMPT.format(
                scan_data=json.dumps(scan_summary, indent=2)
            )

            logger.info(f"Analyzing supply chain for {len(scans)} scans")

            # Call Claude API
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=3072,
                messages=[{"role": "user", "content": prompt}]
            )

            # Extract response
            analysis_markdown = message.content[0].text

            # Calculate metrics
            processing_time = int((time.time() - start_time) * 1000)
            tokens_used = message.usage.input_tokens + message.usage.output_tokens

            result = {
                "analysis": analysis_markdown,
                "tokens_used": tokens_used,
                "processing_time_ms": processing_time,
                "scans_analyzed": len(scans)
            }

            logger.info(f"Successfully analyzed supply chain")
            return result

        except anthropic.APIError as e:
            logger.error(f"Anthropic API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during supply chain analysis: {e}")
            return {
                "error": str(e),
                "analysis": "Error occurred during supply chain analysis"
            }

    def _mock_supply_chain_analysis(self, scans: List[Dict]) -> Dict:
        """
        Generate mock supply chain analysis for testing

        Args:
            scans: List of scan results

        Returns:
            Mock analysis result
        """
        total_cves = sum(len(scan.get("vulnerabilities", [])) for scan in scans)

        analysis = f"""
## Critical Findings
- {len(scans)} scan sources analyzed
- {total_cves} total vulnerabilities detected
- This is mock supply chain analysis for testing

## Overlapping Vulnerabilities
Mock data - overlapping analysis requires real AI agent

## Dependency Analysis
Mock data - dependency chain analysis requires real AI agent

## Root Causes
Mock data - root cause analysis requires real AI agent

## Blast Radius
- Scans analyzed: {len(scans)}
- Total vulnerabilities: {total_cves}

## Consolidated Remediation
Mock remediation suggestions - requires real AI agent for accurate recommendations

## Risk Metrics
- Total unique CVEs: {total_cves}
- Scan sources: {len(scans)}
"""

        return {
            "analysis": analysis,
            "mock": True,
            "scans_analyzed": len(scans)
        }
