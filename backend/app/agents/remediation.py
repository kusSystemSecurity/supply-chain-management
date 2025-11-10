"""Remediation Advisor Agent"""
import anthropic
import logging
import time
from typing import Dict, Optional
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


REMEDIATION_PROMPT = """
You are a DevOps engineer creating detailed, actionable remediation plans.

Create a comprehensive remediation plan for the following vulnerability:

# Vulnerability Information
CVE: {cve_id}
Package: {package} version {current_version}
Fixed Version: {fixed_version}
Severity: {severity}

# Tech Stack Context
- Language/Framework: {language}
- Package Manager: {package_manager}
- Deployment Type: {deployment_type}

# Required Sections

Provide a detailed, step-by-step remediation plan with these sections:

## Pre-Flight Checklist
- Bullet points of what to verify before patching

## Patch Commands
- Exact, copy-paste ready commands to apply the fix
- Use code blocks with language tags

## Configuration Changes
- Any config file modifications needed
- Show diffs where applicable

## Breaking Changes & Compatibility
- Potential issues when upgrading
- Version incompatibilities to watch for

## Testing Procedure
- Step-by-step testing checklist
- How to verify the patch worked

## Rollback Plan
- Commands to revert if something goes wrong
- Use code blocks

## Alternative Mitigations
- Temporary workarounds if immediate patching is not possible
- Network-level or configuration-based mitigations

Use clear Markdown formatting with code blocks. Be specific and actionable - avoid generic advice.
"""


class RemediationAgent:
    """AI Agent for generating remediation plans"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize remediation agent

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
    async def generate_remediation(
        self,
        vulnerability: Dict,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Generate detailed remediation plan for a vulnerability

        Args:
            vulnerability: Vulnerability details
            context: Tech stack and deployment context

        Returns:
            Dictionary containing remediation plan
        """
        if not self.client:
            return self._mock_remediation(vulnerability)

        start_time = time.time()

        try:
            # Set default context if not provided
            if context is None:
                context = {
                    "language": "Unknown",
                    "package_manager": "Unknown",
                    "deployment_type": "Unknown"
                }

            # Format prompt
            prompt = REMEDIATION_PROMPT.format(
                cve_id=vulnerability.get("cve_id", "Unknown"),
                package=vulnerability.get("package_name", "Unknown"),
                current_version=vulnerability.get("package_version", "Unknown"),
                fixed_version=vulnerability.get("fixed_version", "Latest"),
                severity=vulnerability.get("severity", "Unknown"),
                language=context.get("language", "Unknown"),
                package_manager=context.get("package_manager", "Unknown"),
                deployment_type=context.get("deployment_type", "Unknown")
            )

            logger.info(f"Generating remediation for {vulnerability.get('cve_id')}")

            # Call Claude API
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=3072,
                messages=[{"role": "user", "content": prompt}]
            )

            # Extract response
            remediation_markdown = message.content[0].text

            # Calculate metrics
            processing_time = int((time.time() - start_time) * 1000)
            tokens_used = message.usage.input_tokens + message.usage.output_tokens

            result = {
                "remediation_plan": remediation_markdown,
                "tokens_used": tokens_used,
                "processing_time_ms": processing_time,
                "cve_id": vulnerability.get("cve_id")
            }

            logger.info(f"Successfully generated remediation for {vulnerability.get('cve_id')}")
            return result

        except anthropic.APIError as e:
            logger.error(f"Anthropic API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during remediation generation: {e}")
            return {
                "error": str(e),
                "remediation_plan": "Error occurred during remediation plan generation"
            }

    def _mock_remediation(self, vulnerability: Dict) -> Dict:
        """
        Generate mock remediation plan for testing

        Args:
            vulnerability: Vulnerability details

        Returns:
            Mock remediation result
        """
        cve_id = vulnerability.get("cve_id", "Unknown")
        package = vulnerability.get("package_name", "Unknown")
        current_version = vulnerability.get("package_version", "Unknown")
        fixed_version = vulnerability.get("fixed_version", "Latest")

        remediation = f"""
# Remediation Plan: {cve_id}

## Pre-Flight Checklist
- [ ] Backup current configuration
- [ ] Review change log for {package}
- [ ] Test in staging environment

## Patch Commands

### Update package
```bash
# Update {package} to {fixed_version}
# Command depends on package manager
```

## Configuration Changes
No configuration changes expected (mock data)

## Breaking Changes & Compatibility
Review the package changelog for version {fixed_version}

## Testing Procedure
1. Verify package version after update
2. Run application tests
3. Monitor for errors

## Rollback Plan
```bash
# Revert to previous version if needed
```

## Alternative Mitigations
If immediate patching is not possible:
- Review access controls
- Monitor for suspicious activity
- Consider network-level restrictions

---
**Note**: This is a mock remediation plan. Use the AI agent with a valid API key for detailed, context-specific recommendations.
"""

        return {
            "remediation_plan": remediation,
            "mock": True,
            "cve_id": cve_id
        }
