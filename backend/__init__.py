"""
Backend modules for Supply Chain Security Platform
"""

from .models import ScanType, ScanStatus
from .storage import (
    scans_storage,
    vulnerabilities_storage,
    projects_storage,
    ai_analyses_storage,
    create_scan,
    get_scan,
    get_all_scans,
    update_scan_status,
    add_vulnerability,
    get_vulnerabilities_by_scan,
    update_vulnerability_with_cve_details,
)
from .cve import fetch_cve_details, fetch_epss_scores
from .trivy import (
    check_trivy_installed,
    install_trivy,
    run_trivy_scan,
    parse_trivy_vulnerabilities,
)
from .projects import (
    create_project,
    get_project,
    get_all_projects,
    assign_scan_to_project,
    get_scans_by_project,
)
from .data_collection import collect_scan_data_for_analysis
from .ai_analysis import (
    initialize_ai_agents,
    initialize_agent_os,
    get_agent_os_app,
    run_ai_analysis,
    serve_agent_os,
    get_ai_analyses_by_project,
)

__all__ = [
    # Models
    "ScanType",
    "ScanStatus",
    # Storage
    "scans_storage",
    "vulnerabilities_storage",
    "projects_storage",
    "ai_analyses_storage",
    "create_scan",
    "get_scan",
    "get_all_scans",
    "update_scan_status",
    "add_vulnerability",
    "get_vulnerabilities_by_scan",
    "update_vulnerability_with_cve_details",
    # CVE
    "fetch_cve_details",
    "fetch_epss_scores",
    # Trivy
    "check_trivy_installed",
    "install_trivy",
    "run_trivy_scan",
    "parse_trivy_vulnerabilities",
    # Projects
    "create_project",
    "get_project",
    "get_all_projects",
    "assign_scan_to_project",
    "get_scans_by_project",
    # Data Collection
    "collect_scan_data_for_analysis",
    # AI Analysis
    "initialize_ai_agents",
    "initialize_agent_os",
    "get_agent_os_app",
    "run_ai_analysis",
    "serve_agent_os",
    "get_ai_analyses_by_project",
]

