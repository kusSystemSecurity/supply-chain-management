"""
Data models for Supply Chain Security Platform
"""

from enum import Enum


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

