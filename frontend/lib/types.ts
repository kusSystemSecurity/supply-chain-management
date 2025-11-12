/**
 * Type definitions for the supply chain management frontend
 */

export type ScanType = "git_repo" | "container" | "vm" | "sbom" | "k8s";
export type ScanStatus = "pending" | "running" | "completed" | "failed";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type AgentType = "prioritization" | "supply_chain" | "remediation";

export interface Scan {
  id: string;
  scan_type: ScanType;
  target: string;
  status: ScanStatus;
  started_at: string;
  completed_at: string | null;
  vulnerability_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface Vulnerability {
  id: string;
  cve_id: string;
  package_name: string | null;
  package_version: string | null;
  severity: Severity;
  cvss_score: number | null;
  epss_score: number | null;
  epss_predicted: boolean;
}

export interface ScanRequest {
  scan_type: ScanType;
  target: string;
  options?: Record<string, any>;
}

export interface ScanResponse {
  scan_id: string;
  status: string;
  message?: string;
}

export interface AnalysisRequest {
  scan_id: string;
  agents: AgentType[];
  context?: Record<string, any>;
}

export interface AnalysisResponse {
  analysis_id: string;
  status: string;
  message?: string;
}

export interface AnalysisDetail {
  id: string;
  scan_id: string;
  agent_type: AgentType;
  output_data: Record<string, any>;
  tokens_used?: number;
  processing_time_ms?: number;
}
