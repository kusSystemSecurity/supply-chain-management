/**
 * TypeScript type definitions matching backend schemas
 */

export type ScanType = "git_repo" | "container" | "vm" | "sbom" | "k8s"
export type ScanStatus = "pending" | "running" | "completed" | "failed"

export interface Scan {
  id: string
  scan_type: ScanType
  target: string
  status: ScanStatus
  started_at: string
  completed_at: string | null
  vulnerability_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  project_name: string | null
  result_json: Record<string, any> | null
}

export interface ScanCreate {
  scan_type: ScanType
  target: string
  project_name?: string | null
}

export interface Vulnerability {
  id: string
  scan_id: string
  cve_id: string
  package_name: string | null
  package_version: string | null
  severity: string
  cvss_score: number | null
  epss_score: number | null
  epss_percentile: number | null
  epss_date: string | null
  epss_predicted: boolean
  cve_details: Record<string, any> | null
  cve_api_details: Record<string, any> | null
}

export interface Project {
  name: string
  created_at: string
  scan_ids: string[]
}

export interface ProjectCreate {
  name: string
}

export interface AssignScanRequest {
  scan_id: string
  project_name: string
}

export interface AIAnalysis {
  project_name: string
  analyzed_at: string
  scans?: Record<string, any>[] | null
  scan_metadata?: Record<string, any> | null
  scan_data_json?: string | null
  workflow_run_id?: string | null
  contextual_summary?: string | null
  prioritization?: string | null
  supply_chain?: string | null
  remediation?: string | null
  qa_review?: string | null
  qa_confidence?: number | null
  qa_iterations?: number | null
  executive_summary?: string | null
}

export interface AIAnalysisRequest {
  project_name: string
  selected_scan_ids?: string[] | null
}

export interface ScanListResponse {
  scans: Scan[]
  total: number
}

export interface VulnerabilityListResponse {
  vulnerabilities: Vulnerability[]
  total: number
  scan_id: string
}

export interface ProjectListResponse {
  projects: Project[]
  total: number
}

export interface AIAnalysisListResponse {
  analyses: AIAnalysis[]
  total: number
}

