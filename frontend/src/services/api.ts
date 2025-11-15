/**
 * API client service layer
 */

import axios from "axios"
import type {
  Scan,
  ScanCreate,
  ScanListResponse,
  Vulnerability,
  VulnerabilityListResponse,
  Project,
  ProjectCreate,
  ProjectListResponse,
  AssignScanRequest,
  AIAnalysis,
  AIAnalysisRequest,
  AIAnalysisListResponse,
} from "@/types"

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000"

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
})

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor
apiClient.interceptors.response.use(
  (response) => {
    return response
  },
  (error) => {
    console.error("API Error:", error.response?.data || error.message)
    return Promise.reject(error)
  }
)

// Scans API
export const scansApi = {
  getAll: async (): Promise<ScanListResponse> => {
    const response = await apiClient.get<ScanListResponse>("/api/scans/")
    return response.data
  },

  getById: async (scanId: string): Promise<Scan> => {
    const response = await apiClient.get<Scan>(`/api/scans/${scanId}`)
    return response.data
  },

  create: async (scanData: ScanCreate): Promise<Scan> => {
    const response = await apiClient.post<Scan>("/api/scans/", scanData)
    return response.data
  },
}

// Vulnerabilities API
export const vulnerabilitiesApi = {
  getByScanId: async (scanId: string): Promise<VulnerabilityListResponse> => {
    const response = await apiClient.get<VulnerabilityListResponse>(
      `/api/vulnerabilities/scan/${scanId}`
    )
    return response.data
  },

  getById: async (vulnerabilityId: string): Promise<Vulnerability> => {
    const response = await apiClient.get<Vulnerability>(
      `/api/vulnerabilities/${vulnerabilityId}`
    )
    return response.data
  },
}

// Projects API
export const projectsApi = {
  getAll: async (): Promise<ProjectListResponse> => {
    const response = await apiClient.get<ProjectListResponse>("/api/projects/")
    return response.data
  },

  getByName: async (projectName: string): Promise<Project> => {
    const response = await apiClient.get<Project>(`/api/projects/${projectName}`)
    return response.data
  },

  create: async (projectData: ProjectCreate): Promise<Project> => {
    const response = await apiClient.post<Project>("/api/projects/", projectData)
    return response.data
  },

  assignScan: async (request: AssignScanRequest): Promise<void> => {
    await apiClient.post("/api/projects/assign-scan", request)
  },

  getScans: async (projectName: string): Promise<Scan[]> => {
    const response = await apiClient.get<Scan[]>(`/api/projects/${projectName}/scans`)
    return response.data
  },
}

// AI Analysis API
export const aiAnalysisApi = {
  run: async (request: AIAnalysisRequest): Promise<AIAnalysis> => {
    const response = await apiClient.post<AIAnalysis>("/api/ai-analysis/run", request)
    return response.data
  },

  getByProject: async (projectName: string): Promise<AIAnalysisListResponse> => {
    const response = await apiClient.get<AIAnalysisListResponse>(
      `/api/ai-analysis/project/${projectName}`
    )
    return response.data
  },

  getLatest: async (projectName: string): Promise<AIAnalysis> => {
    const response = await apiClient.get<AIAnalysis>(
      `/api/ai-analysis/project/${projectName}/latest`
    )
    return response.data
  },
}

// CVE API
export const cveApi = {
  getDetails: async (cveId: string): Promise<Record<string, any>> => {
    const response = await apiClient.get(`/api/cve/${cveId}`)
    return response.data
  },
}

// Health check
export const healthApi = {
  check: async (): Promise<{ status: string }> => {
    const response = await apiClient.get("/health")
    return response.data
  },
}

export default apiClient

