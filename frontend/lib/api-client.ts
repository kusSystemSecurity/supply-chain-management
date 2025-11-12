/**
 * API client for backend communication
 */

import {
  Scan,
  Vulnerability,
  ScanRequest,
  ScanResponse,
  AnalysisRequest,
  AnalysisResponse,
  AnalysisDetail
} from "./types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options?: RequestInit
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;

    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.detail || `API request failed: ${response.statusText}`
      );
    }

    return response.json();
  }

  async getScan(scanId: string): Promise<Scan> {
    return this.request<Scan>(`/api/scans/${scanId}`);
  }

  async listScans(params?: {
    status?: string;
    scan_type?: string;
    limit?: number;
    offset?: number;
  }): Promise<Scan[]> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.append("status", params.status);
    if (params?.scan_type) searchParams.append("scan_type", params.scan_type);
    if (params?.limit) searchParams.append("limit", params.limit.toString());
    if (params?.offset) searchParams.append("offset", params.offset.toString());

    const query = searchParams.toString();
    const endpoint = query ? `/api/scans?${query}` : "/api/scans";

    return this.request<Scan[]>(endpoint);
  }

  async getScanVulnerabilities(
    scanId: string,
    severity?: string
  ): Promise<Vulnerability[]> {
    const searchParams = new URLSearchParams();
    if (severity) searchParams.append("severity", severity);

    const query = searchParams.toString();
    const endpoint = query
      ? `/api/scans/${scanId}/vulnerabilities?${query}`
      : `/api/scans/${scanId}/vulnerabilities`;

    return this.request<Vulnerability[]>(endpoint);
  }

  async triggerScan(scanRequest: ScanRequest): Promise<ScanResponse> {
    return this.request<ScanResponse>("/api/scans/trigger", {
      method: "POST",
      body: JSON.stringify(scanRequest),
    });
  }

  async deleteScan(scanId: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/api/scans/${scanId}`, {
      method: "DELETE",
    });
  }

  async analyzeScan(analysisRequest: AnalysisRequest): Promise<AnalysisResponse> {
    return this.request<AnalysisResponse>("/api/ai/analyze", {
      method: "POST",
      body: JSON.stringify(analysisRequest),
    });
  }

  async getAnalysis(analysisId: string): Promise<AnalysisDetail> {
    return this.request<AnalysisDetail>(`/api/ai/analysis/${analysisId}`);
  }
}

export const apiClient = new ApiClient(API_BASE_URL);
