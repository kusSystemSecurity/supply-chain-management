"use client";

import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/lib/api-client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { VulnerabilityTable } from "@/components/vulnerability-table";
import { formatDate, getSeverityBadgeColor } from "@/lib/utils";
import { Loader2, ArrowLeft, RefreshCw } from "lucide-react";
import Link from "next/link";
import { use } from "react";

export default function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const scanId = resolvedParams.id;

  const { data: scan, isLoading: scanLoading, refetch: refetchScan } = useQuery({
    queryKey: ["scans", scanId],
    queryFn: () => apiClient.getScan(scanId),
    refetchInterval: (query) => {
      const data = query.state.data;
      // Poll every 3 seconds if scan is running or pending
      if (data?.status === "running" || data?.status === "pending") {
        return 3000;
      }
      return false;
    },
  });

  const { data: vulnerabilities, isLoading: vulnLoading } = useQuery({
    queryKey: ["vulnerabilities", scanId],
    queryFn: () => apiClient.getScanVulnerabilities(scanId),
    enabled: scan?.status === "completed",
  });

  if (scanLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <p className="text-muted-foreground">Scan not found</p>
        <Link href="/scans">
          <Button className="mt-4" variant="outline">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Scans
          </Button>
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/scans">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <h1 className="text-3xl font-bold">{scan.target}</h1>
            <div className="flex items-center gap-2 mt-2">
              <Badge variant="outline" className="uppercase">
                {scan.scan_type}
              </Badge>
              <Badge
                className={
                  scan.status === "completed"
                    ? "bg-green-500"
                    : scan.status === "failed"
                    ? "bg-red-500"
                    : scan.status === "running"
                    ? "bg-blue-500"
                    : "bg-gray-500"
                }
              >
                {scan.status}
              </Badge>
            </div>
          </div>
        </div>
        <Button variant="outline" size="icon" onClick={() => refetchScan()}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>

      {/* Scan Information */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Information</CardTitle>
          <CardDescription>Details about this security scan</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <div>
            <div className="text-sm font-medium text-muted-foreground">Started</div>
            <div className="text-sm">{formatDate(scan.started_at)}</div>
          </div>
          <div>
            <div className="text-sm font-medium text-muted-foreground">Completed</div>
            <div className="text-sm">
              {scan.completed_at ? formatDate(scan.completed_at) : "In progress"}
            </div>
          </div>
          <div>
            <div className="text-sm font-medium text-muted-foreground">Total Vulnerabilities</div>
            <div className="text-2xl font-bold">{scan.vulnerability_count}</div>
          </div>
          <div className="flex gap-4">
            <div>
              <div className="text-sm font-medium text-muted-foreground">By Severity</div>
              <div className="flex items-center gap-3 mt-1">
                {scan.critical_count > 0 && (
                  <div className="flex items-center gap-1">
                    <div className={`h-3 w-3 rounded-full ${getSeverityBadgeColor("CRITICAL")}`} />
                    <span className="text-sm font-medium">{scan.critical_count}</span>
                  </div>
                )}
                {scan.high_count > 0 && (
                  <div className="flex items-center gap-1">
                    <div className={`h-3 w-3 rounded-full ${getSeverityBadgeColor("HIGH")}`} />
                    <span className="text-sm font-medium">{scan.high_count}</span>
                  </div>
                )}
                {scan.medium_count > 0 && (
                  <div className="flex items-center gap-1">
                    <div className={`h-3 w-3 rounded-full ${getSeverityBadgeColor("MEDIUM")}`} />
                    <span className="text-sm font-medium">{scan.medium_count}</span>
                  </div>
                )}
                {scan.low_count > 0 && (
                  <div className="flex items-center gap-1">
                    <div className={`h-3 w-3 rounded-full ${getSeverityBadgeColor("LOW")}`} />
                    <span className="text-sm font-medium">{scan.low_count}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Vulnerabilities */}
      {scan.status === "completed" && (
        <Card>
          <CardHeader>
            <CardTitle>Vulnerabilities</CardTitle>
            <CardDescription>
              Detailed list of discovered vulnerabilities
            </CardDescription>
          </CardHeader>
          <CardContent>
            {vulnLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : vulnerabilities && vulnerabilities.length > 0 ? (
              <VulnerabilityTable vulnerabilities={vulnerabilities} />
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                No vulnerabilities found
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {scan.status === "running" && (
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center justify-center gap-4">
              <Loader2 className="h-12 w-12 animate-spin text-primary" />
              <div className="text-center">
                <p className="font-medium">Scan in progress</p>
                <p className="text-sm text-muted-foreground">
                  This page will update automatically when the scan completes
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {scan.status === "failed" && (
        <Card className="border-red-200">
          <CardContent className="py-12">
            <div className="text-center">
              <p className="font-medium text-red-600">Scan failed</p>
              <p className="text-sm text-muted-foreground mt-2">
                There was an error processing this scan
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
