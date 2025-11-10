"use client";

import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/lib/api-client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Activity, AlertTriangle, CheckCircle } from "lucide-react";
import { formatDate, getSeverityBadgeColor } from "@/lib/utils";
import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function DashboardPage() {
  const { data: scans, isLoading } = useQuery({
    queryKey: ["scans", "recent"],
    queryFn: () => apiClient.listScans({ limit: 5 }),
  });

  const stats = {
    totalScans: scans?.length || 0,
    completedScans: scans?.filter((s) => s.status === "completed").length || 0,
    totalVulnerabilities: scans?.reduce((acc, s) => acc + s.vulnerability_count, 0) || 0,
    criticalVulnerabilities: scans?.reduce((acc, s) => acc + s.critical_count, 0) || 0,
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground mt-2">
          Overview of your supply chain security posture
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalScans}</div>
            <p className="text-xs text-muted-foreground">Active security scans</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Completed</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.completedScans}</div>
            <p className="text-xs text-muted-foreground">Successfully completed</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalVulnerabilities}</div>
            <p className="text-xs text-muted-foreground">Total findings</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {stats.criticalVulnerabilities}
            </div>
            <p className="text-xs text-muted-foreground">Requires immediate attention</p>
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Recent Scans</CardTitle>
              <CardDescription>Latest security scan results</CardDescription>
            </div>
            <Link href="/scans">
              <Button variant="outline">View All</Button>
            </Link>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">
              Loading scans...
            </div>
          ) : scans && scans.length > 0 ? (
            <div className="space-y-4">
              {scans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="block p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{scan.target}</span>
                        <Badge variant="outline" className="uppercase text-xs">
                          {scan.scan_type}
                        </Badge>
                        <Badge
                          className={
                            scan.status === "completed"
                              ? "bg-green-500"
                              : scan.status === "failed"
                              ? "bg-red-500"
                              : "bg-blue-500"
                          }
                        >
                          {scan.status}
                        </Badge>
                      </div>
                      <div className="text-sm text-muted-foreground mt-1">
                        {formatDate(scan.started_at)}
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {scan.critical_count > 0 && (
                        <div className="flex items-center gap-1">
                          <div
                            className={`h-2 w-2 rounded-full ${getSeverityBadgeColor(
                              "CRITICAL"
                            )}`}
                          />
                          <span className="text-sm font-medium">
                            {scan.critical_count}
                          </span>
                        </div>
                      )}
                      {scan.high_count > 0 && (
                        <div className="flex items-center gap-1">
                          <div
                            className={`h-2 w-2 rounded-full ${getSeverityBadgeColor(
                              "HIGH"
                            )}`}
                          />
                          <span className="text-sm font-medium">
                            {scan.high_count}
                          </span>
                        </div>
                      )}
                      <div className="text-sm text-muted-foreground">
                        {scan.vulnerability_count} total
                      </div>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <p className="text-muted-foreground mb-4">No scans yet</p>
              <Link href="/scans">
                <Button>Create First Scan</Button>
              </Link>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
