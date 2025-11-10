"use client";

import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/lib/api-client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScanForm } from "@/components/scan-form";
import { formatDate, getSeverityBadgeColor } from "@/lib/utils";
import Link from "next/link";
import { Loader2 } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function ScansPage() {
  const { data: scans, isLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: () => apiClient.listScans({ limit: 50 }),
  });

  const filterScansByStatus = (status?: string) => {
    if (!status) return scans || [];
    return scans?.filter((s) => s.status === status) || [];
  };

  const renderScansList = (filteredScans: typeof scans) => {
    if (isLoading) {
      return (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      );
    }

    if (!filteredScans || filteredScans.length === 0) {
      return (
        <div className="text-center py-12">
          <p className="text-muted-foreground">No scans found</p>
        </div>
      );
    }

    return (
      <div className="space-y-3">
        {filteredScans.map((scan) => (
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
                        : scan.status === "running"
                        ? "bg-blue-500"
                        : "bg-gray-500"
                    }
                  >
                    {scan.status}
                  </Badge>
                </div>
                <div className="text-sm text-muted-foreground mt-1">
                  Started: {formatDate(scan.started_at)}
                  {scan.completed_at && ` • Completed: ${formatDate(scan.completed_at)}`}
                </div>
              </div>
              <div className="flex items-center gap-4">
                {scan.critical_count > 0 && (
                  <div className="flex items-center gap-1">
                    <div
                      className={`h-2 w-2 rounded-full ${getSeverityBadgeColor("CRITICAL")}`}
                    />
                    <span className="text-sm font-medium text-red-600">
                      {scan.critical_count} Critical
                    </span>
                  </div>
                )}
                {scan.high_count > 0 && (
                  <div className="flex items-center gap-1">
                    <div
                      className={`h-2 w-2 rounded-full ${getSeverityBadgeColor("HIGH")}`}
                    />
                    <span className="text-sm font-medium text-orange-600">
                      {scan.high_count} High
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
    );
  };

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-4xl font-bold">Security Scans</h1>
          <p className="text-muted-foreground mt-2">
            Manage and monitor your security scans
          </p>
        </div>
        <ScanForm />
      </div>

      <Tabs defaultValue="all" className="space-y-4">
        <TabsList>
          <TabsTrigger value="all">All Scans</TabsTrigger>
          <TabsTrigger value="completed">Completed</TabsTrigger>
          <TabsTrigger value="running">Running</TabsTrigger>
          <TabsTrigger value="pending">Pending</TabsTrigger>
          <TabsTrigger value="failed">Failed</TabsTrigger>
        </TabsList>

        <TabsContent value="all">
          <Card>
            <CardHeader>
              <CardTitle>All Scans</CardTitle>
              <CardDescription>
                {scans?.length || 0} total scans
              </CardDescription>
            </CardHeader>
            <CardContent>
              {renderScansList(scans)}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="completed">
          <Card>
            <CardHeader>
              <CardTitle>Completed Scans</CardTitle>
              <CardDescription>
                {filterScansByStatus("completed").length} completed scans
              </CardDescription>
            </CardHeader>
            <CardContent>
              {renderScansList(filterScansByStatus("completed"))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="running">
          <Card>
            <CardHeader>
              <CardTitle>Running Scans</CardTitle>
              <CardDescription>
                {filterScansByStatus("running").length} scans in progress
              </CardDescription>
            </CardHeader>
            <CardContent>
              {renderScansList(filterScansByStatus("running"))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="pending">
          <Card>
            <CardHeader>
              <CardTitle>Pending Scans</CardTitle>
              <CardDescription>
                {filterScansByStatus("pending").length} pending scans
              </CardDescription>
            </CardHeader>
            <CardContent>
              {renderScansList(filterScansByStatus("pending"))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="failed">
          <Card>
            <CardHeader>
              <CardTitle>Failed Scans</CardTitle>
              <CardDescription>
                {filterScansByStatus("failed").length} failed scans
              </CardDescription>
            </CardHeader>
            <CardContent>
              {renderScansList(filterScansByStatus("failed"))}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
