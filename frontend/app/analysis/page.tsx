"use client";

import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "@/lib/api-client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/components/ui/use-toast";
import { BrainCircuit, Loader2, Sparkles, TrendingUp, Wrench } from "lucide-react";
import { AgentType } from "@/lib/types";

const AI_AGENTS: { value: AgentType; label: string; icon: React.ElementType; description: string }[] = [
  {
    value: "prioritization",
    label: "Prioritization Agent",
    icon: TrendingUp,
    description: "Analyze and prioritize vulnerabilities based on risk",
  },
  {
    value: "supply_chain",
    label: "Supply Chain Agent",
    icon: Sparkles,
    description: "Analyze supply chain impact across multiple scans",
  },
  {
    value: "remediation",
    label: "Remediation Agent",
    icon: Wrench,
    description: "Generate detailed remediation plans",
  },
];

export default function AnalysisPage() {
  const [selectedScan, setSelectedScan] = React.useState<string>("");
  const [selectedAgent, setSelectedAgent] = React.useState<AgentType>("prioritization");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => apiClient.listScans({ status: "completed", limit: 50 }),
  });

  const mutation = useMutation({
    mutationFn: () =>
      apiClient.analyzeScan({
        scan_id: selectedScan,
        agents: [selectedAgent],
      }),
    onSuccess: (data) => {
      toast({
        title: "Analysis started",
        description: `AI analysis ${data.analysis_id} has been initiated.`,
      });
      queryClient.invalidateQueries({ queryKey: ["analyses"] });
    },
    onError: (error) => {
      toast({
        title: "Failed to start analysis",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleRunAnalysis = () => {
    if (!selectedScan) {
      toast({
        title: "No scan selected",
        description: "Please select a scan to analyze",
        variant: "destructive",
      });
      return;
    }
    mutation.mutate();
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold">AI Analysis</h1>
        <p className="text-muted-foreground mt-2">
          Leverage AI agents to analyze vulnerabilities and generate insights
        </p>
      </div>

      <Tabs defaultValue="run" className="space-y-6">
        <TabsList>
          <TabsTrigger value="run">Run Analysis</TabsTrigger>
          <TabsTrigger value="agents">AI Agents</TabsTrigger>
        </TabsList>

        <TabsContent value="run" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Configure Analysis</CardTitle>
              <CardDescription>
                Select a completed scan and AI agent to run analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Select Scan</label>
                  <Select value={selectedScan} onValueChange={setSelectedScan}>
                    <SelectTrigger>
                      <SelectValue placeholder="Choose a completed scan" />
                    </SelectTrigger>
                    <SelectContent>
                      {scans && scans.length > 0 ? (
                        scans.map((scan) => (
                          <SelectItem key={scan.id} value={scan.id}>
                            <div className="flex flex-col">
                              <span>{scan.target}</span>
                              <span className="text-xs text-muted-foreground">
                                {scan.vulnerability_count} vulnerabilities
                              </span>
                            </div>
                          </SelectItem>
                        ))
                      ) : (
                        <SelectItem value="none" disabled>
                          No completed scans available
                        </SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Select AI Agent</label>
                  <Select
                    value={selectedAgent}
                    onValueChange={(value) => setSelectedAgent(value as AgentType)}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {AI_AGENTS.map((agent) => (
                        <SelectItem key={agent.value} value={agent.value}>
                          <div className="flex items-center gap-2">
                            <agent.icon className="h-4 w-4" />
                            <span>{agent.label}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Button
                onClick={handleRunAnalysis}
                disabled={!selectedScan || mutation.isPending}
                className="w-full"
              >
                {mutation.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                <BrainCircuit className="mr-2 h-4 w-4" />
                Run AI Analysis
              </Button>
            </CardContent>
          </Card>

          {selectedScan && scans && (
            <Card>
              <CardHeader>
                <CardTitle>Selected Scan Details</CardTitle>
              </CardHeader>
              <CardContent>
                {(() => {
                  const scan = scans.find((s) => s.id === selectedScan);
                  if (!scan) return null;
                  return (
                    <div className="grid gap-4 md:grid-cols-3">
                      <div>
                        <div className="text-sm font-medium text-muted-foreground">
                          Target
                        </div>
                        <div className="text-sm font-medium">{scan.target}</div>
                      </div>
                      <div>
                        <div className="text-sm font-medium text-muted-foreground">
                          Type
                        </div>
                        <Badge variant="outline" className="uppercase">
                          {scan.scan_type}
                        </Badge>
                      </div>
                      <div>
                        <div className="text-sm font-medium text-muted-foreground">
                          Vulnerabilities
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          {scan.critical_count > 0 && (
                            <Badge className="bg-red-600">
                              {scan.critical_count} Critical
                            </Badge>
                          )}
                          {scan.high_count > 0 && (
                            <Badge className="bg-orange-500">
                              {scan.high_count} High
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })()}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="agents" className="space-y-4">
          {AI_AGENTS.map((agent) => {
            const Icon = agent.icon;
            return (
              <Card key={agent.value}>
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                      <Icon className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <CardTitle>{agent.label}</CardTitle>
                      <CardDescription>{agent.description}</CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {agent.value === "prioritization" && (
                      <>
                        <div>
                          <h4 className="text-sm font-medium mb-1">Features:</h4>
                          <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                            <li>Risk-based vulnerability scoring</li>
                            <li>EPSS score integration for exploitation likelihood</li>
                            <li>Business impact assessment</li>
                            <li>Actionable prioritization recommendations</li>
                          </ul>
                        </div>
                      </>
                    )}
                    {agent.value === "supply_chain" && (
                      <>
                        <div>
                          <h4 className="text-sm font-medium mb-1">Features:</h4>
                          <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                            <li>Cross-scan vulnerability analysis</li>
                            <li>Dependency chain mapping</li>
                            <li>Common vulnerability identification</li>
                            <li>Consolidated remediation strategies</li>
                          </ul>
                        </div>
                      </>
                    )}
                    {agent.value === "remediation" && (
                      <>
                        <div>
                          <h4 className="text-sm font-medium mb-1">Features:</h4>
                          <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                            <li>Step-by-step remediation instructions</li>
                            <li>Upgrade commands and configuration changes</li>
                            <li>Testing and validation procedures</li>
                            <li>Rollback plans for safe deployment</li>
                          </ul>
                        </div>
                      </>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </TabsContent>
      </Tabs>
    </div>
  );
}
