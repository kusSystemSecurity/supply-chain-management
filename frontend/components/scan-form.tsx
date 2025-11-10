"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "@/lib/api-client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { useToast } from "@/components/ui/use-toast";
import { ScanType } from "@/lib/types";
import { Loader2, Plus } from "lucide-react";

const SCAN_TYPES: { value: ScanType; label: string; description: string }[] = [
  { value: "git_repo", label: "Git Repository", description: "Scan a Git repository" },
  { value: "container", label: "Container Image", description: "Scan a Docker container" },
  { value: "vm", label: "Virtual Machine", description: "Scan a VM image" },
  { value: "sbom", label: "SBOM", description: "Analyze an SBOM file" },
  { value: "k8s", label: "Kubernetes", description: "Scan Kubernetes manifests" },
];

export function ScanForm() {
  const [open, setOpen] = React.useState(false);
  const [scanType, setScanType] = React.useState<ScanType>("git_repo");
  const [target, setTarget] = React.useState("");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      apiClient.triggerScan({
        scan_type: scanType,
        target: target,
      }),
    onSuccess: (data) => {
      toast({
        title: "Scan initiated",
        description: `Scan ${data.scan_id} has been started successfully.`,
      });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setOpen(false);
      setTarget("");
    },
    onError: (error) => {
      toast({
        title: "Failed to create scan",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate();
  };

  const getTargetPlaceholder = () => {
    switch (scanType) {
      case "git_repo":
        return "https://github.com/user/repo";
      case "container":
        return "nginx:latest";
      case "vm":
        return "/path/to/vm-image";
      case "sbom":
        return "/path/to/sbom.json";
      case "k8s":
        return "/path/to/manifest.yaml";
      default:
        return "Enter target";
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="h-4 w-4 mr-2" />
          New Scan
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px]">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Create New Scan</DialogTitle>
            <DialogDescription>
              Configure and initiate a new security scan for your software supply chain.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="scan-type">Scan Type</Label>
              <Select
                value={scanType}
                onValueChange={(value) => setScanType(value as ScanType)}
              >
                <SelectTrigger id="scan-type">
                  <SelectValue placeholder="Select scan type" />
                </SelectTrigger>
                <SelectContent>
                  {SCAN_TYPES.map((type) => (
                    <SelectItem key={type.value} value={type.value}>
                      <div className="flex flex-col">
                        <span className="font-medium">{type.label}</span>
                        <span className="text-xs text-muted-foreground">
                          {type.description}
                        </span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="target">Target</Label>
              <Input
                id="target"
                placeholder={getTargetPlaceholder()}
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                required
              />
              <p className="text-xs text-muted-foreground">
                Enter the URL, path, or identifier for the target to scan
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setOpen(false)}
              disabled={mutation.isPending}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending || !target}>
              {mutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Start Scan
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
