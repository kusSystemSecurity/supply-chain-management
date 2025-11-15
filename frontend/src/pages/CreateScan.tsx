import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { scansApi } from "@/services/api"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import { Loading } from "@/components/loading"
import { useProjects } from "@/hooks/useProjects"
import { Scan as ScanIcon, Plus } from "lucide-react"
import type { ScanType } from "@/types"

const SCAN_TYPES: Array<{ value: ScanType; label: string }> = [
  { value: "git_repo", label: "Git Repository" },
  { value: "container", label: "Container Image" },
  { value: "vm", label: "VM Image" },
  { value: "sbom", label: "SBOM File" },
  { value: "k8s", label: "Kubernetes" },
]

export function CreateScan() {
  const navigate = useNavigate()
  const { projects, refetch: refetchProjects } = useProjects()
  const [scanType, setScanType] = useState<ScanType>("git_repo")
  const [target, setTarget] = useState("")
  const [projectName, setProjectName] = useState<string>("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const handleCreateScan = async () => {
    if (!target.trim()) {
      setError("Please enter a target")
      return
    }

    try {
      setLoading(true)
      setError(null)
      setSuccess(false)

      const scanData = {
        scan_type: scanType,
        target: target.trim(),
        project_name: projectName || null,
      }

      await scansApi.create(scanData)

      setSuccess(true)
      setTarget("")
      setProjectName("")

      // Refresh projects if a project was assigned
      if (projectName) {
        await refetchProjects()
      }

      // Navigate to dashboard after a short delay
      setTimeout(() => {
        navigate("/")
      }, 1500)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create scan")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight flex items-center space-x-2">
          <ScanIcon className="h-8 w-8" />
          <span>Create Scan</span>
        </h1>
        <p className="text-muted-foreground">
          Start a new security scan for your target
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Scan Configuration</CardTitle>
          <CardDescription>Configure your security scan</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium mb-2 block">Scan Type</label>
            <Select
              value={scanType}
              onChange={(e) => setScanType(e.target.value as ScanType)}
            >
              {SCAN_TYPES.map((type) => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </Select>
          </div>

          <div>
            <label className="text-sm font-medium mb-2 block">Target</label>
            <Input
              placeholder={
                scanType === "git_repo"
                  ? "https://github.com/user/repo"
                  : scanType === "container"
                  ? "docker.io/library/nginx:latest"
                  : scanType === "vm"
                  ? "/path/to/vm/image"
                  : scanType === "sbom"
                  ? "/path/to/sbom.json"
                  : "k8s://namespace/resource"
              }
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && handleCreateScan()}
            />
            <p className="text-xs text-muted-foreground mt-1">
              {scanType === "git_repo" && "Enter the Git repository URL"}
              {scanType === "container" && "Enter the container image name"}
              {scanType === "vm" && "Enter the VM image path"}
              {scanType === "sbom" && "Enter the SBOM file path"}
              {scanType === "k8s" && "Enter the Kubernetes resource"}
            </p>
          </div>

          <div>
            <label className="text-sm font-medium mb-2 block">
              Project (Optional)
            </label>
            <Select
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
            >
              <option value="">No project</option>
              {projects.map((project) => (
                <option key={project.name} value={project.name}>
                  {project.name}
                </option>
              ))}
            </Select>
            <p className="text-xs text-muted-foreground mt-1">
              Assign this scan to a project for better organization
            </p>
          </div>

          {error && (
            <div className="p-3 bg-destructive/10 text-destructive rounded-md text-sm">
              {error}
            </div>
          )}

          {success && (
            <div className="p-3 bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 rounded-md text-sm">
              Scan created successfully! Redirecting to dashboard...
            </div>
          )}

          <Button
            onClick={handleCreateScan}
            disabled={loading || !target.trim()}
            className="w-full"
          >
            {loading ? (
              <>
                <Loading size="sm" className="mr-2" />
                Creating Scan...
              </>
            ) : (
              <>
                <Plus className="h-4 w-4 mr-2" />
                Create Scan
              </>
            )}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}

