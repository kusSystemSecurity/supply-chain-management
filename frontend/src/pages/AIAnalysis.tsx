import { useState, useEffect } from "react"
import { useProjects } from "@/hooks/useProjects"
import { useScans } from "@/hooks/useScans"
import { useAIAnalysis } from "@/hooks/useAIAnalysis"
import { projectsApi, aiAnalysisApi } from "@/services/api"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import { CheckboxGroup } from "@/components/ui/checkbox-group"
import { Loading } from "@/components/loading"
import { Brain, Plus, Play, RefreshCw, AlertCircle, Link as LinkIcon, CheckCircle2 } from "lucide-react"
import type { Scan, AIAnalysis } from "@/types"

export function AIAnalysisPage() {
  const { projects, refetch: refetchProjects } = useProjects()
  const { scans, refetch: refetchScans } = useScans()
  const { runAnalysis, loading: analysisLoading, error: analysisError } = useAIAnalysis()

  const [selectedProject, setSelectedProject] = useState<string>("")
  const [projectScans, setProjectScans] = useState<Scan[]>([])
  const [selectedScans, setSelectedScans] = useState<string[]>([])
  const [newProjectName, setNewProjectName] = useState("")
  const [analysisResult, setAnalysisResult] = useState<AIAnalysis | null>(null)
  const [loadingScans, setLoadingScans] = useState(false)

  // Scan assignment states
  const [assignProjectName, setAssignProjectName] = useState<string>("")
  const [selectedScansToAssign, setSelectedScansToAssign] = useState<string[]>([])
  const [assigningScans, setAssigningScans] = useState(false)
  const [assignSuccess, setAssignSuccess] = useState<string | null>(null)
  const [assignError, setAssignError] = useState<string | null>(null)

  // Load scans when project is selected
  useEffect(() => {
    if (selectedProject) {
      const loadScans = async () => {
        try {
          setLoadingScans(true)
          const scans = await projectsApi.getScans(selectedProject)
          setProjectScans(scans)
        } catch (err) {
          console.error("Failed to load scans:", err)
        } finally {
          setLoadingScans(false)
        }
      }
      loadScans()
    } else {
      setProjectScans([])
      setSelectedScans([])
    }
  }, [selectedProject])

  const handleCreateProject = async () => {
    if (!newProjectName.trim()) return

    try {
      await projectsApi.create({ name: newProjectName.trim() })
      setNewProjectName("")
      await refetchProjects()
    } catch (err) {
      console.error("Failed to create project:", err)
    }
  }

  const handleRunAnalysis = async () => {
    if (!selectedProject) return

    const result = await runAnalysis({
      project_name: selectedProject,
      selected_scan_ids: selectedScans.length > 0 ? selectedScans : null,
    })

    if (result) {
      setAnalysisResult(result)
    }
  }

  const handleLoadLatestAnalysis = async () => {
    if (!selectedProject) return

    try {
      const latest = await aiAnalysisApi.getLatest(selectedProject)
      setAnalysisResult(latest)
    } catch (err) {
      console.error("Failed to load latest analysis:", err)
    }
  }

  const handleAssignScans = async () => {
    if (!assignProjectName || selectedScansToAssign.length === 0) {
      setAssignError("Please select a project and at least one scan")
      return
    }

    try {
      setAssigningScans(true)
      setAssignError(null)
      setAssignSuccess(null)

      // Assign each selected scan to the project
      const assignPromises = selectedScansToAssign.map((scanId) =>
        projectsApi.assignScan({
          scan_id: scanId,
          project_name: assignProjectName,
        })
      )

      await Promise.all(assignPromises)

      setAssignSuccess(
        `Successfully assigned ${selectedScansToAssign.length} scan(s) to project "${assignProjectName}"`
      )
      setSelectedScansToAssign([])

      // Refresh data
      await refetchProjects()
      await refetchScans()

      // If the selected project matches, refresh project scans
      if (selectedProject === assignProjectName) {
        const scans = await projectsApi.getScans(assignProjectName)
        setProjectScans(scans)
      }
    } catch (err) {
      setAssignError(err instanceof Error ? err.message : "Failed to assign scans")
    } finally {
      setAssigningScans(false)
    }
  }


  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight flex items-center space-x-2">
          <Brain className="h-8 w-8" />
          <span>AI Analysis</span>
        </h1>
        <p className="text-muted-foreground">
          Analyze vulnerabilities using AI agents for prioritization, supply chain impact, and remediation guidance
        </p>
      </div>

      {/* Project Management */}
      <Card>
        <CardHeader>
          <CardTitle>Project Management</CardTitle>
          <CardDescription>Create and manage projects</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex space-x-2">
            <Input
              placeholder="Enter project name..."
              value={newProjectName}
              onChange={(e) => setNewProjectName(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && handleCreateProject()}
            />
            <Button onClick={handleCreateProject}>
              <Plus className="h-4 w-4 mr-2" />
              Create Project
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Assign Scans to Project */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <LinkIcon className="h-5 w-5" />
            <span>Assign Scans to Project</span>
          </CardTitle>
          <CardDescription>Select scans and assign them to a project</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium mb-2 block">Project</label>
            <Select
              value={assignProjectName}
              onChange={(e) => {
                setAssignProjectName(e.target.value)
                setAssignSuccess(null)
                setAssignError(null)
              }}
            >
              <option value="">Select a project...</option>
              {projects.map((project) => (
                <option key={project.name} value={project.name}>
                  {project.name} ({project.scan_ids.length} scans)
                </option>
              ))}
            </Select>
          </div>

          {assignProjectName && (
            <div>
              <label className="text-sm font-medium mb-2 block">
                Select Scans to Assign ({selectedScansToAssign.length} selected)
              </label>
              {scans.length > 0 ? (
                <div className="max-h-60 overflow-y-auto border rounded-md p-4">
                  <CheckboxGroup
                    options={scans.map((scan) => {
                      const isAlreadyAssigned = scan.project_name === assignProjectName
                      return {
                        value: scan.id,
                        label: `${scan.target} (${scan.vulnerability_count} vulnerabilities) ${
                          isAlreadyAssigned ? "✓ Already assigned" : ""
                        }`,
                      }
                    })}
                    value={selectedScansToAssign}
                    onChange={setSelectedScansToAssign}
                  />
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No scans available</p>
              )}
            </div>
          )}

          <Button
            onClick={handleAssignScans}
            disabled={!assignProjectName || selectedScansToAssign.length === 0 || assigningScans}
          >
            {assigningScans ? (
              <>
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                Assigning...
              </>
            ) : (
              <>
                <LinkIcon className="h-4 w-4 mr-2" />
                Assign Selected Scans
              </>
            )}
          </Button>

          {assignSuccess && (
            <div className="flex items-center space-x-2 p-3 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 rounded-md">
              <CheckCircle2 className="h-4 w-4" />
              <span className="text-sm">{assignSuccess}</span>
            </div>
          )}

          {assignError && (
            <div className="flex items-center space-x-2 p-3 bg-destructive/10 text-destructive rounded-md">
              <AlertCircle className="h-4 w-4" />
              <span className="text-sm">{assignError}</span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Project Selection and Scan Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Select Project & Scans</CardTitle>
          <CardDescription>Choose a project and select scans to analyze</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium mb-2 block">Project</label>
            <Select
              value={selectedProject}
              onChange={(e) => setSelectedProject(e.target.value)}
            >
              <option value="">Select a project...</option>
              {projects.map((project) => (
                <option key={project.name} value={project.name}>
                  {project.name}
                </option>
              ))}
            </Select>
          </div>

          {selectedProject && (
            <div>
              <label className="text-sm font-medium mb-2 block">
                Select Scans to Analyze (leave empty to analyze all)
              </label>
              {loadingScans ? (
                <Loading />
              ) : projectScans.length > 0 ? (
                <div className="max-h-60 overflow-y-auto border rounded-md p-4">
                  <CheckboxGroup
                    options={projectScans.map((scan) => ({
                      value: scan.id,
                      label: `${scan.target} (${scan.vulnerability_count} vulnerabilities)`,
                    }))}
                    value={selectedScans}
                    onChange={setSelectedScans}
                  />
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No scans in this project</p>
              )}
            </div>
          )}

          <div className="flex space-x-2">
            <Button
              onClick={handleRunAnalysis}
              disabled={!selectedProject || analysisLoading || loadingScans}
            >
              {analysisLoading ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 mr-2" />
                  Run AI Analysis
                </>
              )}
            </Button>
            {selectedProject && (
              <Button variant="outline" onClick={handleLoadLatestAnalysis}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Load Latest Analysis
              </Button>
            )}
          </div>

          {analysisError && (
            <div className="flex items-center space-x-2 p-3 bg-destructive/10 text-destructive rounded-md">
              <AlertCircle className="h-4 w-4" />
              <span className="text-sm">{analysisError}</span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Analysis Results */}
      {analysisResult && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Prioritization Analysis</CardTitle>
              <CardDescription>Vulnerability prioritization recommendations</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="prose dark:prose-invert max-w-none">
                <pre className="whitespace-pre-wrap text-sm bg-muted p-4 rounded-md">
                  {analysisResult.prioritization || "No analysis available"}
                </pre>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Supply Chain Analysis</CardTitle>
              <CardDescription>Supply chain security impact assessment</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="prose dark:prose-invert max-w-none">
                <pre className="whitespace-pre-wrap text-sm bg-muted p-4 rounded-md">
                  {analysisResult.supply_chain || "No analysis available"}
                </pre>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Remediation Guidance</CardTitle>
              <CardDescription>Actionable remediation steps</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="prose dark:prose-invert max-w-none">
                <pre className="whitespace-pre-wrap text-sm bg-muted p-4 rounded-md">
                  {analysisResult.remediation || "No analysis available"}
                </pre>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}

