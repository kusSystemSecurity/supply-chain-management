import { useState, useEffect } from "react"
import { useParams, useNavigate } from "react-router-dom"
import { scansApi, vulnerabilitiesApi } from "@/services/api"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Loading } from "@/components/loading"
import { ArrowLeft, AlertTriangle, CheckCircle, Clock, XCircle } from "lucide-react"
import { CVEDetailsModal } from "@/components/cve-details-modal"
import type { Scan, Vulnerability } from "@/types"

export function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const [scan, setScan] = useState<Scan | null>(null)
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null)
  const [isModalOpen, setIsModalOpen] = useState(false)

  useEffect(() => {
    const loadData = async () => {
      if (!scanId) return

      try {
        setLoading(true)
        const [scanData, vulnData] = await Promise.all([
          scansApi.getById(scanId),
          vulnerabilitiesApi.getByScanId(scanId),
        ])
        setScan(scanData)
        setVulnerabilities(vulnData.vulnerabilities)
        setError(null)
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load scan details")
      } finally {
        setLoading(false)
      }
    }

    loadData()
  }, [scanId])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loading size="lg" />
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="space-y-4">
        <Button variant="outline" onClick={() => navigate("/")}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Dashboard
        </Button>
        <Card>
          <CardContent className="pt-6">
            <p className="text-destructive">{error || "Scan not found"}</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  const getStatusIcon = () => {
    switch (scan.status) {
      case "completed":
        return <CheckCircle className="h-5 w-5 text-green-500" />
      case "running":
        return <Clock className="h-5 w-5 text-blue-500 animate-spin" />
      case "failed":
        return <XCircle className="h-5 w-5 text-red-500" />
      default:
        return <Clock className="h-5 w-5 text-gray-500" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
      case "HIGH":
        return "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
      case "MEDIUM":
        return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
      case "LOW":
        return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
      default:
        return "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200"
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Button variant="outline" onClick={() => navigate("/")} className="mb-4">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Dashboard
          </Button>
          <h1 className="text-3xl font-bold tracking-tight">Scan Details</h1>
          <p className="text-muted-foreground">{scan.target}</p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Status</CardTitle>
            {getStatusIcon()}
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold capitalize">{scan.status}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{scan.vulnerability_count}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Started At</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-sm">
              {new Date(scan.started_at).toLocaleString()}
            </div>
          </CardContent>
        </Card>

        {scan.completed_at && (
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Completed At</CardTitle>
              <CheckCircle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-sm">
                {new Date(scan.completed_at).toLocaleString()}
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Vulnerabilities</CardTitle>
          <CardDescription>
            {vulnerabilities.length} vulnerabilities found
          </CardDescription>
        </CardHeader>
        <CardContent>
          {vulnerabilities.length > 0 ? (
            <div className="space-y-2">
              {vulnerabilities.map((vuln) => (
                <div
                  key={vuln.id}
                  onClick={() => {
                    setSelectedVulnerability(vuln)
                    setIsModalOpen(true)
                  }}
                  className="flex items-center justify-between p-4 border rounded-lg cursor-pointer hover:bg-accent transition-colors"
                >
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="font-medium">{vuln.cve_id}</span>
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(
                          vuln.severity
                        )}`}
                      >
                        {vuln.severity}
                      </span>
                    </div>
                    {vuln.package_name && (
                      <p className="text-sm text-muted-foreground">
                        {vuln.package_name}
                        {vuln.package_version && ` (${vuln.package_version})`}
                      </p>
                    )}
                    {vuln.cvss_score && (
                      <p className="text-xs text-muted-foreground mt-1">
                        CVSS: {vuln.cvss_score.toFixed(1)}
                        {vuln.epss_score && ` | EPSS: ${(vuln.epss_score * 100).toFixed(2)}%`}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground text-center py-8">
              No vulnerabilities found
            </p>
          )}
        </CardContent>
      </Card>

      {selectedVulnerability && (
        <CVEDetailsModal
          cveId={selectedVulnerability.cve_id}
          packageName={selectedVulnerability.package_name}
          packageVersion={selectedVulnerability.package_version}
          severity={selectedVulnerability.severity}
          cvssScore={selectedVulnerability.cvss_score}
          epssScore={selectedVulnerability.epss_score}
          open={isModalOpen}
          onOpenChange={setIsModalOpen}
        />
      )}
    </div>
  )
}

