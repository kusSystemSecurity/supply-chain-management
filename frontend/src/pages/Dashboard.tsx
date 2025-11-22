import { useScans } from "@/hooks/useScans"
import { useProjects } from "@/hooks/useProjects"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Loading } from "@/components/loading"
import { Scan, Shield, AlertTriangle, TrendingUp, Clock } from "lucide-react"
import { useNavigate } from "react-router-dom"
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts"
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart"

const COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
}

export function Dashboard() {
  const navigate = useNavigate()
  const { scans, loading: scansLoading } = useScans()
  const { projects, loading: projectsLoading } = useProjects()

  if (scansLoading || projectsLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loading size="lg" />
      </div>
    )
  }

  // Calculate statistics
  const totalScans = scans.length
  const totalVulnerabilities = scans.reduce((sum, scan) => sum + scan.vulnerability_count, 0)
  const totalProjects = projects.length
  const completedScans = scans.filter((s) => s.status === "completed").length

  // Severity distribution
  const severityData = [
    { name: "Critical", value: scans.reduce((sum, s) => sum + s.critical_count, 0), color: COLORS.CRITICAL },
    { name: "High", value: scans.reduce((sum, s) => sum + s.high_count, 0), color: COLORS.HIGH },
    { name: "Medium", value: scans.reduce((sum, s) => sum + s.medium_count, 0), color: COLORS.MEDIUM },
    { name: "Low", value: scans.reduce((sum, s) => sum + s.low_count, 0), color: COLORS.LOW },
  ].filter((item) => item.value > 0)

  // Recent scans (last 10)
  const recentScans = scans
    .sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime())
    .slice(0, 10)

  // Scan status distribution
  const statusData = [
    { name: "Completed", value: completedScans },
    { name: "Running", value: scans.filter((s) => s.status === "running").length },
    { name: "Pending", value: scans.filter((s) => s.status === "pending").length },
    { name: "Failed", value: scans.filter((s) => s.status === "failed").length },
  ].filter((item) => item.value > 0)
  const maxStatusValue = statusData.reduce((max, item) => Math.max(max, item.value), 0)
  const statusAxisMax = Math.max(maxStatusValue, 1)
  const statusTicks = Array.from({ length: statusAxisMax + 1 }, (_, i) => i)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your security scans and vulnerabilities
        </p>
      </div>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Scan className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalScans}</div>
            <p className="text-xs text-muted-foreground">
              {completedScans} completed
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalVulnerabilities}</div>
            <p className="text-xs text-muted-foreground">
              Across all scans
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Projects</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalProjects}</div>
            <p className="text-xs text-muted-foreground">
              Active projects
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {totalScans > 0 ? Math.round((completedScans / totalScans) * 100) : 0}%
            </div>
            <p className="text-xs text-muted-foreground">
              Scan completion rate
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Vulnerability Severity</CardTitle>
            <CardDescription>Distribution by severity level</CardDescription>
          </CardHeader>
          <CardContent>
            {severityData.length > 0 ? (
              <ChartContainer
                config={{
                  value: {
                    label: "Count",
                  },
                }}
                className="h-[300px] w-full"
              >
                <PieChart>
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${percent ? (percent * 100).toFixed(0) : 0}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ChartContainer>
            ) : (
              <div className="flex items-center justify-center h-[300px] text-muted-foreground">
                No vulnerabilities found
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scan Status</CardTitle>
            <CardDescription>Distribution by status</CardDescription>
          </CardHeader>
          <CardContent>
            {statusData.length > 0 ? (
              <ChartContainer
                config={{
                  value: {
                    label: "Count",
                  },
                }}
                className="h-[300px] w-full"
              >
                <BarChart data={statusData} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                  <XAxis
                    type="number"
                    domain={[0, statusAxisMax]}
                    ticks={statusTicks}
                    allowDecimals={false}
                    tickLine={false}
                    axisLine={false}
                    tickMargin={8}
                  />
                  <YAxis
                    dataKey="name"
                    type="category"
                    tickLine={false}
                    axisLine={false}
                    tickMargin={8}
                  />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar
                    dataKey="value"
                    fill="hsl(var(--chart-1))"
                    radius={4}
                  />
                </BarChart>
              </ChartContainer>
            ) : (
              <div className="flex items-center justify-center h-[300px] text-muted-foreground">
                No scans available
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Scans</CardTitle>
          <CardDescription>Latest scan activities</CardDescription>
        </CardHeader>
        <CardContent>
          {recentScans.length > 0 ? (
            <div className="space-y-4">
              {recentScans.map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between p-4 border rounded-lg cursor-pointer hover:bg-accent transition-colors"
                  onClick={() => navigate(`/scan/${scan.id}`)}
                >
                  <div className="flex items-center space-x-4">
                    <div className="flex flex-col">
                      <span className="font-medium">{scan.target}</span>
                      <span className="text-sm text-muted-foreground">
                        {scan.scan_type} • {scan.id.slice(0, 8)}...
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <div className="text-right">
                      <div className="font-medium">{scan.vulnerability_count} vulnerabilities</div>
                      <div className="text-sm text-muted-foreground flex items-center space-x-1">
                        <Clock className="h-3 w-3" />
                        <span>{new Date(scan.started_at).toLocaleDateString()}</span>
                      </div>
                    </div>
                    <div
                      className={`px-2 py-1 rounded text-xs font-medium ${scan.status === "completed"
                          ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                          : scan.status === "running"
                            ? "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                            : scan.status === "failed"
                              ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                              : "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200"
                        }`}
                    >
                      {scan.status}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-[200px] text-muted-foreground">
              No scans yet
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

