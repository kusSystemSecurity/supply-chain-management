import { BrowserRouter, Routes, Route } from "react-router-dom"
import { ThemeProvider } from "@/components/theme-provider"
import { Layout } from "@/components/layout/layout"
import { ErrorBoundary } from "@/components/error-boundary"
import { Dashboard } from "@/pages/Dashboard"
import { CreateScan } from "@/pages/CreateScan"
import { ScanDetail } from "@/pages/ScanDetail"
import { AIAnalysisPage } from "@/pages/AIAnalysis"

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="system" storageKey="securechain-ui-theme">
        <BrowserRouter>
          <Layout>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/create-scan" element={<CreateScan />} />
              <Route path="/scan/:scanId" element={<ScanDetail />} />
              <Route path="/ai-analysis" element={<AIAnalysisPage />} />
            </Routes>
          </Layout>
        </BrowserRouter>
      </ThemeProvider>
    </ErrorBoundary>
  )
}

export default App
