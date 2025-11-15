import { useState } from "react"
import { aiAnalysisApi } from "@/services/api"
import type { AIAnalysis, AIAnalysisRequest } from "@/types"

export function useAIAnalysis() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const runAnalysis = async (request: AIAnalysisRequest): Promise<AIAnalysis | null> => {
    try {
      setLoading(true)
      setError(null)
      const result = await aiAnalysisApi.run(request)
      return result
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to run AI analysis"
      setError(errorMessage)
      return null
    } finally {
      setLoading(false)
    }
  }

  return { runAnalysis, loading, error }
}

