import { useState, useEffect } from "react"
import { scansApi } from "@/services/api"
import type { Scan } from "@/types"

export function useScans() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchScans = async () => {
      try {
        setLoading(true)
        const response = await scansApi.getAll()
        setScans(response.scans)
        setError(null)
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to fetch scans")
      } finally {
        setLoading(false)
      }
    }

    fetchScans()
  }, [])

  const refetch = async () => {
    try {
      setLoading(true)
      const response = await scansApi.getAll()
      setScans(response.scans)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch scans")
    } finally {
      setLoading(false)
    }
  }

  return { scans, loading, error, refetch }
}

