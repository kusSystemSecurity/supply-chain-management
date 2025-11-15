import { useState, useEffect } from "react"
import { projectsApi } from "@/services/api"
import type { Project } from "@/types"

export function useProjects() {
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchProjects = async () => {
      try {
        setLoading(true)
        const response = await projectsApi.getAll()
        setProjects(response.projects)
        setError(null)
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to fetch projects")
      } finally {
        setLoading(false)
      }
    }

    fetchProjects()
  }, [])

  const refetch = async () => {
    try {
      setLoading(true)
      const response = await projectsApi.getAll()
      setProjects(response.projects)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch projects")
    } finally {
      setLoading(false)
    }
  }

  return { projects, loading, error, refetch }
}

