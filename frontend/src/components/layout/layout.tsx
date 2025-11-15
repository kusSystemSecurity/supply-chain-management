import type { ReactNode } from "react"
import { Navbar } from "./navbar"

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-background px-4 sm:px-6 lg:px-8">
      <Navbar />
      <main className="container py-6">{children}</main>
    </div>
  )
}

