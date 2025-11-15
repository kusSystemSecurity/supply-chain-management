import { Link, useLocation } from "react-router-dom"
import { Shield, BarChart3, Brain } from "lucide-react"
import { ThemeToggle } from "@/components/theme-toggle"
import { cn } from "@/lib/utils"

export function Navbar() {
  const location = useLocation()

  const navItems = [
    { path: "/", label: "Dashboard", icon: BarChart3 },
    { path: "/create-scan", label: "Create Scan", icon: Shield },
    { path: "/ai-analysis", label: "AI Analysis", icon: Brain },
  ]

  return (
    <nav className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-14 items-center">
        <div className="mr-4 flex items-center space-x-2">
          <Shield className="h-6 w-6" />
          <span className="font-bold text-xl">SecureChain AI</span>
        </div>
        <div className="flex flex-1 items-center space-x-6">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = location.pathname === item.path
            return (
              <Link
                key={item.path}
                to={item.path}
                className={cn(
                  "flex items-center space-x-2 text-sm font-medium transition-colors hover:text-primary",
                  isActive
                    ? "text-foreground"
                    : "text-muted-foreground"
                )}
              >
                <Icon className="h-4 w-4" />
                <span>{item.label}</span>
              </Link>
            )
          })}
        </div>
        <div className="flex items-center space-x-2">
          <ThemeToggle />
        </div>
      </div>
    </nav>
  )
}

