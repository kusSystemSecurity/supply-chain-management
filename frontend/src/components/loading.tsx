import { Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"

interface LoadingProps {
  className?: string
  size?: "sm" | "md" | "lg"
}

export function Loading({ className, size = "md" }: LoadingProps) {
  return (
    <div className={cn("flex items-center justify-center", className)}>
      <Loader2
        className={cn(
          "animate-spin text-muted-foreground",
          {
            "h-4 w-4": size === "sm",
            "h-6 w-6": size === "md",
            "h-8 w-8": size === "lg",
          }
        )}
      />
    </div>
  )
}

