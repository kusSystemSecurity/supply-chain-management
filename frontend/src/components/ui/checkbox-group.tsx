import { Checkbox } from "./checkbox"
import { cn } from "@/lib/utils"

export interface CheckboxGroupProps {
  options: Array<{ value: string; label: string }>
  value: string[]
  onChange: (value: string[]) => void
  className?: string
}

export function CheckboxGroup({ options, value, onChange, className }: CheckboxGroupProps) {
  const handleToggle = (optionValue: string) => {
    if (value.includes(optionValue)) {
      onChange(value.filter((v) => v !== optionValue))
    } else {
      onChange([...value, optionValue])
    }
  }

  return (
    <div className={cn("space-y-2", className)}>
      {options.map((option) => (
        <div key={option.value} className="flex items-center space-x-2">
          <Checkbox
            checked={value.includes(option.value)}
            onChange={() => handleToggle(option.value)}
          />
          <label className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer">
            {option.label}
          </label>
        </div>
      ))}
    </div>
  )
}

