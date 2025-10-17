"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"

const tactics = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
]

// Mock activity levels (0-3: none, low, medium, high)
const activityLevels = tactics.map(() => Math.floor(Math.random() * 4))

export function MitreHeatmap() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>MITRE ATT&CK Tactics Overview</CardTitle>
        <CardDescription>Threat activity by tactic category</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2">
          {tactics.map((tactic, index) => {
            const level = activityLevels[index]
            return (
              <button
                key={tactic}
                className={cn(
                  "p-3 rounded-lg border text-left transition-all hover:scale-105",
                  level === 0 && "bg-muted/30 border-muted",
                  level === 1 && "bg-info/20 border-info/30",
                  level === 2 && "bg-warning/20 border-warning/30",
                  level === 3 && "bg-destructive/20 border-destructive/30",
                )}
              >
                <div className="text-xs font-medium line-clamp-2">{tactic}</div>
                <div className="text-lg font-bold mt-1">
                  {level === 0 ? "0" : level === 1 ? "12" : level === 2 ? "28" : "45"}
                </div>
              </button>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}
