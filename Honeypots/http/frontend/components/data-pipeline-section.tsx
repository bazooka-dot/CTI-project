"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { ArrowRight, Database, GitBranch, Zap } from "lucide-react"

export function DataPipelineSection() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">ETL Data Pipeline</h2>
        <p className="text-muted-foreground">Kafka → Processing → Neo4j/Oracle</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Records Processed</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">2.4M</div>
            <p className="text-xs text-muted-foreground">Today</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Processing Rate</CardTitle>
            <GitBranch className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12.5K/s</div>
            <p className="text-xs text-muted-foreground">Records per second</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Error Rate</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">0.02%</div>
            <p className="text-xs text-muted-foreground">Last hour</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Pipeline Flow</CardTitle>
          <CardDescription>Real-time data processing visualization</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between gap-4">
            <div className="flex-1 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Kafka Topics</span>
                <Badge variant="outline" className="bg-success/10 text-success">
                  Active
                </Badge>
              </div>
              <div className="p-4 rounded-lg bg-muted">
                <div className="font-mono text-xs space-y-1">
                  <div>threat-intel-raw</div>
                  <div>mitre-mappings</div>
                  <div>ioc-feeds</div>
                </div>
              </div>
            </div>

            <ArrowRight className="w-6 h-6 text-muted-foreground shrink-0" />

            <div className="flex-1 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Processing</span>
                <Badge variant="outline" className="bg-info/10 text-info">
                  Running
                </Badge>
              </div>
              <div className="p-4 rounded-lg bg-muted">
                <div className="font-mono text-xs space-y-1">
                  <div>ETL Transform</div>
                  <div>Data Enrichment</div>
                  <div>Validation</div>
                </div>
              </div>
            </div>

            <ArrowRight className="w-6 h-6 text-muted-foreground shrink-0" />

            <div className="flex-1 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Storage</span>
                <Badge variant="outline" className="bg-success/10 text-success">
                  Connected
                </Badge>
              </div>
              <div className="p-4 rounded-lg bg-muted">
                <div className="font-mono text-xs space-y-1">
                  <div>Neo4j Graph</div>
                  <div>Oracle DB</div>
                  <div>Cache Layer</div>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Kafka Topics Status</CardTitle>
          <CardDescription>Message queue health and throughput</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span>threat-intel-raw</span>
              <span className="text-muted-foreground">8,234 msgs/min</span>
            </div>
            <Progress value={85} className="h-2" />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span>mitre-mappings</span>
              <span className="text-muted-foreground">2,156 msgs/min</span>
            </div>
            <Progress value={45} className="h-2" />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span>ioc-feeds</span>
              <span className="text-muted-foreground">5,892 msgs/min</span>
            </div>
            <Progress value={68} className="h-2" />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
