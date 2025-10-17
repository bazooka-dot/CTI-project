import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

const threats = [
  {
    id: "THR-2024-001",
    source: "AlienVault OTX",
    type: "Malware",
    severity: "Critical",
    timestamp: "2024-01-15 14:32:18",
    ioc: "192.168.1.100",
  },
  {
    id: "THR-2024-002",
    source: "MISP Feed",
    type: "Phishing",
    severity: "High",
    timestamp: "2024-01-15 14:28:45",
    ioc: "malicious-domain.com",
  },
  {
    id: "THR-2024-003",
    source: "Threat Intel API",
    type: "C2 Server",
    severity: "Critical",
    timestamp: "2024-01-15 14:15:22",
    ioc: "10.0.0.50",
  },
  {
    id: "THR-2024-004",
    source: "Internal Detection",
    type: "Anomaly",
    severity: "Medium",
    timestamp: "2024-01-15 14:05:11",
    ioc: "user@company.com",
  },
  {
    id: "THR-2024-005",
    source: "VirusTotal",
    type: "Malicious File",
    severity: "High",
    timestamp: "2024-01-15 13:58:33",
    ioc: "SHA256:a3f2e1...",
  },
]

export function RecentThreatsTable() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Threat Detections</CardTitle>
        <CardDescription>Latest threats from all sources</CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>IOC</TableHead>
              <TableHead>Timestamp</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {threats.map((threat) => (
              <TableRow key={threat.id}>
                <TableCell className="font-mono text-xs">{threat.id}</TableCell>
                <TableCell>{threat.source}</TableCell>
                <TableCell>{threat.type}</TableCell>
                <TableCell>
                  <Badge
                    variant={
                      threat.severity === "Critical"
                        ? "destructive"
                        : threat.severity === "High"
                          ? "default"
                          : "secondary"
                    }
                  >
                    {threat.severity}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">{threat.ioc}</TableCell>
                <TableCell className="text-xs text-muted-foreground">{threat.timestamp}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
