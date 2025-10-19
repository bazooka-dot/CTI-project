"""
Basic CTI Log Parser - Produces structured data without hardcoded MITRE techniques
Focuses on raw event data for external correlation systems
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from urllib.parse import unquote

@dataclass
class ThreatEvent:
    """Structured threat event for Neo4j ingestion"""
    timestamp: str
    source_ip: str
    event_type: str
    protocol: str
    severity: str
    mitre_techniques: List[str]
    mitre_tactics: List[str]
    attack_category: str
    confidence: float  # 0.0 to 1.0
    raw_data: Dict
    
    # Protocol-specific fields
    method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    session_id: Optional[str] = None
    
    # Analysis fields
    indicators: List[str] = None  # IOCs, signatures, patterns
    metadata: Dict = None

    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []
        if self.metadata is None:
            self.metadata = {}


class BasicEventAnalyzer:
    """Basic event analyzer without hardcoded MITRE techniques"""
    
    def __init__(self):
        pass
    
    def analyze_attack(self, context: str, event_type: str = None) -> Dict:
        """Basic analysis without MITRE correlation"""
        # Just return basic severity based on event type patterns
        severity = self._determine_basic_severity(context, event_type)
        
        return {
            'techniques': [],  # No hardcoded techniques
            'tactics': [],     # No hardcoded tactics
            'severity': severity,
            'confidence': 0.5,  # Neutral confidence
            'indicators': []    # No pattern-based indicators
        }
    
    def _determine_basic_severity(self, context: str, event_type: str = None) -> str:
        """Determine basic severity without MITRE patterns"""
        context_lower = context.lower() if context else ""
        event_lower = event_type.lower() if event_type else ""
        
        # Basic severity heuristics
        if any(term in context_lower or term in event_lower for term in ['critical', 'attack', 'exploit', 'shell']):
            return 'critical'
        elif any(term in context_lower or term in event_lower for term in ['failed', 'error', 'unauthorized']):
            return 'high'
        elif any(term in context_lower or term in event_lower for term in ['login', 'auth', 'connect']):
            return 'medium'
        else:
            return 'low'


class StandaloneCTIParser:
    """Standalone CTI parser that produces structured data without hardcoded MITRE techniques"""
    
    def __init__(self):
        self.analyzer = BasicEventAnalyzer()
        self.parsed_events = []
    
    def parse_http_logs(self, filepath: str) -> List[ThreatEvent]:
        """Parse HTTP logs and create structured threat events"""
        events = []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    try:
                        event = self._parse_http_line(line.strip())
                        if event:
                            events.append(event)
                    except Exception as e:
                        print(f"[!] Error parsing HTTP line {line_num}: {e}")
                        continue
        
        except Exception as e:
            print(f"[!] Error reading HTTP file: {e}")
        
        print(f"[+] Parsed {len(events)} HTTP events")
        return events
    
    def parse_ssh_logs(self, filepath: str) -> List[ThreatEvent]:
        """Parse SSH logs and create structured threat events"""
        events = []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    try:
                        event = self._parse_ssh_line(line.strip())
                        if event:
                            events.append(event)
                    except Exception as e:
                        print(f"[!] Error parsing SSH line {line_num}: {e}")
                        continue
        
        except Exception as e:
            print(f"[!] Error reading SSH file: {e}")
        
        print(f"[+] Parsed {len(events)} SSH events")
        return events
    
    def _parse_http_line(self, line: str) -> Optional[ThreatEvent]:
        """Parse single HTTP log line"""
        try:
            data = json.loads(line)
            
            # Extract basic info from different log formats
            # Handle "GET /path HTTP/1.1" format
            request_line = data.get('request', '')
            if request_line:
                parts = request_line.split(' ')
                method = parts[0] if len(parts) > 0 else 'GET'
                url = parts[1] if len(parts) > 1 else '/'
            else:
                method = data.get('request_method', 'GET')
                url = data.get('request_path', '/')
            
            status_code = data.get('status', data.get('response_code', 200))
            user_agent = data.get('http_user_agent', data.get('user_agent', ''))
            source_ip = data.get('remote_addr', '')
            timestamp = data.get('timestamp', data.get('@timestamp', datetime.now().isoformat()))
            
            # Create analysis context
            context = f"{method} {url} {user_agent}"
            
            # Basic analysis without hardcoded MITRE techniques
            analysis = self.analyzer.analyze_attack(context, "http_request")
            
            # Determine attack category
            attack_category = self._categorize_http_attack(url, user_agent, method)
            
            return ThreatEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=attack_category,
                protocol='HTTP',
                severity=analysis['severity'],
                mitre_techniques=analysis['techniques'],
                mitre_tactics=analysis['tactics'],
                attack_category=attack_category,
                confidence=analysis['confidence'],
                raw_data=data,
                method=method,
                url=url,
                status_code=status_code,
                user_agent=user_agent,
                indicators=analysis['indicators'],
                metadata={
                    'url_decoded': unquote(url),
                    'is_suspicious_ua': self._is_suspicious_ua(user_agent),
                    'path_depth': len(url.split('/')) - 1
                }
            )
        
        except Exception as e:
            print(f"[!] HTTP parse error: {e}")
            return None
    
    def _parse_ssh_line(self, line: str) -> Optional[ThreatEvent]:
        """Parse single SSH log line"""
        try:
            data = json.loads(line)
            
            # Extract basic info
            event_id = data.get('eventid', '')
            source_ip = data.get('src_ip', '')
            timestamp = data.get('timestamp', datetime.now().isoformat())
            username = data.get('username')
            password = data.get('password')
            command = data.get('input')
            session_id = data.get('session', '')
            
            # Create analysis context
            context_parts = [event_id]
            if command:
                context_parts.append(command)
            if username:
                context_parts.append(f"user:{username}")
            
            context = " ".join(context_parts)
            
            # Basic analysis without hardcoded MITRE techniques
            analysis = self.analyzer.analyze_attack(context, event_id)
            
            # Determine attack category and event type
            attack_category, event_type = self._categorize_ssh_event(event_id, command, username, password)
            
            return ThreatEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=event_type,
                protocol='SSH',
                severity=analysis['severity'],
                mitre_techniques=analysis['techniques'],
                mitre_tactics=analysis['tactics'],
                attack_category=attack_category,
                confidence=analysis['confidence'],
                raw_data=data,
                username=username,
                password=password,
                command=command,
                session_id=session_id,
                indicators=analysis['indicators'],
                metadata={
                    'event_id': event_id,
                    'has_credentials': bool(username and password),
                    'command_length': len(command) if command else 0,
                    'is_privileged_command': self._is_privileged_command(command) if command else False
                }
            )
        
        except Exception as e:
            print(f"[!] SSH parse error: {e}")
            return None
    
    def _categorize_http_attack(self, url: str, user_agent: str, method: str) -> str:
        """Categorize HTTP attack type"""
        url_lower = url.lower()
        ua_lower = user_agent.lower()
        
        # Environment/Config file access
        if any(pattern in url_lower for pattern in ['.env', '.git/', 'config.php', '.aws/', '.ssh/']):
            return 'Information Disclosure'
        
        # Admin panel access
        if any(pattern in url_lower for pattern in ['admin', 'phpmyadmin', 'wp-admin', 'cpanel']):
            return 'Admin Panel Access'
        
        # CGI/Script exploitation
        if 'cgi-bin' in url_lower or 'shell.php' in url_lower:
            return 'Web Shell Access'
        
        # Scanning/reconnaissance
        if any(scanner in ua_lower for scanner in ['nmap', 'masscan', 'zgrab', 'bot', 'crawler']):
            return 'Automated Scanning'
        
        # Proxy abuse
        if method == 'CONNECT':
            return 'Proxy Abuse'
        
        return 'Web Request'
    
    def _categorize_ssh_event(self, event_id: str, command: str, username: str, password: str) -> tuple:
        """Categorize SSH event type"""
        if 'login.success' in event_id:
            return 'Authentication', 'Successful Login'
        
        if 'login.failed' in event_id:
            return 'Authentication', 'Failed Login Attempt'
        
        if 'session.connect' in event_id:
            return 'Connection', 'SSH Connection'
        
        if 'command.input' in event_id and command:
            if any(dangerous in command.lower() for dangerous in ['rm -rf', 'dd if=', 'shred']):
                return 'Impact', 'Destructive Command'
            elif any(tool in command.lower() for tool in ['wget', 'curl', 'ftp']):
                return 'Exfiltration', 'File Transfer'
            elif any(recon in command.lower() for recon in ['whoami', 'uname', 'ps aux']):
                return 'Discovery', 'System Reconnaissance'
            else:
                return 'Execution', 'Command Execution'
        
        if 'session.file_download' in event_id:
            return 'Exfiltration', 'File Download'
        
        return 'Connection', 'SSH Activity'
    
    def _is_suspicious_ua(self, user_agent: str) -> bool:
        """Check if user agent is suspicious"""
        suspicious_patterns = ['nmap', 'masscan', 'zgrab', 'sqlmap', 'nikto', 'dirb', 'gobuster']
        return any(pattern in user_agent.lower() for pattern in suspicious_patterns)
    
    def _is_privileged_command(self, command: str) -> bool:
        """Check if command requires privileges"""
        if not command:
            return False
        privileged_patterns = ['sudo', 'su -', 'chmod +x', 'iptables', 'systemctl']
        return any(pattern in command.lower() for pattern in privileged_patterns)
    
    def generate_summary(self, events: List[ThreatEvent]) -> Dict:
        """Generate basic summary without hardcoded MITRE techniques"""
        if not events:
            return {}
        
        # Basic statistics
        unique_ips = len(set(event.source_ip for event in events))
        attack_types = {}
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        ip_counts = {}
        
        for event in events:
            # Count attack types
            attack_types[event.event_type] = attack_types.get(event.event_type, 0) + 1
            
            # Count severity
            severity_counts[event.severity] += 1
            
            # Count IPs
            ip_counts[event.source_ip] = ip_counts.get(event.source_ip, 0) + 1
        
        return {
            'total_events': len(events),
            'unique_ips': unique_ips,
            'attack_types': attack_types,
            'severity_counts': severity_counts,
            'top_attackers': sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'high_critical_count': severity_counts['high'] + severity_counts['critical'],
            'confidence_distribution': self._calculate_confidence_distribution(events)
        }
    
    def _calculate_confidence_distribution(self, events: List[ThreatEvent]) -> Dict:
        """Calculate confidence score distribution"""
        confidence_ranges = {'high': 0, 'medium': 0, 'low': 0}
        
        for event in events:
            if event.confidence >= 0.7:
                confidence_ranges['high'] += 1
            elif event.confidence >= 0.4:
                confidence_ranges['medium'] += 1
            else:
                confidence_ranges['low'] += 1
        
        return confidence_ranges
    
    def export_for_neo4j(self, events: List[ThreatEvent], output_file: str):
        """Export events in Neo4j-ready format"""
        export_data = {
            'metadata': {
                'export_timestamp': datetime.now().isoformat(),
                'total_events': len(events),
                'parser_version': '3.0_no_hardcoded_mitre',
                'format': 'structured_events_for_correlation'
            },
            'events': [asdict(event) for event in events]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Exported {len(events)} events to {output_file}")
        print(f"    Format: Structured events without hardcoded MITRE techniques")


if __name__ == '__main__':
    # Test the basic parser
    parser = StandaloneCTIParser()
    
    # Test HTTP parsing
    print("Testing HTTP parsing...")
    try:
        http_events = parser.parse_http_logs('http/frontend/access.log')
        if http_events:
            print(f"Sample HTTP event: {http_events[0].event_type} - severity: {http_events[0].severity}")
    except:
        print("No HTTP logs found")
    
    # Test SSH parsing
    print("\nTesting SSH parsing...")
    try:
        ssh_events = parser.parse_ssh_logs('ssh & telnet/logs/cowrie.json')
        if ssh_events:
            print(f"Sample SSH event: {ssh_events[0].event_type} - severity: {ssh_events[0].severity}")
    except:
        print("No SSH logs found")