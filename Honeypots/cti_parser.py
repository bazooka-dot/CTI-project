"""
CTI Automated Parser - All-in-One
==================================
Complete automated honeypot log parser with built-in parsing logic.
No external dependencies - everything in one script.

Features:
- Continuous monitoring with checkpoint system
- Smart resume (no output = fresh start, has output = resume)
- Built-in SSH and HTTP parsing
- Clean JSON output
- Production-ready

Usage:
    python3 cti_parser.py [--interval SECONDS] [--output-dir DIR]
"""

import os
import sys
import json
import time
import signal
import argparse
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from urllib.parse import unquote


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ThreatEvent:
    """Structured threat event"""
    timestamp: str
    source_ip: str
    event_type: str
    protocol: str
    severity: str
    mitre_techniques: List[str]
    mitre_tactics: List[str]
    attack_category: str
    confidence: float
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
    indicators: List[str] = None
    metadata: Dict = None

    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ParserConfig:
    """Configuration for the automated parser"""
    check_interval: int = 5
    checkpoint_file: str = ".cti_checkpoint.json"
    output_dir: str = "cti_output"
    ssh_log_paths: List[str] = None
    http_log_paths: List[str] = None
    
    def __post_init__(self):
        if self.ssh_log_paths is None:
            self.ssh_log_paths = [
                "cowrie/logs/cowrie.json",
                "cowrie.json",
                "ssh.json",
                "logs/cowrie.json"
            ]
        
        if self.http_log_paths is None:
            self.http_log_paths = [
                "http/logs/access.json",
                "http/logs/access.log",
                "http/frontend/access.log",
                "http/access.log",
                "access.log",
                "logs/access.log",
                "nginx/access.log"
            ]


# ============================================================================
# EVENT PARSER
# ============================================================================

class EventParser:
    """Parses SSH and HTTP log lines into ThreatEvents"""
    
    def parse_ssh_line(self, line: str) -> Optional[ThreatEvent]:
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
            
            # Determine severity
            severity = self._determine_severity(event_id, command)
            
            # Categorize event
            attack_category, event_type = self._categorize_ssh_event(event_id, command, username, password)
            
            return ThreatEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=event_type,
                protocol='SSH',
                severity=severity,
                mitre_techniques=[],
                mitre_tactics=[],
                attack_category=attack_category,
                confidence=0.5,
                raw_data=data,
                username=username,
                password=password,
                command=command,
                session_id=session_id,
                indicators=[],
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
    
    def parse_http_line(self, line: str) -> Optional[ThreatEvent]:
        """Parse single HTTP log line"""
        try:
            data = json.loads(line)
            
            # Extract basic info from different log formats
            request_line = data.get('request', '')
            if request_line:
                parts = request_line.split(' ')
                method = parts[0] if len(parts) > 0 else 'GET'
                url = parts[1] if len(parts) > 1 else '/'
            else:
                method = data.get('request_method', data.get('method', 'GET'))
                url = data.get('request_path', data.get('url', '/'))
            
            status_code = data.get('status', data.get('response_code', 200))
            user_agent = data.get('http_user_agent', data.get('user_agent', data.get('userAgent', '')))
            source_ip = data.get('remote_addr', data.get('ip', ''))
            timestamp = data.get('timestamp', data.get('@timestamp', datetime.now().isoformat()))
            
            # Determine severity
            severity = self._determine_http_severity(url, user_agent, method, status_code)
            
            # Categorize attack
            attack_category = self._categorize_http_attack(url, user_agent, method)
            
            return ThreatEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=attack_category,
                protocol='HTTP',
                severity=severity,
                mitre_techniques=[],
                mitre_tactics=[],
                attack_category=attack_category,
                confidence=0.5,
                raw_data=data,
                method=method,
                url=url,
                status_code=status_code,
                user_agent=user_agent,
                indicators=[],
                metadata={
                    'url_decoded': unquote(url),
                    'is_suspicious_ua': self._is_suspicious_ua(user_agent),
                    'path_depth': len(url.split('/')) - 1
                }
            )
        
        except Exception as e:
            print(f"[!] HTTP parse error: {e}")
            return None
    
    def _determine_severity(self, event_id: str, command: str) -> str:
        """Determine severity for SSH events"""
        if 'login.success' in event_id:
            return 'high'
        
        if command:
            cmd_lower = command.lower()
            if any(dangerous in cmd_lower for dangerous in ['rm -rf', 'dd if=', 'shred', 'mkfs']):
                return 'critical'
            elif any(tool in cmd_lower for tool in ['wget', 'curl', 'nc ', 'netcat']):
                return 'high'
            elif any(recon in cmd_lower for recon in ['whoami', 'uname', 'ps aux']):
                return 'medium'
        
        if 'login.failed' in event_id:
            return 'medium'
        
        return 'low'
    
    def _determine_http_severity(self, url: str, user_agent: str, method: str, status: int) -> str:
        """Determine severity for HTTP events"""
        url_lower = url.lower()
        ua_lower = user_agent.lower()
        
        # Critical patterns
        if any(pattern in url_lower for pattern in ['shell.php', 'cmd.php', 'eval']):
            return 'critical'
        
        # High severity
        if any(pattern in url_lower for pattern in ['.env', '.git', 'config.php', '.aws']):
            return 'high'
        
        if any(scanner in ua_lower for scanner in ['sqlmap', 'nikto', 'nmap']):
            return 'high'
        
        # Medium severity
        if method == 'CONNECT' or 'admin' in url_lower:
            return 'medium'
        
        # Low severity
        return 'low'
    
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


# ============================================================================
# CHECKPOINT MANAGER
# ============================================================================

class CheckpointManager:
    """Manages file position checkpoints for resumable parsing"""
    
    def __init__(self, checkpoint_file: str):
        self.checkpoint_file = checkpoint_file
        self.checkpoints = self._load_checkpoints()
        self.output_files_exist = {}
    
    def _load_checkpoints(self) -> Dict:
        """Load checkpoints from file"""
        if not os.path.exists(self.checkpoint_file):
            return {}
        
        try:
            with open(self.checkpoint_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading checkpoints: {e}")
            return {}
    
    def save_checkpoints(self):
        """Save checkpoints to file"""
        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump(self.checkpoints, f, indent=2)
        except Exception as e:
            print(f"[!] Error saving checkpoints: {e}")
    
    def set_output_exists(self, log_type: str, exists: bool):
        """Track whether output file exists for this log type"""
        self.output_files_exist[log_type] = exists
    
    def should_use_checkpoint(self, filepath: str, log_type: str) -> bool:
        """Determine if we should use checkpoint or start from beginning"""
        return self.output_files_exist.get(log_type, False)
    
    def get_position(self, filepath: str, log_type: str = None) -> Dict:
        """Get checkpoint data for a file"""
        abs_path = os.path.abspath(filepath)
        
        if log_type and not self.should_use_checkpoint(filepath, log_type):
            print(f"[+] No existing output file for {log_type.upper()}, starting from beginning")
            return {'offset': 0, 'inode': None, 'last_timestamp': None, 'lines_processed': 0}
        
        return self.checkpoints.get(abs_path, {'offset': 0, 'inode': None, 'last_timestamp': None, 'lines_processed': 0})
    
    def update_position(self, filepath: str, offset: int, inode: int, last_timestamp: str = None):
        """Update checkpoint for a file"""
        abs_path = os.path.abspath(filepath)
        
        if abs_path not in self.checkpoints:
            self.checkpoints[abs_path] = {'offset': 0, 'inode': None, 'last_timestamp': None, 'lines_processed': 0}
        
        self.checkpoints[abs_path]['offset'] = offset
        self.checkpoints[abs_path]['inode'] = inode
        self.checkpoints[abs_path]['last_timestamp'] = last_timestamp or datetime.now().isoformat()
        self.checkpoints[abs_path]['lines_processed'] = self.checkpoints[abs_path].get('lines_processed', 0) + 1
        
        self.save_checkpoints()
    
    def detect_rotation(self, filepath: str) -> bool:
        """Detect if log file was rotated"""
        if not os.path.exists(filepath):
            return False
        
        checkpoint = self.get_position(filepath)
        current_inode = os.stat(filepath).st_ino
        current_size = os.path.getsize(filepath)
        
        if checkpoint['inode'] and checkpoint['inode'] != current_inode:
            print(f"[!] Rotation detected (inode change): {filepath}")
            return True
        
        if current_size < checkpoint['offset']:
            print(f"[!] Rotation detected (size decrease): {filepath}")
            return True
        
        return False
    
    def reset_position(self, filepath: str):
        """Reset checkpoint after rotation"""
        abs_path = os.path.abspath(filepath)
        if abs_path in self.checkpoints:
            self.checkpoints[abs_path]['offset'] = 0
            self.save_checkpoints()


# ============================================================================
# LOG TAILER
# ============================================================================

class LogTailer:
    """Tails log files and yields new lines"""
    
    def __init__(self, filepath: str, checkpoint_manager: CheckpointManager, log_type: str = None):
        self.filepath = filepath
        self.checkpoint_manager = checkpoint_manager
        self.log_type = log_type
        self.file_handle = None
    
    def open(self):
        """Open file at checkpoint position"""
        checkpoint = self.checkpoint_manager.get_position(self.filepath, self.log_type)
        
        try:
            self.file_handle = open(self.filepath, 'r', encoding='utf-8')
            
            if checkpoint['offset'] > 0:
                self.file_handle.seek(checkpoint['offset'])
                print(f"[+] Resuming from offset {checkpoint['offset']} in {self.filepath}")
            else:
                print(f"[+] Starting from beginning of {self.filepath}")
            
            return True
        except Exception as e:
            print(f"[!] Error opening {self.filepath}: {e}")
            return False
    
    def close(self):
        """Close file handle"""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
    
    def read_new_lines(self) -> List[str]:
        """Read new lines from file"""
        if not self.file_handle:
            if not self.open():
                return []
        
        new_lines = []
        
        try:
            if self.checkpoint_manager.detect_rotation(self.filepath):
                self.close()
                self.checkpoint_manager.reset_position(self.filepath)
                if not self.open():
                    return []
            
            while True:
                line = self.file_handle.readline()
                if not line:
                    break
                
                if line.strip():
                    new_lines.append(line.strip())
            
            if new_lines:
                current_pos = self.file_handle.tell()
                current_inode = os.stat(self.filepath).st_ino
                self.checkpoint_manager.update_position(self.filepath, current_pos, current_inode)
        
        except Exception as e:
            print(f"[!] Error reading {self.filepath}: {e}")
            self.close()
        
        return new_lines


# ============================================================================
# OUTPUT MANAGER
# ============================================================================

class OutputManager:
    """Manages clean JSON output files"""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.current_files = {'ssh': None, 'http': None, 'summary': None}
        self.event_counts = {'ssh': 0, 'http': 0, 'total': 0}
        self.all_events = {'ssh': [], 'http': []}
    
    def _find_existing_output(self, protocol: str) -> Optional[Path]:
        """Find existing output file for protocol"""
        pattern = f"cti_{protocol}_*.json"
        existing_files = list(self.output_dir.glob(pattern))
        
        if existing_files:
            return max(existing_files, key=lambda p: p.stat().st_mtime)
        return None
    
    def _load_existing_events(self, filepath: Path, protocol: str):
        """Load events from existing output file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if 'events' in data:
                for event_dict in data['events']:
                    event = ThreatEvent(**event_dict)
                    self.all_events[protocol].append(event)
                
                print(f"[+] Loaded {len(data['events'])} existing {protocol.upper()} events from {filepath.name}")
                return len(data['events'])
        except Exception as e:
            print(f"[!] Error loading existing events from {filepath}: {e}")
        
        return 0
    
    def _get_output_filename(self, protocol: str) -> str:
        """Generate output filename with timestamp"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.output_dir / f"cti_{protocol}_{timestamp}.json"
    
    def initialize_output(self, protocol: str):
        """Initialize output file - use existing or create new"""
        protocol_lower = protocol.lower()
        
        existing_file = self._find_existing_output(protocol_lower)
        
        if existing_file:
            self.current_files[protocol_lower] = existing_file
            count = self._load_existing_events(existing_file, protocol_lower)
            self.event_counts[protocol_lower] = count
            self.event_counts['total'] += count
            print(f"[+] Resuming with existing output file: {existing_file.name}")
        else:
            self.current_files[protocol_lower] = self._get_output_filename(protocol_lower)
            print(f"[+] Creating new output file: {self.current_files[protocol_lower].name}")
    
    def append_events(self, events: List[ThreatEvent], protocol: str):
        """Append events and write clean JSON output"""
        if not events:
            return
        
        protocol_lower = protocol.lower()
        
        if not self.current_files.get(protocol_lower):
            self.initialize_output(protocol)
        
        self.all_events[protocol_lower].extend(events)
        
        try:
            export_data = {
                'metadata': {
                    'export_timestamp': datetime.now().isoformat(),
                    'total_events': len(self.all_events[protocol_lower]),
                    'parser_version': '1.0_all_in_one',
                    'protocol': protocol.upper()
                },
                'events': [asdict(event) for event in self.all_events[protocol_lower]]
            }
            
            with open(self.current_files[protocol_lower], 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            self.event_counts[protocol_lower] = len(self.all_events[protocol_lower])
            self.event_counts['total'] = sum(len(events) for events in self.all_events.values())
            
            print(f"[+] Updated {protocol} events: {len(events)} new (total: {len(self.all_events[protocol_lower])})")
        
        except Exception as e:
            print(f"[!] Error writing events: {e}")
    
    def write_summary(self, summary: Dict):
        """Write summary file"""
        summary_file = self.output_dir / f"cti_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            
            print(f"[+] Summary written to {summary_file.name}")
        
        except Exception as e:
            print(f"[!] Error writing summary: {e}")
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        return {
            'ssh_events': self.event_counts['ssh'],
            'http_events': self.event_counts['http'],
            'total_events': self.event_counts['total'],
            'output_files': {k: str(v) for k, v in self.current_files.items() if v}
        }
    
    def generate_summary(self) -> Dict:
        """Generate summary from all events"""
        all_events = self.all_events['ssh'] + self.all_events['http']
        
        if not all_events:
            return {}
        
        unique_ips = len(set(event.source_ip for event in all_events))
        attack_types = {}
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        ip_counts = {}
        
        for event in all_events:
            attack_types[event.event_type] = attack_types.get(event.event_type, 0) + 1
            severity_counts[event.severity] += 1
            ip_counts[event.source_ip] = ip_counts.get(event.source_ip, 0) + 1
        
        return {
            'total_events': len(all_events),
            'unique_ips': unique_ips,
            'attack_types': attack_types,
            'severity_counts': severity_counts,
            'top_attackers': sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'high_critical_count': severity_counts['high'] + severity_counts['critical']
        }


# ============================================================================
# AUTOMATED PARSER
# ============================================================================

class AutomatedCTIParser:
    """Main automated parser"""
    
    def __init__(self, config: ParserConfig):
        self.config = config
        self.checkpoint_manager = CheckpointManager(config.checkpoint_file)
        self.output_manager = OutputManager(config.output_dir)
        self.event_parser = EventParser()
        
        self.log_files = {}
        self.tailers = {}
        self.running = False
        
        self.stats = {
            'start_time': None,
            'cycles': 0,
            'ssh_events_parsed': 0,
            'http_events_parsed': 0,
            'total_events': 0
        }
        
        self._discover_logs()
    
    def _discover_logs(self):
        """Discover available log files"""
        discovered = {}
        
        for path in self.config.ssh_log_paths:
            if os.path.exists(path):
                discovered['ssh'] = path
                print(f"[+] Discovered SSH log: {path}")
                break
        
        for path in self.config.http_log_paths:
            if os.path.exists(path):
                discovered['http'] = path
                print(f"[+] Discovered HTTP log: {path}")
                break
        
        self.log_files = discovered
        return discovered
    
    def _setup_tailers(self):
        """Setup log tailers"""
        for log_type, filepath in self.log_files.items():
            existing_output = self.output_manager._find_existing_output(log_type)
            self.checkpoint_manager.set_output_exists(log_type, existing_output is not None)
            
            self.tailers[log_type] = LogTailer(filepath, self.checkpoint_manager, log_type)
    
    def _parse_new_events(self, log_type: str, lines: List[str]) -> List[ThreatEvent]:
        """Parse new log lines"""
        events = []
        
        for line in lines:
            try:
                if log_type == 'ssh':
                    event = self.event_parser.parse_ssh_line(line)
                elif log_type == 'http':
                    event = self.event_parser.parse_http_line(line)
                else:
                    continue
                
                if event:
                    events.append(event)
            
            except Exception as e:
                print(f"[!] Error parsing {log_type} line: {e}")
                continue
        
        return events
    
    def _process_logs(self):
        """Process new log entries"""
        for log_type, tailer in self.tailers.items():
            new_lines = tailer.read_new_lines()
            
            if not new_lines:
                continue
            
            print(f"[+] Found {len(new_lines)} new {log_type.upper()} lines")
            
            events = self._parse_new_events(log_type, new_lines)
            
            if events:
                print(f"[+] Parsed {len(events)} {log_type.upper()} events")
                
                self.output_manager.append_events(events, log_type.upper())
                
                self.stats[f'{log_type}_events_parsed'] += len(events)
                self.stats['total_events'] += len(events)
    
    def _display_stats(self):
        """Display current statistics"""
        if self.stats['start_time']:
            runtime = (datetime.now() - self.stats['start_time']).total_seconds()
            rate = self.stats['total_events'] / runtime if runtime > 0 else 0
        else:
            runtime = 0
            rate = 0
        
        output_stats = self.output_manager.get_stats()
        
        print("\n" + "=" * 70)
        print("📊 PARSER STATISTICS")
        print("=" * 70)
        print(f"⏱️  Runtime: {int(runtime)}s | Cycles: {self.stats['cycles']}")
        print(f"📈 Events: SSH={self.stats['ssh_events_parsed']} | HTTP={self.stats['http_events_parsed']} | Total={self.stats['total_events']}")
        print(f"⚡ Rate: {rate:.2f} events/sec")
        print(f"💾 Output Files:")
        for protocol, filepath in output_stats['output_files'].items():
            if filepath:
                print(f"   • {protocol.upper()}: {filepath}")
        print("=" * 70 + "\n")
    
    def start(self):
        """Start automated parsing"""
        print("=" * 70)
        print("🚀 AUTOMATED CTI PARSER")
        print("=" * 70)
        print(f"⚙️  Configuration:")
        print(f"   • Check interval: {self.config.check_interval}s")
        print(f"   • Output directory: {self.config.output_dir}")
        print(f"   • Checkpoint file: {self.config.checkpoint_file}")
        print()
        
        if not self.log_files:
            print("❌ No log files discovered!")
            print("   Expected locations:")
            print("   • SSH: cowrie/logs/cowrie.json")
            print("   • HTTP: http/frontend/access.log")
            sys.exit(1)
        
        print(f"📁 Monitoring {len(self.log_files)} log file(s):")
        for log_type, filepath in self.log_files.items():
            print(f"   • {log_type.upper()}: {filepath}")
        print()
        
        self._setup_tailers()
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        print("✅ Parser is running... (Press Ctrl+C to stop)")
        print("=" * 70)
        print()
        
        try:
            while self.running:
                self._process_logs()
                
                self.stats['cycles'] += 1
                
                if self.stats['cycles'] % 10 == 0:
                    self._display_stats()
                    
                    summary = self.output_manager.generate_summary()
                    if summary:
                        self.output_manager.write_summary(summary)
                
                time.sleep(self.config.check_interval)
        
        except KeyboardInterrupt:
            print("\n\n⏹️  Shutting down gracefully...")
            self.stop()
    
    def stop(self):
        """Stop automated parsing"""
        self.running = False
        
        for tailer in self.tailers.values():
            tailer.close()
        
        self._display_stats()
        
        print("\n" + "=" * 70)
        print("✅ PARSER STOPPED")
        print("=" * 70)
        print(f"📈 Session Summary:")
        print(f"   • Total cycles: {self.stats['cycles']}")
        print(f"   • Events processed: {self.stats['total_events']}")
        print(f"   • SSH events: {self.stats['ssh_events_parsed']}")
        print(f"   • HTTP events: {self.stats['http_events_parsed']}")
        print("=" * 70)


# ============================================================================
# MAIN
# ============================================================================

def signal_handler(sig, frame, parser):
    """Handle interrupt signals gracefully"""
    print(f"\n[!] Received signal {sig}")
    parser.stop()
    sys.exit(0)


def main():
    parser_arg = argparse.ArgumentParser(description="Automated CTI Parser - All-in-One")
    
    parser_arg.add_argument('--interval', type=int, default=5, help='Check interval in seconds (default: 5)')
    parser_arg.add_argument('--output-dir', type=str, default='cti_output', help='Output directory (default: cti_output)')
    parser_arg.add_argument('--checkpoint', type=str, default='.cti_checkpoint.json', help='Checkpoint file (default: .cti_checkpoint.json)')
    
    args = parser_arg.parse_args()
    
    config = ParserConfig(
        check_interval=args.interval,
        output_dir=args.output_dir,
        checkpoint_file=args.checkpoint
    )
    
    parser = AutomatedCTIParser(config)
    
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, parser))
    signal.signal(signal.SIGTERM, lambda sig, frame: signal_handler(sig, frame, parser))
    
    parser.start()


if __name__ == '__main__':
    main()
