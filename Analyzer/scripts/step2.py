import json
import re
from datetime import datetime
from typing import Dict, Optional

class LogParser:
    """Parses different types of log files"""
    
    def __init__(self):
        # Regex pattern for nginx/apache access logs
        self.access_log_pattern = re.compile(
            r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<url>[^\s]+) HTTP/[\d\.]+"\s+'
            r'(?P<status>\d+) (?P<bytes>\d+) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
    
    def parse_line(self, line: str, file_type: str) -> Optional[Dict]:
        """
        Parse a single log line based on file type
        
        Args:
            line: The log line to parse
            file_type: Type of log file (access.log, access.json, attacks.log)
        
        Returns:
            Dictionary with parsed data or None if parsing fails
        """
        try:
            if file_type == 'access.json':
                return self.parse_json_log(line)
            elif file_type == 'access.log':
                return self.parse_access_log(line)
            elif file_type == 'attacks.log':
                return self.parse_attack_log(line)
            else:
                return None
        except Exception as e:
            print(f"❌ Error parsing line: {e}")
            return None
    
    def parse_json_log(self, line: str) -> Optional[Dict]:
        """Parse JSON formatted log"""
        try:
            data = json.loads(line)
            
            # Enrich with parsed information
            parsed = {
                'log_type': 'json_access',
                'timestamp': data.get('timestamp'),
                'ip': data.get('remote_addr') or data.get('ip'),
                'method': data.get('method'),
                'url': data.get('url') or self._extract_url(data.get('request', '')),
                'status': data.get('status'),
                'user_agent': data.get('http_user_agent') or data.get('userAgent'),
                'request_time': data.get('request_time'),
                'raw_data': data
            }
            
            # Check if it's an auth request
            if 'body' in data and isinstance(data['body'], dict):
                if 'username' in data['body']:
                    parsed['log_type'] = 'authentication'
                    parsed['username'] = data['body'].get('username')
                    parsed['action'] = data['body'].get('action')
            
            return parsed
        except json.JSONDecodeError:
            return None
    
    def parse_access_log(self, line: str) -> Optional[Dict]:
        """Parse standard access log format"""
        match = self.access_log_pattern.match(line)
        if match:
            data = match.groupdict()
            return {
                'log_type': 'access',
                'timestamp': data['timestamp'],
                'ip': data['ip'],
                'method': data['method'],
                'url': data['url'],
                'status': int(data['status']),
                'bytes': int(data['bytes']),
                'referer': data['referer'],
                'user_agent': data['user_agent']
            }
        return None
    
    def parse_attack_log(self, line: str) -> Optional[Dict]:
        """Parse attacks log - combination of access log and JSON"""
        # Try JSON first
        if line.strip().startswith('{'):
            
            return self.parse_json_log(line)
        
        # Try access log format
        parsed = self.parse_access_log(line)
        if parsed:
            parsed['log_type'] = 'potential_attack'
            return parsed
        
        # Try custom attack log format
        if 'Body:' in line:
            parts = line.split(' - ')
            if len(parts) >= 4:
                return {
                    'log_type': 'attack_attempt',
                    'timestamp': parts[0],
                    'ip': parts[1].replace('IP: ', ''),
                    'endpoint': parts[2],
                    'user_agent': parts[3].split(' - Body:')[0].replace('UA: ', ''),
                    'body': parts[3].split('Body: ')[1] if 'Body: ' in parts[3] else None
                }
        
        return None
    
    def _extract_url(self, request: str) -> str:
        """Extract URL from request string like 'GET /path HTTP/1.1'"""
        parts = request.split()
        return parts[1] if len(parts) >= 2 else request
    
    def categorize_event(self, parsed_data: Dict) -> str:
        """
        Categorize the event for Kafka topic routing
        
        Returns:
            Topic name for Kafka
        """
        log_type = parsed_data.get('log_type', '')
        
        if log_type == 'authentication' or log_type == 'attack_attempt':
            return 'security-events'
        
        status = parsed_data.get('status', 0)
        if status >= 400:
            return 'error-logs'
        
        if parsed_data.get('url', '').startswith('/admin'):
            return 'admin-access'
        
        return 'general-logs'


# Test the parser
if __name__ == "__main__":
    parser = LogParser()
    
    # Test samples from your logs
    test_logs = [
        ('access.log', '172.18.0.1 - - [17/Oct/2025:15:50:12 +0000] "GET / HTTP/2.0" 200 2043 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0" "-"'),
        ('access.json', '{"timestamp":"2025-10-17T15:51:11.883Z","ip":"172.18.0.4","method":"POST","url":"/api/auth","userAgent":"Mozilla/5.0","body":{"username":"admin","password":"SecureBackdoor2025!","action":"login"}}'),
    ]
    
    print("🧪 Testing Log Parser\n" + "="*60)
    for file_type, log_line in test_logs:
        print(f"\n📄 File: {file_type}")
        print(f"📝 Input: {log_line[:80]}...")
        
        parsed = parser.parse_line(log_line, file_type)
        if parsed:
            print(f"   Parsed successfully!")
            print(f"   Type: {parsed['log_type']}")
            print(f"   Topic: {parser.categorize_event(parsed)}")
            print(f"   IP: {parsed.get('ip')}")
            print(f"   URL: {parsed.get('url')}")
        else:
            print(" Failed to parse")