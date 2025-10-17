import json
import time
import re
from datetime import datetime
from typing import Dict, Optional
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from kafka import KafkaProducer
from kafka.errors import KafkaError


class LogParser:
    """Parses different types of log files"""
    
    def __init__(self):
        self.access_log_pattern = re.compile(
            r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<url>[^\s]+) HTTP/[\d\.]+"\s+'
            r'(?P<status>\d+) (?P<bytes>\d+) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
    
    def parse_line(self, line: str, file_type: str) -> Optional[Dict]:
        """Parse a single log line"""
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
            
            parsed = {
                'log_type': 'json_access',
                'timestamp': data.get('timestamp'),
                'ip': data.get('remote_addr') or data.get('ip'),
                'method': data.get('method'),
                'url': data.get('url') or self._extract_url(data.get('request', '')),
                'status': data.get('status'),
                'user_agent': data.get('http_user_agent') or data.get('userAgent'),
                'request_time': data.get('request_time'),
                'source_file': 'access.json'
            }
            
            # Check for authentication attempts
            if 'body' in data and isinstance(data['body'], dict):
                if 'username' in data['body']:
                    parsed['log_type'] = 'authentication'
                    parsed['username'] = data['body'].get('username')
                    parsed['action'] = data['body'].get('action')
                    # Don't log passwords
                    parsed['auth_attempt'] = True
            
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
                'user_agent': data['user_agent'],
                'source_file': 'access.log'
            }
        return None
    
    def parse_attack_log(self, line: str) -> Optional[Dict]:
        """Parse attacks log"""
        if line.strip().startswith('{'):
            parsed = self.parse_json_log(line)
            if parsed:
                parsed['log_type'] = 'security_event'
                parsed['source_file'] = 'attacks.log'
            return parsed
        
        parsed = self.parse_access_log(line)
        if parsed:
            parsed['log_type'] = 'potential_attack'
            parsed['source_file'] = 'attacks.log'
            return parsed
        
        if 'Body:' in line:
            parts = line.split(' - ')
            if len(parts) >= 4:
                return {
                    'log_type': 'attack_attempt',
                    'timestamp': parts[0],
                    'ip': parts[1].replace('IP: ', ''),
                    'endpoint': parts[2],
                    'user_agent': parts[3].split(' - Body:')[0].replace('UA: ', ''),
                    'source_file': 'attacks.log'
                }
        
        return None
    
    def _extract_url(self, request: str) -> str:
        """Extract URL from request string"""
        parts = request.split()
        return parts[1] if len(parts) >= 2 else request
    
    def categorize_event(self, parsed_data: Dict) -> str:
        """Determine which Kafka topic to use"""
        log_type = parsed_data.get('log_type', '')
        
        # Security-related events
        if log_type in ['authentication', 'attack_attempt', 'security_event']:
            return 'security-events'
        
        # Error responses
        status = parsed_data.get('status', 0)
        if isinstance(status, int) and status >= 400:
            return 'error-logs'
        
        # Admin access
        if parsed_data.get('url', '').startswith('/admin'):
            return 'admin-access'
        
        return 'general-logs'


class KafkaLogProducer:
    """Produces parsed logs to Kafka"""
    
    def __init__(self, bootstrap_servers=['localhost:9092']):
        print(f"🔌 Connecting to Kafka at {bootstrap_servers}...")
        
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                acks='all',  # Wait for all replicas
                retries=3,
                max_in_flight_requests_per_connection=1
            )
            print("✅ Connected to Kafka successfully!")
            self.stats = {
                'messages_sent': 0,
                'errors': 0,
                'by_topic': {}
            }
        except Exception as e:
            print(f"❌ Failed to connect to Kafka: {e}")
            raise
    
    def send_log(self, topic: str, log_data: Dict, key: Optional[str] = None):
        """Send a log entry to Kafka"""
        try:
            # Add metadata
            log_data['kafka_timestamp'] = datetime.utcnow().isoformat()
            log_data['processed_by'] = 'log-producer-v1'
            
            # Send to Kafka
            future = self.producer.send(
                topic,
                value=log_data,
                key=key
            )
            
            # Wait for confirmation (with timeout)
            record_metadata = future.get(timeout=10)
            
            # Update stats
            self.stats['messages_sent'] += 1
            self.stats['by_topic'][topic] = self.stats['by_topic'].get(topic, 0) + 1
            
            print(f"✉️  Sent to {topic}: {log_data.get('log_type')} from {log_data.get('ip', 'unknown')}")
            
        except KafkaError as e:
            self.stats['errors'] += 1
            print(f"❌ Kafka error: {e}")
        except Exception as e:
            self.stats['errors'] += 1
            print(f"❌ Error sending log: {e}")
    
    def print_stats(self):
        """Print producer statistics"""
        print("\n" + "="*60)
        print("📊 Producer Statistics:")
        print(f"   Total messages sent: {self.stats['messages_sent']}")
        print(f"   Errors: {self.stats['errors']}")
        print("\n   Messages by topic:")
        for topic, count in self.stats['by_topic'].items():
            print(f"      {topic}: {count}")
        print("="*60 + "\n")
    
    def close(self):
        """Close the producer"""
        print("\n🔒 Closing Kafka producer...")
        self.producer.flush()
        self.producer.close()
        print("✅ Producer closed.")


class LogFileWatcher(FileSystemEventHandler):
    """Watches log files and sends changes to Kafka"""
    
    def __init__(self, kafka_producer: KafkaLogProducer, log_dir: str):
        self.producer = kafka_producer
        self.parser = LogParser()
        self.log_dir = Path(log_dir)
        
        # Track file positions to avoid re-reading
        self.file_positions = {}
        
        # Initialize positions for existing files
        self._initialize_file_positions()
    
    def _initialize_file_positions(self):
        """Set initial positions to end of files"""
        for log_file in self.log_dir.glob('*.log'):
            self.file_positions[str(log_file)] = log_file.stat().st_size
        
        for json_file in self.log_dir.glob('*.json'):
            self.file_positions[str(json_file)] = json_file.stat().st_size
        
        print(f"📂 Initialized tracking for {len(self.file_positions)} files")
    
    def on_modified(self, event):
        """Called when a file is modified"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        if not (file_path.endswith('.log') or file_path.endswith('.json')):
            return
        
        print(f"\n📝 File modified: {file_path}")
        self._process_new_lines(file_path)
    
    def _process_new_lines(self, file_path: str):
        """Process new lines added to the file"""
        try:
            file_path_obj = Path(file_path)
            file_name = file_path_obj.name
            
            # Get current position
            last_position = self.file_positions.get(file_path, 0)
            
            # Read from last position
            with open(file_path, 'r') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                new_position = f.tell()
            
            # Update position
            self.file_positions[file_path] = new_position
            
            # Process each new line
            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                
                # Parse the line
                parsed = self.parser.parse_line(line, file_name)
                
                if parsed:
                    # Determine topic
                    topic = self.parser.categorize_event(parsed)
                    
                    # Use IP as key for partitioning
                    key = parsed.get('ip', 'unknown')
                    
                    # Send to Kafka
                    self.producer.send_log(topic, parsed, key)
                else:
                    print(f"⚠️  Could not parse line from {file_name}")
        
        except Exception as e:
            print(f"❌ Error processing file {file_path}: {e}")


def main():
    """Main function to run the log producer"""
    
    print("""
╔════════════════════════════════════════════════════════════╗
║          Kafka Log Producer System v1.0                    ║
║                                                            ║
║  Watches log files and sends parsed data to Kafka         ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Configuration
    LOG_DIRECTORY = "Honeypots/http/logs"  # Current directory - change as needed
    KAFKA_SERVERS = ['localhost:9092']
    
    print(f"📂 Watching directory: {LOG_DIRECTORY}")
    print(f"🔌 Kafka servers: {KAFKA_SERVERS}\n")
    
    try:
        # Initialize Kafka producer
        kafka_producer = KafkaLogProducer(bootstrap_servers=KAFKA_SERVERS)
        
        # Initialize file watcher
        event_handler = LogFileWatcher(kafka_producer, LOG_DIRECTORY)
        
        # Start observer
        observer = Observer()
        observer.schedule(event_handler, LOG_DIRECTORY, recursive=False)
        observer.start()
        
        print(" System is running!")
        print(" Monitoring log files for changes...")
        print(" Stats will be printed every 30 seconds")
        print(" Press Ctrl+C to stop\n")
        
        # Main loop
        try:
            counter = 0
            while True:
                time.sleep(10)
                counter += 1
                
                if counter % 3 == 0:  # Every 30 seconds
                    kafka_producer.print_stats()
        
        except KeyboardInterrupt:
            print("\n\n🛑 Shutdown requested...")
        
        # Cleanup
        observer.stop()
        observer.join()
        kafka_producer.print_stats()
        kafka_producer.close()
        
        print("\n✅ System stopped gracefully. Goodbye! 👋\n")
    
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()