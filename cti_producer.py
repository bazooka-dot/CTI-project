#!/usr/bin/env python3
"""
Kafka CTI Event Producer
========================
Monitors CTI parser output files and streams events to Kafka topics
based on event classification.

Features:
- Real-time monitoring of CTI output files
- Smart deduplication (tracks sent events)
- Classification-based routing to topics
- Handles parser restarts gracefully
- Produces to multiple topics simultaneously

Usage:
    python3 kafka_cti_producer.py --broker 10.0.2.48:9092
    python3 kafka_cti_producer.py --broker 10.0.2.48:9092 --interval 2
"""

import os
import sys
import json
import time
import argparse
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional
from kafka import KafkaProducer
from kafka.errors import KafkaError

# ============================================================================
# CONFIGURATION
# ============================================================================

class ProducerConfig:
    """Configuration for Kafka producer"""
    def __init__(self):
        self.broker = "10.0.2.48:9092"
        self.output_dir = "/cti_output"
        self.check_interval = 3  # seconds
        self.state_file = ".kafka_producer_state.json"
        
        # Topic mapping based on classification
        self.topic_mapping = {
            # Reconnaissance events
            'reconnaissance': [
                'SSH Connection',
                'Web Request',
                'Automated Scanning'
            ],
            
            # Authentication events
            'authentication': [
                'Failed Login Attempt',
                'Successful Login',
                'Authentication'
            ],
            
            # Exploitation events
            'exploitation': [
                'Command Execution',
                'Web Shell Access',
                'Destructive Command',
                'File Transfer',
                'Impact'
            ],
            
            # Information leakage events
            'information-leakage': [
                'Information Disclosure',
                'Admin Panel Access'
            ]
        }
        
        # Kafka topics
        self.topics = {
            'reconnaissance': 'cti-reconnaissance',
            'authentication': 'cti-authentication',
            'exploitation': 'cti-exploitation',
            'information-leakage': 'cti-information-leakage',
            'alerts': 'cti-alerts-critical',
            'raw': 'cti-raw-events'
        }

# ============================================================================
# EVENT DEDUPLICATOR
# ============================================================================

class EventDeduplicator:
    """Tracks sent events to prevent duplicates"""
    
    def __init__(self, state_file: str):
        self.state_file = state_file
        self.sent_events: Set[str] = set()
        self.stats = {
            'total_sent': 0,
            'duplicates_skipped': 0,
            'last_event_time': None
        }
        self._load_state()
    
    def _event_signature(self, event: Dict) -> str:
        """Create unique signature for event"""
        # Use timestamp + source_ip + event_type as unique identifier
        sig_data = f"{event.get('timestamp')}:{event.get('source_ip')}:{event.get('event_type')}:{event.get('url', event.get('command', ''))}"
        return hashlib.md5(sig_data.encode()).hexdigest()
    
    def _load_state(self):
        """Load previously sent events from state file"""
        if not os.path.exists(self.state_file):
            print("[+] No previous state found, starting fresh")
            return
        
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
                self.sent_events = set(state.get('sent_events', []))
                self.stats = state.get('stats', self.stats)
                print(f"[+] Loaded state: {len(self.sent_events)} events previously sent")
        except Exception as e:
            print(f"[!] Error loading state: {e}")
    
    def save_state(self):
        """Save state to file"""
        try:
            state = {
                'sent_events': list(self.sent_events),
                'stats': self.stats,
                'last_saved': datetime.now().isoformat()
            }
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"[!] Error saving state: {e}")
    
    def is_duplicate(self, event: Dict) -> bool:
        """Check if event was already sent"""
        signature = self._event_signature(event)
        return signature in self.sent_events
    
    def mark_sent(self, event: Dict):
        """Mark event as sent"""
        signature = self._event_signature(event)
        self.sent_events.add(signature)
        self.stats['total_sent'] += 1
        self.stats['last_event_time'] = event.get('timestamp')
    
    def mark_duplicate(self):
        """Mark duplicate event"""
        self.stats['duplicates_skipped'] += 1

# ============================================================================
# EVENT CLASSIFIER
# ============================================================================

class EventClassifier:
    """Classifies events into Kafka topics"""
    
    def __init__(self, config: ProducerConfig):
        self.config = config
    
    def classify_event(self, event: Dict) -> List[str]:
        """
        Classify event and return list of topics to send to
        Returns multiple topics (event goes to classification topic + raw + alerts if critical)
        """
        topics = []
        
        event_type = event.get('event_type', '')
        attack_category = event.get('attack_category', '')
        severity = event.get('severity', 'low')
        url = event.get('url', '')
        
        # 1. Classification-based routing
        classification_topic = self._get_classification_topic(event_type, attack_category, url)
        if classification_topic:
            topics.append(classification_topic)
        
        # 2. Always send to raw events (backup)
        topics.append(self.config.topics['raw'])
        
        # 3. Send to alerts if high/critical severity
        if severity in ['high', 'critical']:
            topics.append(self.config.topics['alerts'])
        
        return topics
    
    def _get_classification_topic(self, event_type: str, attack_category: str, url: str) -> Optional[str]:
        """Determine classification topic based on event characteristics"""
        
        # Check event_type mapping
        for classification, event_types in self.config.topic_mapping.items():
            if event_type in event_types or attack_category in event_types:
                return self.config.topics.get(classification)
        
        # URL-based classification for information leakage
        if url:
            sensitive_patterns = ['.env', '.git', '.config', '.aws', '.ssh', 'backup', '.sql', '.bak']
            if any(pattern in url.lower() for pattern in sensitive_patterns):
                return self.config.topics['information-leakage']
            
            # Web shell patterns
            if 'cgi-bin' in url.lower() or 'shell.php' in url.lower():
                return self.config.topics['exploitation']
        
        # Default to reconnaissance for unknown types
        return self.config.topics['reconnaissance']

# ============================================================================
# FILE MONITOR
# ============================================================================

class FileMonitor:
    """Monitors CTI output files for changes"""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.file_states = {}  # filepath -> last_modified_time
    
    def get_changed_files(self) -> List[Path]:
        """Get list of files that changed since last check"""
        changed_files = []
        
        if not self.output_dir.exists():
            return changed_files
        
        # Find all JSON files
        json_files = list(self.output_dir.glob("cti_*.json"))
        
        for filepath in json_files:
            try:
                current_mtime = filepath.stat().st_mtime
                last_mtime = self.file_states.get(str(filepath))
                
                if last_mtime is None or current_mtime > last_mtime:
                    changed_files.append(filepath)
                    self.file_states[str(filepath)] = current_mtime
            
            except Exception as e:
                print(f"[!] Error checking file {filepath}: {e}")
        
        return changed_files

# ============================================================================
# KAFKA CTI PRODUCER
# ============================================================================

class KafkaCTIProducer:
    """Main Kafka producer for CTI events"""
    
    def __init__(self, config: ProducerConfig):
        self.config = config
        self.producer = None
        self.deduplicator = EventDeduplicator(config.state_file)
        self.classifier = EventClassifier(config)
        self.file_monitor = FileMonitor(config.output_dir)
        
        self.stats = {
            'start_time': datetime.now(),
            'cycles': 0,
            'events_sent': 0,
            'events_by_topic': {},
            'files_processed': 0,
            'last_event': None
        }
        
        self.running = False
    
    def _init_producer(self) -> bool:
        """Initialize Kafka producer"""
        try:
            print(f"[+] Connecting to Kafka broker: {self.config.broker}")
            
            self.producer = KafkaProducer(
                bootstrap_servers=[self.config.broker],
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                compression_type='snappy',
                acks='all',  # Wait for all replicas
                retries=3,
                max_in_flight_requests_per_connection=5,
                request_timeout_ms=30000,
                linger_ms=10,  # Batch messages for 10ms for efficiency
                batch_size=16384
            )
            
            print("[✓] Kafka producer initialized successfully")
            return True
        
        except Exception as e:
            print(f"[✗] Failed to initialize Kafka producer: {e}")
            return False
    
    def _send_event(self, event: Dict, topics: List[str]):
        """Send event to multiple Kafka topics"""
        for topic in topics:
            try:
                # Prepare message with metadata
                message = {
                    'event': event,
                    'metadata': {
                        'produced_at': datetime.now().isoformat(),
                        'producer_version': '1.0',
                        'original_topic': topic
                    }
                }
                
                # Send to Kafka
                future = self.producer.send(topic, value=message)
                
                # Wait for confirmation (optional, can be async)
                record_metadata = future.get(timeout=10)
                
                # Track stats
                if topic not in self.stats['events_by_topic']:
                    self.stats['events_by_topic'][topic] = 0
                self.stats['events_by_topic'][topic] += 1
                
            except KafkaError as e:
                print(f"[!] Kafka error sending to {topic}: {e}")
            except Exception as e:
                print(f"[!] Error sending event to {topic}: {e}")
    
    def _process_file(self, filepath: Path):
        """Process a CTI output file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            events = data.get('events', [])
            
            if not events:
                return
            
            new_events = 0
            
            for event in events:
                # Check for duplicates
                if self.deduplicator.is_duplicate(event):
                    self.deduplicator.mark_duplicate()
                    continue
                
                # Classify event to determine target topics
                topics = self.classifier.classify_event(event)
                
                # Send to Kafka
                self._send_event(event, topics)
                
                # Mark as sent
                self.deduplicator.mark_sent(event)
                
                new_events += 1
                self.stats['events_sent'] += 1
                self.stats['last_event'] = event.get('timestamp')
            
            if new_events > 0:
                print(f"[+] Processed {filepath.name}: {new_events} new events sent to Kafka")
            
            self.stats['files_processed'] += 1
        
        except Exception as e:
            print(f"[!] Error processing file {filepath}: {e}")
    
    def _display_stats(self):
        """Display producer statistics"""
        runtime = (datetime.now() - self.stats['start_time']).total_seconds()
        rate = self.stats['events_sent'] / runtime if runtime > 0 else 0
        
        print("\n" + "=" * 70)
        print("📊 KAFKA PRODUCER STATISTICS")
        print("=" * 70)
        print(f"⏱️  Runtime: {int(runtime)}s | Cycles: {self.stats['cycles']}")
        print(f"📤 Events Sent: {self.stats['events_sent']} | Rate: {rate:.2f} events/sec")
        print(f"📁 Files Processed: {self.stats['files_processed']}")
        print(f"🔄 Duplicates Skipped: {self.deduplicator.stats['duplicates_skipped']}")
        
        if self.stats['events_by_topic']:
            print(f"\n📊 Events by Topic:")
            for topic, count in sorted(self.stats['events_by_topic'].items()):
                print(f"   • {topic}: {count}")
        
        if self.stats['last_event']:
            print(f"\n⏰ Last Event: {self.stats['last_event']}")
        
        print("=" * 70 + "\n")
    
    def start(self):
        """Start the Kafka producer"""
        print("=" * 70)
        print("🚀 KAFKA CTI EVENT PRODUCER")
        print("=" * 70)
        print(f"⚙️  Configuration:")
        print(f"   • Broker: {self.config.broker}")
        print(f"   • Output Directory: {self.config.output_dir}")
        print(f"   • Check Interval: {self.config.check_interval}s")
        print(f"   • State File: {self.config.state_file}")
        print()
        
        # Initialize Kafka producer
        if not self._init_producer():
            print(" Failed to initialize Kafka producer")
            sys.exit(1)
        
        print(f"📋 Topic Mapping:")
        for classification, topic in self.config.topics.items():
            print(f"   • {classification}: {topic}")
        print()
        
        print("✅ Producer is running... (Press Ctrl+C to stop)")
        print("=" * 70)
        print()
        
        self.running = True
        
        try:
            while self.running:
                # Check for changed files
                changed_files = self.file_monitor.get_changed_files()
                
                if changed_files:
                    print(f"[+] Detected {len(changed_files)} changed file(s)")
                    
                    for filepath in changed_files:
                        self._process_file(filepath)
                    
                    # Flush producer to ensure all messages are sent
                    self.producer.flush()
                    
                    # Save state
                    self.deduplicator.save_state()
                
                self.stats['cycles'] += 1
                
                # Display stats every 20 cycles
                if self.stats['cycles'] % 20 == 0:
                    self._display_stats()
                
                time.sleep(self.config.check_interval)
        
        except KeyboardInterrupt:
            print("\n\n⏹️  Shutting down gracefully...")
            self.stop()
    
    def stop(self):
        """Stop the producer"""
        self.running = False
        
        if self.producer:
            print("[+] Flushing remaining messages...")
            self.producer.flush()
            self.producer.close()
        
        # Save final state
        self.deduplicator.save_state()
        
        self._display_stats()
        
        print("\n" + "=" * 70)
        print("✅ PRODUCER STOPPED")
        print("=" * 70)
        print(f"📈 Session Summary:")
        print(f"   • Total events sent: {self.stats['events_sent']}")
        print(f"   • Duplicates skipped: {self.deduplicator.stats['duplicates_skipped']}")
        print(f"   • Files processed: {self.stats['files_processed']}")
        print("=" * 70)

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Kafka CTI Event Producer")
    
    parser.add_argument('--broker', type=str, default='10.0.2.48:9092',
                       help='Kafka broker address (default: 10.0.2.48:9092)')
    parser.add_argument('--output-dir', type=str, default='cti_output',
                       help='CTI output directory to monitor (default: cti_output)')
    parser.add_argument('--interval', type=int, default=3,
                       help='Check interval in seconds (default: 3)')
    parser.add_argument('--state-file', type=str, default='.kafka_producer_state.json',
                       help='State file for tracking sent events (default: .kafka_producer_state.json)')
    
    args = parser.parse_args()
    
    # Create config
    config = ProducerConfig()
    config.broker = args.broker
    config.output_dir = args.output_dir
    config.check_interval = args.interval
    config.state_file = args.state_file
    
    # Create and start producer
    producer = KafkaCTIProducer(config)
    
    try:
        producer.start()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        producer.stop()
        sys.exit(1)

if __name__ == '__main__':
    main()