import json
import signal
import sys
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List

from kafka import KafkaConsumer
from kafka.errors import KafkaError


class LogAnalyzer:
    """Analyzes logs and generates insights"""
    
    def __init__(self):
        self.stats = {
            'total_logs': 0,
            'by_type': Counter(),
            'by_status': Counter(),
            'by_ip': Counter(),
            'by_url': Counter(),
            'failed_auth': [],
            'suspicious_ips': set(),
            'error_urls': []
        }
        self.start_time = datetime.utcnow()
    
    def analyze_log(self, log_data: Dict):
        """Analyze a single log entry"""
        self.stats['total_logs'] += 1
        
        # Count by type
        log_type = log_data.get('log_type', 'unknown')
        self.stats['by_type'][log_type] += 1
        
        # Count by status
        status = log_data.get('status')
        if status:
            self.stats['by_status'][status] += 1
        
        # Count by IP
        ip = log_data.get('ip', 'unknown')
        self.stats['by_ip'][ip] += 1
        
        # Count by URL
        url = log_data.get('url', 'unknown')
        self.stats['by_url'][url] += 1
        
        # Track failed authentication
        if log_type == 'authentication':
            username = log_data.get('username', 'unknown')
            self.stats['failed_auth'].append({
                'timestamp': log_data.get('timestamp'),
                'username': username,
                'ip': ip
            })
            self.stats['suspicious_ips'].add(ip)
        
        # Track errors
        if isinstance(status, int) and status >= 400:
            self.stats['error_urls'].append({
                'url': url,
                'status': status,
                'ip': ip,
                'timestamp': log_data.get('timestamp')
            })
    
    def get_report(self) -> str:
        """Generate analysis report"""
        runtime = (datetime.utcnow() - self.start_time).total_seconds()
        
        report = f"""
╔════════════════════════════════════════════════════════════╗
║                  LOG ANALYSIS REPORT                       ║
╚════════════════════════════════════════════════════════════╝

⏱️  Runtime: {runtime:.1f} seconds
📊 Total Logs Processed: {self.stats['total_logs']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📝 Log Types:
"""
        for log_type, count in self.stats['by_type'].most_common():
            report += f"   {log_type:30s}: {count:5d}\n"
        
        report += "\n🌐 Top IPs:\n"
        for ip, count in self.stats['by_ip'].most_common(10):
            flag = "⚠️ " if ip in self.stats['suspicious_ips'] else "   "
            report += f"{flag}{ip:20s}: {count:5d} requests\n"
        
        if self.stats['by_status']:
            report += "\n📈 Status Codes:\n"
            for status, count in sorted(self.stats['by_status'].items()):
                emoji = "✅" if status < 400 else "⚠️ " if status < 500 else "❌"
                report += f"   {emoji} {status}: {count:5d}\n"
        
        if self.stats['failed_auth']:
            report += f"\n🔐 Failed Authentication Attempts: {len(self.stats['failed_auth'])}\n"
            for attempt in self.stats['failed_auth'][-5:]:  # Last 5
                report += f"   User: {attempt['username']:15s} IP: {attempt['ip']:15s}\n"
        
        if self.stats['error_urls']:
            report += f"\n❌ Error URLs (last 10):\n"
            for error in self.stats['error_urls'][-10:]:
                report += f"   {error['status']} - {error['url']}\n"
        
        report += "\n" + "="*60 + "\n"
        
        return report
    
    def get_security_alerts(self) -> List[str]:
        """Generate security alerts"""
        alerts = []
        
        # Check for brute force attempts
        for ip, count in self.stats['by_ip'].items():
            if count > 10 and ip in self.stats['suspicious_ips']:
                alerts.append(f"🚨 Potential brute force from {ip} ({count} requests)")
        
        # Check for multiple failed auth
        if len(self.stats['failed_auth']) > 3:
            alerts.append(f"🚨 Multiple failed authentication attempts: {len(self.stats['failed_auth'])}")
        
        # Check for high error rate
        total = self.stats['total_logs']
        errors = sum(count for status, count in self.stats['by_status'].items() if status >= 400)
        if total > 0 and errors / total > 0.1:
            error_rate = (errors / total) * 100
            alerts.append(f"⚠️  High error rate: {error_rate:.1f}%")
        
        return alerts


class MultiTopicConsumer:
    """Consumes from multiple Kafka topics"""
    
    def __init__(self, topics: List[str], bootstrap_servers=['localhost:9092'], 
                 group_id='log-analyzer-group'):
        
        print(f"🔌 Connecting to Kafka at {bootstrap_servers}...")
        print(f"📚 Topics: {', '.join(topics)}")
        print(f"👥 Consumer group: {group_id}\n")
        
        try:
            self.consumer = KafkaConsumer(
                *topics,
                bootstrap_servers=bootstrap_servers,
                group_id=group_id,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='earliest',  # Start from beginning
                enable_auto_commit=True,
                auto_commit_interval_ms=1000
            )
            print("✅ Connected to Kafka successfully!\n")
        except Exception as e:
            print(f"❌ Failed to connect to Kafka: {e}")
            raise
        
        self.analyzer = LogAnalyzer()
        self.running = False
    
    def start_consuming(self):
        """Start consuming messages"""
        self.running = True
        
        print("Listening for messages...")
        print("Real-time analysis enabled")
        print("Press Ctrl+C to stop and see report\n")
        print("="*60 + "\n")
        
        message_count = 0
        
        try:
            for message in self.consumer:
                if not self.running:
                    break
                
                message_count += 1
                topic = message.topic
                log_data = message.value
                
                # Display message
                log_type = log_data.get('log_type', 'unknown')
                ip = log_data.get('ip', 'unknown')
                url = log_data.get('url', 'N/A')
                
                print(f"📨 [{topic}] {log_type:20s} | IP: {ip:15s} | {url}")
                
                # Analyze
                self.analyzer.analyze_log(log_data)
                
                # Show mini report every 20 messages
                if message_count % 20 == 0:
                    print(f"\n📊 Processed {message_count} messages so far...\n")
                    
                    alerts = self.analyzer.get_security_alerts()
                    if alerts:
                        print("🚨 SECURITY ALERTS:")
                        for alert in alerts:
                            print(f"   {alert}")
                        print()
        
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping consumer...")
        
        finally:
            self.stop()
    
    def stop(self):
        """Stop consuming and show final report"""
        self.running = False
        
        print("\n" + "="*60)
        print("Generating final report...")
        print("="*60)
        
        # Show analysis report
        print(self.analyzer.get_report())
        
        # Show security alerts
        alerts = self.analyzer.get_security_alerts()
        if alerts:
            print("🚨 SECURITY ALERTS SUMMARY:")
            for alert in alerts:
                print(f"   {alert}")
            print()
        
        # Close consumer
        self.consumer.close()
        print("✅ Consumer closed.\n")


def main():
    """Main function"""
    
    print("""
╔════════════════════════════════════════════════════════════╗
║          Kafka Log Consumer & Analyzer v1.0                ║
║                                                            ║
║  Consumes logs from Kafka and performs real-time analysis ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Configuration
    TOPICS = ['security-events', 'error-logs', 'admin-access', 'general-logs']
    KAFKA_SERVERS = ['localhost:9092']
    GROUP_ID = 'log-analyzer-group'
    
    # Setup signal handler for graceful shutdown
    consumer = None
    
    def signal_handler(sig, frame):
        print("\n🛑 Received shutdown signal...")
        if consumer:
            consumer.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Create and start consumer
        consumer = MultiTopicConsumer(
            topics=TOPICS,
            bootstrap_servers=KAFKA_SERVERS,
            group_id=GROUP_ID
        )
        
        consumer.start_consuming()
    
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()