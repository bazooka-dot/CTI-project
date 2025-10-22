#!/usr/bin/env python3
"""
One-Command CTI Analysis - Does everything automatically
Usage: python run_cti.py
"""

import os
import sys
from datetime import datetime
from standalone_cti_parser import StandaloneCTIParser


def main():
    print("=" * 70)
    print("🚀 ONE-COMMAND CTI ANALYSIS")
    print("=" * 70)
    print("🎯 Automatically finds and processes all honeypot logs")
    print("📊 Raw event parsing without hardcoded MITRE techniques")
    print("🔗 Produces structured data for external correlation")
    print()
    
    # Initialize parser
    cti_parser = StandaloneCTIParser()
    all_events = []
    processed_files = []
    
    # Auto-discover SSH logs
    ssh_paths = [
        "cowrie/logs/cowrie.json",
        "cowrie.json",
        "ssh.json",
        "logs/cowrie.json"
    ]
    
    ssh_file = None
    for path in ssh_paths:
        if os.path.exists(path):
            ssh_file = path
            break
    
    # Auto-discover HTTP logs
    http_paths = [
        "http/logs/access.json",  # JSON format logs
        "http/logs/access.log",   # Standard access logs
        "http/frontend/access.log",
        "http/access.log",
        "access.log",
        "logs/access.log",
        "nginx/access.log"
    ]
    
    http_file = None
    for path in http_paths:
        if os.path.exists(path):
            http_file = path
            break
    
    # Process SSH logs if found
    if ssh_file:
        print(f"🔍 Found SSH logs: {ssh_file}")
        print("-" * 70)
        ssh_events = cti_parser.parse_ssh_logs(ssh_file)
        all_events.extend(ssh_events)
        processed_files.append(f"SSH: {ssh_file} ({len(ssh_events)} events)")
        print(f"[+] Processed {len(ssh_events)} SSH events")
        print()
    else:
        print("⚠️  No SSH logs found in standard locations")
        print()
    
    # Process HTTP logs if found
    if http_file:
        print(f"🔍 Found HTTP logs: {http_file}")
        print("-" * 70)
        http_events = cti_parser.parse_http_logs(http_file)
        all_events.extend(http_events)
        processed_files.append(f"HTTP: {http_file} ({len(http_events)} events)")
        print(f"[+] Processed {len(http_events)} HTTP events")
        print()
    else:
        print("⚠️  No HTTP logs found in standard locations")
        print()
    
    if not all_events:
        print("❌ No honeypot logs found!")
        print("   Expected locations:")
        print("   - SSH: ssh & telnet/logs/cowrie.json")
        print("   - HTTP: http/frontend/access.log")
        sys.exit(1)
    
    # Generate summary
    summary = cti_parser.generate_summary(all_events)
    
    # Display comprehensive stats
    print("📊 ANALYSIS RESULTS")
    print("=" * 70)
    print(f"📁 Files Processed:")
    for file_info in processed_files:
        print(f"   • {file_info}")
    print()
    
    print(f"📈 Statistics:")
    print(f"   • Total Events: {summary['total_events']}")
    print(f"   • Unique Attackers: {summary['unique_ips']}")
    print(f"   • High/Critical Events: {summary['high_critical_count']}")
    print()
    
    # Show severity breakdown
    print(f"🚨 Severity Breakdown:")
    for severity, count in summary['severity_counts'].items():
        if count > 0:
            print(f"   • {severity.capitalize()}: {count}")
    print()
    
    # Show top attacks
    print(f"🎯 Top Attack Types:")
    for attack_type, count in sorted(summary['attack_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   • {attack_type}: {count}")
    print()
    
    # MITRE techniques removed - no hardcoded correlation
    
    # Show top attackers
    if summary['top_attackers']:
        print(f"🔍 Top Attackers:")
        for ip, count in summary['top_attackers'][:3]:
            print(f"   • {ip}: {count} events")
        print()
    
    # Auto-generate output files with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Separate events by protocol
    ssh_events = [event for event in all_events if event.protocol == 'SSH']
    http_events = [event for event in all_events if event.protocol == 'HTTP']
    
    # Export separate files for each protocol
    import json
    generated_files = []
    
    if ssh_events:
        ssh_file = f"cti_ssh_{timestamp}.json"
        cti_parser.export_for_neo4j(ssh_events, ssh_file)
        generated_files.append(f"🔐 SSH Events: {ssh_file}")
    
    if http_events:
        http_file = f"cti_http_{timestamp}.json"
        cti_parser.export_for_neo4j(http_events, http_file)
        generated_files.append(f"🌐 HTTP Events: {http_file}")
    
    # Export combined summary
    summary_file = f"cti_summary_{timestamp}.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    generated_files.append(f"📈 Summary: {summary_file}")
    
    print("💾 OUTPUT FILES GENERATED")
    print("=" * 70)
    for file_info in generated_files:
        print(f"   {file_info}")
    print()
    print("🔗 Separate protocol files ready for correlation!")
    print("=" * 70)
    print("✅ CTI ANALYSIS COMPLETE!")
    print("=" * 70)


# Text report generation removed - only JSON outputs needed


if __name__ == '__main__':
    main()