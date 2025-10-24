# CTI Kafka Topics Setup Guide

## 📋 Overview

Classification-based Kafka topic architecture for honeypot CTI (Cyber Threat Intelligence) event streaming.

**Kafka Broker:** `10.0.2.48:9092`

---

## 🎯 Topic Architecture

### TIER 1: Classification-Based Topics
| Topic | Partitions | Retention | Purpose |
|-------|-----------|-----------|---------|
| `cti-reconnaissance` | 3 | 7 days | Scanning, enumeration, bot activity |
| `cti-authentication` | 5 | 14 days | Login attempts, brute-force attacks |
| `cti-exploitation` | 3 | 30 days | Command execution, web shells, RCE |
| `cti-information-leakage` | 2 | 30 days | `.env`, `.git`, sensitive file access |

### TIER 2: Severity-Based Alerts
| Topic | Partitions | Retention | Purpose |
|-------|-----------|-----------|---------|
| `cti-alerts-critical` | 1 | 90 days | High/critical severity events only |

### TIER 3: Raw Backup
| Topic | Partitions | Retention | Purpose |
|-------|-----------|-----------|---------|
| `cti-raw-events` | 6 | 180 days | Complete immutable audit log |

---

## 🚀 Create Topics

```bash
# Set Kafka broker address
export KAFKA_BROKER="10.0.2.48:9092"

# Topic 1: Reconnaissance
kafka-topics.sh --create \
  --bootstrap-server $KAFKA_BROKER \
  --topic cti-reconnaissance \
  --partitions 3 \
  --replication-factor 1 \
  --config retention.ms=604800000 \
  --config compression.type=snappy

# Topic 2: Authentication
kafka-topics.sh --create \
  --bootstrap-server $KAFKA_BROKER \
  --topic cti-authentication \
  --partitions 5 \
  --replication-factor 1 \
  --config retention.ms=1209600000 \
  --config compression.type=snappy

# Topic 3: Exploitation
kafka-topics.sh --create \
  --bootstrap-server $KAFKA_BROKER \
  --topic cti-exploitation \
  --partitions 3 \
  --replication-factor 1 \
  --config retention.ms=2592000000 \
  --config compression.type=snappy

# Topic 4: Information Leakage
kafka-topics.sh --create \
  --bootstrap-server $KAFKA_BROKER \
  --topic cti-information-leakage \
  --partitions 2 \
  --replication-factor 1 \
  --config retention.ms=2592000000 \
  --config compression.type=snappy

# Topic 5: Critical Alerts
kafka-topics.sh --create \
  --bootstrap-server $KAFKA_BROKER \
  --topic cti-alerts-critical \
  --partitions 1 \
  --replication-factor 1 \
  --config retention.ms=7776000000 \
  --config compression.type=snappy

# Topic 6: Raw Events (Backup)
kafka-topics.sh --create \
  --bootstrap-server $KAFKA_BROKER \
  --topic cti-raw-events \
  --partitions 6 \
  --replication-factor 1 \
  --config retention.ms=15552000000 \
  --config compression.type=lz4
```

---

## ✅ Verify Topics

```bash
# List all topics
kafka-topics.sh --list --bootstrap-server 10.0.2.48:9092

# Describe specific topic
kafka-topics.sh --describe \
  --bootstrap-server 10.0.2.48:9092 \
  --topic cti-reconnaissance

# Check in Kafka UI
# Open: http://10.0.2.48:8080 (or your Kafka UI port)
```

---

## 📊 Event Routing Logic

### Reconnaissance
- `event_type`: "SSH Connection", "Web Request"
- `url`: "/", "/robots.txt", "/favicon.ico"

### Authentication
- `event_type`: "Failed Login Attempt"
- `attack_category`: "Authentication"

### Exploitation
- `event_type`: "Command Execution", "Web Shell Access"
- `url` contains: "/cgi-bin/", exploit paths

### Information Leakage
- `event_type`: "Information Disclosure"
- `url` matches: `/.env`, `/.git/config`, `*.bak`, `*.sql`

### Critical Alerts
- `severity`: "high" or "critical"

### Raw Events
- ALL events (duplicate backup)

---

## 🧪 Test Topics

```bash
# Send test message
echo '{"test": "reconnaissance", "ip": "1.2.3.4"}' | \
kafka-console-producer.sh \
  --bootstrap-server 10.0.2.48:9092 \
  --topic cti-reconnaissance

# Consume test message
kafka-console-consumer.sh \
  --bootstrap-server 10.0.2.48:9092 \
  --topic cti-reconnaissance \
  --from-beginning \
  --max-messages 1
```

---

## 🔧 Troubleshooting

### Check Kafka Status
```bash
systemctl status kafka
sudo netstat -tlnp | grep 9092
```

### Delete Topic (if needed)
```bash
kafka-topics.sh --delete \
  --bootstrap-server 10.0.2.48:9092 \
  --topic cti-reconnaissance
```

### Delete All CTI Topics
```bash
for topic in cti-reconnaissance cti-authentication cti-exploitation \
             cti-information-leakage cti-alerts-critical cti-raw-events; do
  kafka-topics.sh --delete --bootstrap-server 10.0.2.48:9092 --topic $topic
done
```

---

**Date:** October 24, 2025  
**Kafka Version:** 3.9.0  
**Broker:** 10.0.2.48:9092