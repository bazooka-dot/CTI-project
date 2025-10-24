# CTI Parser - Complete Documentation

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Installation & Setup](#installation--setup)
5. [Usage](#usage)
6. [How It Works](#how-it-works)
7. [Output Format](#output-format)
8. [Configuration](#configuration)
9. [Troubleshooting](#troubleshooting)
10. [Advanced Topics](#advanced-topics)

---

## Overview

### What Is This?

The **CTI Parser** (`cti_parser.py`) is an automated honeypot log parser that continuously monitors SSH and HTTP logs, parses them into structured threat events, and outputs clean JSON files ready for threat intelligence correlation.

### Key Capabilities

- ✅ **Automated Monitoring** - Continuously watches log files for new entries
- ✅ **Smart Resume** - Remembers where it left off, no duplicate parsing
- ✅ **Clean Parsing** - Converts raw logs into structured threat events
- ✅ **Production Ready** - Handles log rotation, errors, graceful shutdown
- ✅ **Self-Contained** - No external dependencies, all-in-one script

### Use Case

This parser is designed for:
- **Security Operations Centers (SOC)** - Real-time threat event streaming
- **Threat Intelligence Teams** - Building threat profiles from honeypot data
- **Research Projects** - Analyzing attacker behavior patterns
- **CTI Correlation** - Feeding structured data into graph databases (Neo4j)

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      HONEYPOT SERVER                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐         ┌──────────────┐                 │
│  │ SSH Honeypot│────────▶│  cowrie.json │                 │
│  │  (Cowrie)   │         │  (Log File)  │                 │
│  └─────────────┘         └───────┬──────┘                 │
│                                   │                         │
│  ┌─────────────┐         ┌───────▼──────┐                 │
│  │HTTP Honeypot│────────▶│  access.log  │                 │
│  │             │         │  (Log File)  │                 │
│  └─────────────┘         └───────┬──────┘                 │
│                                   │                         │
│                          ┌────────▼─────────┐              │
│                          │   CTI PARSER     │              │
│                          │  cti_parser.py   │              │
│                          └────────┬─────────┘              │
│                                   │                         │
│                          ┌────────▼─────────┐              │
│                          │  cti_output/     │              │
│                          │  - cti_ssh_*.json│              │
│                          │  - cti_http_*.json              │
│                          │  - cti_summary_*  │              │
│                          └──────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

### Component Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    CTI PARSER                            │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────┐                                     │
│  │  Log Discovery │  Finds log files automatically      │
│  └───────┬────────┘                                     │
│          │                                              │
│          ▼                                              │
│  ┌────────────────┐                                     │
│  │  Log Tailer    │  Reads new lines (tail -f style)   │
│  └───────┬────────┘                                     │
│          │                                              │
│          ▼                                              │
│  ┌────────────────┐                                     │
│  │ Event Parser   │  Parses JSON logs into events      │
│  └───────┬────────┘                                     │
│          │                                              │
│          ▼                                              │
│  ┌────────────────┐                                     │
│  │Output Manager  │  Writes structured JSON output     │
│  └───────┬────────┘                                     │
│          │                                              │
│          ▼                                              │
│  ┌────────────────┐                                     │
│  │Checkpoint Mgr  │  Tracks file positions             │
│  └────────────────┘                                     │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Features

### 1. **Continuous Monitoring**

The parser runs continuously, checking for new log entries every 5 seconds (configurable).

```bash
# Runs forever until stopped
python3 cti_parser.py
```

**How it works:**
- Opens log files
- Reads new lines as they're written
- Parses them immediately
- Updates output files in real-time

### 2. **Smart Resume (Checkpoint System)**

The parser remembers where it stopped reading, so no events are duplicated or missed.

**Scenario 1: First Run**
```
No output files exist
→ Parser starts from beginning of log files
→ Parses ALL events
→ Creates output files
→ Saves checkpoint
```

**Scenario 2: Restart After Stop**
```
Output files exist
→ Parser loads existing events from output
→ Reads checkpoint (last position in log file)
→ Resumes from that position
→ Only parses NEW events
→ Appends to existing output
```

**Scenario 3: Fresh Start**
```bash
# Delete output files
rm -rf cti_output/*.json

# Run parser
python3 cti_parser.py

# Parser sees no output files
→ Starts from beginning again
→ Re-parses everything
```

### 3. **Log Rotation Handling**

Automatically detects when log files are rotated and adjusts accordingly.

```
Log file rotated:
  cowrie.json → cowrie.json.1 (old)
  cowrie.json (new empty file)

Parser detects:
  - File inode changed OR
  - File size decreased
  
Parser action:
  - Closes old file
  - Opens new file
  - Resets checkpoint to position 0
  - Continues parsing from new file
```

### 4. **Multi-Protocol Support**

Parses both SSH and HTTP honeypot logs.

#### **SSH (Cowrie Format)**
```json
{
  "eventid": "cowrie.login.failed",
  "src_ip": "192.168.1.100",
  "timestamp": "2025-10-24T14:00:00Z",
  "username": "root",
  "password": "password123",
  "session": "abc123"
}
```

#### **HTTP (Nginx/Apache JSON Format)**
```json
{
  "timestamp": "2025-10-24T14:00:00+00:00",
  "remote_addr": "192.168.1.100",
  "request": "GET /admin HTTP/1.1",
  "status": 404,
  "http_user_agent": "Mozilla/5.0...",
  "request_time": 0.1
}
```

### 5. **Structured Output**

Creates clean, structured JSON files ready for analysis.

```json
{
  "metadata": {
    "export_timestamp": "2025-10-24T15:00:00Z",
    "total_events": 156,
    "parser_version": "1.0_all_in_one",
    "protocol": "SSH"
  },
  "events": [
    {
      "timestamp": "2025-10-24T14:00:00Z",
      "source_ip": "192.168.1.100",
      "event_type": "Failed Login Attempt",
      "protocol": "SSH",
      "severity": "medium",
      "attack_category": "Authentication",
      "username": "root",
      "password": "password123",
      ...
    }
  ]
}
```

### 6. **Error Handling**

Robust error handling ensures the parser keeps running even when problems occur.

```python
# Handles:
- Malformed JSON lines (skips and continues)
- File read errors (retries)
- Permission issues (logs and continues)
- Missing fields (uses defaults)
- Encoding errors (tries different encodings)
```

### 7. **Performance Monitoring**

Built-in statistics tracking.

```
📊 PARSER STATISTICS
======================================================================
⏱️  Runtime: 3600s | Cycles: 720
📈 Events: SSH=1247 | HTTP=3891 | Total=5138
⚡ Rate: 1.43 events/sec
💾 Output Files:
   • SSH: cti_output/cti_ssh_20251024_140000.json
   • HTTP: cti_output/cti_http_20251024_140000.json
======================================================================
```

---

## Installation & Setup

### Prerequisites

- **Python 3.7+** (no external packages needed)
- **Read access** to honeypot log files
- **Write access** to output directory

### Installation

```bash
# 1. Copy the script to your honeypot server
scp cti_parser.py user@honeypot:/home/user/

# 2. Make it executable
chmod +x cti_parser.py

# 3. Test it
python3 cti_parser.py --help
```

### Directory Structure

```
/home/user/honeypot/
├── cti_parser.py              # The parser script
├── cowrie/
│   └── logs/
│       └── cowrie.json        # SSH logs
├── http/
│   └── frontend/
│       └── access.log         # HTTP logs
├── cti_output/                # Created automatically
│   ├── cti_ssh_*.json
│   └── cti_http_*.json
└── .cti_checkpoint.json       # Created automatically
```

### Quick Start

```bash
# 1. Navigate to honeypot directory
cd /home/user/honeypot/

# 2. Run parser
python3 cti_parser.py

# 3. Check output
ls -lh cti_output/

# 4. View parsed events
cat cti_output/cti_ssh_*.json | jq '.events[0]'
```

---

## Usage

### Basic Usage

```bash
# Run with defaults
python3 cti_parser.py
```

### With Options

```bash
# Check every 10 seconds instead of 5
python3 cti_parser.py --interval 10

# Custom output directory
python3 cti_parser.py --output-dir /var/log/cti

# Custom checkpoint file
python3 cti_parser.py --checkpoint /tmp/checkpoint.json

# All together
python3 cti_parser.py --interval 10 --output-dir /var/log/cti --checkpoint /tmp/checkpoint.json
```

### Running as a Service

#### **Using systemd (Linux)**

Create `/etc/systemd/system/cti-parser.service`:

```ini
[Unit]
Description=CTI Parser Service
After=network.target

[Service]
Type=simple
User=honeypot
WorkingDirectory=/home/honeypot
ExecStart=/usr/bin/python3 /home/honeypot/cti_parser.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cti-parser
sudo systemctl start cti-parser

# Check status
sudo systemctl status cti-parser

# View logs
sudo journalctl -u cti-parser -f
```

#### **Using screen (Quick & Dirty)**

```bash
# Start in background
screen -dmS cti-parser python3 cti_parser.py

# Reattach to view
screen -r cti-parser

# Detach: Ctrl+A, then D
```

#### **Using nohup**

```bash
# Run in background
nohup python3 cti_parser.py > parser.log 2>&1 &

# Check if running
ps aux | grep cti_parser

# View logs
tail -f parser.log
```

### Stopping the Parser

```bash
# Graceful stop (Ctrl+C)
# Parser will:
# 1. Stop reading new events
# 2. Save checkpoint
# 3. Display final statistics
# 4. Exit cleanly

# Force stop (not recommended)
kill -9 <pid>
```

---

## How It Works

### Startup Sequence

```
1. Load configuration
   ├─ Check interval: 5 seconds
   ├─ Output directory: cti_output/
   └─ Checkpoint file: .cti_checkpoint.json

2. Discover log files
   ├─ Check SSH log paths:
   │  ├─ cowrie/logs/cowrie.json ✓ Found
   │  └─ (other paths skipped)
   └─ Check HTTP log paths:
      ├─ http/frontend/access.log ✓ Found
      └─ (other paths skipped)

3. Check for existing output files
   ├─ SSH: cti_ssh_20251024_140000.json exists
   │  ├─ Load 1000 existing events
   │  └─ Will resume from checkpoint
   └─ HTTP: No existing file
      └─ Will start from beginning

4. Setup tailers
   ├─ SSH tailer:
   │  ├─ Open cowrie.json
   │  └─ Seek to offset 524288 (from checkpoint)
   └─ HTTP tailer:
      ├─ Open access.log
      └─ Start at offset 0 (beginning)

5. Start monitoring loop
   └─ Ready to parse events!
```

### Processing Loop

```
Every 5 seconds:

1. Check SSH log
   ├─ Read new lines from file
   ├─ Parse each line into ThreatEvent
   ├─ Add to collection
   └─ Update checkpoint

2. Check HTTP log
   ├─ Read new lines from file
   ├─ Parse each line into ThreatEvent
   ├─ Add to collection
   └─ Update checkpoint

3. Write output
   ├─ Generate JSON with all events
   ├─ Write to output file
   └─ Update metadata (timestamp, count)

4. Every 10 cycles (50 seconds):
   ├─ Display statistics
   └─ Generate summary file

5. Sleep 5 seconds

6. Repeat
```

### Parsing Logic

#### **SSH Event Parsing**

```python
Input:
{
  "eventid": "cowrie.login.failed",
  "src_ip": "192.168.1.100",
  "username": "root",
  "password": "password123",
  "timestamp": "2025-10-24T14:00:00Z"
}

Processing:
1. Extract fields:
   - event_id = "cowrie.login.failed"
   - source_ip = "192.168.1.100"
   - username = "root"
   - password = "password123"

2. Categorize event:
   - "login.failed" → Authentication, "Failed Login Attempt"

3. Determine severity:
   - "login.failed" → medium

4. Create metadata:
   - has_credentials = true
   - is_privileged_command = false

Output:
{
  "timestamp": "2025-10-24T14:00:00Z",
  "source_ip": "192.168.1.100",
  "event_type": "Failed Login Attempt",
  "protocol": "SSH",
  "severity": "medium",
  "attack_category": "Authentication",
  "username": "root",
  "password": "password123",
  "confidence": 0.5,
  "metadata": {
    "event_id": "cowrie.login.failed",
    "has_credentials": true,
    "command_length": 0,
    "is_privileged_command": false
  }
}
```

#### **HTTP Event Parsing**

```python
Input:
{
  "timestamp": "2025-10-24T14:00:00+00:00",
  "remote_addr": "192.168.1.100",
  "request": "GET /.env HTTP/1.1",
  "status": 404,
  "http_user_agent": "curl/7.68.0"
}

Processing:
1. Extract fields:
   - Parse request: method="GET", url="/.env"
   - source_ip = "192.168.1.100"
   - status = 404

2. Categorize attack:
   - "/.env" detected → "Information Disclosure"

3. Determine severity:
   - "/.env" in URL → high

4. Check user agent:
   - "curl" detected → is_suspicious_ua = true

Output:
{
  "timestamp": "2025-10-24T14:00:00+00:00",
  "source_ip": "192.168.1.100",
  "event_type": "Information Disclosure",
  "protocol": "HTTP",
  "severity": "high",
  "attack_category": "Information Disclosure",
  "method": "GET",
  "url": "/.env",
  "status_code": 404,
  "user_agent": "curl/7.68.0",
  "confidence": 0.5,
  "metadata": {
    "url_decoded": "/.env",
    "is_suspicious_ua": true,
    "path_depth": 1
  }
}
```

### Event Categorization

#### **SSH Events**

| Event ID | Category | Event Type | Severity |
|----------|----------|------------|----------|
| `cowrie.login.success` | Authentication | Successful Login | high |
| `cowrie.login.failed` | Authentication | Failed Login Attempt | medium |
| `cowrie.session.connect` | Connection | SSH Connection | low |
| `cowrie.command.input` | Execution | Command Execution | varies |
| `cowrie.session.file_download` | Exfiltration | File Download | high |

**Command-Based Categorization:**

| Command Pattern | Category | Severity |
|----------------|----------|----------|
| `rm -rf`, `dd if=` | Impact | critical |
| `wget`, `curl` | Exfiltration | high |
| `whoami`, `uname` | Discovery | medium |
| `sudo`, `chmod +x` | Execution | medium |

#### **HTTP Events**

| URL Pattern | Category | Severity |
|-------------|----------|----------|
| `/.env`, `/.git/` | Information Disclosure | high |
| `/admin`, `/wp-admin` | Admin Panel Access | medium |
| `shell.php`, `cgi-bin` | Web Shell Access | critical |
| Scanner user agents | Automated Scanning | medium |
| `CONNECT` method | Proxy Abuse | medium |
| Normal requests | Web Request | low |

### Checkpoint System

#### **What Gets Saved**

```json
{
  "/full/path/cowrie/logs/cowrie.json": {
    "offset": 524288,
    "inode": 1234567,
    "last_timestamp": "2025-10-24T14:30:00Z",
    "lines_processed": 1000
  },
  "/full/path/http/frontend/access.log": {
    "offset": 1048576,
    "inode": 7654321,
    "last_timestamp": "2025-10-24T14:30:00Z",
    "lines_processed": 3000
  }
}
```

#### **How It Works**

```
When parser reads a line:

1. Read line from file
2. Parse line into event
3. Get current file position (offset)
4. Get file inode
5. Save checkpoint:
   {
     "offset": 524388,  # Current position
     "inode": 1234567,  # File identifier
     "last_timestamp": "...",
     "lines_processed": 1001
   }

When parser restarts:

1. Check if output file exists
   ├─ YES → Load checkpoint
   │   ├─ Open log file
   │   └─ Seek to checkpoint offset
   └─ NO → Start from beginning
       └─ Open log file at offset 0

2. Continue parsing from that position
```

#### **Rotation Detection**

```
Before rotation:
  cowrie.json (inode: 1234567, size: 524288)
  Checkpoint: offset=524288

After rotation:
  cowrie.json (inode: 9999999, size: 0)    # New file!
  cowrie.json.1 (inode: 1234567)           # Old file

Parser detects:
  Current inode (9999999) ≠ Checkpoint inode (1234567)
  OR
  Current size (0) < Checkpoint offset (524288)

Parser action:
  1. Close current file handle
  2. Reset checkpoint offset to 0
  3. Open new file
  4. Continue parsing from beginning of new file
```

---

## Output Format

### File Structure

```
cti_output/
├── cti_ssh_20251024_140000.json     # SSH events
├── cti_http_20251024_140000.json    # HTTP events
└── cti_summary_20251024_150000.json # Summary (every 10 cycles)
```

### Event File Format

```json
{
  "metadata": {
    "export_timestamp": "2025-10-24T15:00:00.123456",
    "total_events": 1247,
    "parser_version": "1.0_all_in_one",
    "protocol": "SSH"
  },
  "events": [
    {
      "timestamp": "2025-10-24T14:00:00Z",
      "source_ip": "192.168.1.100",
      "event_type": "Failed Login Attempt",
      "protocol": "SSH",
      "severity": "medium",
      "mitre_techniques": [],
      "mitre_tactics": [],
      "attack_category": "Authentication",
      "confidence": 0.5,
      "raw_data": { /* original log entry */ },
      
      // SSH-specific fields
      "username": "root",
      "password": "password123",
      "command": null,
      "session_id": "abc123",
      
      // HTTP-specific fields (null for SSH)
      "method": null,
      "url": null,
      "status_code": null,
      "user_agent": null,
      
      // Analysis fields
      "indicators": [],
      "metadata": {
        "event_id": "cowrie.login.failed",
        "has_credentials": true,
        "command_length": 0,
        "is_privileged_command": false
      }
    }
  ]
}
```

### Summary File Format

```json
{
  "total_events": 5138,
  "unique_ips": 237,
  "attack_types": {
    "Failed Login Attempt": 892,
    "Command Execution": 355,
    "Web Request": 2891,
    "Information Disclosure": 47,
    "Admin Panel Access": 23
  },
  "severity_counts": {
    "low": 3200,
    "medium": 1500,
    "high": 380,
    "critical": 58
  },
  "top_attackers": [
    ["192.168.1.100", 523],
    ["10.0.0.50", 412],
    ["45.95.147.173", 389]
  ],
  "high_critical_count": 438
}
```

### Field Descriptions

#### **Common Fields (All Events)**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `timestamp` | string | ISO 8601 timestamp | `"2025-10-24T14:00:00Z"` |
| `source_ip` | string | Attacker IP address | `"192.168.1.100"` |
| `event_type` | string | Human-readable event type | `"Failed Login Attempt"` |
| `protocol` | string | Protocol used | `"SSH"` or `"HTTP"` |
| `severity` | string | Event severity | `"low"`, `"medium"`, `"high"`, `"critical"` |
| `attack_category` | string | Attack classification | `"Authentication"`, `"Execution"`, etc. |
| `confidence` | float | Confidence score (0.0-1.0) | `0.5` |
| `raw_data` | object | Original log entry | `{...}` |
| `indicators` | array | IOCs/signatures | `[]` |
| `metadata` | object | Additional context | `{...}` |

#### **SSH-Specific Fields**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `username` | string | Login username | `"root"` |
| `password` | string | Login password | `"password123"` |
| `command` | string | Command executed | `"whoami"` |
| `session_id` | string | Session identifier | `"abc123"` |
| `metadata.event_id` | string | Cowrie event ID | `"cowrie.login.failed"` |
| `metadata.has_credentials` | boolean | Credentials present | `true` |
| `metadata.command_length` | int | Command length | `6` |
| `metadata.is_privileged_command` | boolean | Requires privileges | `false` |

#### **HTTP-Specific Fields**

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `method` | string | HTTP method | `"GET"` |
| `url` | string | Requested URL | `"/.env"` |
| `status_code` | int | HTTP status code | `404` |
| `user_agent` | string | User-Agent header | `"curl/7.68.0"` |
| `metadata.url_decoded` | string | URL-decoded path | `"/.env"` |
| `metadata.is_suspicious_ua` | boolean | Suspicious UA detected | `true` |
| `metadata.path_depth` | int | URL path depth | `1` |

---

## Configuration

### Command-Line Options

```bash
python3 cti_parser.py [OPTIONS]

Options:
  --interval INTEGER       Check interval in seconds (default: 5)
  --output-dir PATH       Output directory (default: cti_output)
  --checkpoint PATH       Checkpoint file (default: .cti_checkpoint.json)
  --help                  Show help message
```

### Log File Discovery

The parser automatically searches for log files in these paths:

**SSH Logs (checked in order):**
```
1. cowrie/logs/cowrie.json
2. cowrie.json
3. ssh.json
4. logs/cowrie.json
```

**HTTP Logs (checked in order):**
```
1. http/logs/access.json
2. http/logs/access.log
3. http/frontend/access.log
4. http/access.log
5. access.log
6. logs/access.log
7. nginx/access.log
```

### Customizing Log Paths

Edit the `ParserConfig` class in `cti_parser.py`:

```python
@dataclass
class ParserConfig:
    ssh_log_paths: List[str] = None
    http_log_paths: List[str] = None
    
    def __post_init__(self):
        if self.ssh_log_paths is None:
            self.ssh_log_paths = [
                "cowrie/logs/cowrie.json",
                # Add your custom paths here
                "/var/log/honeypot/ssh.json",
                "/custom/path/cowrie.json"
            ]
```

### Performance Tuning

```python
# Adjust check interval
python3 cti_parser.py --interval 1  # Check every second (high load)
python3 cti_parser.py --interval 30 # Check every 30 seconds (low load)

# For high-volume logs (1000+ events/sec):
# - Increase batch processing
# - Reduce checkpoint frequency
# - Consider separate consumer process
```

---

## Troubleshooting

### Common Issues

#### **Issue 1: Parser Can't Find Log Files**

**Symptoms:**
```
❌ No log files discovered!
   Expected locations:
   • SSH: cowrie/logs/cowrie.json
   • HTTP: http/frontend/access.log
```

**Solutions:**
```bash
# 1. Check if log files exist
ls -la cowrie/logs/cowrie.json
ls -la http/frontend/access.log

# 2. Check current directory
pwd
# Should be in honeypot root directory

# 3. Check file permissions
ls -l cowrie/logs/cowrie.json
# Should be readable by your user

# 4. Run from correct directory
cd /home/user/honeypot
python3 cti_parser.py
```

#### **Issue 2: Permission Denied**

**Symptoms:**
```
[!] Error opening cowrie/logs/cowrie.json: Permission denied
```

**Solutions:**
```bash
# Option A: Fix permissions
chmod +r cowrie/logs/cowrie.json

# Option B: Run as correct user
sudo -u honeypot python3 cti_parser.py

# Option C: Add user to honeypot group
sudo usermod -a -G honeypot $USER
# Log out and log back in
```

#### **Issue 3: No Events Being Parsed**

**Symptoms:**
```
[+] Found 100 new SSH lines
[+] Parsed 0 SSH events
```

**Solutions:**
```bash
# 1. Check log format
head -1 cowrie/logs/cowrie.json

# Should be valid JSON:
{"eventid":"cowrie.login.failed","src_ip":"..."}

# 2. Check for parsing errors
# Look for error messages in output

# 3. Test parsing manually
python3 -c "
import json
with open('cowrie/logs/cowrie.json') as f:
    line = f.readline()
    data = json.loads(line)
    print(data)
"
```

#### **Issue 4: Duplicate Events**

**Symptoms:**
```
Events appearing multiple times in output file
```

**Solutions:**
```bash
# 1. Check if multiple parsers are running
ps aux | grep cti_parser

# 2. Delete checkpoint and output, start fresh
rm .cti_checkpoint.json
rm -rf cti_output/
python3 cti_parser.py

# 3. Ensure only one parser instance
pkill -f cti_parser.py
python3 cti_parser.py
```

#### **Issue 5: High Memory Usage**

**Symptoms:**
```
Parser using >1GB RAM
```

**Solutions:**
```python
# The parser loads ALL events into memory
# For millions of events, this can be problematic

# Solution 1: Restart parser periodically
# Delete old output files to start fresh

# Solution 2: Archive old events
mv cti_output/cti_ssh_20251024_*.json archive/
# Parser will start new file

# Solution 3: Use streaming mode (future feature)
# Or implement Kafka producer to stream events
```

#### **Issue 6: Checkpoint Not Working**

**Symptoms:**
```
Parser always starts from beginning
```

**Solutions:**
```bash
# 1. Check checkpoint file exists
ls -la .cti_checkpoint.json

# 2. Check checkpoint file is writable
chmod +w .cti_checkpoint.json

# 3. Check output files exist
ls -la cti_output/

# If output files don't exist, parser starts from beginning
# This is expected behavior (smart resume)

# 4. Verify checkpoint content
cat .cti_checkpoint.json | jq .
```

### Debug Mode

Add debug logging:

```python
# At top of cti_parser.py, add:
import logging
logging.basicConfig(level=logging.DEBUG)

# Or run with Python debugging:
python3 -m pdb cti_parser.py
```

### Getting Help

```bash
# View help
python3 cti_parser.py --help

# Check version
python3 cti_parser.py --version  # (if implemented)

# Test configuration
python3 -c "
from cti_parser import ParserConfig
config = ParserConfig()
print('SSH paths:', config.ssh_log_paths)
print('HTTP paths:', config.http_log_paths)
"
```

---

## Advanced Topics

### Using with Kafka

**Coming soon:** Kafka producer integration to stream events to other systems.

```python
# Future usage:
python3 cti_parser.py --kafka-enabled --kafka-broker machine2:9092
```

### Custom Event Processing

To add custom processing logic:

```python
# In EventParser class, modify parse_ssh_line():

def parse_ssh_line(self, line: str) -> Optional[ThreatEvent]:
    # ... existing parsing logic ...
    
    # Add custom logic here
    if event.username == "admin":
        event.severity = "critical"
        event.metadata['custom_flag'] = "admin_attempt"
    
    return event
```

### Integrating with Neo4j

```python
# Separate consumer script (example):

import json
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687")

def load_events_to_neo4j(json_file):
    with open(json_file) as f:
        data = json.load(f)
    
    with driver.session() as session:
        for event in data['events']:
            session.run("""
                CREATE (e:ThreatEvent {
                    timestamp: $timestamp,
                    source_ip: $source_ip,
                    event_type: $event_type,
                    severity: $severity
                })
            """, event)

load_events_to_neo4j("cti_output/cti_ssh_20251024_140000.json")
```

### Performance Metrics

Track parser performance:

```bash
# Events per second
cat cti_output/cti_ssh_*.json | jq '.metadata.total_events'

# Calculate rate
events=$(cat cti_output/cti_ssh_*.json | jq '.metadata.total_events')
runtime=3600  # seconds
rate=$(echo "scale=2; $events / $runtime" | bc)
echo "Rate: $rate events/sec"
```

### Batch Processing Historical Logs

To process old logs:

```bash
# 1. Delete checkpoint
rm .cti_checkpoint.json

# 2. Delete output files (or move to archive)
rm -rf cti_output/*.json

# 3. Run parser on old logs
python3 cti_parser.py

# Parser will process all historical events
# Once caught up, it continues in real-time
```

### Multi-Instance Deployment

Run multiple parsers on different machines:

```
Machine 1: Parse SSH logs
python3 cti_parser.py # only SSH logs present

Machine 2: Parse HTTP logs  
python3 cti_parser.py # only HTTP logs present

Machine 3: Aggregate outputs
# Collect JSON files from both machines
```

### Monitoring & Alerting

```bash
# Check if parser is running
if ! pgrep -f cti_parser.py > /dev/null; then
    echo "Parser not running!" | mail -s "Alert" admin@example.com
fi

# Check for new events
last_event=$(cat cti_output/cti_ssh_*.json | jq -r '.events[-1].timestamp')
current_time=$(date -u +%s)
last_event_time=$(date -d "$last_event" +%s)
diff=$((current_time - last_event_time))

if [ $diff -gt 600 ]; then  # 10 minutes
    echo "No events in 10 minutes!" | mail -s "Alert" admin@example.com
fi
```

---

## Summary

### Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                    CTI PARSER QUICK REFERENCE                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ START:        python3 cti_parser.py                        │
│ STOP:         Ctrl+C                                        │
│ STATUS:       ps aux | grep cti_parser                      │
│                                                             │
│ VIEW OUTPUT:  cat cti_output/cti_ssh_*.json | jq .        │
│ FRESH START:  rm -rf cti_output/*.json                     │
│                                                             │
│ LOGS:         Check terminal output                         │
│ CHECKPOINT:   .cti_checkpoint.json                          │
│ OUTPUT:       cti_output/cti_*.json                        │
│                                                             │
│ INTERVAL:     --interval 5 (seconds)                        │
│ OUTPUT DIR:   --output-dir cti_output                       │
│ CHECKPOINT:   --checkpoint .cti_checkpoint.json            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Key Takeaways

✅ **Self-contained** - No external dependencies  
✅ **Continuous** - Monitors logs in real-time  
✅ **Smart** - Checkpoints prevent duplicates  
✅ **Robust** - Handles errors and rotation  
✅ **Clean** - Structured JSON output  
✅ **Ready** - For Kafka, Neo4j, or any downstream system  

---

**For questions or issues, contact the development team.**

**Version:** 1.0  
**Last Updated:** October 24, 2025  
**Author:** CTI Team
