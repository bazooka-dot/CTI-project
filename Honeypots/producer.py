import json
import time
from kafka import KafkaProducer

# ============================================================================
# STEP 1: CONFIGURATION
# ============================================================================
print("=" * 60)
print("SIMPLE KAFKA PRODUCER - TEST MODE")
print("=" * 60)

# Kafka broker address
KAFKA_BROKER = "10.0.2.48:9092"

# Your CTI output files
SSH_FILE = "cti_output/cti_ssh_20251024_142240.json"
HTTP_FILE = "cti_output/cti_http_20251024_142240.json"

# Kafka topics to send to
TOPIC_SSH = "cti-raw-events"  # We'll send everything here for testing
TOPIC_HTTP = "cti-raw-events"  # Same topic for simplicity

print(f"\nConfiguration:")
print(f"   Kafka Broker: {KAFKA_BROKER}")
print(f"   SSH File: {SSH_FILE}")
print(f"   HTTP File: {HTTP_FILE}")
print(f"   Target Topic: {TOPIC_SSH}")

# ============================================================================
# STEP 2: CONNECT TO KAFKA
# ============================================================================
print(f"\nConnecting to Kafka...")

try:
    producer = KafkaProducer(
        bootstrap_servers=[KAFKA_BROKER],
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )
    print("Connected to Kafka successfully!")
except Exception as e:
    print(f"Failed to connect: {e}")
    print("\nMake sure:")
    print("   1. Kafka is running: systemctl status kafka")
    print("   2. Broker address is correct: 10.0.2.48:9092")
    exit(1)

# ============================================================================
# STEP 3: READ SSH EVENTS
# ============================================================================
print(f"\nReading SSH events from {SSH_FILE}...")

try:
    with open(SSH_FILE, 'r') as f:
        ssh_data = json.load(f)
    
    ssh_events = ssh_data.get('events', [])
    print(f"Found {len(ssh_events)} SSH events")
    
    # Show first event as example
    if ssh_events:
        print(f"\nExample SSH event:")
        first_event = ssh_events[0]
        print(f"   - Timestamp: {first_event.get('timestamp')}")
        print(f"   - Source IP: {first_event.get('source_ip')}")
        print(f"   - Event Type: {first_event.get('event_type')}")
        print(f"   - Severity: {first_event.get('severity')}")

except FileNotFoundError:
    print(f"File not found: {SSH_FILE}")
    print("Make sure your parser has created this file")
    ssh_events = []
except Exception as e:
    print(f"Error reading file: {e}")
    ssh_events = []

# ============================================================================
# STEP 4: SEND SSH EVENTS TO KAFKA
# ============================================================================
if ssh_events:
    print(f"\nSending SSH events to Kafka topic: {TOPIC_SSH}")
    print("   (This might take a few seconds...)")
    
    sent_count = 0
    
    for event in ssh_events:
        try:
            # Send event to Kafka
            future = producer.send(TOPIC_SSH, value=event)
            
            # Wait for confirmation
            result = future.get(timeout=10)
            
            sent_count += 1
            
            # Show progress every 5 events
            if sent_count % 5 == 0:
                print(f"   Sent {sent_count}/{len(ssh_events)} events...")
        
        except Exception as e:
            print(f"   Error sending event: {e}")
    
    print(f"Sent {sent_count} SSH events to Kafka")

# ============================================================================
# STEP 5: READ HTTP EVENTS
# ============================================================================
print(f"\nReading HTTP events from {HTTP_FILE}...")

try:
    with open(HTTP_FILE, 'r') as f:
        http_data = json.load(f)
    
    http_events = http_data.get('events', [])
    print(f"Found {len(http_events)} HTTP events")
    
    # Show first event as example
    if http_events:
        print(f"\nExample HTTP event:")
        first_event = http_events[0]
        print(f"   - Timestamp: {first_event.get('timestamp')}")
        print(f"   - Source IP: {first_event.get('source_ip')}")
        print(f"   - Method: {first_event.get('method')}")
        print(f"   - URL: {first_event.get('url')}")
        print(f"   - Status: {first_event.get('status_code')}")

except FileNotFoundError:
    print(f"File not found: {HTTP_FILE}")
    http_events = []
except Exception as e:
    print(f"Error reading file: {e}")
    http_events = []

# ============================================================================
# STEP 6: SEND HTTP EVENTS TO KAFKA
# ============================================================================
if http_events:
    print(f"\nSending HTTP events to Kafka topic: {TOPIC_HTTP}")
    print("   (This might take a few seconds...)")
    
    sent_count = 0
    
    for event in http_events:
        try:
            # Send event to Kafka
            future = producer.send(TOPIC_HTTP, value=event)
            
            # Wait for confirmation
            result = future.get(timeout=10)
            
            sent_count += 1
            
            # Show progress every 10 events
            if sent_count % 10 == 0:
                print(f"   Sent {sent_count}/{len(http_events)} events...")
        
        except Exception as e:
            print(f"   Error sending event: {e}")
    
    print(f"Sent {sent_count} HTTP events to Kafka")

# ============================================================================
# STEP 7: CLOSE CONNECTION
# ============================================================================
print(f"\nFlushing remaining messages...")
producer.flush()

print(f"Closing Kafka connection...")
producer.close()

# ============================================================================
# STEP 8: SUMMARY
# ============================================================================
print("\n" + "=" * 60)
print("PRODUCER TEST COMPLETED!")
print("=" * 60)
print(f"\nSummary:")
print(f"   - SSH events sent: {len(ssh_events)}")
print(f"   - HTTP events sent: {len(http_events)}")
print(f"   - Total events: {len(ssh_events) + len(http_events)}")
print(f"   - Target topic: {TOPIC_SSH}")

print(f"\nNext Steps:")
print(f"   1. Check Kafka UI: http://10.0.2.48:8080")
print(f"   2. Look for topic: {TOPIC_SSH}")
print(f"   3. You should see {len(ssh_events) + len(http_events)} messages!")

print(f"\nTo consume messages from command line:")
print(f"   kafka-console-consumer.sh \\")
print(f"     --bootstrap-server {KAFKA_BROKER} \\")
print(f"     --topic {TOPIC_SSH} \\")
print(f"     --from-beginning | jq .")

print("\n" + "=" * 60)