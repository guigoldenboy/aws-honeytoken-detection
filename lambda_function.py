cat > lambda_function.py << 'EOF'
import json
import boto3
import os
import urllib.request
import gzip
import base64

def lambda_handler(event, context):
    if 'awslogs' in event:
        compressed = base64.b64decode(event['awslogs']['data'])
        decompressed = gzip.decompress(compressed)
        log_data = json.loads(decompressed)
        
        for log_event in log_data.get('logEvents', []):
            try:
                trail_event = json.loads(log_event['message'])
                process_event(trail_event)
            except:
                continue
    else:
        process_event(event.get('detail', event))
    
    return {'statusCode': 200, 'body': 'Alert sent'}

def process_event(detail):
    source_ip = detail.get('sourceIPAddress', 'Unknown')
    user_agent = detail.get('userAgent', 'Unknown')
    event_name = detail.get('eventName', 'Unknown')
    user = detail.get('userIdentity', {}).get('userName', 'Unknown')
    event_time = detail.get('eventTime', 'Unknown')
    bucket = detail.get('requestParameters', {}).get('bucketName', '')

    is_honeytoken_user = user == 'honeytoken-backup-svc'
    is_honey_bucket = bucket == 'honey-leaked-credentials'

    if not is_honeytoken_user and not is_honey_bucket:
        return

    # geolocalização
    try:
        geo_url = f"http://ip-api.com/json/{source_ip}"
        geo_response = urllib.request.urlopen(geo_url, timeout=3)
        geo_data = json.loads(geo_response.read())
        location = f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
    except:
        location = "Unknown"

    if is_honeytoken_user:
        subject = '🚨 IAM HONEYTOKEN TRIGGERED - credential access detected'
        message = f"""
🚨 IAM HONEYTOKEN TRIGGERED 🚨

fake IAM credentials were used. an attacker may have found exposed AWS keys.

Event: {event_name}
User: {user}
Time: {event_time}
Source IP: {source_ip}
Location: {location}
User Agent: {user_agent}

investigate immediately and revoke credentials.
        """
    else:
        subject = '🚨 S3 HONEYTOKEN TRIGGERED - Unauthorized Bucket Access Detected'
        message = f"""
🚨 S3 HONEYTOKEN TRIGGERED 🚨

honey bucket was accessed. an attacker may be performing reconnaissance inside your AWS account.

Event: {event_name}
Bucket: {bucket}
User: {user}
Time: {event_time}
Source IP: {source_ip}
Location: {location}
User Agent: {user_agent}

investigate immediately.
        """

    sns = boto3.client('sns', region_name='eu-west-1')
    sns.publish(
        TopicArn=os.environ['SNS_TOPIC_ARN'],
        Subject=subject,
        Message=message
    )
EOF