"""Mock MozDef Faker Client"""
import boto3
import datetime
import json


MESSAGE = {
    "timestamp": datetime.datetime.utcnow().isoformat(),
    "severity": "CRITICAL",
    "summary": "Cloudtrail Logging Disabled: arn:aws:cloudtrail:us-west-2:656532927350:trail/MozillaGlobalSecureCloudTrailStorage-CloudTrail-UCQPVJ9K1X5I",
    "category": "AWSCloudtrail",
    "tags": [
        "cloudtrail",
        "aws",
        "cloudtrailpagerduty"
    ]
}

def put_message():
    sqs = boto3.client('sqs', region_name='us-east-1')
    sqs.send_message(
        QueueUrl='https://sqs.us-east-1.amazonaws.com/371522382791/iraas-AlertsInQueue.fifo',
        MessageBody=json.dumps(MESSAGE),
        MessageGroupId='alerts'
    )

if __name__ == "__main__":
    put_message()
