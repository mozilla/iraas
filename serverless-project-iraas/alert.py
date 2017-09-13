import base64
import boto3
import datetime
import json
import logging
import re

from utils import set_stream_logger

set_stream_logger(level=logging.INFO)
logger = logging.getLogger('iraas.alert')


class Queue(object):
    """Object to govern interaction with SQS in and out data."""
    def __init__(self):
        self.sqs = boto3.client('sqs')

    @property
    def input_url(self):
        return self.sqs.get_queue_url(
            QueueName='iraas-AlertsInQueue.fifo'
        ).get('QueueUrl')

    @property
    def output_url(self):
        return self.sqs.get_queue_url(
            QueueName='iraas-AlertsOutQueue.fifo'
        ).get('QueueUrl')

    def unprocessed(self, queue_url):
        """Return the number of visible messages in queue."""
        return self.sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                'ApproximateNumberOfMessages'
            ]
        )['Attributes']['ApproximateNumberOfMessages']

    def get_alerts_in(self):
        """
        Searches SQS to see if messages are available. Return messages without
        alerting the visibility.
        """
        response = self.sqs.receive_message(
            QueueUrl=self.input_url,
            AttributeNames=[
                'All'
            ],
            VisibilityTimeout=0,
            MaxNumberOfMessages=10
        )

        logger.info('Alerts retrieved from the input queue.  Proceeding to action identification.')

        return response.get('Messages')


class Message(object):
    """Object for generic output to MozDef in the required event format."""
    def __init__(self, alert):
        self.alert = {}

    def store_result(object):
        """Send the job result to the SQS queue to be collected by MozDef."""
        pass


class Respond(object):
    """Respond by taking actions in the AWS account based on event."""
    def __init__(self, incident_type, alert):
        self.incident_type = incident_type
        self.alert = json.loads(alert)
        self.account_id = None
        self.action_result = {}
        credentials = None

    def _get_cloudtrail_account(self, summary):
        self.account_id = summary.split('arn:aws:')[1].split(':')[2]
        return self.account_id

    def _invoke_response_function(self, response_event):
        lc = boto3.client('lambda')
        response = lc.invoke(
            FunctionName='iraas-prod-response-processor',
            InvocationType='RequestResponse',
            Payload=bytes(
                json.dumps(
                    response_event
                ).encode('utf-8')
            )
        )
        return response

    def take_action(self):
        self.action_result['timestamp'] = datetime.datetime.utcnow().isoformat()
        if self.incident_type == 'cloudtrail':
            logger.info('CloudTrail incident identified. Proceeding to role assumption.')

            self.account_id = self._get_cloudtrail_account(
                self.alert.get('summary')
            )

            self.assume_role()
            logger.info('Responder role has been assumed crafting response event.')

            if self.credentials is not {}:
                # We have a set of creds let's respond.
                response_event = self.generate_payload()

                logger.info('Response event crafted proceeding to lambda invocation.')
                reponse_result = self._invoke_response_function(response_event)

                logger.info('Reponse complete for resource.  Outputting message to queue.')


        elif self.incident_type == 'instance-compromise':
            # To-Do
            pass
        elif self.incident_type == 'access_key-compromise':
            # To-Do
            pass
        else:
            response_result = None
        return response_result
    def _extract_region(self, summary):
         return summary.split('arn:aws:')[1].split(':')[1]

    def generate_payload(self):

        compromised_resource = {
            'compromise_type': self.incident_type
        }

        return {
            'sts_token': self.credentials,
            'examiner_cidr_range': '0.0.0.0/0',
            'incident_plan': ['cloudtrail_reenable'],
            'compromised_resource': compromised_resource, # No need for this in CloudTrail.
            'region': self._extract_region(self.alert.get('summary'))
        }

    def assume_role(self):
        lc = boto3.client('lambda')
        response = lc.invoke(
            FunctionName='iraas-prod-credential-processor',
            InvocationType='RequestResponse',
            Payload=bytes(
                json.dumps({'account_id': self.account_id}).encode('utf-8')
            )
        )

        logger.info('Invocation of credential processor complete.  Returning credentials.')
        self.credentials = json.loads(response.get('Payload').read())['sts_token']

    def log(self):
        ### ToDO craft an output event to MozDef
        pass


class Incident(object):
    def __init__(self, alert_message):
        self.alert = json.loads(alert_message)

    def resource_type(self):
        """Returns CloudTrail, instance, or access based on tag and message."""

        if 'cloudtrail' in self.alert.get('tags'):
            return 'cloudtrail'
        else:
            return None


def handler(event=None, context=None):
    # Determine if there is work to do by polling SQS.  If message > 0
    q = Queue()

    if int(q.unprocessed(q.input_url)) > 0:
        # Load the messages
        logger.info('There is work to be done.  Proceeding to identification.')

        alerts = q.get_alerts_in()

        if alerts is not None:
            for message in alerts:
                logger.info('Working incident for message: {body}'.format(body=message.get('Body')))

                alert = message.get('Body', None) # This is the event summary as it came from MozDef
                incident = Incident(alert)

                # Determine if resource should be auto-ir'ed based on Cloud Health API
                # (if access_key, instance_id, instance_ip, or ... ?)
                respond = Respond(incident.resource_type(), alert)
                respond.take_action()

                # Log the result to the Output SQS queue
                respond.log()
    else:
        logger.info('No unprocessed queue messages.  Happy day.')

    return 200


if __name__ == "__main__":

    print(handler())
