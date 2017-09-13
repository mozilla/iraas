"""Class that controls all response plugins and wrappers around aws_ir and custom."""
import boto3
import logging

from plugins import cloudtrail_reenable
from utils import set_stream_logger

set_stream_logger(level=logging.INFO)
logger = logging.getLogger('iraas')


class Compromise(object):
    """Compromise object that sets up the correct vars to call aws_ir."""
    def __init__(
        self,
        examiner_cidr_range='0.0.0.0',
        compromised_resource={},
        region='us-west-2',
        case=None,
        steps=None,
        credentials=None
    ):

        self.case_type = compromised_resource.get('compromise_type')
        self.credentials = credentials
        self.compromised_resource = compromised_resource
        self.region = region
        self.case = case
        self.steps = steps

    def mitigate(self):
        if self.case_type == 'cloudtrail':
            plugin = cloudtrail_reenable.Plugin(
                boto_session=self._boto_session(),
                compromised_resource=self.compromised_resource,
                dry_run=False
            )

            plugin.setup()

    def _boto_session(self):
        """Use the assume role credentials obtained earlier to form a boto session we can pass around."""
        return boto3.session.Session(
            aws_access_key_id=self.credentials.get('AccessKeyId'),
            aws_secret_access_key=self.credentials.get('SecretAccessKey'),
            aws_session_token=self.credentials.get('SessionToken')
        )

def handler(event, context={}):
    logger.info('Reponse function invocation.  Newing up a compromise object.')
    c = Compromise(
        examiner_cidr_range=event.get('examiner_cidr_range', '0.0.0.0'),
        compromised_resource=event.get('compromised_resource'),
        region=event.get('region'),
        case=None,
        steps=event.get('steps'),
        credentials=event.get('sts_token')
    )

    c.mitigate()

    return 200 #TBD return status for response request or move SQS logging here.

if __name__ == "__main__":
    # Sample Event
    event = {
        'sts_token': {'AccessKeyId': '', 'SecretAccessKey': '', 'SessionToken': ''},
        'examiner_cidr_range': '0.0.0.0/0',
        'incident_plan': ['cloudtrail_reenable'],
        'compromised_resource': {
            'compromise_type': 'cloudtrail'
        },
        'region': 'us-west-2'
    }
