import base64
import boto3
import json
import logging
import os

from utils import set_stream_logger


logger = logging.getLogger('iraas.credential')


class Roles(object):
    def __init__(self):
        self.s3 = boto3.client('s3')
        self.sts = None
        self.roles = None

    def get(self):
        """Returns a list containing the roles for incident response."""
        response = self.s3.get_object(
            Bucket=self._get_bucket(), Key=self._get_key()
        )['Body']
        self.roles = json.load(response)
        return self.roles

    @property
    def response(self):
        """Returns only the Incident response roles from the list as a list."""
        if self.roles is None:
            self.get()

        response_roles = [
            x['Arn'] for x in self.roles if x['Type'] == 'InfosecIncidentResponseRole'
        ]

        return response_roles

    @property
    def audit(self):
        """Returns only the Audit Roles from the list of roles as a list."""
        if self.roles is None:
            self.get()

        audit_roles = [
            x['Arn'] for x in self.roles if x['Type'] == 'InfosecSecurityAuditRole'
        ]

        return audit_roles

    def account_id_for_role(self, role_arn):
        """
        :param role_arn the AWS ARN of the role.
        :return account_id in Amazon format.
        """
        return int(role_arn.split(':')[4])

    def role_for_account_id(self, account_id, role_list):
        """Get a given role for an account id.
        :param account_id the id your trying to correlate with a role.
        :param role_list a python list of the Mozilla role format.
        """
        for role in role_list:
            if self.account_id_for_role(role) == account_id:
                return role
            else:
                continue
        return None

    def assume(self, arn):
        """Performs role assumption for an ARN and return an STS Token."""
        if self.sts is None:
            self.sts = boto3.client('sts')

        sts_token = self.sts.assume_role(
            RoleArn=arn,
            RoleSessionName='iraas-response',
            DurationSeconds=5000
        )

        # Remove expiration to avoid datetime serialization.
        # We know how long these are good for ( not long at all )
        del sts_token['Credentials']['Expiration']

        return sts_token.get('Credentials')

    def _get_bucket(self):
        """Config convinience function to get the bucket location out of the env."""
        return os.getenv(
            's3_bucket',
            'infosec-internal-data'
        )

    def _get_key(self):
        """Get the name of the file to retreive with the role.json from S3."""
        return os.getenv(
            'key',
            'iam-roles/roles.json'
        )


def handler(event=None, context={}):
    account_id = int(event.get('account_id', None))
    if account_id:
        # New up a role object.
        r = Roles()

        # Take the event and find the response role.
        role_arn = r.role_for_account_id(account_id, r.response)

        # Get a temp credential using assume_role and return it to the caller.
        temporary_credential = {
            'sts_token': r.assume(role_arn)
        }

        return temporary_credential
    else:
        """TBD: Fix this to return an error and log message that role could not be assumed."""
        pass
