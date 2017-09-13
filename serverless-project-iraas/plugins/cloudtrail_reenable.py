"""CloudTrail Plugin that will eventually go to aws_ir."""
import logging


logger = logging.getLogger('iraas')


class Plugin(object):
    def __init__(
        self,
        boto_session,
        compromised_resource,
        dry_run=False
    ):

        self.session = boto_session
        self.compromised_resource = compromised_resource
        self.compromise_type = compromised_resource['compromise_type']
        self.dry_run = dry_run

        self.client = None
        self.disabled_trails = []

        # Execute what the plugin does.
        self.setup()

    def setup(self):
        logger.info('CloudTrail plugin activated.')
        if not self.client:
            self._connect()

        self._assess_state()
        self._restart_trails()

    def _restart_trails(self):
        if len(self.disabled_trails) > 0:
            for trail_arn in self.disabled_trails:
                logger.info('Attempting to re-enabled {trail}.'.format(trail=trail_arn))
                self.start_logging(trail_arn)

    def _connect(self):
        self.client = self.session.client(
            'cloudtrail',
            region_name=self.compromised_resource.get(
                'region', 'us-west-2'
            )
        )

    def _locate_trails(self):
        if not self.client:
            self._connect()

        logger.info('Populating trail list.')

        response = self.client.describe_trails()
        return response.get('trailList')

    def _assess_state(self):
        trails = self._locate_trails()
        if trails is not None:
            logger.info('Trails located checking the state of each trail.')
            for trail in trails:
                if not self._trail_is_enabled(trail.get('Name')):
                    logger.info('Disabled trail found adding to the list for processing.')
                    self.disabled_trails.append(trail.get('TrailArn'))
                else:
                    continue

    def _trail_is_enabled(self, name):
        if not self.client:
            self._connect()

        response = self.client.get_trail_status(
            Name=name
        )

        if response.get('IsLogging') is True:
            logger.info('CloudTrail is operating normally for {trail}.'.format(trail=name))
            return True
        else:
            logger.info('CloudTrail is not operating normally {trail} queuing remediation.'.format(trail=name))
            return False

    def _start_logging(self, arn):
        if not self.client:
            self._connect()

        return self.client.start_logging(Name=arn)
