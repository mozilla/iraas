# Incident Response as a Service - Work in Progress

This toolkit is a serverless framework application that builds on the
capabilities in aws_ir.  It can do host_compromises, key_compromises, and
cloudtrail_compromises.

## Dev Environment Setup

1. `cd serverless-project-iraas`
1. `npm install --save serverless`
1. `npm install --save serverless-python-requirements`
1. `npm install --save https://github.com/vortarian/serverless-sqs-fifo`

## Incident Flow

1. CIM ( MozDef in our case ) generates an alert to the service by outputting to an SQS Queue for
incidents in.

2. CloudWatch events poll the SQS queue every 1-minute and if there's work to do spin up the credential
helper function.  The credential helper looks at the list of roles and attempts to match the account ID
with the resource we're remediating.  Once a role is matched that role is assumed and the credentials are
passed to the IR function.

3. The IR function determines the type of resource it is taking actions on and follows the plan
for that type of resource as determined by the configuration of the deployment.

## Sample event to output to SQS

_CloudTrail Disabled_

_Instance Suspected of Malicious Activity_
(Future)

_Access Key Suspected Leak or Anomaly_
(Future)

## Resources to Create

1. SQS Input FIFO Queue
2. SQS Output FIFO Queue
3. CloudWatch metric + CloudWatch Event to invoke lambda if SQS.ApproxMessagesVisible > 0
4. Credential Assumption Function
5. IR Function

## Deploying this Service
A Dockerfile is present in the project to facilitate deployment with the serverless framework.

```bash
docker run --rm -ti \
-v ~/.aws:/root/.aws \
-v ~/workspace/iraas/:/workspace \
mozillaiam/docker-sls:latest \
/bin/bash
```

## Sample Client Output

A sample client for event mocking purposes has been provided in the example-client directory.
