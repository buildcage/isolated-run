#!/bin/bash
# Runs inside the sandbox with aws_key_check on and no allowed_aws_role_accounts
# (see test/integration-test-inspect-aws-keys.sh): the step's own key passes,
# a key AssumeRole issues, even for a role in the start key's account, is never
# learned, and one ECR issues for a layer's presigned URL is.
#
# ---------------------------------------------------------------------------
# Under test:
#   aws_key_check:        true
#   AWS_ACCESS_KEY_ID:    ${AKIA}TESTSTARTKEY0001
#   allowed_url_rules:
#     * https://**.amazonaws.com/**
# ---------------------------------------------------------------------------
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

# Assembled at runtime: a literal shaped like an AWS access key ID trips secret
# scanning on push.
AKIA="AK""IA"
ASIA="AS""IA"

C="curl -sS -o /dev/null -w %{http_code} --max-time 10"
CF=https://cloudformation.us-east-1.amazonaws.com/
STS=https://sts.us-east-1.amazonaws.com
sigv4() { echo "AWS4-HMAC-SHA256 Credential=$1/20261008/us-east-1/cloudformation/aws4_request, SignedHeaders=host, Signature=ab"; }

check_status "a request signed with the start key" "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" $CF)" "200"
check_status "a request signed with a key of the build's own" "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTATTACKER0001)" $CF)" "403"
check_status "AssumeRole for a role in the start key's account" \
  "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" $STS/sts/same-account)" "200"
check_status "the key it issued, learned by no role account" "$($C -X POST -H "Authorization: $(sigv4 ${ASIA}TESTLEARNEDKEY01)" $CF)" "403"

LAYER="https://prod-us-east-1-starport-layer-bucket.s3.amazonaws.com/layer?X-Amz-Credential=${ASIA}TESTISSUEDKEY01%2F20261010%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=ab"
check_status "a layer download from a registry" \
  "$($C https://111111111111.dkr.ecr.us-east-1.amazonaws.com/v2/app/blobs/sha256:abc)" "307"
check_status "the presigned URL it redirected to, learned with no role account" "$($C "$LAYER")" "200"

check_status "a web identity call, with no role account to judge it by" \
  "$($C -X POST -H "Content-Type: application/x-www-form-urlencoded" --data "Action=AssumeRoleWithWebIdentity&RoleArn=arn%3Aaws%3Aiam%3A%3A111111111111%3Arole%2Fdeploy" $STS/sts/web-identity)" "403"

scenario_results "AWS key-only scenarios"
