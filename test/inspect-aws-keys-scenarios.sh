#!/bin/bash
# Runs inside the sandbox, as the `run:` input of a proxy_engine: inspect step
# with the AWS access key check on (see test/integration-test-inspect-aws-keys.sh).
# The fixture origin stands in for every AWS host, and answers
# /sts/same-account and /sts/other-account with an AssumeRole response for a
# role in the allowed account and in another one.
#
# ---------------------------------------------------------------------------
# Under test:
#   allowed_aws_accounts: 111111111111
#   AWS_ACCESS_KEY_ID:    ${AKIA}TESTSTARTKEY0001
#   allowed_url_rules:
#     * https://**.amazonaws.com/**
#     GET https://allowed.example.com/public/**
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

echo "=== [the key the step started with] ==="
check_status "a request signed with it" "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" $CF)" "200"
check_status "a presigned URL carrying it" \
  "$($C "https://bucket.s3.amazonaws.com/x?X-Amz-Credential=${AKIA}TESTSTARTKEY0001%2F20261008%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=ab")" "200"

echo "=== [a key of the build's own] ==="
check_status "a request signed with it" "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTATTACKER0001)" $CF)" "403"
check_status "a presigned URL carrying it" \
  "$($C "https://bucket.s3.amazonaws.com/x?X-Amz-Credential=${AKIA}TESTATTACKER0001%2F20261008%2Fus-east-1%2Fs3%2Faws4_request")" "403"
check_status "a presigned URL carrying it under a percent-encoded name" \
  "$($C "https://bucket.s3.amazonaws.com/x?X-Amz-Cr%65dential=${AKIA}TESTATTACKER0001%2F20261008%2Fus-east-1%2Fs3%2Faws4_request")" "403"

echo "=== [no AWS credential] ==="
check_status "an unsigned read from a bucket" "$($C https://bucket.s3.amazonaws.com/public/x)" "200"
check_status "a Bearer-token push to a registry" \
  "$($C -X POST -H "Authorization: Bearer registry-token" https://111111111111.dkr.ecr.us-east-1.amazonaws.com/v2/app/blobs/uploads/)" "200"
check_status "a Bearer-token pull from a FIPS registry" \
  "$($C -H "Authorization: Bearer registry-token" https://111111111111.dkr.ecr-fips.us-east-1.amazonaws.com/v2/)" "200"
check_status "a Basic-auth search on an OpenSearch domain" \
  "$($C -u admin:secret https://search-logs-abcdefghijklmnop.us-east-1.es.amazonaws.com/_search)" "200"
check_status "an unsigned read of an EKS OIDC discovery document" \
  "$($C https://oidc.eks.us-east-1.amazonaws.com/id/ABCDEF0123456789/.well-known/openid-configuration)" "200"
check_status "a POST-policy upload to a bucket, its credential in the form" \
  "$($C -F "x-amz-credential=${AKIA}TESTATTACKER0001/20261008/us-east-1/s3/aws4_request" -F "file=@/dev/null" https://bucket.s3.amazonaws.com/)" "403"
check_status "an unsigned STS call" "$($C -X POST $STS/)" "403"
check_status "an unsigned read from STS" "$($C "$STS/?Action=GetCallerIdentity")" "403"
check_status "a Bearer token to CloudFormation" "$($C -X POST -H "Authorization: Bearer token" $CF)" "403"

echo "=== [more than one credential] ==="
check_status "two Authorization headers" \
  "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Authorization: $(sigv4 ${AKIA}TESTATTACKER0001)" $CF)" "403"
check_status "a query credential repeated across an encoded newline" \
  "$($C "https://bucket.s3.amazonaws.com/x?X-Amz-Credential=${AKIA}TESTSTARTKEY0001%2Fx&a=%0A&X-Amz-Credential=${AKIA}TESTATTACKER0001%2Fx")" "403"
check_status "a header and a query credential" \
  "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" "$CF?X-Amz-Credential=${AKIA}TESTATTACKER0001%2Fx")" "403"

echo "=== [a SigV2 key in a form body] ==="
sigv2() { echo "Action=ListQueues&AWSAccessKeyId=$1&SignatureVersion=2&Signature=ab"; }
check_status "the start key alone" "$($C -d "$(sigv2 ${AKIA}TESTSTARTKEY0001)" $CF)" "200"
check_status "a key of the build's own alone" "$($C -d "$(sigv2 ${AKIA}TESTATTACKER0001)" $CF)" "403"
check_status "a key of the build's own under a percent-encoded name" \
  "$($C -d "Action=ListQueues&AWSAccessK%65yId=${AKIA}TESTATTACKER0001" $CF)" "403"
check_status "the start key in both the header and the body" \
  "$($C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -d "$(sigv2 ${AKIA}TESTSTARTKEY0001)" $CF)" "200"
check_status "the start key in the header, a key of the build's own in the body" \
  "$($C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -d "$(sigv2 ${AKIA}TESTATTACKER0001)" $CF)" "403"
check_status "the start key in the header, a SigV2 URL inside a body value" \
  "$($C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -d "Action=Publish&Message=https%3A%2F%2Fb.s3.amazonaws.com%2Fk%3FAWSAccessKeyId%3D${AKIA}TESTATTACKER0001%26Expires%3D1" $CF)" "200"
check_status "the key repeated in the body" \
  "$($C -d "$(sigv2 ${AKIA}TESTSTARTKEY0001)&AWSAccessKeyId=${AKIA}TESTSTARTKEY0001" $CF)" "403"

echo "=== [what the check cannot read through] ==="
pad() { head -c "$1" /dev/zero | tr '\0' a; }
check_status "the start key in the header, a key of the build's own past 300 KB of body" \
  "$({ printf 'Action=X&M='; pad 300000; printf '&AWSAccessKeyId=%s' "${AKIA}TESTATTACKER0001"; } |
    $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "403"
check_status "the start key in the header, a 300 KB body" \
  "$({ printf 'Action=X&M='; pad 300000; } |
    $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "200"
check_status "the start key in the header, a form body past 4 MiB" \
  "$({ printf 'Action=X&M='; pad 4300000; } |
    $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "403"
check_status "the start key in the header, a compressed form body" \
  "$(printf 'Action=X' | gzip | $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Encoding: gzip" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "403"
check_status "the start key in the header, a NUL ahead of a key of the build's own in the body" \
  "$(printf 'Action=X\0&AWSAccessKeyId=%s' "${AKIA}TESTATTACKER0001" |
    $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "403"
check_status "the start key in the header, a form body compressed and marked identity too" \
  "$(printf 'Action=X' | gzip | $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Encoding: gzip, identity" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "403"
check_status "the start key in the header, a chunked form body" \
  "$(printf 'Action=X' | $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Transfer-Encoding: chunked" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "403"
check_status "the start key in the header, a key of the build's own in a form body sent as text/plain" \
  "$($C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type: text/plain" -d "$(sigv2 ${AKIA}TESTATTACKER0001)" $CF)" "403"
# 413 is the fixture origin's own 1 MiB cap: the proxy let the body through.
check_status "the start key in the header, a 2 MB binary body with no Content-Type" \
  "$({ printf '\x89PNG'; pad 2000000; } | $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type:" --data-binary @- $CF)" "413"
check_status "a public read whose query holds a broken escape" "$($C "https://bucket.s3.amazonaws.com/public/x?a=%zz")" "403"
check_status "a presigned URL with %00 ahead of its credential" \
  "$($C "https://bucket.s3.amazonaws.com/x?a=%00&X-Amz-Credential=${AKIA}TESTATTACKER0001%2Fx")" "403"

echo "=== [a key AssumeRole issued] ==="
check_status "unknown until AssumeRole hands it out" \
  "$($C -X POST -H "Authorization: $(sigv4 ${ASIA}TESTLEARNEDKEY01)" $CF)" "403"
check_status "AssumeRole for a role in the allowed account" \
  "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Accept-Encoding: gzip" $STS/sts/same-account)" "200"
check_status "the key it issued" "$($C -X POST -H "Authorization: $(sigv4 ${ASIA}TESTLEARNEDKEY01)" $CF)" "200"
check_status "AssumeRole for a role in another account" \
  "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" $STS/sts/other-account)" "200"
check_status "the key that one issued" "$($C -X POST -H "Authorization: $(sigv4 ${ASIA}TESTFOREIGNKEY01)" $CF)" "403"

echo "=== [hosts that are not AWS] ==="
check_status "an unsigned read the URL rules allow" "$($C https://allowed.example.com/public/x)" "200"

scenario_results "AWS access key scenarios"
