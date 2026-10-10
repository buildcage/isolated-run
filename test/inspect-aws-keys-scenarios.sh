#!/bin/bash
# Runs inside the sandbox, as the `run:` input of a proxy_engine: inspect step
# with the AWS access key check on (see test/integration-test-inspect-aws-keys.sh).
# The fixture origin stands in for every AWS host, and answers
# /sts/same-account and /sts/other-account with an AssumeRole response for a
# role in the allowed account and in another one.
#
# ---------------------------------------------------------------------------
# Under test:
#   aws_key_check: true
#   allowed_aws_role_accounts: 111111111111
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
check_status "a request signed with it under SigV4a" \
  "$($C -H "Authorization: AWS4-ECDSA-P256-SHA256 Credential=${AKIA}TESTSTARTKEY0001/20261008/s3/aws4_request, SignedHeaders=host, Signature=ab" https://bucket.s3.amazonaws.com/x)" "200"

echo "=== [a key of the build's own] ==="
check_status "a request signed with it" "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTATTACKER0001)" $CF)" "403"
check_status "a presigned URL carrying it" \
  "$($C "https://bucket.s3.amazonaws.com/x?X-Amz-Credential=${AKIA}TESTATTACKER0001%2F20261008%2Fus-east-1%2Fs3%2Faws4_request")" "403"
check_status "a request to checkip signed with it" "$($C -H "Authorization: $(sigv4 ${AKIA}TESTATTACKER0001)" https://checkip.amazonaws.com/)" "403"
check_status "a presigned URL carrying it under a percent-encoded name" \
  "$($C "https://bucket.s3.amazonaws.com/x?X-Amz-Cr%65dential=${AKIA}TESTATTACKER0001%2F20261008%2Fus-east-1%2Fs3%2Faws4_request")" "403"
# The proxy issues no certificate for such a name, but a client that skips
# verification still reaches the check.
check_status "a request signed with it, to a name with a _" \
  "$($C -k -X POST -H "Authorization: $(sigv4 ${AKIA}TESTATTACKER0001)" https://a_b.us-east-1.amazonaws.com/)" "403"

echo "=== [no AWS credential] ==="
check_status "an unsigned read from a bucket" "$($C https://bucket.s3.amazonaws.com/public/x)" "200"
check_status "a Bearer-token push to a registry" \
  "$($C -X POST -H "Authorization: Bearer registry-token" https://111111111111.dkr.ecr.us-east-1.amazonaws.com/v2/app/blobs/uploads/)" "200"
check_status "a Bearer-token pull from a FIPS registry" \
  "$($C -H "Authorization: Bearer registry-token" https://111111111111.dkr.ecr-fips.us-east-1.amazonaws.com/v2/)" "200"
check_status "a Basic-auth search on an OpenSearch domain" \
  "$($C -u admin:secret https://search-logs-abcdefghijklmnop.us-east-1.es.amazonaws.com/_search)" "200"
check_status "a Basic-auth search on an OpenSearch VPC domain" \
  "$($C -u admin:secret https://vpc-logs-abcdefghijklmnop.us-east-1.es.amazonaws.com/_search)" "200"
check_status "an API-key call to a Managed Grafana workspace" \
  "$($C -H "Authorization: Bearer glsa_token" https://g-abcdef1234.grafana-workspace.us-east-1.amazonaws.com/api/dashboards)" "200"
check_status "a Basic-auth call to an Amazon MQ broker console" \
  "$($C -u admin:secret https://b-0123abcd-4567-89ef-0123-456789abcdef.mq.us-east-1.amazonaws.com/api/overview)" "200"
check_status "an unsigned read of an EKS OIDC discovery document" \
  "$($C https://oidc.eks.us-east-1.amazonaws.com/id/ABCDEF0123456789/.well-known/openid-configuration)" "200"
check_status "an unsigned read of checkip" "$($C https://checkip.amazonaws.com/)" "200"
check_status "an unsigned read of the IP ranges" "$($C https://ip-ranges.amazonaws.com/ip-ranges.json)" "200"
check_status "an unsigned read of a Price List Bulk file" "$($C https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json)" "200"
check_status "a Bearer token to checkip" "$($C -H "Authorization: Bearer token" https://checkip.amazonaws.com/)" "403"
check_status "a POST-policy upload to a bucket, its credential in the form" \
  "$($C -F "x-amz-credential=${AKIA}TESTATTACKER0001/20261008/us-east-1/s3/aws4_request" -F "file=@/dev/null" https://bucket.s3.amazonaws.com/)" "403"
check_status "a POST-policy upload with the start key in the header too" \
  "$($C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -F "x-amz-credential=${AKIA}TESTATTACKER0001/20261008/us-east-1/s3/aws4_request" -F "file=@/dev/null" https://bucket.s3.amazonaws.com/)" "403"
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

echo "=== [a credential other than SigV4's, whatever its key] ==="
sigv2() { echo "Action=ListQueues&AWSAccessKeyId=$1&SignatureVersion=2&Signature=ab"; }
check_status "SigV2 in a form body, with the start key" "$($C -d "$(sigv2 ${AKIA}TESTSTARTKEY0001)" $CF)" "403"
check_status "SigV2 in a form body under a percent-encoded name" \
  "$($C -d "Action=ListQueues&AWSAccessK%65yId=${AKIA}TESTSTARTKEY0001" $CF)" "403"
check_status "SigV2 in a form body, the start key in the header too" \
  "$($C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -d "$(sigv2 ${AKIA}TESTSTARTKEY0001)" $CF)" "403"
check_status "SigV2's header, with the start key" \
  "$($C -X POST -H "Authorization: AWS ${AKIA}TESTSTARTKEY0001:c2lnbmF0dXJl" $CF)" "403"
check_status "SigV2's header to a bucket, with the start key" \
  "$($C -H "Authorization: AWS ${AKIA}TESTSTARTKEY0001:c2lnbmF0dXJl" https://bucket.s3.amazonaws.com/x)" "403"
check_status "a SigV2 presigned URL, with the start key" \
  "$($C "https://bucket.s3.amazonaws.com/x?AWSAccessKeyId=${AKIA}TESTSTARTKEY0001&Expires=1&Signature=ab")" "403"
check_status "SigV3's header beside the start key's" \
  "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "X-Amzn-Authorization: AWS3-HTTPS AWSAccessKeyId=${AKIA}TESTSTARTKEY0001,Algorithm=HmacSHA256,Signature=ab" $CF)" "403"
check_status "SigV4's parameters in a form body, the start key in the header" \
  "$($C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -d "Action=ListQueues&X-Amz-Credential=${AKIA}TESTSTARTKEY0001%2F20261008%2Fus-east-1%2Fsqs%2Faws4_request" $CF)" "403"
check_status "a presigned URL with the start key, a SigV2 URL inside a query value" \
  "$($C "https://bucket.s3.amazonaws.com/x?X-Amz-Credential=${AKIA}TESTSTARTKEY0001%2Fx&response-content-disposition=https%3A%2F%2Fb.s3.amazonaws.com%2Fk%3FAWSAccessKeyId%3D${AKIA}TESTATTACKER0001%26Expires%3D1")" "200"
check_status "the start key in the header, a SigV2 URL inside a body value" \
  "$($C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -d "Action=Publish&Message=https%3A%2F%2Fb.s3.amazonaws.com%2Fk%3FAWSAccessKeyId%3D${AKIA}TESTATTACKER0001%26Expires%3D1" $CF)" "200"
# AWS reads a body as a form only under that Content-Type.
check_status "the start key in the header, SigV2 in a body sent as text/plain" \
  "$($C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type: text/plain" -d "$(sigv2 ${AKIA}TESTATTACKER0001)" $CF)" "200"

echo "=== [what the check cannot read through] ==="
pad() { head -c "$1" /dev/zero | tr '\0' a; }
check_status "the start key in the header, a key of the build's own past 300 KB of body" \
  "$({ printf 'Action=X&M='; pad 300000; printf '&AWSAccessKeyId=%s' "${AKIA}TESTATTACKER0001"; } |
    $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "403"
check_status "the start key in the header, a 300 KB body" \
  "$({ printf 'Action=X&M='; pad 300000; } |
    $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "200"
# 413 is the fixture origin's own 1 MiB cap: the proxy read the body to its
# end and let it through.
check_status "the start key in the header, a body just under 4 MiB" \
  "$({ printf 'Action=X&M='; pad 4150000; } |
    $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "413"
check_status "the start key in the header, a key of the build's own at the end of a body just under 4 MiB" \
  "$({ printf 'Action=X&M='; pad 4150000; printf '&AWSAccessKeyId=%s' "${AKIA}TESTATTACKER0001"; } |
    $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @- $CF)" "403"
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
# 413 is the fixture origin's own 1 MiB cap: the proxy let the body through.
check_status "the start key in the header, a 2 MB binary body with no Content-Type" \
  "$({ printf '\x89PNG'; pad 2000000; } | $C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Content-Type:" --data-binary @- $CF)" "413"
check_status "a public read whose query holds a broken escape" "$($C "https://bucket.s3.amazonaws.com/public/x?a=%zz")" "200"
check_status "a presigned URL with %00 ahead of its credential" \
  "$($C "https://bucket.s3.amazonaws.com/x?a=%00&X-Amz-Credential=${AKIA}TESTATTACKER0001%2Fx")" "403"

echo "=== [an EKS cluster, which the URL rules pin] ==="
check_status "a kubectl Bearer token to the EKS service API, which names no cluster" \
  "$($C -H "Authorization: Bearer k8s-aws-v1.token" https://eks.us-east-1.amazonaws.com/clusters)" "403"
check_status "a kubectl Bearer token to a cluster" \
  "$($C -H "Authorization: Bearer k8s-aws-v1.token" https://abcdef0123456789abcdef0123456789.gr7.us-east-1.eks.amazonaws.com/api/v1/pods)" "200"

echo "=== [a CodeCommit login, which carries a key or an account] ==="
CC=https://git-codecommit.us-east-1.amazonaws.com/v1/repos/app/info/refs
check_status "Git's first CodeCommit request, with no credential" "$($C $CC)" "200"
check_status "a chunked Git fetch to CodeCommit with the start key" \
  "$(printf '0014command=fetch0000' | $C -u "${AKIA}TESTSTARTKEY0001:20261008T000000Zab" -H "Transfer-Encoding: chunked" -H "Content-Type: application/x-git-upload-pack-request" --data-binary @- https://git-codecommit.us-east-1.amazonaws.com/v1/repos/app/git-upload-pack)" "200"
check_status "a CodeCommit credential-helper login with the start key" \
  "$($C -u "${AKIA}TESTSTARTKEY0001:20261008T000000Zab" $CC)" "200"
check_status "a CodeCommit credential-helper login with a key of the build's own" \
  "$($C -u "${AKIA}TESTATTACKER0001:20261008T000000Zab" $CC)" "403"
check_status "a static CodeCommit Git credential of the allowed account" "$($C -u deploy-at-111111111111:secret $CC)" "200"
check_status "a static CodeCommit Git credential of another account" "$($C -u deploy-at-222222222222:secret $CC)" "403"
check_status "a CodeCommit login with the start key and a session token" \
  "$($C -u "${AKIA}TESTSTARTKEY0001%FQoGZXIvYXdz:20261008T000000Zab" $CC)" "200"
check_status "a CodeCommit login named only by an allowed account ID" "$($C -u 111111111111:secret $CC)" "403"
check_status "a static Git credential sent to another AWS API host" \
  "$($C -u deploy-at-111111111111:secret https://sqs.us-east-1.amazonaws.com/)" "403"

echo "=== [a key AssumeRole issued] ==="
check_status "unknown until AssumeRole hands it out" \
  "$($C -X POST -H "Authorization: $(sigv4 ${ASIA}TESTLEARNEDKEY01)" $CF)" "403"
check_status "an AssumeRole answer read unsigned from a bucket named sts" "$($C https://sts.s3.amazonaws.com/sts/same-account)" "200"
check_status "the same answer read with the start key" \
  "$($C -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" https://sts.s3.amazonaws.com/sts/same-account)" "200"
check_status "the key in it, still unknown" "$($C -X POST -H "Authorization: $(sigv4 ${ASIA}TESTLEARNEDKEY01)" $CF)" "403"
check_status "AssumeRole for a role in the allowed account" \
  "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" -H "Accept-Encoding: gzip" $STS/sts/same-account)" "200"
check_status "the key it issued" "$($C -X POST -H "Authorization: $(sigv4 ${ASIA}TESTLEARNEDKEY01)" $CF)" "200"
check_status "AssumeRole for a role in another account" \
  "$($C -X POST -H "Authorization: $(sigv4 ${AKIA}TESTSTARTKEY0001)" $STS/sts/other-account)" "200"
check_status "the key that one issued" "$($C -X POST -H "Authorization: $(sigv4 ${ASIA}TESTFOREIGNKEY01)" $CF)" "403"

echo "=== [a key ECR issued for a layer's presigned URL] ==="
LAYER=https://prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com/layer
presigned() { echo "$1?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${ASIA}TESTISSUEDKEY01%2F20261010%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=ab"; }
check_status "unknown until a registry redirects to it" "$($C "$(presigned $LAYER)")" "403"
check_status "the same redirect from an API Gateway host" \
  "$($C https://b123abcde4.execute-api.us-east-1.amazonaws.com/v2/app/blobs/sha256:abc)" "307"
check_status "the key in it, still unknown" "$($C "$(presigned $LAYER)")" "403"
check_status "a layer download from a registry" \
  "$($C -H "Authorization: Bearer registry-token" https://111111111111.dkr.ecr.us-east-1.amazonaws.com/v2/app/blobs/sha256:abc)" "307"
check_status "the presigned URL it redirected to" "$($C "$(presigned $LAYER)")" "200"
check_status "the key in a presigned URL to another bucket" "$($C "$(presigned https://bucket.s3.amazonaws.com/x)")" "200"
check_status "the key in a presigned URL to another service" "$($C "$(presigned $CF)")" "403"
check_status "the key in a header" \
  "$($C -H "Authorization: AWS4-HMAC-SHA256 Credential=${ASIA}TESTISSUEDKEY01/20261010/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=ab" $LAYER)" "403"

echo "=== [AssumeRoleWithWebIdentity, judged by the role's account] ==="
form() { $C -X POST -H "Content-Type: application/x-www-form-urlencoded" --data "$1" "$2"; }
ROLE="arn%3Aaws%3Aiam%3A%3A111111111111%3Arole%2Fdeploy"
check_status "unknown until a web identity call hands it out" \
  "$($C -X POST -H "Authorization: $(sigv4 ${ASIA}TESTWEBIDKEY0001)" $CF)" "403"
check_status "a web identity call for a role in the allowed account" \
  "$(form "Action=AssumeRoleWithWebIdentity&RoleArn=$ROLE&RoleSessionName=gh&WebIdentityToken=eyJ" $STS/sts/web-identity)" "200"
check_status "the key it issued" "$($C -X POST -H "Authorization: $(sigv4 ${ASIA}TESTWEBIDKEY0001)" $CF)" "200"
check_status "a web identity call for a role in another account" \
  "$(form "Action=AssumeRoleWithWebIdentity&RoleArn=arn%3Aaws%3Aiam%3A%3A999999999999%3Arole%2Fevil&RoleSessionName=gh&WebIdentityToken=eyJ" $STS/)" "403"
check_status "a web identity call naming two roles" \
  "$(form "Action=AssumeRoleWithWebIdentity&RoleArn=$ROLE&RoleArn=arn%3Aaws%3Aiam%3A%3A999999999999%3Arole%2Fevil" $STS/)" "403"

echo "=== [hosts that are not AWS] ==="
check_status "an unsigned read the URL rules allow" "$($C https://allowed.example.com/public/x)" "200"

scenario_results "AWS access key scenarios"
