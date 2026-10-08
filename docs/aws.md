# AWS access key check

> [!WARNING]
> `aws_key_check` and `allowed_aws_role_accounts` are **experimental**: their behavior, inputs, and
> error messages may still change in a future release without following semver. Without them,
> nothing on this page applies and the action behaves as before. Try them in a non-critical workflow
> first, and pin this action to a commit SHA rather than a version tag if you adopt it.

Name the AWS resources a step uses in its URL rules wherever the host or path names them: a bucket,
a registry, a cluster. Those rules already decide whose resource a request reaches. Most AWS APIs,
though, are hosts such as `cloudformation.us-east-1.amazonaws.com` or `sts.amazonaws.com` that serve
every AWS account, and the account a request reaches is decided by the key that signs it. A rule
that allows them lets the step reach any account, not only yours. `aws_key_check` covers those
hosts: it accepts only the key the step starts with. `allowed_aws_role_accounts` adds the keys
issued for roles the step assumes in the accounts you name.

## Why URL rules are not enough

Code running in the step, such as a compromised dependency, can carry an access key for an account
its author controls. It signs a request to any AWS API with that key and puts the data it wants to
take in the query string or the `User-Agent`. The request goes to a host your rules allow, and AWS
records it in the CloudTrail of the account that owns the key, where the author reads it back.

Nothing in your own account sees this: the call is authorized and logged entirely in the other
account, so no IAM policy or SCP of yours applies to it. The only place to stop it is the network
path, before the request leaves the runner.

## What the check does

A step that uses only the credentials it is given needs `aws_key_check` alone:

```yaml
- uses: aws-actions/configure-aws-credentials@<sha>
  with:
    role-to-assume: arn:aws:iam::111111111111:role/deploy
    aws-region: us-east-1
- uses: buildcage/isolated-run@<sha>
  with:
    aws_key_check: true
    allowed_url_rules: |
      * https://ecs.us-east-1.amazonaws.com/**
    run: aws ecs update-service --cluster app --service web --force-new-deployment
```

A step that assumes roles of its own, as the CDK does, names the accounts those roles are in, which
turns the check on too:

```yaml
- uses: aws-actions/configure-aws-credentials@<sha>
  id: aws
  with:
    role-to-assume: arn:aws:iam::111111111111:role/deploy
    aws-region: us-east-1
- uses: buildcage/isolated-run@<sha>
  with:
    allowed_aws_role_accounts: ${{ steps.aws.outputs.aws-account-id }}
    allowed_url_rules: |
      * https://cloudformation.us-east-1.amazonaws.com/**
      * https://sts.us-east-1.amazonaws.com/**
    run: npx cdk deploy
```

With the check on, a request to an AWS API host that carries an AWS signature must be
signed with a key the proxy knows (below). The proxy reads the access key ID from the
`Authorization` header (SigV4, SigV4a or SigV2), from a presigned URL's `X-Amz-Credential` or
`AWSAccessKeyId` parameter, or from the `AWSAccessKeyId` parameter of a SigV2 form body, and
compares it with the keys it knows as a whole string. It never decodes a key ID or verifies a
signature: a request that copies one of your key IDs without the secret is refused by AWS and logged
in your own account.

A CodeCommit `Basic` login carries a key too: the user name CodeCommit's Git credential helper sends
is the key ID, checked the same way. A static CodeCommit Git credential names its account instead
(`<user>-at-<account>`), and passes when that account is in `allowed_aws_role_accounts`. Either way
the repository is looked up in that account.

A form body is the body of a `POST` to a host that names no resource (below), when its Content-Type
is `application/x-www-form-urlencoded` or, whatever the Content-Type says, the body starts as a form
does (`name=value`). The proxy reads the whole body, up to 4 MiB with the headers, before deciding.
It refuses what it cannot read through as `aws-unreadable`: a form body that is larger, compressed,
sent chunked or holds a NUL byte, and a query string that does not URL-decode.

Current AWS SDKs send none of these. Older ones that still call CloudWatch over its form protocol
compress a `PutMetricData` body over 10 KB; set `AWS_DISABLE_REQUEST_COMPRESSION=true` for such a
step, or update the SDK. A compressed body whose Content-Type is not a form one is left alone, as
the proxy cannot tell it is a form.

The proxy knows two kinds of key:

- **The key the step starts with**, read from `AWS_ACCESS_KEY_ID` in the step's environment, which
  is where `aws-actions/configure-aws-credentials` puts it. It is taken as given: the proxy does not
  ask AWS whose key it is, so a key of another account set there by mistake passes too.
- **Keys STS issues for a role in one of the `allowed_aws_role_accounts`**, through `AssumeRole`,
  `AssumeRoleWithWebIdentity` or `AssumeRoleWithSAML`. The proxy reads the role ARN and the new
  access key ID from the response, which AWS writes, and adds the key. This is what lets tools that
  switch roles mid-step keep working, such as the CDK assuming its `cdk-hnb659fds-deploy-role-*`
  roles, Terraform's `assume_role`, or an SDK using a GitHub OIDC token through
  `AWS_WEB_IDENTITY_TOKEN_FILE`. A role in any other account issues a key the proxy never learns, so
  requests signed with it are refused. With no account named, no key is learned at all, and the
  proxy leaves STS answers alone.

AWS API hosts are names under `amazonaws.com`, `amazonaws.com.cn` and `amazonaws.eu` (the European
Sovereign Cloud), and under their dual-stack counterparts `api.aws`, `api.amazonwebservices.com.cn`
and `api.amazonwebservices.eu`. Other AWS names, such as `public.ecr.aws` or Lambda
function URLs under `on.aws`, are left to the URL rules alone.

The URL rules still decide first. A request they refuse stays `not-allowed`, and the key check only
applies to requests they allow.

What happens to a request that carries no AWS signature depends on whether the host names the
resource it is for. A request with no `Authorization` header, or one with any other `Bearer` or
`Basic` token, counts as unsigned here. CodeCommit is the exception both ways: a `Basic` login to it
that carries neither a known key nor an allowed account is `aws-key-not-allowed`, and a request to
it with no `Authorization` at all, which Git sends first to be told to log in, is let through.

| Request                                                                                                          | Result                     |
| ---------------------------------------------------------------------------------------------------------------- | -------------------------- |
| Signed with a known key                                                                                          | allowed                    |
| Signed with any other key                                                                                        | `aws-key-not-allowed`      |
| Unsigned, to a host that names its resource (below)                                                              | allowed                    |
| Unsigned, to any other AWS API host, whatever the method                                                         | `aws-no-credential`        |
| A CodeCommit `Basic` login with a known key, or a static Git credential of an allowed account                    | allowed                    |
| A CodeCommit `Basic` login with any other key or account                                                         | `aws-key-not-allowed`      |
| A CodeCommit request with no `Authorization`, as Git sends first                                                 | allowed                    |
| More than one credential: two `Authorization` headers, a header and a query credential, or a credential repeated | `aws-ambiguous-credential` |
| A key in a form body and another in the header or query, either of them unknown                                  | `aws-key-not-allowed`      |
| A form body or query string the proxy cannot read through (above)                                                | `aws-unreadable`           |
| `AssumeRoleWithWebIdentity` or `AssumeRoleWithSAML` for a role in an account not listed (below)                  | `aws-role-not-allowed`     |

These hosts name the resource a request reaches, in the host name or, for S3's path style and an EKS
OIDC issuer, in the path. The URL rules can pin the resource there, so an unsigned request to them is
left to the URL rules:

| Service                | Host                                                                                                                                                         |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| S3                     | every S3 form: `<bucket>.s3.<region>.amazonaws.com`, `s3.<region>.amazonaws.com/<bucket>/…`, access points, `s3-control`, website and acceleration endpoints |
| ECR                    | `<account>.dkr.ecr.<region>.amazonaws.com`, `<account>.dkr.ecr-fips.<region>.amazonaws.com`                                                                  |
| CodeArtifact           | `<domain>-<owner>.d.codeartifact.<region>.amazonaws.com`                                                                                                     |
| API Gateway            | `<api-id>.execute-api.<region>.amazonaws.com`                                                                                                                |
| AppSync                | `<id>.appsync-api.<region>.amazonaws.com`, `<id>.appsync-realtime-api.<region>.amazonaws.com`                                                                |
| Managed Grafana        | `g-<id>.grafana-workspace.<region>.amazonaws.com`                                                                                                            |
| Amazon MQ              | `b-<id>.mq.<region>.amazonaws.com`                                                                                                                           |
| OpenSearch Service     | `search-<domain>-<id>.<region>.es.amazonaws.com`, `vpc-<domain>-<id>.<region>.es.amazonaws.com`                                                              |
| EKS cluster            | `<id>.<label>.<region>.eks.amazonaws.com` (such as `gr7` or `yl4`), `<id>.<region>.api.aws`                                                                  |
| EKS OIDC issuer        | `oidc.eks.<region>.amazonaws.com/id/<id>`, `oidc-eks.<region>.api.aws/id/<id>`                                                                               |
| Elastic Load Balancing | `<name>-<id>.elb.<region>.amazonaws.com`, `<name>-<id>.<region>.elb.amazonaws.com`                                                                           |
| EC2                    | `ec2-<ip>.<region>.compute.amazonaws.com`, `ec2-<ip>.compute-1.amazonaws.com`                                                                                |
| AWS CLI downloads      | `awscli.amazonaws.com`                                                                                                                                       |

Each `amazonaws.com` name but `awscli.amazonaws.com` also matches under `amazonaws.com.cn` and
`amazonaws.eu`, and each `api.aws` one under `api.amazonwebservices.com.cn` and
`api.amazonwebservices.eu`. Every other AWS API host names only a service and a region, such as
`sts.us-east-1.amazonaws.com` or `sqs.us-east-1.amazonaws.com`. The account a request to one of
those reaches is in its parameters or its body, where the proxy does not look, so an unsigned
request there is refused, `GET` included. A host missing from the table above is treated the same
way; if a legitimate request is refused as `aws-no-credential` for that reason, report it.

Some AWS APIs take a token that ties the request to no account the proxy can see, and are refused
for that reason too: Cognito user pool calls made without AWS credentials, Bedrock API keys,
CloudWatch Logs ingestion tokens and the IAM Identity Center portal. Sign those calls with SigV4
where the API takes it.

An S3 POST-policy upload, the browser-style upload that carries its credential in the form body, is
refused as `aws-no-credential`, since the proxy does not read a multipart body. Upload with `PutObject`
instead, as the AWS CLI and the SDKs do, or with a presigned `PutObject` URL. Both carry the key
where the check reads it.

These hosts are only as narrow as the URL rules that allow them. A rule such as
`* https://**.amazonaws.com/**` lets an unsigned request reach anyone's bucket, registry, cluster or
API, and whoever owns it can read what was sent, `User-Agent` and query string included, in their
own logs. Allow them by name, as you would any other host:

```yaml
allowed_url_rules: |
  * https://111111111111.dkr.ecr.us-east-1.amazonaws.com/**
  GET|PUT https://my-artifacts.s3.us-east-1.amazonaws.com/**
```

### In `audit` mode

`audit` refuses nothing, and that includes this check. A warning annotation counts the requests it
would have refused, and the report lists each under **🚨 Restrict Would Refuse** with the reason, so a
step can be checked before it is switched to `restrict`:

```
🚨 00:03.120: POST https://cloudformation.us-east-1.amazonaws.com/ -> 200 (1.2KB) (restrict would refuse: aws-key-not-allowed)
```

The traffic artifact carries the same reason in `wouldRefuse`.

## What it does not stop

The check looks at whose key signed a request, not at whose resource the request is for. A request
signed with your own key that names a resource in another account passes. The target account is in
the request body, not in the URL, so the proxy cannot see it. Requests like these remain possible:

| Route                                 | Example                                                                                                                                                                                |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cross-account `AssumeRole`            | Assuming a role in another account, with data in the session name, source identity or session tags. A successful call is recorded in the role owner's CloudTrail. A denied one is not. |
| Services with resource-based policies | Publishing to an SNS topic, sending to an SQS queue, invoking a Lambda function, putting events on an EventBridge bus or writing to an S3 bucket in another account                    |
| KMS                                   | Encrypting with a key in another account, whose owner sees the encryption context in CloudTrail                                                                                        |
| CloudFormation itself                 | A custom resource whose `ServiceToken` or a stack whose `NotificationARNs` names a topic or function in another account. AWS makes those calls, so they never pass the proxy.          |

## Closing the rest in IAM

Each route above needs your role to be allowed to act on a resource in another account, so IAM can
close them. Set these on the role the step assumes, and on the CloudFormation service role if you
use one:

- **Deny access to resources outside your accounts** with the `aws:ResourceAccount` condition key,
  or `aws:ResourceOrgID` if you use AWS Organizations. AWS's
  [data perimeter guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_data-perimeters.html)
  covers the exceptions a real policy needs, such as resources AWS services own.
- **Name the account in every `sts:AssumeRole` resource.** A resource such as
  `arn:aws:iam::*:role/cdk-*`, common in CDK setups, lets the role assume a role of that name in any
  account, including one someone else creates for the purpose. Write
  `arn:aws:iam::111111111111:role/cdk-*` instead. A denied `AssumeRole` is not recorded in the target
  account, so this closes the route entirely.

## Requirements and limits

- `proxy_engine: inspect` only, since `universal` never sees a request's headers. `restrict` fails
  the step on `universal`; `audit` warns and ignores the input.
- The step has to start with a key in `AWS_ACCESS_KEY_ID`. In `restrict`, a step with the check on
  and no such variable fails before the proxy starts; `audit` warns and turns
  the check off. Credentials read from `~/.aws/credentials`, a profile or a container credentials
  endpoint are not used as a starting key.
- `AssumeRoleWithWebIdentity` and `AssumeRoleWithSAML` take no signature, so the proxy judges them
  by the account of the role in `RoleArn`, read from the query or the form body. A role in an
  account not listed in `allowed_aws_role_accounts` is refused as `aws-role-not-allowed`, and with
  none listed both calls stay `aws-no-credential`. Keys from IAM Identity Center's
  `GetRoleCredentials` or Cognito's `GetCredentialsForIdentity` are never learned. Get those
  credentials before the step and pass them in `AWS_ACCESS_KEY_ID`.
- Keys are learned only from STS answers over HTTPS. The proxy asks STS for an uncompressed answer,
  unless the client signed its own `Accept-Encoding`, which the proxy then leaves alone. It reads an
  answer up to its buffer size (16 KB). A key in a compressed answer or past the buffer is not
  learned, and requests signed with it are refused.
- A connection `allowed_tls_rules` or `allowed_ip_rules` passes through is never decrypted, so the
  check never sees its requests. Do not pass AWS API hosts through.
- S3 Express One Zone directory buckets are signed with keys `CreateSession` issues, which the proxy
  does not learn: its answer names no account to check them against. Requests to directory buckets
  are refused as `aws-key-not-allowed`.
- The starting key ID is handed to the proxy container as an environment variable, so it is visible
  to `docker inspect` on the runner while the step runs. A key ID is not a secret on its own:
  signing needs the secret access key, which never reaches the proxy.
