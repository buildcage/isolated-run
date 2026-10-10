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

## Getting started

Turn the check on in `audit` mode first: nothing is refused, and the report shows what `restrict`
would refuse. A step that uses only the credentials it is given needs `aws_key_check` alone:

```yaml
- uses: aws-actions/configure-aws-credentials@<sha>
  with:
    role-to-assume: arn:aws:iam::111111111111:role/deploy
    aws-region: us-east-1
- uses: buildcage/isolated-run@<sha>
  with:
    proxy_mode: audit
    aws_key_check: true
    run: aws ecs update-service --cluster app --service web --force-new-deployment
```

A step that assumes roles of its own, as the CDK does, also names the accounts those roles are in,
and still needs `aws_key_check: true`. That keeps the check on if the expression comes out empty, as
from a mistyped `id:`, so the role switch is refused rather than the check going off unnoticed.
Start with the account of the role the step is given:

```yaml
- uses: aws-actions/configure-aws-credentials@<sha>
  id: aws
  with:
    role-to-assume: arn:aws:iam::111111111111:role/deploy
    aws-region: us-east-1
- uses: buildcage/isolated-run@<sha>
  with:
    proxy_mode: audit
    aws_key_check: true
    allowed_aws_role_accounts: ${{ steps.aws.outputs.aws-account-id }}
    upload_traffic_artifact: true
    run: npx cdk deploy
```

Then:

1. Read **🚨 Restrict Would Refuse** in the report. Each request the check would refuse ends in its
   reason, such as `(restrict would refuse: aws-key-not-allowed)`, and
   [Troubleshooting](#troubleshooting) gives the usual causes of each.
2. Check the accounts of the other roles the step assumed. The report's **Switch to restrict mode**
   example lists them under `allowed_aws_role_accounts` and marks each one not named yet
   `# assumed in this run, check it is yours`; the [traffic artifact](#in-the-traffic-artifact)
   gives each as `aws.assumedAccount`. A CDK app deploying to several accounts assumes a
   `cdk-hnb659fds-deploy-role-*` role in each. Keep only accounts that are yours: one you do not
   recognise there is what the check is meant to catch.
3. Switch the step to `restrict`. The report's **Switch to restrict mode** example carries the URL
   rules, `aws_key_check: true` and the accounts from step 2 over.

## What the check does

### Which keys pass

The proxy knows three kinds of key:

- **The key the step starts with**, read from `AWS_ACCESS_KEY_ID` in the step's environment, which
  is where `aws-actions/configure-aws-credentials` puts it. It is taken as given: the proxy does not
  ask AWS whose key it is, so a key of another account set there by mistake passes too.
- **Keys STS issues for a role in one of the `allowed_aws_role_accounts`**, through `AssumeRole` or
  `AssumeRoleWithWebIdentity`. The proxy reads the role ARN and the new access key ID from the
  answer, which AWS writes, and adds the key. This is what lets tools that switch roles mid-step
  keep working, such as the CDK assuming its `cdk-hnb659fds-deploy-role-*` roles, Terraform's
  `assume_role`, or the AWS CLI run with a `--profile` that sets `role_arn` and
  `web_identity_token_file`. A role in any other account issues a key the proxy never learns, so
  requests signed with it are refused. With no account named, no STS key is learned, but the proxy
  still reads each answer for the account of its role, so a run shows which accounts to name.
- **Keys ECR signs a layer's presigned URL with.** An ECR registry,
  `<account>.dkr.ecr.<region>.amazonaws.com` or its dual-stack `<account>.dkr-ecr.<region>.on.aws`,
  answers a layer download with a redirect to a presigned S3 URL, signed with a key of ECR's own.
  The proxy reads that key from the redirect, which only ECR writes, and adds it whether or not any
  account is named, so a registry client in the step, such as `crane`, `skopeo` or Jib, can follow
  the redirect. The key passes only as the credential of a presigned URL to S3. Whoever holds its
  ID cannot sign with it: the secret stays with ECR.

### Which credentials it reads

The proxy reads the credential of each request to an AWS API host: the signature the AWS CLI v2 and
current AWS SDKs put in the `Authorization` header (Signature Version 4, or its multi-region variant
SigV4a), or the `X-Amz-Credential` of a presigned URL. Its access key ID has to be one the proxy
knows, compared as a whole string. The proxy never decodes a key ID or verifies a signature: a
request that copies one of your key IDs without the secret is refused by AWS and logged in your own
account.

Any other AWS credential is refused as `aws-unsupported-credential` without its key being read: the
older Signature Version 2 and 3, a token in place of a signature on a host that serves every
account, a credential carried in a form body, and an S3 POST-policy upload, the HTML form browsers
upload to S3 with.

Some AWS APIs, such as STS, IAM, CloudFormation, SNS and EC2, take their parameters as a form: the
body of a `POST` whose Content-Type is `application/x-www-form-urlencoded`. A credential could hide
in it, so the proxy reads such a body whole, up to about 4 MiB, before deciding, unless the host
names a resource (below). A form body it cannot read through is refused as `aws-unreadable`: one
that is larger, compressed, or sent without a `Content-Length`.

A CodeCommit `Basic` login carries a key too: the user name CodeCommit's Git credential helper sends
is the key ID, checked the same way. A static CodeCommit Git credential names its account instead
(`<user>-at-<account>`), and passes when that account is in `allowed_aws_role_accounts`. Either way
the repository is looked up in that account.

### Which hosts

AWS API hosts are names under `amazonaws.com`, `amazonaws.com.cn` and `amazonaws.eu` (the European
Sovereign Cloud), and under their dual-stack counterparts `api.aws`, `api.amazonwebservices.com.cn`
and `api.amazonwebservices.eu`. Other AWS names, such as `public.ecr.aws` or Lambda function URLs
under `on.aws`, are left to the URL rules alone.

The URL rules still decide first. A request they refuse stays `not-allowed`, and the key check only
applies to requests they allow.

What happens to a request that carries no AWS signature depends on whether the host names the
resource it is for. On such a host, a `Bearer` or `Basic` token, such as ECR's or CodeArtifact's,
counts as no signature, though a scheme starting with `AWS` does not. CodeCommit is the exception
both ways: a `Basic` login to it that carries neither a known key nor an allowed account is
`aws-key-not-allowed`, and a request to it with no `Authorization` at all, which Git sends first to
be told to log in, is let through.

| Request                                                                                                          | Result                       |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| Signed with a known key                                                                                          | allowed                      |
| Signed with any other key                                                                                        | `aws-key-not-allowed`        |
| Unsigned, to a host that names its resource or a public host (below)                                             | allowed                      |
| Unsigned, to any other AWS API host, whatever the method                                                         | `aws-no-credential`          |
| A CodeCommit `Basic` login with a known key, or a static Git credential of an allowed account                    | allowed                      |
| A CodeCommit `Basic` login with any other key or account                                                         | `aws-key-not-allowed`        |
| A CodeCommit request with no `Authorization`, as Git sends first                                                 | allowed                      |
| More than one credential: two `Authorization` headers, a header and a query credential, or a credential repeated | `aws-ambiguous-credential`   |
| A credential other than SigV4's or SigV4a's, or an S3 POST-policy upload (above)                                 | `aws-unsupported-credential` |
| A form body the proxy cannot read through (above)                                                                | `aws-unreadable`             |
| `AssumeRoleWithWebIdentity` for a role in an account not in `allowed_aws_role_accounts`                          | `aws-role-not-allowed`       |

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

Each `amazonaws.com` name also matches under `amazonaws.com.cn` and `amazonaws.eu`, and each
`api.aws` one under `api.amazonwebservices.com.cn` and `api.amazonwebservices.eu`.

An unsigned request to these public hosts, which reach no account, is left to the URL rules too:
`awscli.amazonaws.com` (AWS CLI downloads), `checkip.amazonaws.com`, `ip-ranges.amazonaws.com`, and
the Price List Bulk API's files on `pricing.us-east-1.amazonaws.com` and
`pricing.cn-northwest-1.amazonaws.com.cn`.

Every other AWS API host names only a service and a region, such as `sts.us-east-1.amazonaws.com` or
`sqs.us-east-1.amazonaws.com`. The account a request to one of those reaches is in its parameters or
its body, where the proxy does not look, so an unsigned request there is refused, `GET` included,
`AssumeRoleWithWebIdentity` excepted (below). A host missing from the lists above is treated the
same way; if a legitimate request is refused for that reason, as `aws-no-credential` or, carrying a
token, `aws-unsupported-credential`, report it.

These hosts are only as narrow as the URL rules that allow them. A rule such as
`* https://**.amazonaws.com/**` lets an unsigned request reach anyone's bucket, registry, cluster or
API, and whoever owns it can read what was sent, `User-Agent` and query string included, in their
own logs. Allow them by name, as you would any other host:

```yaml
allowed_url_rules: |
  * https://111111111111.dkr.ecr.us-east-1.amazonaws.com/**
  GET|PUT https://my-artifacts.s3.us-east-1.amazonaws.com/**
```

### What it works with

A step passes the check when:

- It calls AWS through the AWS CLI v2, a current AWS SDK, or a tool built on them, such as the CDK
  and Terraform.
- It switches roles only through STS `AssumeRole` or `AssumeRoleWithWebIdentity`, into the
  `allowed_aws_role_accounts`: the CDK's deploy roles, Terraform's `assume_role`, or a CLI profile
  whose `role_arn` starts from `credential_source = Environment` or a `web_identity_token_file`.
- It reaches CodeCommit over Git through CodeCommit's credential helper, or with a static Git
  credential of a listed account.
- It pulls from ECR through the registry API, with a client such as `crane`, `skopeo` or Jib.

### What it stops

With `aws_key_check` on, these are refused:

- Amazon SimpleDB (`sdb`), which accepts only the older Signature Version 2, and the retired AWS
  Import/Export.
- Very old SDKs and hand-written clients that still sign with Signature Version 2 or 3.
- Form calls over about 4 MiB, such as SES v1 `SendRawEmail` with large attachments. Use SES v2
  (`sesv2`).
- Compressed form calls, such as CloudWatch `PutMetricData` from older SDKs, which compress a body
  over 10 KB. Set `AWS_DISABLE_REQUEST_COMPRESSION=true` for the step, or update the SDK.
- S3 POST-policy uploads. Upload with `PutObject` or a presigned `PutObject` URL.
- Tokens that carry no AWS signature: Cognito user pool calls made without AWS credentials, Bedrock
  API keys, CloudWatch Logs ingestion tokens and the IAM Identity Center portal.
- Keys the step switches to through `GetSessionToken`, SAML or IAM Identity Center, which the proxy
  does not learn.
- Presigned URLs someone else signed that reach the step other than through an ECR registry's
  redirect, such as the `Code.Location` of Lambda `GetFunction` or a vendor's download link.
- S3 Express One Zone directory buckets, signed with keys `CreateSession` issues, which the proxy
  does not learn.

Two of these come up often in CI.

**Bedrock API keys.** The Bearer token in `AWS_BEARER_TOKEN_BEDROCK` names no account the proxy can
see, so it is refused. Call Bedrock with the role keys `configure-aws-credentials` gets through OIDC
instead: they are signed with SigV4 and pass with `aws_key_check: true` alone, given a role allowed
`bedrock:InvokeModel`.

**Cognito user pools without AWS credentials**, as an E2E test logging in does. The pool a call
reaches is named by `ClientId` in its body, so the proxy cannot protect it, with the check or
without. Keep the check on the deploy step, and run the test as a step of its own whose URL rules
allow Cognito only. The check stays on where it works, and the traffic it cannot protect is kept to
that one step:

```yaml
- uses: buildcage/isolated-run@<sha>
  with:
    aws_key_check: true
    allowed_url_rules: |
      * https://cloudformation.us-east-1.amazonaws.com/**
    run: npx cdk deploy
- uses: buildcage/isolated-run@<sha>
  with:
    allowed_url_rules: |
      POST https://cognito-idp.us-east-1.amazonaws.com/
      * https://app.example.com/**
    run: npx playwright test
```

### In `audit` mode

`audit` refuses nothing, and that includes this check. A warning annotation counts the requests it
would have refused, and the report lists each under **🚨 Restrict Would Refuse** with the reason, so a
step can be checked before it is switched to `restrict`:

```
🚨 00:03.120: POST https://cloudformation.us-east-1.amazonaws.com/ -> 200 (1.2KB) (restrict would refuse: aws-key-not-allowed)
```

The traffic artifact carries the same reason in `wouldRefuse`.

When the check was on for the run, the report's **Switch to restrict mode** example includes
`aws_key_check: true`, and `allowed_aws_role_accounts` with the accounts given and each account the
run assumed a role in, read from every STS answer, including one to a request restrict would refuse.
A chain of roles, as the CDK assumes them, shows in full after one audit run. An answer the proxy
cannot read, compressed or past its buffer, names no account. Anything in the step can assume a
role, including in an account of its own, so each account the example adds that was not given is
marked:

```yaml
aws_key_check: true
allowed_aws_role_accounts: |
  111111111111
  222222222222 # assumed in this run, check it is yours
```

### In the traffic artifact

Each request the check let through has an `aws` object in the
[traffic artifact](./reference.md#traffic-artifact), so a run shows that the check was on even
where it refused nothing. A request the check refused has none, save an STS call in audit mode,
whose answer still gives `assumedAccount`. Its `reason` or `wouldRefuse` says why.

| Field            | Always | Notes                                                                                                                                                                        |
| ---------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `key`            | yes    | `env` for the key the step started with, `assumed` for one STS issued, `issued` for one ECR signed a layer's presigned URL with, `none` for a request carrying no access key |
| `accountId`      |        | an account the check confirmed: the one an `assumed` key came from, or the one a static CodeCommit Git credential or a role ARN names                                        |
| `assumedAccount` |        | the account of the role an STS answer issued a key for, whether or not that account is allowed or named                                                                      |

The starting key's account is never shown, since the proxy does not ask AWS whose key it is. No key
ID is written either.

```json
{
  "action": "allow",
  "host": "cloudformation.us-east-1.amazonaws.com",
  "method": "POST",
  "aws": { "key": "assumed", "accountId": "111111111111" }
}
```

## Troubleshooting

Each refusal has a reason that starts with `aws-`. In `restrict` the check judges only the requests
the URL rules allowed, and its refusals show under **🚫 Blocked Hosts**. In `audit` it judges every
request, and lists the ones it would refuse under **🚨 Restrict Would Refuse**. Under whichever of
the two comes last, the report links here, unless `known_blocked_rules` expects every one.

| Reason                       | Usual cause                                                                                                                                                                                              | What to do                                                                                                                                                                          |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `aws-key-not-allowed`        | The step assumed a role in an account `allowed_aws_role_accounts` does not name, and signed with that role's key                                                                                         | Add the account if it is yours. The restrict example and the STS answer's `aws.assumedAccount` name it; see [Getting started](#getting-started)                                     |
|                              | The request was signed with a key from a profile, `~/.aws/credentials` or `credential_process` rather than `AWS_ACCESS_KEY_ID`                                                                           | Put the key to check in `AWS_ACCESS_KEY_ID`, or run those commands in a step without the check                                                                                      |
|                              | The key came from `GetSessionToken`, SAML or IAM Identity Center, which the proxy does not learn                                                                                                         | Get the credentials before the step and pass them in `AWS_ACCESS_KEY_ID`                                                                                                            |
|                              | A presigned URL someone else signed, such as Lambda `GetFunction`'s `Code.Location` or a vendor's download link                                                                                          | Download it in a step without the check. `aws sts get-access-key-info --access-key-id <key-id>`, with the key ID from the URL's `X-Amz-Credential`, names the account it belongs to |
|                              | An S3 Express One Zone directory bucket                                                                                                                                                                  | Use it from a step without the check                                                                                                                                                |
|                              | The STS answer that issued the key could not be read, because the client signed its own `Accept-Encoding` and got it compressed, or it was unusually large                                               | Let the SDK send its default headers to STS; shorten a large session policy or tag set                                                                                              |
|                              | A CodeCommit static Git credential of an account not listed                                                                                                                                              | Add the account, or use CodeCommit's credential helper                                                                                                                              |
| `aws-no-credential`          | An unsigned request to a host that serves every account, such as a Cognito user pool call made without AWS credentials                                                                                   | Sign it, or run it in a step of its own without the check; see [Cognito user pools](#what-it-stops)                                                                                 |
|                              | `AssumeRoleWithWebIdentity` with no `allowed_aws_role_accounts`, or `AssumeRoleWithSAML`                                                                                                                 | Name the role's account, or get the credentials before the step                                                                                                                     |
|                              | A host that names a resource but is missing from the [list](#which-hosts)                                                                                                                                | Report it                                                                                                                                                                           |
| `aws-role-not-allowed`       | `AssumeRoleWithWebIdentity` for a role in an account not listed                                                                                                                                          | Add the account                                                                                                                                                                     |
| `aws-unsupported-credential` | An old SDK or a hand-written client signing with Signature Version 2 or 3, or a service that takes only those                                                                                            | Update the SDK, or run it in a step without the check                                                                                                                               |
|                              | A token in place of a signature, such as a Bedrock API key, on a host that serves every account                                                                                                          | Sign with AWS credentials; see [Bedrock API keys](#what-it-stops)                                                                                                                   |
|                              | An S3 POST-policy upload                                                                                                                                                                                 | Upload with `PutObject` or a presigned `PutObject` URL                                                                                                                              |
|                              | A token on a host that names a resource but is missing from the [list](#which-hosts)                                                                                                                     | Report it                                                                                                                                                                           |
| `aws-unreadable`             | A form call over about 4 MiB, such as SES v1 `SendRawEmail` with large attachments                                                                                                                       | Use SES v2 (`sesv2`)                                                                                                                                                                |
|                              | A compressed form call, such as CloudWatch `PutMetricData` from an older SDK                                                                                                                             | Set `AWS_DISABLE_REQUEST_COMPRESSION=true`, or update the SDK                                                                                                                       |
|                              | A form body sent without a `Content-Length`                                                                                                                                                              | Send the body with a known length                                                                                                                                                   |
| `aws-ambiguous-credential`   | More than one credential on one request: two `Authorization` headers, a header and a presigned URL credential, or one repeated. Or an `AssumeRoleWithWebIdentity` naming its role twice, or in the query | Send one credential, and the role in the body only; a current SDK does                                                                                                              |

A role switch into an account not listed is not refused itself: STS answers it, but the proxy does
not learn the key it issues. What shows is a run of `aws-key-not-allowed` on the requests signed
with that key, after an STS call that went through.

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
  and no access key ID there fails before the proxy starts; `audit` warns and turns the check off.
  Credentials read from `~/.aws/credentials`, a profile or a container credentials endpoint are not
  used as a starting key, so a step that signs with a profile's key, or switches between two static
  keys, cannot use the check: put the key to check in `AWS_ACCESS_KEY_ID`, or run the AWS commands
  in a step without the check. A web identity token is not one either: a step that gets its
  credentials only through `AWS_WEB_IDENTITY_TOKEN_FILE` cannot turn the check on, and a key set
  beside it comes first in the SDKs' default credential chain, ahead of the token. Exchange the
  token before the step instead, as `configure-aws-credentials` does with GitHub's OIDC token.
- `AssumeRoleWithWebIdentity` takes no signature, so the proxy judges it by the account of the role
  it names. A role in an account not listed in `allowed_aws_role_accounts` is refused as
  `aws-role-not-allowed`, and with none listed the call stays `aws-no-credential`.
  `AssumeRoleWithSAML` is refused as `aws-no-credential`, and keys from IAM Identity Center's
  `GetRoleCredentials` or Cognito's `GetCredentialsForIdentity` are never learned. Get those
  credentials before the step and pass them in `AWS_ACCESS_KEY_ID`.
- Keys are learned only from STS answers and ECR registry redirects over HTTPS, to a request the key
  check did not refuse, so in audit mode a request it would refuse teaches no key. A host that names
  a resource is never taken for STS, even an S3 bucket named `sts`. A key in an STS answer the proxy
  cannot read, because the client asked for it compressed or it is unusually large, is not learned,
  and requests signed with it are refused.
- A connection `allowed_tls_rules` or `allowed_ip_rules` passes through is never decrypted, so the
  check never sees its requests. Do not pass AWS API hosts through.
- The starting key ID is handed to the proxy container as an environment variable, so it is visible
  to `docker inspect` on the runner while the step runs. A key ID is not a secret on its own:
  signing needs the secret access key, which never reaches the proxy.
