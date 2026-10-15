# AWS access key check

> [!WARNING]
> `aws_key_check` and `allowed_aws_role_accounts` are **experimental**: their behavior, inputs, and
> error messages may still change in a future release without following semver. Without them,
> nothing on this page applies and the action behaves as before. Try them in a non-critical workflow
> first, and pin this action to a commit SHA rather than a version tag if you adopt it.

`aws_key_check: true` blocks a request to an AWS API unless it is signed with the key the step
was given. `allowed_aws_role_accounts` names the accounts whose roles the step may assume, so the
keys those roles get pass too. [Getting started](#getting-started) walks through adopting it.

On this page a key means an access key ID: `AKIA…` for a long-term key, `ASIA…` for temporary
credentials such as a role's. The proxy reads only the ID; the secret access key never reaches it.
`audit` and `restrict` are the action's [operation modes](../README.md#operation-modes).

## Why URL rules are not enough

URL rules decide whose resource a request reaches wherever the host or path names it. Many AWS APIs
name no resource, though, and the account a request reaches is decided by the key that signs it.
This page sorts AWS API hosts into those two kinds:

| Kind                                      | Example                                                                 | The account a request reaches                     |
| ----------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------- |
| Names its resource (a resource endpoint)  | `my-bucket.s3.us-east-1.amazonaws.com`, an ECR registry, an EKS cluster | The one in the host or path, which a rule can pin |
| Serves every account (a service endpoint) | `sts.amazonaws.com`, `cloudformation.us-east-1.amazonaws.com`           | Whichever account signed the request              |

A rule that allows a host of the second kind lets the step reach any account, not only yours.
[Which hosts](#which-hosts) has the full list.

Code running in the step, such as a compromised dependency, can carry an access key for an account
its author controls. It signs a request to any AWS API with that key and puts the data it wants to
take in the query string or the `User-Agent`. The request goes to a host your rules allow, and AWS
records it in the CloudTrail of the account that owns the key, where the author reads it back.

Nothing in your own account sees this: the call is authorized and logged entirely in the other
account, so no IAM policy or SCP of yours applies to it. The only place to stop it is the network
path, before the request leaves the runner.

## What it stops and what it doesn't

With the check on, a request signed for an AWS API passes only when the proxy knows its key: mainly
the key the step started with, and the keys STS issues for roles in the accounts you named. A key
carried in from anywhere else is blocked, and so are most unsigned requests to a host that serves
every account. [How the check decides](#how-the-check-decides) has the exact rules.

It does not stop a request signed with your own key from reaching another account's resource, such
as its SNS topic; IAM closes those, see
[What it does not protect against](#what-it-does-not-protect-against).

## Before you start

### What it needs

- The default `proxy_engine: inspect`. `universal` never sees a request's headers, so the check
  fails the step there, in `audit` too.
- An access key ID in `AWS_ACCESS_KEY_ID` when the step starts. Without one, or with a value that is
  not an access key ID, the step fails before the proxy starts, in `audit` too.

A deploy step often needs Docker too, which no isolated command can use, with the check or without
([Inside the sandbox](../README.md#inside-the-sandbox)). `docker push` to ECR and
`sam build --use-container` fail there; build and push images in a step of their own, or with
[Buildcage for Docker](https://github.com/buildcage/docker). `cdk deploy` builds Docker image assets
and Docker bundling itself, so a CDK app that has them cannot deploy in an isolated step.

Run `aws-actions/configure-aws-credentials` as an ordinary step before this one. Its own STS call
does not pass through the proxy, and the temporary credentials it exports, an `ASIA…` key, are the
key the step starts with.

Only `AWS_ACCESS_KEY_ID` gives the key the step starts with. None of these does:

- **A profile, `~/.aws/credentials` or `credential_process`.** A step that signs with a profile's
  key, or alternates between two static keys, cannot use the check. Put the key to check in
  `AWS_ACCESS_KEY_ID`, or run those commands in a step without the check.
- **An EC2 instance profile or a container credentials endpoint**, as on a self-hosted runner on EC2
  or ECS. Run `configure-aws-credentials` in an earlier step with `role-to-assume`: it assumes that
  role from the instance's credentials and exports the role's keys in `AWS_ACCESS_KEY_ID`. Add
  `role-chaining: true` if it fails with
  `Credentials loaded by the SDK do not match the expected access key ID configured by the action`.
- **A web identity token**, in `AWS_WEB_IDENTITY_TOKEN_FILE`. With only the token, the step has no
  key to start with and fails. With `AWS_ACCESS_KEY_ID` set too, the SDKs use the key and ignore
  the token. Exchange the token before the step instead, as `configure-aws-credentials` does with
  GitHub's OIDC token.

### What works unchanged

A step passes the check when:

- It calls AWS through the AWS CLI v2, a current AWS SDK, or a tool built on them, such as the CDK
  and Terraform.
- It assumes roles only in accounts in `allowed_aws_role_accounts`, through STS `AssumeRole`, or
  `AssumeRoleWithWebIdentity` sent as a form (the Query protocol,
  `application/x-www-form-urlencoded`) as an AWS SDK sends it: the CDK's deploy roles, Terraform's
  `assume_role`, or a CLI profile whose `role_arn` starts from `credential_source = Environment` or
  a `web_identity_token_file`.
- It reaches CodeCommit over Git through CodeCommit's credential helper, or with a static Git
  credential of an account in `allowed_aws_role_accounts`.
- It pulls from or pushes to ECR through the registry API, with a client such as `crane`, `skopeo`
  or Jib.
- It sends unsigned requests, or a token such as CodeArtifact's or an API Gateway authorizer's, to a
  host that names its resource, such as a public S3 bucket, or to a public host such as
  `checkip.amazonaws.com`. Only the URL rules decide those.

### What it does not support

The ones that come up most in CI are Bedrock API keys and presigned URLs someone else signed;
[Common setups](#common-setups) shows how to arrange each. The rest are rarer:

- S3 Express One Zone directory buckets, and S3 uploads from an HTML form (a POST policy).
- Calls to APIs that take a form, such as STS, IAM, CloudFormation, SNS, EC2 and SES v1, over about
  4 MiB or compressed: SES v1 `SendRawEmail` with large attachments, or CloudWatch `PutMetricData`
  from an older SDK.
- Old SDKs and hand-written clients signing with Signature Version 2 or 3, and the services that
  take only those, such as Amazon SimpleDB.
- Unsigned calls to a host that serves every account, such as a Cognito user pool sign-in or the
  IAM Identity Center portal.
- Keys from `GetSessionToken`, SAML or IAM Identity Center.

[Troubleshooting](#troubleshooting) says what to do for each, under the reason the report gives.

## Getting started

Turn the check on in `audit` mode first: nothing is blocked, and the report shows what `restrict`
would block. A step that uses only the credentials it is given needs `aws_key_check` alone:

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

`audit` needs no URL rules; the report writes them for `restrict`, as below. They allow what the run
reached, so read them before switching.

A step that assumes roles of its own, as the CDK does, also names the accounts those roles are in.
`allowed_aws_role_accounts` works only with `aws_key_check: true`; without it the step fails. Start
with the account of the role the step is given:

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

Then, with the report described in [Reading the report](#reading-the-report):

1. Check the accounts of the other roles the step assumed, which the report's **Switch to restrict
   mode** example marks. A CDK app deploying to several accounts assumes a
   `cdk-hnb659fds-deploy-role-*` role in each. Keep only accounts that are yours: one you do not
   recognize there is what the check is meant to catch.
2. Name those accounts.
3. Read **⚠️ Restrict Would Block** in the report. [Troubleshooting](#troubleshooting) gives the
   usual causes of each reason.
4. Switch the step to `restrict`. The report's **Switch to restrict mode** example carries the URL
   rules, `aws_key_check: true` and the accounts over.

## Reading the report

The report is the step's section in the workflow run's Job Summary. In `audit` nothing is blocked.
A warning annotation counts the requests `restrict` would block once the report's **Switch to
restrict mode** example is applied, and **⚠️ Restrict Would Block** lists them in two tables: one
row per key for `aws-key-not-allowed`, and one row per host for every other reason, as in **🚫
Blocked Hosts**. In `audit` the check judges every request, so one no URL rule allows can carry an
`aws-` reason too.

| Key (aws-key-not-allowed)         | Hosts                                                              | Count |
| --------------------------------- | ------------------------------------------------------------------ | ----: |
| key 1 from a role in 222222222222 | cloudformation.us-east-1.amazonaws.com, s3.us-east-1.amazonaws.com |    66 |
| key 2                             | ssm.us-east-1.amazonaws.com                                        |     3 |

| Host                              | Rule  | Reason            | Count |
| --------------------------------- | ----- | ----------------- | ----: |
| `sts.us-east-1.amazonaws.com:443` | HTTPS | aws-no-credential |     1 |

A key's row names up to three of the hosts its requests went to. Keys are numbered `key 1`, `key 2`
and so on, in the order they first appear; when only one key was blocked, it has no number. A key
STS issued during the run shows the account of the role it was issued for. The example names that
account, so the key is listed only when the STS call that issued it was itself one `restrict`
would block, which teaches no key. A `key N` with no `from a role in` came from somewhere else,
such as a profile, or from an STS answer the proxy could not read;
[`aws-key-not-allowed`](#aws-key-not-allowed) lists the causes.

**Communication details** names the key on each of those requests:

```
⚠️ 00:12.345: POST https://cloudformation.us-east-1.amazonaws.com/ -> 200 (1.2KB) (restrict would block: aws-key-not-allowed, key 1 from a role in 222222222222)
```

With `upload_traffic_artifact: true`, the traffic artifact has every one, with the reason in
`wouldBlock`. If the section does not fit the Job Summary even so, it is cut and a warning
annotation says so.

In `restrict` the URL rules decide first, so a request none of them allows is blocked as
`not-allowed` rather than with an `aws-` reason. The ones they allow and the check blocks are
listed under **🚫 Blocked Hosts**. In Communication details a blocked one ends in
`-> aws-key-not-allowed, key 1 from a role in 222222222222`, and the traffic artifact gives its
reason in `reason`.

The report's **Switch to restrict mode** example includes `aws_key_check: true` and
`allowed_aws_role_accounts`. The accounts it lists are the ones you gave, plus each account the run
assumed a role in. It reads them from every STS answer, including one to a request `restrict` would
block, so a chain of roles, as the CDK assumes them, shows in full after one run. Anything in the
step can assume a role, in an account of its own too, so each added account is marked:

```yaml
aws_key_check: true
allowed_aws_role_accounts: |
  111111111111
  222222222222 # assumed in this run, check it is yours
```

The example brings the URL rules and the accounts over, not the credentials, so every row of
**⚠️ Restrict Would Block** is still blocked after the switch. [Troubleshooting](#troubleshooting)
says what each needs.

## Common setups

### Bedrock

The Bearer token in `AWS_BEARER_TOKEN_BEDROCK`, a Bedrock API key, names no account the proxy can
see, so it is blocked as `aws-unsupported-credential`. Call Bedrock with the role keys
`configure-aws-credentials` gets through OIDC instead: they are signed with SigV4 and pass with
`aws_key_check: true` alone, given a role allowed `bedrock:InvokeModel`.

### Downloading a presigned URL

A presigned URL carries the key of whoever signed it, such as Lambda `GetFunction`'s
`Code.Location` or a vendor's download link, and is blocked as `aws-key-not-allowed`. Download it
in a step without the check. `aws sts get-access-key-info --access-key-id <key-id>`, with the key
ID from the URL's `X-Amz-Credential`, names the account it belongs to.

That does not work when one command both signs AWS requests and fetches such a URL, as `crane copy`
does from a registry that keeps its layers in S3 into ECR. Such a command has to run in a step
without the check; if a tool you need does this,
[open an issue](https://github.com/buildcage/isolated-run/issues). ECR's own redirects are not
affected: the proxy learns the key ECR signs them with (see [Which keys pass](#which-keys-pass)).

## Troubleshooting

A blocked request names its reason, such as `aws-key-not-allowed`, under **⚠️ Restrict Would
Block** in `audit` or **🚫 Blocked Hosts** in `restrict`, and in **Communication details**. Look the
reason up below.

To accept a block you expect, list its host or URL in `known_blocked_rules` as for any other: it
then no longer fails `restrict`, though the `audit` preview still counts it. See
[Reference](./reference.md#aws-access-key-check).

### `aws-key-not-allowed`

The request was signed with a key the proxy does not know. Look first at which requests are blocked.

**Requests of one kind**, while others signed in the step pass:

- To a host containing `--x-s3`: an S3 Express One Zone directory bucket, whose keys come from
  `CreateSession`, which the proxy does not learn. Use it from a step without the check.
- To a URL carrying `X-Amz-Credential`: a presigned URL someone else signed. See
  [Downloading a presigned URL](#downloading-a-presigned-url).
- To a `git-codecommit` host: a CodeCommit static Git credential of an account not in
  `allowed_aws_role_accounts`. Add the account, or use CodeCommit's credential helper.

**Every request signed after some point**, whatever its host: a key the proxy did not learn. Its
line in Communication details ends in:

- `key N from a role in <account>`: an assumed role. STS issued the key, but the proxy learns it
  only for a role in an account in `allowed_aws_role_accounts`. Add the account once you have
  checked it is yours. If it is already there, or the key is in **⚠️ Restrict Would Block**, the
  STS call was itself one `restrict` would block, so its answer taught no key. In the traffic
  artifact (`upload_traffic_artifact: true`), the STS call whose `aws.issuedKeyRef` is the request's
  `aws.keyRef` has the account in `aws.assumedAccount`.
- `key N` alone, or nothing after the reason when it is the only key blocked, from one of:
  - A profile, `~/.aws/credentials` or `credential_process`; see [What it needs](#what-it-needs).
  - `GetSessionToken`, SAML or IAM Identity Center, which the proxy does not learn. Get the
    credentials before the step and pass them in `AWS_ACCESS_KEY_ID`.
  - An STS answer the proxy could not read, because the client asked for JSON with
    `Accept: application/json`, or it was unusually large. Let the SDK send its default headers to
    STS; shorten a large session policy or tag set.

### `aws-no-credential`

An unsigned request to a host the proxy treats as serving every account:

- A Cognito user pool call made without AWS credentials, or the IAM Identity Center portal. Sign it,
  or move it to a step of its own without the check, whose URL rules allow only that host.
- `AssumeRoleWithWebIdentity` with no `allowed_aws_role_accounts`, or not sent as a form, or
  `AssumeRoleWithSAML`. Name the role's account, send the call as an SDK does, or get the
  credentials before the step.
- A host that names a resource but is missing from the [list](#which-hosts).
  [Report it](https://github.com/buildcage/isolated-run/issues).

### `aws-role-not-allowed`

`AssumeRoleWithWebIdentity` for a role in an account not in `allowed_aws_role_accounts`. Add the
account.

### `aws-unsupported-credential`

An AWS credential the proxy does not read:

- An old SDK or a hand-written client signing with Signature Version 2 or 3, or a service that takes
  only those, such as Amazon SimpleDB (`sdb`) or the retired AWS Import/Export. Update the SDK, or
  run it in a step without the check.
- A token in place of a signature on a host that serves every account, such as a Bedrock API key or
  a CloudWatch Logs ingestion token. Sign with AWS credentials; see [Bedrock](#bedrock).
- An S3 POST-policy upload, the HTML form browsers upload to S3 with. Upload with `PutObject` or a
  presigned `PutObject` URL.
- A POST to EC2 whose `Content-Type` is not a form, which EC2 reads as one whatever it says. Send
  EC2's Query API as the SDK does, with `Content-Type: application/x-www-form-urlencoded`.
- A token on a host that names a resource but is missing from the [list](#which-hosts).
  [Report it](https://github.com/buildcage/isolated-run/issues).

### `aws-unreadable`

A form body the proxy could not read through (see
[Which credentials it reads](#which-credentials-it-reads)):

- Over about 4 MiB, such as SES v1 `SendRawEmail` with large attachments. Use SES v2 (`sesv2`).
- Compressed, such as CloudWatch `PutMetricData` from an older SDK, which compresses a body over
  10 KB. Set `AWS_DISABLE_REQUEST_COMPRESSION=true` for the step, or update the SDK.
- Sent without a `Content-Length`. Send the body with a known length.

### `aws-ambiguous-credential`

More than one credential on one request: two `Authorization` headers, a header and a presigned URL
credential, or one repeated. Or an `AssumeRoleWithWebIdentity` form naming its role twice, or
naming `Action` or `RoleArn` in the query too. Send one credential, and the role in the body only; a
current SDK does.

## What it does not protect against

The check looks at whose key signed a request, not at whose resource the request is for. A request
signed with your own key that names a resource in another account passes. The target account is in
the request body, not in the URL, so the proxy cannot see it. Requests like these remain possible:

| Route                                 | Example                                                                                                                                                                                |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cross-account `AssumeRole`            | Assuming a role in another account, with data in the session name, source identity or session tags. A successful call is recorded in the role owner's CloudTrail. A denied one is not. |
| Services with resource-based policies | Publishing to an SNS topic, sending to an SQS queue, invoking a Lambda function, putting events on an EventBridge bus or writing to an S3 bucket in another account                    |
| KMS                                   | Encrypting with a key in another account, whose owner sees the encryption context in CloudTrail                                                                                        |
| CloudFormation itself                 | A custom resource whose `ServiceToken` or a stack whose `NotificationARNs` names a topic or function in another account. AWS makes those calls, so they never pass the proxy.          |

### Closing the rest in IAM

Each route above needs your role to be allowed to act on a resource in another account, so IAM can
close them. Set these on the role the step assumes, and on the CloudFormation service role if you
use one. With the CDK, the step acts through the bootstrap roles it assumes, `cdk-*-deploy-role`,
`cdk-*-file-publishing-role` and the rest, and CloudFormation through `cdk-*-cfn-exec-role`, so set
them on those, through a customized bootstrap template:

- **Deny access to resources outside your accounts** with the `aws:ResourceAccount` condition key,
  or `aws:ResourceOrgID` if you use AWS Organizations:

  ```json
  {
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringNotEqualsIfExists": { "aws:ResourceAccount": ["111111111111", "222222222222"] }
    }
  }
  ```

  Add it as a statement to an existing policy. List every account the step deploys to, those in
  `allowed_aws_role_accounts` included, or the role cannot assume its roles there. A real policy
  also needs exceptions for resources AWS owns, such as the SSM public parameters under
  `/aws/service/` that the CDK reads to look up an AMI; AWS's
  [data perimeter guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_data-perimeters.html)
  lists them.

- **Name the account in every `sts:AssumeRole` resource.** A resource such as
  `arn:aws:iam::*:role/cdk-*`, common in CDK setups, lets the role assume a role of that name in any
  account, including one someone else creates for the purpose. Write
  `arn:aws:iam::111111111111:role/cdk-*` instead. A denied `AssumeRole` is not recorded in the target
  account, so this closes the route entirely.

## Reference

### Limits

- `AssumeRoleWithWebIdentity` takes no signature, so the proxy judges one sent as a form, as the
  SDKs send it, by the account of the role it names; one with its `Action` in the query instead is
  `aws-no-credential`. A role in an account not listed in `allowed_aws_role_accounts` is blocked as
  `aws-role-not-allowed`, and with none listed the call stays `aws-no-credential`.
  `AssumeRoleWithSAML` is blocked as `aws-no-credential`, and keys from `GetSessionToken`, IAM
  Identity Center's `GetRoleCredentials` or Cognito's `GetCredentialsForIdentity` are never
  learned.
- Keys are learned only from STS answers and ECR registry redirects received over HTTPS, to a
  request the key check did not block, so in `audit` mode a request it would block teaches no key.
  An STS answer over plain HTTP names no account in the restrict example either. A host that names a
  resource is never taken for STS, even an S3 bucket named `sts`. A key in an STS answer the proxy
  cannot read, because the client asked for JSON or it is unusually large, is not learned,
  and requests signed with it are blocked. Such an answer names no account in the restrict example
  either.
- A connection `allowed_tls_rules` or `allowed_ip_rules` passes through is never decrypted, so the
  check never sees its requests. Do not pass AWS API hosts through.
- The starting key ID is handed to the proxy container as an environment variable, so it is visible
  to `docker inspect` on the runner while the step runs. A key ID is not a secret on its own:
  signing needs the secret access key, which never reaches the proxy.

### How the check decides

In `restrict` the URL rules decide first: a request they block stays `not-allowed`, and the key
check judges only the requests they allow. In `audit` the check judges every request.

#### Host and credential

On every AWS API host, a request [signed](#which-credentials-it-reads) with a [known
key](#which-keys-pass) is allowed, one signed with any other key is `aws-key-not-allowed`, and one
carrying an AWS credential the proxy does not read is `aws-unsupported-credential`. A key ECR issued
is the exception: it passes only as the credential of a presigned URL to S3, and is
`aws-key-not-allowed` anywhere else. What happens to a request with no AWS signature depends on the
host:

| Host                                                                                     | No credential              | Non-AWS token, such as `Bearer` or `Basic` |
| ---------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------ |
| Serves every account, such as STS or CloudFormation                                      | `aws-no-credential`¹       | `aws-unsupported-credential`               |
| A [public host](#which-hosts), which reaches no account, such as `checkip.amazonaws.com` | allowed                    | `aws-unsupported-credential`               |
| Names its resource, such as an S3 bucket or ECR                                          | allowed                    | allowed                                    |
| CodeCommit                                                                               | allowed, as Git asks first | `Basic`: see²                              |

1. `AssumeRoleWithWebIdentity` sent as a form, as the SDKs send it, for a role in an account in
   `allowed_aws_role_accounts` is allowed, and for one in any other account is
   `aws-role-not-allowed`. With no account named it stays `aws-no-credential`.
2. A `Basic` login passes with a known key as its user name, as CodeCommit's credential helper sends
   it, or with a static Git credential of an account in `allowed_aws_role_accounts`, and is
   `aws-key-not-allowed` otherwise. Any other token is `aws-unsupported-credential`.

The proxy looks for a credential in a form body only on hosts that serve every account and on
public hosts. There, a body it cannot read to the end is `aws-unreadable`. On a host that names its
resource, and on CodeCommit, it does not read the body. Whatever the host, a request carrying more
than one credential is `aws-ambiguous-credential`. Where more than one reason applies,
`aws-unreadable` comes first, then `aws-unsupported-credential`, then `aws-ambiguous-credential`.

#### Which keys pass

The proxy knows only these three kinds of key, and blocks any other:

- **The key the step starts with**, read from `AWS_ACCESS_KEY_ID` in the step's environment, which
  is where `aws-actions/configure-aws-credentials` puts it. It is taken as given: the proxy does not
  ask AWS whose key it is, so a key of another account set there by mistake passes too.
- **Keys STS issues for a role in one of the `allowed_aws_role_accounts`**, through `AssumeRole` or
  `AssumeRoleWithWebIdentity`. The proxy reads the role ARN and the new access key ID from the
  answer, which AWS writes, and adds the key. This is what lets tools that assume roles mid-step
  keep working, such as the CDK assuming its `cdk-hnb659fds-deploy-role-*` roles, Terraform's
  `assume_role`, or the AWS CLI run with a `--profile` that sets `role_arn` and
  `web_identity_token_file`. A role in any other account issues a key the proxy never learns, so
  requests signed with it are blocked. With no account named, no STS key is learned, but the proxy
  still reads each answer for the account of its role, so a run shows which accounts to name.
- **Keys ECR signs a layer's presigned URL with.** An ECR registry,
  `<account>.dkr.ecr.<region>.amazonaws.com` or its dual-stack `<account>.dkr-ecr.<region>.on.aws`,
  answers a layer download with a redirect to a presigned S3 URL, signed with a key of ECR's own.
  The proxy reads that key from the redirect, which only ECR writes, and adds it whether or not any
  account is named, so a registry client in the step, such as `crane`, `skopeo` or Jib, can follow
  the redirect. The key passes only as the credential of a presigned URL to S3. Whoever holds its
  ID cannot sign with it: the secret stays with ECR.

#### Which credentials it reads

The proxy reads the credential of each request to an AWS API host: the signature the AWS CLI v2 and
current AWS SDKs put in the `Authorization` header (Signature Version 4, or its multi-region variant
SigV4a), or the `X-Amz-Credential` of a presigned URL. Its access key ID has to be one the proxy
knows, compared as a whole string. The proxy never decodes a key ID or verifies a signature: a
request that copies one of your key IDs without the secret is refused by AWS and logged in your own
account.

Any other AWS credential is blocked as `aws-unsupported-credential` without its key being read: the
older Signature Version 2 and 3, a token in place of a signature on a host that serves every
account, a credential in a form body on a host where the proxy reads one (below), and an S3
POST-policy upload, the HTML form browsers upload to S3 with. A POST to EC2 is blocked unless its
`Content-Type` is a form: EC2 alone reads the body as a form whatever the type says, so a credential
there would otherwise go unread.

Some AWS APIs, such as STS, IAM, CloudFormation, SNS and EC2, take their parameters as a form: the
body of a `POST` whose Content-Type is `application/x-www-form-urlencoded`. A credential could hide
in it, so the proxy reads such a body whole, up to about 4 MiB, before deciding, unless the host
names a resource ([below](#which-hosts)). A form body it cannot read through is blocked as
`aws-unreadable`: one that is larger, compressed, or sent without a `Content-Length`.

A CodeCommit `Basic` login carries a key too: the user name CodeCommit's Git credential helper sends
is the key ID, checked the same way. A static CodeCommit Git credential names its account instead
(`<user>-at-<account>`), and passes when that account is in `allowed_aws_role_accounts`. Either way
the repository is looked up in that account.

#### Which hosts

AWS API hosts are names under `amazonaws.com`, `amazonaws.com.cn` and `amazonaws.eu` (the European
Sovereign Cloud), and under their dual-stack counterparts `api.aws`, `api.amazonwebservices.com.cn`
and `api.amazonwebservices.eu`. Other AWS names, such as `public.ecr.aws` or Lambda function URLs
under `on.aws`, are left to the URL rules alone.

These hosts name the resource a request reaches, in the host name or, for S3's path style and an EKS
OIDC issuer, in the path. The URL rules can pin the resource there, so an unsigned request to them is
left to the URL rules:

| Service                | Host                                                                                                                                                                   |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S3                     | every S3 form: `<bucket>.s3.<region>.amazonaws.com`, `s3.<region>.amazonaws.com/<bucket>/…`, access points, `<account>.s3-control`, website and acceleration endpoints |
| ECR                    | `<account>.dkr.ecr.<region>.amazonaws.com`, `<account>.dkr.ecr-fips.<region>.amazonaws.com`                                                                            |
| CodeArtifact           | `<domain>-<owner>.d.codeartifact.<region>.amazonaws.com`                                                                                                               |
| API Gateway            | `<api-id>.execute-api.<region>.amazonaws.com`                                                                                                                          |
| AppSync                | `<id>.appsync-api.<region>.amazonaws.com`, `<id>.appsync-realtime-api.<region>.amazonaws.com`                                                                          |
| Managed Grafana        | `g-<id>.grafana-workspace.<region>.amazonaws.com`                                                                                                                      |
| Amazon MQ              | `b-<id>.mq.<region>.amazonaws.com`                                                                                                                                     |
| OpenSearch Service     | `search-<domain>-<id>.<region>.es.amazonaws.com`, `vpc-<domain>-<id>.<region>.es.amazonaws.com`                                                                        |
| EKS cluster            | `<id>.<label>.<region>.eks.amazonaws.com` (such as `gr7` or `yl4`), `<id>.<region>.api.aws`                                                                            |
| EKS OIDC issuer        | `oidc.eks.<region>.amazonaws.com/id/<id>`, `oidc-eks.<region>.api.aws/id/<id>`                                                                                         |
| Elastic Load Balancing | `<name>-<id>.elb.<region>.amazonaws.com`, `<name>-<id>.<region>.elb.amazonaws.com`                                                                                     |
| EC2                    | `ec2-<ip>.<region>.compute.amazonaws.com`, `ec2-<ip>.compute-1.amazonaws.com`                                                                                          |

Each `amazonaws.com` name also matches under `amazonaws.com.cn` and `amazonaws.eu`, and each
`api.aws` one under `api.amazonwebservices.com.cn` and `api.amazonwebservices.eu`.

An unsigned request to these public hosts, which reach no account, is left to the URL rules too:
`awscli.amazonaws.com` (AWS CLI downloads), `checkip.amazonaws.com`, `ip-ranges.amazonaws.com`, and
the Price List Bulk API's files on `pricing.us-east-1.amazonaws.com` and
`pricing.cn-northwest-1.amazonaws.com.cn`.

Every other AWS API host names only a service and a region, such as `sts.us-east-1.amazonaws.com`,
`sqs.us-east-1.amazonaws.com` or `s3-control.us-east-1.amazonaws.com`. The account a request to one
of those reaches is in its parameters or its body, where the proxy does not look, so an unsigned
request there is blocked, `GET` included, `AssumeRoleWithWebIdentity` excepted (see
[Host and credential](#host-and-credential)). A host missing from the lists above is treated the
same way; if a legitimate request is blocked for that reason, as `aws-no-credential` or, carrying a
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

### In the traffic artifact

Each request to an AWS API host that the check let through has an `aws` object in the
[traffic artifact](./reference.md#traffic-artifact), so a run shows that the check was on even
where it blocked nothing. A request the check blocked has one only for `keyRef`, and for
`assumedAccount` and `issuedKeyRef` on an STS call in `audit` mode. Its `reason` or `wouldBlock`
says why. `wouldBlock` is judged with the inputs the run was given, so a request signed with the
key of a role in an account the **Switch to restrict mode** example adds has one, though **⚠️
Restrict Would Block** leaves it out.

| Field            | When                                                                           | Notes                                                                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `key`            | on every request the check let through                                         | `env` for the key the step started with, `assumed` for one STS issued, `issued` for one ECR signed a layer's presigned URL with, `none` for a request carrying no access key |
| `accountId`      | when the check confirmed an account                                            | the one an `assumed` key came from, a static CodeCommit Git credential names, or the role of an `AssumeRoleWithWebIdentity` call is in                                       |
| `assumedAccount` | on an STS call whose answer named a role, whether or not the check let it go   | the account of that role, whether or not it is named                                                                                                                         |
| `keyRef`         | on every request signed with an access key, whether or not the check let it go | 16 hex digits standing for the key, the same for one key throughout a run                                                                                                    |
| `issuedKeyRef`   | on an STS call or an ECR registry redirect that issued a key                   | the `keyRef` of the requests signed with that key                                                                                                                            |

The starting key's account is never shown, since the proxy does not ask AWS whose key it is. No key
ID is written either: `keyRef` is an HMAC of it under a secret the proxy draws for each run, so it
cannot be turned back into a key ID or matched across runs.

```json
{
  "action": "allow",
  "host": "cloudformation.us-east-1.amazonaws.com",
  "method": "POST",
  "aws": { "key": "assumed", "accountId": "111111111111", "keyRef": "6e30dca31102cb8a" }
}
```
