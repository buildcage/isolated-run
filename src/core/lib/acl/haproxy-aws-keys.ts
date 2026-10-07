/**
 * The AWS access key check: a request to an AWS API host must be signed with a
 * key that belongs to an allowed account, or a build could sign with keys of
 * its own and write data into another account's CloudTrail through any API.
 *
 * The keys come from two places: the ones the step started with, and the ones
 * an STS AssumeRole answer hands back for a role in an allowed account, read
 * off the response and added to the map at runtime. A key is matched as a
 * whole string and never decoded.
 */

/** Where the two files the check reads are. */
export interface AwsKeyCheck {
  accountFile: string;
  keyMapFile: string;
}

/** The verdicts restrict mode refuses on, each logged as `reason=aws-<verdict>`. */
export const AWS_REFUSED_VERDICTS = ["no-credential", "ambiguous-credential", "key-not-allowed"];

// API endpoints only: the classic and China domains, and the dual-stack ones.
// Matched against txn.host, which is lowercased and has no port.
export const AWS_API_HOST =
  "^([a-z0-9-]+\\.)+(amazonaws\\.com|amazonaws\\.com\\.cn|api\\.aws|api\\.amazonwebservices\\.com\\.cn)$";
export const STS_HOST =
  "^sts(-fips)?(\\.[a-z0-9-]+)?\\.(amazonaws\\.com|amazonaws\\.com\\.cn|api\\.aws|api\\.amazonwebservices\\.com\\.cn)$";
// Hosts that name the resource a request is for, in the host or (S3's path
// style) the path, so the URL rules can pin the account and an unsigned request
// is left to them: S3 in every form, ECR registries, CodeArtifact repositories,
// API Gateway, AppSync, load balancers, EC2 public names, and the AWS CLI's
// download host. Every other API host names only a service and a region.
export const AWS_RESOURCE_HOST =
  "(^|\\.)s3(-[a-z0-9-]+)?(\\.[a-z0-9-]+)*\\.amazonaws\\.com(\\.cn)?$" +
  "|\\.(dkr\\.ecr|d\\.codeartifact|execute-api|appsync-api|appsync-realtime-api)\\.[a-z0-9-]+\\.amazonaws\\.com(\\.cn)?$" +
  "|\\.elb(\\.[a-z0-9-]+)?\\.amazonaws\\.com(\\.cn)?$" +
  "|\\.compute(-1)?\\.amazonaws\\.com(\\.cn)?$" +
  "|^awscli\\.amazonaws\\.com$";
// Both query spellings of a credential: SigV4's and SigV2's. Matched without
// regard to case, so a spelling the extraction below does not read is still
// counted as a credential and left unmatched rather than read as none.
const QUERY_CREDENTIAL = "(x-amz-credential|awsaccesskeyid)";

/** The log field, empty where the check is off. */
export function awsLogField(check: AwsKeyCheck | undefined): string {
  return check ? " aws=%[var(txn.aws)]" : "";
}

/**
 * Request rules: name the key a request was signed with and decide on it.
 * `audit` decides too, for the log, but refuses nothing.
 */
export function awsKeyRequestRules(check: AwsKeyCheck, mode: "restrict" | "audit"): string[] {
  const l = [
    "    # AWS access key check. req.fhdr, not req.hdr: Authorization holds commas.",
    `    acl aws_host var(txn.host) -m reg ${AWS_API_HOST}`,
    `    acl aws_sts_host var(txn.host) -m reg ${STS_HOST}`,
    `    acl aws_resource_host var(txn.host) -m reg ${AWS_RESOURCE_HOST}`,
    "    # Only AWS's own schemes are a credential here: CodeArtifact and ECR take",
    "    # Bearer and Basic tokens, which no AWS account signs with. Any case, so a",
    "    # spelling AWS might accept is never let through unjudged.",
    "    acl aws_auth req.fhdr(authorization) -m reg -i ^aws",
    "    acl aws_auth_many req.fhdr_cnt(authorization) gt 1",
    "    acl aws_auth_many req.fhdr(authorization) -m reg -i credential=.*credential=",
    "    # Decoded first: a name spelled as X-Amz-Cr%65dential still counts.",
    `    acl aws_query query,url_dec -m reg -i (^|&)${QUERY_CREDENTIAL}=`,
    `    acl aws_query_many query,url_dec -m reg -i (^|&)${QUERY_CREDENTIAL}=.*&${QUERY_CREDENTIAL}=`,
    "    # A header neither pattern matches comes out unchanged, and so never",
    "    # equals a key in the map.",
    `    http-request set-var(txn.aws_key) 'req.fhdr(authorization),regsub("^AWS4-[A-Z0-9-]+ +Credential=([A-Za-z0-9]+)/.*$","\\1",i),regsub("^AWS ([A-Za-z0-9]+):.*$","\\1",i)' if aws_host aws_auth !aws_query`,
    `    http-request set-var(txn.aws_key) 'url_param(X-Amz-Credential),url_dec,regsub("^([A-Za-z0-9]+)/.*$","\\1")' if aws_host aws_query !aws_auth { url_param(X-Amz-Credential) -m found }`,
    "    http-request set-var(txn.aws_key) url_param(AWSAccessKeyId) if aws_host aws_query !aws_auth { url_param(AWSAccessKeyId) -m found }",
    "    http-request set-var(txn.aws) str(ambiguous-credential) if aws_host aws_auth aws_query or aws_host aws_auth aws_auth_many or aws_host aws_query_many",
    "    # Unsigned, whatever the method: where the host names no resource, the",
    "    # account it reaches is in the parameters or the body, out of sight.",
    "    http-request set-var(txn.aws) str(unsigned) if aws_host !aws_auth !aws_query aws_resource_host",
    "    http-request set-var(txn.aws) str(no-credential) if aws_host !aws_auth !aws_query !aws_resource_host",
    `    http-request set-var(txn.aws) str(key-not-allowed) if aws_host !{ var(txn.aws) -m found } !{ var(txn.aws_key),map(${check.keyMapFile}) -m found }`,
    "    http-request set-var(txn.aws) str(allowed) if aws_host !{ var(txn.aws) -m found }",
  ];
  if (mode === "restrict") {
    l.push(
      `    acl aws_refused var(txn.aws) -m str ${AWS_REFUSED_VERDICTS.join(" ")}`,
      "    http-request set-var-fmt(txn.reason) aws-%[var(txn.aws)] if aws_refused",
      "    http-request deny deny_status 403 if aws_refused",
    );
  }
  l.push(
    "    # The body has to be readable to learn a key from it; no Accept-Encoding",
    "    # at all would mean any coding is acceptable (RFC 9110). Left alone where",
    "    # it is signed, which rewriting would break: a compressed answer then",
    "    # teaches nothing, and the key it issues is refused.",
    "    acl aws_coding_signed req.fhdr(authorization) -m reg -i signedheaders=[^,]*accept-encoding",
    "    http-request set-header Accept-Encoding identity if aws_sts_host !aws_coding_signed",
    "    http-request set-var(txn.aws_sts) bool(true) if aws_sts_host",
    "",
  );
  return l;
}

/**
 * Response rules: learn the key an AssumeRole answer issues, only when the
 * role's account is allowed. The role ARN is AWS's own, not the caller's.
 * A body larger than the buffer is read only in part, so a key past it is
 * not learned and its requests are refused.
 */
export function awsKeyResponseRules(check: AwsKeyCheck): string[] {
  return [
    "    acl aws_sts var(txn.aws_sts) -m bool",
    "    acl aws_assume_role res.body -m reg ^(<\\?xml[^>]*\\?>)?\\s*<AssumeRoleResponse[\\s>]",
    "    acl aws_many_keys res.body -m reg (?s)<AccessKeyId>.*<AccessKeyId>",
    "    acl aws_many_arns res.body -m reg (?s)<Arn>.*<Arn>",
    "    http-response wait-for-body time 10s if aws_sts { status 200 }",
    `    http-response set-var(txn.aws_new_key) 'res.body,regsub("(?s)^.*<AccessKeyId>(ASIA[A-Z0-9]+)</AccessKeyId>.*$","\\1")' if aws_sts { status 200 } aws_assume_role !aws_many_keys !aws_many_arns`,
    `    http-response set-var(txn.aws_new_account) 'res.body,regsub("(?s)^.*<Arn>arn:aws[a-z-]*:sts::([0-9]{12}):assumed-role/[^<]*</Arn>.*$","\\1")' if aws_sts { status 200 } aws_assume_role !aws_many_keys !aws_many_arns`,
    "    acl aws_new_key var(txn.aws_new_key) -m reg ^ASIA[A-Z0-9]+$",
    "    acl aws_new_account var(txn.aws_new_account) -m reg ^[0-9]{12}$",
    `    acl aws_new_account_allowed var(txn.aws_new_account) -m str -f ${check.accountFile}`,
    `    http-response set-map(${check.keyMapFile}) %[var(txn.aws_new_key)] 1 if aws_new_key aws_new_account aws_new_account_allowed`,
    "",
  ];
}
