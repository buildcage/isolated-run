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

import type { InspectStageExtension } from "#core/lib/acl/haproxy-inspect-stage.ts";

/** Where the two files the check reads are. */
export interface AwsKeyCheck {
  accountFile: string;
  keyMapFile: string;
}

/** The verdicts restrict mode refuses on, each logged as `reason=aws-<verdict>`. */
export const AWS_REFUSED_VERDICTS = [
  "no-credential",
  "ambiguous-credential",
  "unreadable",
  "key-not-allowed",
];

// A form body is read whole up to this size, less its headers, so a credential
// cannot sit past what was read. SQS SendMessage, the largest form request, is
// 1 MiB before URL encoding at most triples it.
const FORM_BODY_LIMIT = 4 * 1024 * 1024;

// API endpoints only: the commercial, China and European Sovereign Cloud
// domains, and the dual-stack ones.
const AWS_DOMAINS =
  "(amazonaws\\.com|amazonaws\\.com\\.cn|amazonaws\\.eu|api\\.aws|api\\.amazonwebservices\\.com\\.cn|api\\.amazonwebservices\\.eu)";
// Matched against txn.host, which is lowercased and has no port.
export const AWS_API_HOST = `^([a-z0-9-]+\\.)+${AWS_DOMAINS}$`;
// The names an interface VPC endpoint gives a service.
const vpceHost = (service: string) =>
  `^([a-z0-9-]+\\.)*vpce-[a-z0-9-]+\\.${service}\\.[a-z0-9-]+\\.vpce\\.amazonaws\\.com$`;
export const STS_HOST = `^sts(-fips)?(\\.[a-z0-9-]+)?\\.${AWS_DOMAINS}$|${vpceHost("sts")}`;
// Hosts that name the resource a request is for, in the host or (S3's path
// style, an EKS OIDC issuer) the path, so the URL rules can pin it and an
// unsigned request is left to them: S3 in every form, ECR registries,
// CodeArtifact repositories, API Gateway, AppSync, Managed Grafana workspaces,
// Amazon MQ brokers, OpenSearch domains, EKS clusters and OIDC issuers, load
// balancers, EC2 public names, and the AWS CLI's download host. Every other API host names
// only a service and a region.
export const S3_HOST = "(^|\\.)s3(-[a-z0-9-]+)?(\\.[a-z0-9-]+)*\\.amazonaws\\.(com|com\\.cn|eu)$";
export const AWS_RESOURCE_HOST =
  S3_HOST +
  "|\\.(dkr\\.ecr(-fips)?|d\\.codeartifact|execute-api|appsync-api|appsync-realtime-api)\\.[a-z0-9-]+\\.amazonaws\\.(com|com\\.cn|eu)$" +
  "|^g-[a-z0-9]+\\.grafana-workspace\\.[a-z0-9-]+\\.amazonaws\\.(com|com\\.cn|eu)$" +
  "|^b-[a-z0-9-]+\\.mq\\.[a-z0-9-]+\\.amazonaws\\.(com|com\\.cn|eu)$" +
  "|^(search|vpc)-[a-z0-9-]+\\.[a-z0-9-]+\\.es\\.amazonaws\\.(com|com\\.cn|eu)$" +
  "|^[0-9a-f]{32}\\.([a-z0-9]+\\.)?[a-z0-9-]+\\.eks\\.amazonaws\\.(com|com\\.cn|eu)$" +
  "|^[0-9a-f]{32}\\.[a-z0-9-]+\\.(api\\.aws|api\\.amazonwebservices\\.com\\.cn|api\\.amazonwebservices\\.eu)$" +
  "|^oidc\\.eks\\.[a-z0-9-]+\\.amazonaws\\.(com|com\\.cn|eu)$" +
  "|^oidc-eks\\.[a-z0-9-]+\\.(api\\.aws|api\\.amazonwebservices\\.com\\.cn|api\\.amazonwebservices\\.eu)$" +
  "|\\.elb(\\.[a-z0-9-]+)?\\.amazonaws\\.(com|com\\.cn|eu)$" +
  "|\\.compute(-1)?\\.amazonaws\\.(com|com\\.cn|eu)$" +
  "|^awscli\\.amazonaws\\.com$";
export const CODECOMMIT_HOST =
  "^git-codecommit(-fips)?\\.[a-z0-9-]+\\.amazonaws\\.(com|com\\.cn|eu)$|" +
  vpceHost("git-codecommit(-fips)?");
// Both query spellings of a credential: SigV4's and SigV2's. Matched without
// regard to case, so a spelling the extraction below does not read is still
// counted as a credential and left unmatched rather than read as none.
const QUERY_CREDENTIAL = "(x-amz-credential|awsaccesskeyid)";
// SigV2's name as a form body may spell it, any letter percent-encoded.
export const FORM_CREDENTIAL = "awsaccesskeyid"
  .split("")
  .map(
    (c) => `(${c}|%${c.charCodeAt(0).toString(16)}|%${c.toUpperCase().charCodeAt(0).toString(16)})`,
  )
  .join("");

/** The check as the inspect stage takes it. */
export function awsKeyExtension(check: AwsKeyCheck): InspectStageExtension {
  return {
    requestRules: (mode) => awsKeyRequestRules(check, mode),
    responseRules: () => awsKeyResponseRules(check),
    global: [`    tune.bufsize.large ${FORM_BODY_LIMIT}`],
  };
}

/**
 * Request rules: name the key a request was signed with and decide on it.
 * `audit` decides too, for the log, but refuses nothing.
 */
export function awsKeyRequestRules(check: AwsKeyCheck, mode: "restrict" | "audit"): string[] {
  const l = [
    "    # AWS access key check. req.fhdr, not req.hdr: Authorization holds commas.",
    "    # Matched once: an acl is evaluated again on every line that names it.",
    `    http-request set-var(txn.aws_host) bool(true) if { var(txn.host) -m reg ${AWS_API_HOST} }`,
    "    acl aws_host var(txn.aws_host) -m bool",
    `    acl aws_sts_host var(txn.host) -m reg ${STS_HOST}`,
    `    acl aws_resource_host var(txn.host) -m reg ${AWS_RESOURCE_HOST}`,
    "    # A credential is one of AWS's own schemes, or a Basic login to CodeCommit,",
    "    # two lines declaring the one acl. CodeCommit's Git credential helper",
    "    # sends the key ID as the user name, and a static Git credential names",
    "    # its account, <user>-at-<id>; either way the repository is looked up in",
    "    # that account. Other Bearer and Basic tokens, such as CodeArtifact's and",
    "    # ECR's, are signed by no AWS account. Any case, so a spelling AWS might",
    "    # accept is never let through unjudged.",
    `    http-request set-var(txn.aws_git_host) bool(true) if { var(txn.host) -m reg ${CODECOMMIT_HOST} }`,
    "    acl aws_git_host var(txn.aws_git_host) -m bool",
    "    http-request set-var(txn.aws_git) bool(true) if aws_git_host { req.fhdr(authorization) -m reg -i ^basic\\s }",
    "    acl aws_auth req.fhdr(authorization) -m reg -i ^aws",
    "    acl aws_auth var(txn.aws_git) -m bool",
    `    http-request set-var(txn.aws_git_user) 'req.fhdr(authorization),regsub("^basic\\s+","",i),b64dec,regsub(":.*$","")' if { var(txn.aws_git) -m bool }`,
    "    acl aws_auth_many req.fhdr_cnt(authorization) gt 1",
    "    acl aws_auth_many req.fhdr(authorization) -m reg -i credential=.*credential=",
    "    # Decoded first: a name spelled as X-Amz-Cr%65dential still counts.",
    `    acl aws_query query,url_dec -m reg -i (^|&)${QUERY_CREDENTIAL}=`,
    `    acl aws_query_many query,url_dec -m reg -i (?s)(^|&)${QUERY_CREDENTIAL}=.*&${QUERY_CREDENTIAL}=`,
    "    # SigV2 also takes its parameters from a form body, and a key there is",
    "    # judged alongside one in the header or the query. A body counts as a",
    "    # form by its Content-Type or, whatever that says, by starting as one.",
    "    # Hosts that name a resource are left out, and so is CodeCommit, whose",
    "    # Git requests carry their credential in the header.",
    "    http-request set-var(txn.aws_post) bool(true) if aws_host METH_POST !aws_resource_host !aws_git_host",
    "    acl aws_post var(txn.aws_post) -m bool",
    "    http-request wait-for-body time 30s if aws_post",
    "    http-request set-var(txn.aws_form_post) bool(true) if aws_post { req.hdr(content-type) -m beg -i application/x-www-form-urlencoded } or aws_post { req.body -m reg ^&*[A-Za-z0-9._~%*+!(),:/@-]*= }",
    "    acl aws_form_post var(txn.aws_form_post) -m bool",
    "    http-request wait-for-body time 30s use-large-buffer if aws_form_post",
    "    # Matched undecoded, since a value carries & and = encoded, but each",
    "    # letter of the name may be.",
    `    http-request set-var(txn.aws_body) bool(true) if aws_form_post { req.body -m reg -i (^|&)${FORM_CREDENTIAL}= }`,
    "    acl aws_body var(txn.aws_body) -m bool",
    `    acl aws_body_many req.body -m reg -i (?s)(^|&)${FORM_CREDENTIAL}=.*&${FORM_CREDENTIAL}=`,
    "    http-request set-var(txn.aws_body_key) req.body_param(AWSAccessKeyId,i) if aws_body",
    "    # A header neither pattern matches comes out unchanged, and so never",
    "    # equals a key in the map.",
    `    http-request set-var(txn.aws_key) 'req.fhdr(authorization),regsub("^AWS4-[A-Z0-9-]+ +Credential=([A-Za-z0-9]+)/.*$","\\1",i),regsub("^AWS ([A-Za-z0-9]+):.*$","\\1",i)' if aws_host aws_auth !aws_query`,
    `    http-request set-var(txn.aws_key) 'url_param(X-Amz-Credential),url_dec,regsub("^([A-Za-z0-9]+)/.*$","\\1")' if aws_host aws_query !aws_auth { url_param(X-Amz-Credential) -m found }`,
    "    http-request set-var(txn.aws_key) url_param(AWSAccessKeyId) if aws_host aws_query !aws_auth { url_param(AWSAccessKeyId) -m found }",
    "    http-request set-var(txn.aws_key) var(txn.aws_body_key) if aws_body !aws_auth !aws_query",
    '    http-request set-var(txn.aws_key) \'var(txn.aws_git_user),regsub("%.*$","")\' if { var(txn.aws_git) -m bool } !aws_query',
    "    http-request set-var(txn.aws) str(ambiguous-credential) if aws_host aws_auth aws_query or aws_host aws_auth aws_auth_many or aws_host aws_query_many or aws_body aws_body_many",
    "    # Unsigned, whatever the method: where the host names no resource, the",
    "    # account it reaches is in the parameters or the body, out of sight.",
    "    # An S3 POST-policy upload carries its credential in a multipart body,",
    "    # which this does not read, so it counts as unsigned and is refused.",
    `    http-request set-var(txn.aws_form) bool(true) if METH_POST { var(txn.host) -m reg ${S3_HOST} } { req.hdr(content-type) -m beg -i multipart/form-data }`,
    "    acl aws_form var(txn.aws_form) -m bool",
    "    # Git asks CodeCommit with no credential first, and logs in on its 401.",
    "    http-request set-var(txn.aws_git_bare) bool(true) if aws_git_host !{ req.fhdr(authorization) -m found }",
    "    acl aws_git_bare var(txn.aws_git_bare) -m bool",
    "    http-request set-var(txn.aws) str(unsigned) if aws_host !aws_auth !aws_query !aws_body aws_resource_host !aws_form or aws_git_bare !aws_query",
    "    http-request set-var(txn.aws) str(no-credential) if aws_host !aws_auth !aws_query !aws_body !aws_resource_host !aws_git_bare or aws_host !aws_auth !aws_query !aws_body aws_form",
    "    # Where a credential could be out of sight: a query url_dec cannot decode",
    "    # (%00 or a broken escape), or a form body that is compressed, sent",
    "    # chunked, larger than the buffer, or holds a NUL, where matching stops.",
    "    http-request set-var(txn.aws_body_size) req.body_size if aws_form_post",
    "    http-request set-var(txn.aws_body_len) req.body_len if aws_form_post",
    "    http-request set-var(txn.aws) str(unreadable) if aws_host { query -m found } !{ query,url_dec -m found }",
    "    http-request set-var(txn.aws) str(unreadable) if aws_form_post { req.hdr(content-encoding) -m reg -i ^(?!identity$) } or aws_form_post { req.hdr(transfer-encoding) -m found }",
    "    http-request set-var(txn.aws) str(unreadable) if aws_form_post { req.body_len,sub(txn.aws_body_size) lt 0 } or aws_form_post { req.body,length,sub(txn.aws_body_len) lt 0 }",
    "    # A body key next to another one; a body key alone is aws_key below.",
    `    http-request set-var(txn.aws) str(key-not-allowed) if aws_body aws_auth !{ var(txn.aws) -m found } !{ var(txn.aws_body_key),map(${check.keyMapFile}) -m found } or aws_body aws_query !{ var(txn.aws) -m found } !{ var(txn.aws_body_key),map(${check.keyMapFile}) -m found }`,
    `    http-request set-var(txn.aws) str(allowed) if { var(txn.aws_git_user) -m reg ^((?!-at-).)+-at-[0-9]{12}$ } { 'var(txn.aws_git_user),regsub("^.*-at-([0-9]{12})$","\\1")' -m str -f ${check.accountFile} } !{ var(txn.aws) -m found }`,
    `    http-request set-var(txn.aws) str(key-not-allowed) if aws_host !{ var(txn.aws) -m found } !{ var(txn.aws_key),map(${check.keyMapFile}) -m found }`,
    "    http-request set-var(txn.aws) str(allowed) if aws_host !{ var(txn.aws) -m found }",
  ];
  l.push(`    acl aws_refused var(txn.aws) -m str ${AWS_REFUSED_VERDICTS.join(" ")}`);
  l.push(
    ...(mode === "restrict"
      ? [
          "    http-request set-var-fmt(txn.reason) aws-%[var(txn.aws)] if aws_refused",
          "    http-request deny deny_status 403 if aws_refused",
        ]
      : ["    http-request set-var-fmt(txn.would_refuse) aws-%[var(txn.aws)] if aws_refused"]),
  );
  l.push(
    "    # The body has to be readable to learn a key from it; no Accept-Encoding",
    "    # at all would mean any coding is acceptable (RFC 9110). Left alone where",
    "    # it is signed, which rewriting would break: a compressed answer then",
    "    # teaches nothing, and the key it issues is refused.",
    "    acl aws_coding_signed req.fhdr(authorization) -m reg -i signedheaders=[^,]*accept-encoding",
    "    acl aws_coding_signed query,url_dec -m reg -i (^|&)x-amz-signedheaders=[^&]*accept-encoding",
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
