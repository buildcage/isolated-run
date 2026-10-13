/**
 * The AWS access key check: a request to an AWS API host must be signed with a
 * key the proxy knows, or a build could sign with keys of its own and write
 * data into another account's CloudTrail through any API.
 *
 * The keys come from three places: the one the step started with, taken as
 * given; when role accounts are named, the ones an STS AssumeRole or
 * AssumeRoleWithWebIdentity answer hands back for a role in one of them; and
 * the ones in the presigned URLs ECR's registry redirects a layer download
 * to. The last two are read off the response and added to the map at runtime.
 * A key is matched as a whole string and never decoded.
 *
 * Only one credential is matched, SigV4's or SigV4a's, in the Authorization
 * header or a presigned URL, as current SDKs send it. Any other AWS
 * credential is refused without reading its key.
 */

import type { InspectStageExtension } from "#core/lib/acl/haproxy-inspect-stage.ts";

import {
  AWS_API_SUFFIXES,
  AWS_PUBLIC_HOST,
  AWS_RESOURCE_HOST,
  CODECOMMIT_HOST,
  EC2_HOST,
  ECR_DUALSTACK_REGISTRY_HOST,
  ECR_REGISTRY_HOST,
  S3_HOST,
  SIGV2_PARAM,
  SIGV4_PARAM,
  STS_HOST,
  formName,
} from "./aws-hosts.ts";
import type { AwsTrafficFields } from "./aws-log.ts";

/** Where the files the check reads are. */
export interface AwsKeyCheck {
  keyMapFile: string;
  /** The accounts whose roles may issue keys; absent, no STS key is learned,
   *  though the account an STS answer names is still recorded. */
  accountFile?: string;
  /** The base64 HMAC key a run's key references are made with. */
  refSecret: string;
}

/** Starts every reason the check refuses with. */
export const AWS_REASON_PREFIX = "aws-";

/** The verdicts restrict mode refuses on, each logged as `reason=aws-<verdict>`. */
export const AWS_REFUSED_VERDICTS = [
  "no-credential",
  "ambiguous-credential",
  "unsupported-credential",
  "unreadable",
  "key-not-allowed",
  "role-not-allowed",
] as const;

/** A reason the check refuses with. */
export type AwsRefusedReason =
  `${typeof AWS_REASON_PREFIX}${(typeof AWS_REFUSED_VERDICTS)[number]}`;

// A form body is read whole up to this size, less its headers, so a credential
// cannot sit past what was read. SQS SendMessage, the largest form request, is
// 1 MiB before URL encoding at most triples it.
const FORM_BODY_LIMIT = 4 * 1024 * 1024;

// The key ID in a Location's query credential.
export const LOCATION_CREDENTIAL = "^[^?#]*[?]([^#]*&)?X-Amz-Credential=([A-Za-z0-9]+)(%2F|/).*$";
// SigV4's or SigV4a's Authorization header, in the spelling SDKs send. Any
// other spelling is not matched, and so refused as another scheme.
export const SIGV4_HEADER = "^AWS4-(HMAC-SHA256|ECDSA-P256-SHA256)\\s+Credential=[A-Za-z0-9]+/";
const FORM_ROLE_ARN = formName("rolearn");
const FORM_ACTION = formName("action");
const ROLE_ARN = "^arn:aws[a-z-]*:iam::([0-9]{12}):role/.*$";

const REF_SECRET = /^[A-Za-z0-9+/]{40}$/;

/** An expression for an opaque reference to the key ID in a variable: the
 *  same for a key throughout a run, and unrelated across runs. */
function keyRef(variable: string, secret: string): string {
  if (!REF_SECRET.test(secret)) throw new Error("invalid AWS key reference secret");
  return `'var(${variable}),hmac(sha256,${secret}),bytes(0,8),hex,lower'`;
}

/** The check as the inspect stage takes it. */
export function awsKeyExtension(check: AwsKeyCheck): InspectStageExtension {
  return {
    requestRules: (mode) => awsKeyRequestRules(check, mode),
    responseRules: () => awsKeyResponseRules(check),
    global: [`    tune.bufsize.large ${FORM_BODY_LIMIT}`],
    logFields: {
      name: "aws",
      fields: {
        key: "txn.aws_log_key",
        accountId: "txn.aws_log_account",
        assumedAccount: "txn.aws_log_assumed",
        keyRef: "txn.aws_log_key_ref",
        issuedKeyRef: "txn.aws_log_issued_ref",
      } satisfies Record<keyof AwsTrafficFields["aws"], string>,
    },
  };
}

/**
 * Request rules: record what a request carries, then decide on it.
 * `audit` decides too, for the log, but refuses nothing.
 */
export function awsKeyRequestRules(check: AwsKeyCheck, mode: "restrict" | "audit"): string[] {
  const roles = check.accountFile ? roleRules(check.accountFile) : undefined;
  return [
    ...credentialFacts(),
    ...keyExtraction(check.keyMapFile, check.refSecret),
    ...unsignedAndSts(),
    ...(roles?.facts ?? []),
    ...verdicts(mode, roles),
    ...trafficRecord(roles),
    ...learnFlags(),
  ];
}

/** What credential a request carries, and whether it is one the check refuses
 *  unread. */
function credentialFacts(): string[] {
  return [
    "    # AWS access key check. req.fhdr, not req.hdr: Authorization holds commas.",
    "    # Each fact is matched once and kept in a variable: an acl is evaluated",
    "    # again on every line that names it.",
    `    http-request set-var(txn.aws_host) bool(true) if { var(txn.host) -m end ${AWS_API_SUFFIXES.join(" ")} }`,
    "    acl aws_host var(txn.aws_host) -m bool",
    `    http-request set-var(txn.aws_resource_host) bool(true) if aws_host { var(txn.host) -m reg ${AWS_RESOURCE_HOST} }`,
    "    acl aws_resource_host var(txn.aws_resource_host) -m bool",
    "    http-request set-var(txn.aws_auth) bool(true) if aws_host { req.fhdr(authorization) -m found }",
    "    acl aws_auth var(txn.aws_auth) -m bool",
    `    http-request set-var(txn.aws_sigv4) bool(true) if aws_host { req.fhdr(authorization) -m reg ${SIGV4_HEADER} }`,
    "    acl aws_sigv4 var(txn.aws_sigv4) -m bool",
    "    # A Basic login to CodeCommit is matched too. CodeCommit's Git credential",
    "    # helper sends the key ID as the user name, and a static Git credential",
    "    # names its account, <user>-at-<id>; either way the repository is looked",
    "    # up in that account.",
    `    http-request set-var(txn.aws_git_host) bool(true) if aws_host { var(txn.host) -m reg ${CODECOMMIT_HOST} }`,
    "    acl aws_git_host var(txn.aws_git_host) -m bool",
    "    http-request set-var(txn.aws_git) bool(true) if aws_git_host { req.fhdr(authorization) -m reg -i ^basic\\s }",
    "    acl aws_git var(txn.aws_git) -m bool",
    "    # A query is matched undecoded, as a form body is, so a name inside a",
    "    # value does not count, but X-Amz-Cr%65dential does.",
    `    http-request set-var(txn.aws_query) bool(true) if aws_host { query -m reg -i (^|&)${SIGV4_PARAM}= }`,
    "    acl aws_query var(txn.aws_query) -m bool",
    `    acl aws_query_many query -m reg -i (^|&)${SIGV4_PARAM}=.*&${SIGV4_PARAM}=`,
    "    # Refused without reading the key: SigV2 in the header or the query,",
    "    # SigV3's header, and any other Authorization. On a host that names a",
    "    # resource, only a scheme starting with AWS is: a Bearer or Basic token",
    "    # there, such as ECR's or CodeArtifact's, is left to the URL rules.",
    "    http-request set-var(txn.aws_unsupported) bool(true) if aws_host !aws_resource_host !aws_sigv4 !aws_git aws_auth",
    "    http-request set-var(txn.aws_unsupported) bool(true) if aws_resource_host !aws_sigv4 { req.fhdr(authorization) -m reg -i ^aws }",
    `    http-request set-var(txn.aws_unsupported) bool(true) if aws_host { req.hdr(x-amzn-authorization) -m found } or aws_host { query -m reg -i (^|&)${SIGV2_PARAM}= }`,
    "    # An S3 POST-policy upload keeps its credential in a multipart body.",
    `    http-request set-var(txn.aws_unsupported) bool(true) if aws_resource_host METH_POST { req.hdr(content-type) -m beg -i multipart/form-data } { var(txn.host) -m reg ${S3_HOST} }`,
    "    # A Query-protocol form body, read only where AWS reads one. Not on a host",
    "    # that names a resource, or CodeCommit, whose Git requests carry their",
    "    # credential in the header.",
    "    http-request set-var(txn.aws_form) bool(true) if aws_host METH_POST !aws_resource_host !aws_git_host { req.hdr(content-type) -m beg -i application/x-www-form-urlencoded }",
    "    acl aws_form var(txn.aws_form) -m bool",
    "    http-request wait-for-body time 30s use-large-buffer if aws_form",
    "    # Matched undecoded, since a value carries & and = encoded, but each",
    "    # letter of the name may be. EC2 splits a body on ; too, which a value",
    "    # encodes as %3B.",
    `    http-request set-var(txn.aws_unsupported) bool(true) if aws_form { req.body -m reg -i (^|[&;])(${SIGV2_PARAM}|${SIGV4_PARAM})= }`,
    "    # A non-form body would carry a SigV2 past the form-body check above, and",
    "    # EC2 takes it over the Authorization header. EC2 has no JSON API, so a",
    "    # non-form POST is never legitimate.",
    `    http-request set-var(txn.aws_unsupported) bool(true) if aws_host METH_POST { var(txn.host) -m reg ${EC2_HOST} } !{ req.hdr(content-type) -m beg -i application/x-www-form-urlencoded }`,
    "    # A query credential spelled other than the one name the key is read from.",
    "    http-request set-var(txn.aws_unsupported) bool(true) if aws_query !{ url_param(X-Amz-Credential) -m found }",
    "    acl aws_unsupported var(txn.aws_unsupported) -m bool",
  ];
}

/** The key ID a SigV4 header, a query credential or a CodeCommit login names. */
function keyExtraction(keyMapFile: string, refSecret: string): string[] {
  return [
    `    http-request set-var(txn.aws_key) 'req.fhdr(authorization),regsub("^AWS4-[A-Z0-9-]+\\s+Credential=([A-Za-z0-9]+)/.*$","\\1")' if aws_sigv4`,
    `    http-request set-var(txn.aws_key) 'url_param(X-Amz-Credential),url_dec,regsub("^([A-Za-z0-9]+)/.*$","\\1")' if aws_query !aws_sigv4`,
    `    http-request set-var(txn.aws_git_user) 'req.fhdr(authorization),regsub("^basic\\s+","",i),b64dec,regsub(":.*$","")' if aws_git`,
    '    http-request set-var(txn.aws_key) \'var(txn.aws_git_user),regsub("%.*$","")\' if aws_git',
    "    # A static Git credential's user name is no key ID.",
    `    http-request set-var(txn.aws_log_key_ref) ${keyRef("txn.aws_key", refSecret)} if { var(txn.aws_key) -m reg ^[A-Za-z0-9]+$ }`,
    "    # Looked up once: only the response rules add to the map, and no rule",
    "    # from here to the traffic record waits.",
    `    http-request set-var(txn.aws_key_entry) var(txn.aws_key),map(${keyMapFile})`,
    "    acl aws_key_known var(txn.aws_key_entry) -m found",
  ];
}

/** Whether a request may go unsigned, and whether it is to STS. */
function unsignedAndSts(): string[] {
  return [
    "    # Unsigned, whatever the method, only where the host names a resource:",
    "    # elsewhere the account a request reaches is in the parameters or the",
    "    # body, out of sight. Git asks CodeCommit with no credential first, and",
    "    # logs in on its 401.",
    "    http-request set-var(txn.aws_unsigned_ok) bool(true) if aws_resource_host or aws_git_host !aws_auth",
    "    # And on a public host, which reaches no account.",
    `    http-request set-var(txn.aws_unsigned_ok) bool(true) if aws_host !aws_auth { var(txn.host) -m reg ${AWS_PUBLIC_HOST} }`,
    "    acl aws_unsigned_ok var(txn.aws_unsigned_ok) -m bool",
    "    # A host that names a resource is never STS, whatever its name: S3",
    "    # takes a bucket named sts.",
    `    http-request set-var(txn.aws_sts_host) bool(true) if aws_host !aws_resource_host { var(txn.host) -m reg ${STS_HOST} }`,
    "    acl aws_sts_host var(txn.aws_sts_host) -m bool",
  ];
}

/** The verdict, and in restrict the refusal. */
function verdicts(mode: "restrict" | "audit", roles?: RoleRules): string[] {
  return [
    "    # Where a credential could be out of sight: a form body that is",
    "    # compressed, has no Content-Length (which HAProxy drops from a chunked",
    "    # one), is larger than the buffer, or holds a NUL, where matching stops.",
    "    http-request set-var(txn.aws_body_size) req.body_size if aws_form",
    "    http-request set-var(txn.aws_body_len) req.body_len if aws_form",
    "    # The verdict: each line overrides the ones above it, so they run from",
    "    # the least decisive to the most.",
    "    http-request set-var(txn.aws) str(allowed) if aws_host",
    ...(roles?.verdict ?? []),
    `    http-request set-var(txn.aws) str(key-not-allowed) if aws_sigv4 !aws_key_known or aws_git !aws_key_known${roles?.gitAccountExempt ?? ""} or aws_query !aws_key_known`,
    "    # A key ECR issued passes only as a presigned URL's credential to S3.",
    "    acl aws_issued var(txn.aws_key_entry) -m str issued",
    `    http-request set-var(txn.aws) str(key-not-allowed) if aws_issued !aws_query or aws_issued !{ var(txn.host) -m reg ${S3_HOST} }`,
    `    http-request set-var(txn.aws) str(no-credential) if aws_host !aws_sigv4 !aws_git !aws_query !aws_unsupported !aws_unsigned_ok${roles?.roleAccountExempt ?? ""}`,
    `    http-request set-var(txn.aws) str(ambiguous-credential) if aws_host { req.fhdr_cnt(authorization) gt 1 } or aws_sigv4 aws_query or aws_git aws_query or aws_query aws_query_many or aws_sigv4 { req.fhdr(authorization) -m reg -i credential=.*credential= }${roles?.ambiguous ?? ""}`,
    "    http-request set-var(txn.aws) str(unsupported-credential) if aws_unsupported",
    "    http-request set-var(txn.aws) str(unreadable) if aws_form { req.hdr(content-encoding) -m reg -i ^(?!identity$) } or aws_form !{ req.hdr(content-length) -m found }",
    "    http-request set-var(txn.aws) str(unreadable) if aws_form { req.body_len,sub(txn.aws_body_size) lt 0 } or aws_form { req.body,length,sub(txn.aws_body_len) lt 0 }",
    `    acl aws_refused var(txn.aws) -m str ${AWS_REFUSED_VERDICTS.join(" ")}`,
    ...(mode === "restrict"
      ? [
          `    http-request set-var-fmt(txn.reason) ${AWS_REASON_PREFIX}%[var(txn.aws)] if aws_refused`,
          "    http-request deny deny_status 403 if aws_refused",
        ]
      : [
          `    http-request set-var-fmt(txn.would_refuse) ${AWS_REASON_PREFIX}%[var(txn.aws)] if aws_refused`,
        ]),
  ];
}

/** What the traffic record says of a request the check let through. */
function trafficRecord(roles?: RoleRules): string[] {
  return [
    "    # For the traffic record: what a request the check let through was",
    "    # signed with. The map holds env for the starting key, the account for",
    "    # one STS issued, and issued for one ECR did.",
    "    acl aws_allowed var(txn.aws) -m str allowed",
    "    http-request set-var(txn.aws_log_key) str(none) if aws_allowed",
    "    http-request set-var(txn.aws_key_owner) var(txn.aws_key_entry) if aws_allowed",
    "    http-request set-var(txn.aws_log_key) str(env) if { var(txn.aws_key_owner) -m str env }",
    "    http-request set-var(txn.aws_log_key) str(assumed) if { var(txn.aws_key_owner) -m reg ^[0-9]{12}$ }",
    "    http-request set-var(txn.aws_log_key) str(issued) if { var(txn.aws_key_owner) -m str issued }",
    "    http-request set-var(txn.aws_log_account) var(txn.aws_key_owner) if { var(txn.aws_key_owner) -m reg ^[0-9]{12}$ }",
    ...(roles?.logAccount ?? []),
  ];
}

/** Which answers the response rules read, and which of them may teach a key. */
function learnFlags(): string[] {
  return [
    "    # Only a redirect answering a registry request the check did not refuse",
    "    # can teach a key, and only over TLS, where the registry's certificate",
    "    # was verified. Each regex runs only on a host it could match.",
    `    http-request set-var(txn.aws_ecr_learn) bool(true) if { ssl_fc } !aws_refused aws_resource_host { var(txn.host) -m reg ${ECR_REGISTRY_HOST} }`,
    `    http-request set-var(txn.aws_ecr_learn) bool(true) if { ssl_fc } !aws_refused { var(txn.host) -m end .on.aws } { var(txn.host) -m reg ${ECR_DUALSTACK_REGISTRY_HOST} }`,
    "    # Any answer over TLS names the account of its role, but only one to a",
    "    # request the check let through can teach a key. A plaintext answer",
    "    # could have been rewritten on the way.",
    "    http-request set-var(txn.aws_sts_read) bool(true) if { ssl_fc } aws_sts_host",
    "    http-request set-var(txn.aws_learn) bool(true) if { ssl_fc } aws_sts_host { var(txn.aws) -m str allowed }",
    "",
  ];
}

/**
 * What is judged by a role account: AssumeRoleWithWebIdentity, which takes no
 * signature, by the account of the role in RoleArn, and a static CodeCommit
 * Git credential by the account it names. Only a form body naming Action and
 * RoleArn once each, with neither in the query, is judged. Names are counted
 * in any spelling: STS decodes a name, and takes the query's value over the
 * body's even for a POST.
 */
function roleRules(accountFile: string) {
  return {
    facts: [
      `    acl aws_fed_action req.body -m reg -i (^|&)${FORM_ACTION}=AssumeRoleWithWebIdentity(&|$)`,
      `    acl aws_fed_action_many req.body -m reg -i (?s)(^|&)${FORM_ACTION}=.*&${FORM_ACTION}=`,
      `    acl aws_role_body_many req.body -m reg -i (?s)(^|&)${FORM_ROLE_ARN}=.*&${FORM_ROLE_ARN}=`,
      `    acl aws_fed_in_query query -m reg -i (^|&)(${FORM_ACTION}|${FORM_ROLE_ARN})=`,
      "    http-request set-var(txn.aws_fed) bool(true) if aws_sts_host aws_form !aws_sigv4 !aws_query !aws_unsupported aws_fed_action !aws_fed_action_many",
      "    acl aws_fed var(txn.aws_fed) -m bool",
      `    http-request set-var(txn.aws_role_account) 'req.body_param(RoleArn),url_dec,regsub("${ROLE_ARN}","\\1")' if aws_fed`,
      "    acl aws_role_account var(txn.aws_role_account) -m reg ^[0-9]{12}$",
      `    http-request set-var(txn.aws_git_account_id) 'var(txn.aws_git_user),regsub("^.*-at-([0-9]{12})$","\\1")' if aws_git { var(txn.aws_git_user) -m reg ^((?!-at-).)+-at-[0-9]{12}\\z }`,
      `    http-request set-var(txn.aws_git_account) bool(true) if { var(txn.aws_git_account_id) -m str -f ${accountFile} }`,
      "    acl aws_git_account var(txn.aws_git_account) -m bool",
    ],
    verdict: [
      `    http-request set-var(txn.aws) str(role-not-allowed) if aws_role_account !{ var(txn.aws_role_account) -m str -f ${accountFile} }`,
    ],
    gitAccountExempt: " !aws_git_account",
    roleAccountExempt: " !aws_role_account",
    ambiguous: " or aws_fed aws_role_body_many or aws_fed aws_fed_in_query",
    logAccount: [
      "    http-request set-var(txn.aws_log_account) var(txn.aws_git_account_id) if aws_allowed aws_git_account",
      "    http-request set-var(txn.aws_log_account) var(txn.aws_role_account) if aws_allowed aws_role_account",
    ],
  };
}

type RoleRules = ReturnType<typeof roleRules>;

/**
 * Response rules: learn the key in the presigned URL an ECR registry
 * redirects a layer download to, and, when role accounts are named, the key
 * an AssumeRole or AssumeRoleWithWebIdentity answer issues for a role in one
 * of them. Only an answer over TLS to a request the check did not refuse
 * teaches one. The account of the role, and a reference to the key, are
 * recorded from any answer over TLS, named or not and allowed or not, so one
 * run shows every account to name, a chain of roles included.
 *
 * Only ECR writes that Location, over a connection whose certificate the
 * proxy verified, so a build cannot put its own key there. The role ARN is
 * AWS's own, not the caller's. A body larger than the buffer is read only in
 * part, so a key past it is not learned and its requests are refused.
 */
export function awsKeyResponseRules(check: AwsKeyCheck): string[] {
  return [
    "    acl aws_ecr_learn var(txn.aws_ecr_learn) -m bool",
    "    acl aws_location_many res.fhdr(location) -m reg -i x-amz-credential=.*x-amz-credential=",
    `    http-response set-var(txn.aws_issued_key) 'res.fhdr(location),regsub("${LOCATION_CREDENTIAL}","\\2",i)' if aws_ecr_learn { status 300:399 } { res.fhdr_cnt(location) eq 1 } !aws_location_many`,
    "    acl aws_issued_key var(txn.aws_issued_key) -m reg ^ASIA[A-Z0-9]+$",
    "    # A key the proxy already knows keeps what it was learned as.",
    `    http-response set-map(${check.keyMapFile}) %[var(txn.aws_issued_key)] issued if aws_issued_key !{ var(txn.aws_issued_key),map(${check.keyMapFile}) -m found }`,
    `    http-response set-var(txn.aws_log_issued_ref) ${keyRef("txn.aws_issued_key", check.refSecret)} if aws_issued_key`,
    "    acl aws_sts_read var(txn.aws_sts_read) -m bool",
    "    acl aws_learn var(txn.aws_learn) -m bool",
    "    acl aws_assume_role res.body -m reg ^(<\\?xml[^>]*\\?>)?\\s*<AssumeRole(WithWebIdentity)?Response[\\s>]",
    "    acl aws_many_keys res.body -m reg (?s)<AccessKeyId>.*<AccessKeyId>",
    "    acl aws_many_arns res.body -m reg (?s)<Arn>.*<Arn>",
    "    http-response wait-for-body time 10s if aws_sts_read { status 200 }",
    `    http-response set-var(txn.aws_new_account) 'res.body,regsub("(?s)^.*<Arn>arn:aws[a-z-]*:sts::([0-9]{12}):assumed-role/[^<]*</Arn>.*$","\\1")' if aws_sts_read { status 200 } aws_assume_role !aws_many_keys !aws_many_arns`,
    "    acl aws_new_account var(txn.aws_new_account) -m reg ^[0-9]{12}$",
    `    http-response set-var(txn.aws_new_key) 'res.body,regsub("(?s)^.*<AccessKeyId>(ASIA[A-Z0-9]+)</AccessKeyId>.*$","\\1")' if aws_sts_read { status 200 } aws_assume_role !aws_many_keys !aws_many_arns`,
    "    acl aws_new_key var(txn.aws_new_key) -m reg ^ASIA[A-Z0-9]+$",
    `    http-response set-var(txn.aws_log_issued_ref) ${keyRef("txn.aws_new_key", check.refSecret)} if aws_new_key`,
    ...(check.accountFile
      ? [
          `    acl aws_new_account_allowed var(txn.aws_new_account) -m str -f ${check.accountFile}`,
          `    http-response set-map(${check.keyMapFile}) %[var(txn.aws_new_key)] %[var(txn.aws_new_account)] if aws_learn aws_new_key aws_new_account aws_new_account_allowed`,
        ]
      : []),
    "    http-response set-var(txn.aws_log_assumed) var(txn.aws_new_account) if aws_new_account",
    "",
  ];
}
