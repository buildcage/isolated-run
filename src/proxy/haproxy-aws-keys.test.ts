import { describe, it, expect, reportResults } from "#core/lib/test/test-shim.ts";

import {
  AWS_API_HOST,
  AWS_RESOURCE_HOST,
  CODECOMMIT_HOST,
  FORM_CREDENTIAL,
  awsKeyRequestRules,
  awsKeyResponseRules,
  awsKeyExtension,
  STS_HOST,
} from "./haproxy-aws-keys.ts";

const CHECK = { accountFile: "/rules/accounts.lst", keyMapFile: "/rules/keys.map" };

// What the config writes is also what reaches the regex engine: HAProxy's
// word parser leaves `\.` alone. See escapeForHaproxy.
const apiHost = new RegExp(AWS_API_HOST);
const stsHost = new RegExp(STS_HOST);
const resourceHost = new RegExp(AWS_RESOURCE_HOST);

describe("AWS API hosts", () => {
  it("covers the classic, China and dual-stack domains", () => {
    for (const host of [
      "sts.amazonaws.com",
      "cloudformation.us-east-1.amazonaws.com",
      "my-bucket.s3.us-east-1.amazonaws.com",
      "s3.dualstack.us-east-1.amazonaws.com",
      "sts.cn-north-1.amazonaws.com.cn",
      "iam.global.api.aws",
      "sts.us-east-1.api.aws",
      "sts.cn-north-1.api.amazonwebservices.com.cn",
      "sts.eusc-de-east-1.amazonaws.eu",
      "sts.eusc-de-east-1.api.amazonwebservices.eu",
    ]) {
      expect(apiHost.test(host)).toBe(true);
    }
  });

  it("leaves out AWS names that are no API endpoint, and lookalikes", () => {
    for (const host of [
      "amazonaws.com",
      "public.ecr.aws",
      "abc.lambda-url.us-east-1.on.aws",
      "amazonaws.com.example.com",
      "sts.amazonaws.com.evil",
      "evilamazonaws.com",
    ]) {
      expect(apiHost.test(host)).toBe(false);
    }
  });

  it("names STS by its global, regional, FIPS and dual-stack endpoints", () => {
    for (const host of [
      "sts.amazonaws.com",
      "sts.us-east-1.amazonaws.com",
      "sts-fips.us-east-1.amazonaws.com",
      "sts.us-east-1.api.aws",
      "sts.cn-north-1.amazonaws.com.cn",
      "sts.eusc-de-east-1.amazonaws.eu",
      "vpce-0123456789abcdef0-abcdefgh.sts.us-east-1.vpce.amazonaws.com",
      "us-east-1a.vpce-0123456789abcdef0-abcdefgh.sts.us-east-1.vpce.amazonaws.com",
    ]) {
      expect(stsHost.test(host)).toBe(true);
    }
    expect(stsHost.test("cloudformation.us-east-1.amazonaws.com")).toBe(false);
    expect(stsHost.test("sts.amazonaws.com.evil")).toBe(false);
  });
});

describe("hosts that name the resource", () => {
  it("covers every form AWS documents for them", () => {
    for (const host of [
      // S3: virtual-hosted, legacy, path style, dual-stack, FIPS, access
      // points, control, website, acceleration, China.
      "bucket.s3.us-east-1.amazonaws.com",
      "bucket.s3-us-west-2.amazonaws.com",
      "bucket.s3.amazonaws.com",
      "s3.us-east-1.amazonaws.com",
      "s3.amazonaws.com",
      "s3.dualstack.us-east-1.amazonaws.com",
      "s3-fips.dualstack.us-east-1.amazonaws.com",
      "ap-111111111111.s3-accesspoint.us-east-1.amazonaws.com",
      "ap-111111111111.s3-accesspoint-fips.dualstack.us-east-1.amazonaws.com",
      "111111111111.s3-control.us-east-1.amazonaws.com",
      "bucket.s3-website-us-east-1.amazonaws.com",
      "bucket.s3-website.eu-central-1.amazonaws.com",
      "bucket.s3-accelerate.amazonaws.com",
      "bucket.s3-accelerate.dualstack.amazonaws.com",
      "bucket.s3.cn-north-1.amazonaws.com.cn",
      "bucket.s3.eusc-de-east-1.amazonaws.eu",
      "111111111111.dkr.ecr.us-east-1.amazonaws.com",
      "111111111111.dkr.ecr.cn-north-1.amazonaws.com.cn",
      "111111111111.dkr.ecr-fips.us-east-1.amazonaws.com",
      "my-domain-111111111111.d.codeartifact.us-east-1.amazonaws.com",
      "b123abcde4.execute-api.us-west-2.amazonaws.com",
      "example1234567890000.appsync-api.us-east-1.amazonaws.com",
      "example1234567890000.appsync-realtime-api.us-east-1.amazonaws.com",
      "my-load-balancer-1234567890abcdef.elb.us-east-2.amazonaws.com",
      "my-loadbalancer-1234567890.us-west-2.elb.amazonaws.com",
      "ec2-52-54-55-66.ap-southeast-2.compute.amazonaws.com",
      "ec2-55-41-26-75.compute-1.amazonaws.com",
      "awscli.amazonaws.com",
      "g-abcdef1234.grafana-workspace.us-east-1.amazonaws.com",
      "b-1234a5b6-78cd-901e-2fgh-3i45j6k178l9.mq.us-east-2.amazonaws.com",
      "search-my-domain-abcdefghijklmnop.us-east-1.es.amazonaws.com",
      "vpc-my-domain-abcdefghijklmnop.us-east-1.es.amazonaws.com",
      "oidc.eks.us-east-1.amazonaws.com",
      "oidc-eks.us-east-1.api.aws",
      "oidc-eks.cn-north-1.api.amazonwebservices.com.cn",
      "oidc-eks.eusc-de-east-1.api.amazonwebservices.eu",
      "abcdef0123456789abcdef0123456789.gr7.us-east-1.eks.amazonaws.com",
      "abcdef0123456789abcdef0123456789.yl4.us-east-2.eks.amazonaws.com",
      "abcdef0123456789abcdef0123456789.us-east-1.api.aws",
    ]) {
      expect(resourceHost.test(host)).toBe(true);
    }
  });

  it("leaves out endpoints that name only a service and a region", () => {
    for (const host of [
      "sts.amazonaws.com",
      "sts.us-east-1.amazonaws.com",
      "cloudformation.us-east-1.amazonaws.com",
      "sqs.us-east-1.amazonaws.com",
      "cognito-idp.us-east-1.amazonaws.com",
      "api.ecr.us-east-1.amazonaws.com",
      "codeartifact.us-east-1.amazonaws.com",
      "s3tables.us-east-1.amazonaws.com",
      "ec2.us-east-1.amazonaws.com",
      "elasticloadbalancing.us-east-1.amazonaws.com",
      "sts.us-east-1.api.aws",
      "evil-s3.amazonaws.com",
      "grafana.us-east-1.amazonaws.com",
      "mq.us-east-1.amazonaws.com",
      "es.us-east-1.amazonaws.com",
      "abcdef123456.us-east-1.aoss.amazonaws.com",
      "eks.us-east-1.amazonaws.com",
      "oidc.us-east-1.amazonaws.com",
      "ecr-fips.us-east-1.amazonaws.com",
      "dkr.ecr-fips.us-east-1.amazonaws.com",
      "es-fips.us-east-1.amazonaws.com",
      "grafana-fips.us-east-1.amazonaws.com",
      "x.grafana-workspace.us-east-1.amazonaws.com",
      "x.mq.us-east-1.amazonaws.com",
      "x.us-east-1.es.amazonaws.com",
      "abcdef.us-east-1.eks.amazonaws.com",
      "abcdef0123456789abcdef0123456789.us-east-1.eks.amazonaws.com",
      "eks.us-east-1.api.aws",
      "abcdef0123456789abcdef0123456789.gr7.us-east-1.api.aws",
    ]) {
      expect(resourceHost.test(host)).toBe(false);
    }
  });
});

describe("the SigV2 credential in a form body", () => {
  const credential = new RegExp(`(^|&)${FORM_CREDENTIAL}=`, "i");

  it("counts the name in any case and with any letter percent-encoded", () => {
    for (const body of [
      "AWSAccessKeyId=K&Action=X",
      "Action=X&AWSAccessKeyId=K",
      "Action=X&awsaccesskeyid=K",
      "Action=X&AWSAccessK%65yId=K",
      "Action=X&%41%57%53AccessKeyId=K",
    ]) {
      expect(credential.test(body)).toBe(true);
    }
  });

  it("does not count the name inside a value, whose & and = are encoded", () => {
    for (const body of [
      "Action=Publish&Message=https%3A%2F%2Fb.s3.amazonaws.com%2Fk%3FExpires%3D1%26AWSAccessKeyId%3DK",
      "Action=X&MyAWSAccessKeyId=K",
    ]) {
      expect(credential.test(body)).toBe(false);
    }
  });
});

describe("awsKeyExtension", () => {
  it("hands the stage this check's own rules", () => {
    const extension = awsKeyExtension(CHECK);
    expect(extension.requestRules("audit")).toStrictEqual(awsKeyRequestRules(CHECK, "audit"));
    expect(extension.responseRules()).toStrictEqual(awsKeyResponseRules(CHECK));
    expect(extension.global).toStrictEqual(["    tune.bufsize.large 4194304"]);
  });
});

describe("awsKeyRequestRules", () => {
  it("refuses in restrict, naming the verdict as the reason", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(
      rules.includes(
        "acl aws_refused var(txn.aws) -m str no-credential ambiguous-credential unreadable key-not-allowed",
      ),
    ).toBe(true);
    expect(rules.includes("set-var-fmt(txn.reason) aws-%[var(txn.aws)] if aws_refused")).toBe(true);
    expect(rules.includes("http-request deny deny_status 403 if aws_refused")).toBe(true);
  });

  it("only names what restrict would refuse in audit", () => {
    const rules = awsKeyRequestRules(CHECK, "audit").join("\n");
    expect(rules.includes("set-var(txn.aws) str(key-not-allowed)")).toBe(true);
    expect(rules.includes("set-var-fmt(txn.would_refuse) aws-%[var(txn.aws)] if aws_refused")).toBe(
      true,
    );
    expect(rules.includes("deny")).toBe(false);
  });

  it("matches the host once, and names the result everywhere else", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(rules.split("-m reg ^([a-z0-9-]+\\.)+").length).toBe(2);
    expect(rules.includes("acl aws_host var(txn.aws_host) -m bool")).toBe(true);
  });

  it("looks keys up in the map it is given", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(rules.includes("map(/rules/keys.map) -m found")).toBe(true);
  });

  it("leaves an unsigned request to the URL rules only where the host names a resource", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(
      rules.includes(
        "str(unsigned) if aws_host !aws_auth !aws_query !aws_body aws_resource_host !aws_form or aws_git_bare !aws_query",
      ),
    ).toBe(true);
    expect(
      rules.includes(
        "str(no-credential) if aws_host !aws_auth !aws_query !aws_body !aws_resource_host !aws_git_bare or",
      ),
    ).toBe(true);
  });

  it("refuses an S3 POST-policy upload, whose credential is in a body it does not read", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(rules.includes("{ req.hdr(content-type) -m beg -i multipart/form-data }")).toBe(true);
    expect(rules.includes("or aws_host !aws_auth !aws_query !aws_body aws_form")).toBe(true);
  });

  it("reads a SigV2 key from a form body, and checks it as well as any other", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(rules.includes("wait-for-body time 30s use-large-buffer if aws_form_post")).toBe(true);
    expect(rules.includes(`if aws_form_post { req.body -m reg -i (^|&)${FORM_CREDENTIAL}= }`)).toBe(
      true,
    );
    expect(
      rules.includes(
        "aws_post { req.hdr(content-type) -m beg -i application/x-www-form-urlencoded } or aws_post { req.body -m reg ^&*[A-Za-z0-9._~%*+!(),:/@-]*= }",
      ),
    ).toBe(true);
    expect(
      rules.includes("set-var(txn.aws_key) var(txn.aws_body_key) if aws_body !aws_auth !aws_query"),
    ).toBe(true);
    expect(rules.includes("or aws_body aws_body_many")).toBe(true);
    expect(rules.includes(`(?s)(^|&)${FORM_CREDENTIAL}=.*&${FORM_CREDENTIAL}=`)).toBe(true);
    expect(
      rules.includes(
        "str(key-not-allowed) if aws_body aws_auth !{ var(txn.aws) -m found } !{ var(txn.aws_body_key),map(/rules/keys.map) -m found } or aws_body aws_query",
      ),
    ).toBe(true);
  });

  it("refuses what it cannot read through: an undecodable query, or a form body it has not all of", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(
      rules.includes("str(unreadable) if aws_host { query -m found } !{ query,url_dec -m found }"),
    ).toBe(true);
    expect(
      rules.includes(
        "str(unreadable) if aws_form_post { req.hdr(content-encoding) -m reg -i ^(?!identity$) } or aws_form_post { req.hdr(transfer-encoding) -m found }",
      ),
    ).toBe(true);
    expect(
      rules.includes(
        "str(unreadable) if aws_form_post { req.body_len,sub(txn.aws_body_size) lt 0 } or aws_form_post { req.body,length,sub(txn.aws_body_len) lt 0 }",
      ),
    ).toBe(true);
  });

  it("decodes the query before looking for a credential in it", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(rules.includes("acl aws_query query,url_dec -m reg -i")).toBe(true);
    expect(rules.includes("acl aws_query_many query,url_dec -m reg -i (?s)(^|&)")).toBe(true);
  });

  it("leaves Accept-Encoding alone where the client signed it, in a header or a query", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(
      rules.includes(
        "acl aws_coding_signed query,url_dec -m reg -i (^|&)x-amz-signedheaders=[^&]*accept-encoding",
      ),
    ).toBe(true);
    expect(
      rules.includes("set-header Accept-Encoding identity if aws_sts_host !aws_coding_signed"),
    ).toBe(true);
  });

  it("reads CodeCommit's Basic user name as a key, or as <user>-at-<account>", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(rules.includes("acl aws_auth var(txn.aws_git) -m bool")).toBe(true);
    expect(rules.includes(`'var(txn.aws_git_user),regsub("%.*$","")' if aws_git`)).toBe(true);
    expect(
      rules.includes(
        `str(allowed) if { var(txn.aws_git_user) -m reg ^((?!-at-).)+-at-[0-9]{12}\\z } { 'var(txn.aws_git_user),regsub("^.*-at-([0-9]{12})$","\\1")' -m str -f /rules/accounts.lst }`,
      ),
    ).toBe(true);
    expect(
      rules.includes(
        "set-var(txn.aws_git_bare) bool(true) if aws_git_host !{ req.fhdr(authorization) -m found }",
      ),
    ).toBe(true);
    expect(
      rules.includes(
        "set-var(txn.aws_post) bool(true) if aws_host METH_POST !aws_resource_host !aws_git_host",
      ),
    ).toBe(true);
    const staticUser = /^((?!-at-).)+-at-[0-9]{12}(?![\s\S])/;
    expect(staticUser.test("deploy-at-111111111111")).toBe(true);
    expect(staticUser.test("x-at-222222222222-at-111111111111")).toBe(false);
    expect(staticUser.test("111111111111")).toBe(false);
    expect(staticUser.test("deploy-at-111111111111\n")).toBe(false);
    const codecommit = new RegExp(CODECOMMIT_HOST);
    expect(codecommit.test("git-codecommit.us-east-1.amazonaws.com")).toBe(true);
    expect(codecommit.test("git-codecommit-fips.us-east-1.amazonaws.com")).toBe(true);
    expect(
      codecommit.test(
        "vpce-0123456789abcdef0-abcdefgh.git-codecommit.us-east-1.vpce.amazonaws.com",
      ),
    ).toBe(true);
    expect(codecommit.test("codecommit.us-east-1.amazonaws.com")).toBe(false);
  });

  it("counts AWS's own schemes and a CodeCommit login as a credential, and no other token", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict");
    expect(rules.filter((l) => l.startsWith("    acl aws_auth "))).toStrictEqual([
      "    acl aws_auth req.fhdr(authorization) -m reg -i ^aws",
      "    acl aws_auth var(txn.aws_git) -m bool",
    ]);
  });

  it("asks STS for a body it can read", () => {
    const rules = awsKeyRequestRules(CHECK, "audit").join("\n");
    expect(rules.includes("set-header Accept-Encoding identity if aws_sts_host")).toBe(true);
    // The pattern the signed-header test reads, against real SignedHeaders lists.
    const signed = new RegExp("signedheaders=[^,]*accept-encoding", "i");
    expect(
      signed.test("Credential=K/x, SignedHeaders=accept-encoding;host;x-amz-date, Signature=a"),
    ).toBe(true);
    expect(signed.test("Credential=K/x, SignedHeaders=host;x-amz-date, Signature=a")).toBe(false);
  });
});

describe("awsKeyResponseRules", () => {
  it("adds a key only for a role in an allowed account", () => {
    const rules = awsKeyResponseRules(CHECK).join("\n");
    expect(rules.includes("var(txn.aws_new_account) -m str -f /rules/accounts.lst")).toBe(true);
    expect(
      rules.includes(
        "set-map(/rules/keys.map) %[var(txn.aws_new_key)] 1 if aws_new_key aws_new_account aws_new_account_allowed",
      ),
    ).toBe(true);
  });

  it("learns nothing from an answer that names more than one key or role", () => {
    const rules = awsKeyResponseRules(CHECK).join("\n");
    expect(rules.includes("aws_assume_role !aws_many_keys !aws_many_arns")).toBe(true);
  });
});

reportResults();
