import { describe, it, expect, reportResults } from "#core/lib/test/test-shim.ts";

import {
  AWS_API_HOST,
  AWS_RESOURCE_HOST,
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
      "111111111111.dkr.ecr.us-east-1.amazonaws.com",
      "111111111111.dkr.ecr.cn-north-1.amazonaws.com.cn",
      "my-domain-111111111111.d.codeartifact.us-east-1.amazonaws.com",
      "b123abcde4.execute-api.us-west-2.amazonaws.com",
      "example1234567890000.appsync-api.us-east-1.amazonaws.com",
      "example1234567890000.appsync-realtime-api.us-east-1.amazonaws.com",
      "my-load-balancer-1234567890abcdef.elb.us-east-2.amazonaws.com",
      "my-loadbalancer-1234567890.us-west-2.elb.amazonaws.com",
      "ec2-52-54-55-66.ap-southeast-2.compute.amazonaws.com",
      "ec2-55-41-26-75.compute-1.amazonaws.com",
      "awscli.amazonaws.com",
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
    ]) {
      expect(resourceHost.test(host)).toBe(false);
    }
  });
});

describe("awsKeyExtension", () => {
  it("hands the stage this check's own rules", () => {
    const extension = awsKeyExtension(CHECK);
    expect(extension.requestRules("audit")).toStrictEqual(awsKeyRequestRules(CHECK, "audit"));
    expect(extension.responseRules()).toStrictEqual(awsKeyResponseRules(CHECK));
  });
});

describe("awsKeyRequestRules", () => {
  it("refuses in restrict, naming the verdict as the reason", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(
      rules.includes(
        "acl aws_refused var(txn.aws) -m str no-credential ambiguous-credential key-not-allowed",
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

  it("looks keys up in the map it is given", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(rules.includes("map(/rules/keys.map) -m found")).toBe(true);
  });

  it("leaves an unsigned request to the URL rules only where the host names a resource", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(rules.includes("str(unsigned) if aws_host !aws_auth !aws_query aws_resource_host")).toBe(
      true,
    );
    expect(
      rules.includes("str(no-credential) if aws_host !aws_auth !aws_query !aws_resource_host"),
    ).toBe(true);
  });

  it("decodes the query before looking for a credential in it", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(rules.includes("acl aws_query query,url_dec -m reg -i")).toBe(true);
    expect(rules.includes("acl aws_query_many query,url_dec -m reg -i")).toBe(true);
  });

  it("leaves Accept-Encoding alone where the client signed it", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(
      rules.includes("set-header Accept-Encoding identity if aws_sts_host !aws_coding_signed"),
    ).toBe(true);
  });

  it("counts only AWS's own schemes as a credential", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(rules.includes("acl aws_auth req.fhdr(authorization) -m reg -i ^aws")).toBe(true);
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
