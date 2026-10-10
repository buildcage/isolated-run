import { describe, it, expect, reportResults } from "#core/lib/test/test-shim.ts";

import {
  AWS_API_HOST,
  AWS_PUBLIC_HOST,
  AWS_RESOURCE_HOST,
  CODECOMMIT_HOST,
  ECR_REGISTRY_HOST,
  LOCATION_CREDENTIAL,
  SIGV2_PARAM,
  SIGV4_PARAM,
  awsKeyRequestRules,
  awsKeyResponseRules,
  awsKeyExtension,
  S3_HOST,
  SIGV4_HEADER,
  STS_HOST,
} from "./haproxy-aws-keys.ts";

const REF_SECRET = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
const CHECK = {
  accountFile: "/rules/accounts.lst",
  keyMapFile: "/rules/keys.map",
  refSecret: REF_SECRET,
};

// What the config writes is also what reaches the regex engine: HAProxy's
// word parser leaves `\.` alone. See escapeForHaproxy.
const apiHost = new RegExp(AWS_API_HOST);
const stsHost = new RegExp(STS_HOST);
const resourceHost = new RegExp(AWS_RESOURCE_HOST);
const publicHost = new RegExp(AWS_PUBLIC_HOST);

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

  it("covers a name whose labels hold a character AWS's own names do not", () => {
    for (const host of [
      "my_bucket.s3.amazonaws.com",
      "a_b.ddb.us-east-1.amazonaws.com",
      "_x.sqs.us-east-1.amazonaws.com",
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
      "checkip.amazonaws.com",
    ]) {
      expect(resourceHost.test(host)).toBe(false);
    }
  });
});

describe("public hosts", () => {
  it("covers the hosts AWS serves unsigned that reach no account", () => {
    for (const host of [
      "awscli.amazonaws.com",
      "checkip.amazonaws.com",
      "ip-ranges.amazonaws.com",
      "pricing.us-east-1.amazonaws.com",
      "pricing.cn-northwest-1.amazonaws.com.cn",
    ]) {
      expect(publicHost.test(host)).toBe(true);
    }
  });

  it("leaves out the signed Price List API and other names", () => {
    for (const host of [
      "api.pricing.us-east-1.amazonaws.com",
      "pricing.eu-central-1.amazonaws.com",
      "checkip.amazonaws.com.cn",
      "x.checkip.amazonaws.com",
    ]) {
      expect(publicHost.test(host)).toBe(false);
    }
  });
});

describe("the SigV2 credential in a form body", () => {
  const credential = new RegExp(`(^|&)${SIGV2_PARAM}=`, "i");

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

describe("SigV4's credential in a form body", () => {
  const credential = new RegExp(`(^|&)${SIGV4_PARAM}=`, "i");

  it("counts the name in any case and with any character percent-encoded", () => {
    for (const body of [
      "X-Amz-Credential=K",
      "Action=X&x-amz-credential=K",
      "Action=X&X%2DAmz-Cr%65dential=K",
    ]) {
      expect(credential.test(body)).toBe(true);
    }
    expect(credential.test("Action=X&Message=a%26X-Amz-Credential%3DK")).toBe(false);
  });
});

describe("AssumeRoleWithWebIdentity", () => {
  const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");

  it("matches Action undecoded, so a name hidden in another value does not count", () => {
    const action = /\(\^\|&\)(.*)=AssumeRoleWithWebIdentity\(&\|\$\)/.exec(rules)![1];
    const named = new RegExp(`(^|&)${action}=AssumeRoleWithWebIdentity(&|$)`, "i");
    expect(named.test("Action=AssumeRoleWithWebIdentity&RoleArn=x")).toBe(true);
    expect(named.test("Action=GetFederationToken&Name=%26Action%3DAssumeRoleWithWebIdentity")).toBe(
      false,
    );
  });
});

describe("the check with no role account", () => {
  const KEY_ONLY = { keyMapFile: "/rules/keys.map", refSecret: REF_SECRET };
  const rules = awsKeyRequestRules(KEY_ONLY, "restrict").join("\n");

  it("learns no STS key, but still records the account an STS answer names", () => {
    const response = awsKeyResponseRules(KEY_ONLY);
    expect(response.some((l) => l.includes("set-map") && l.includes("aws_new_key"))).toBe(false);
    expect(
      response.includes(
        "    http-response set-var(txn.aws_log_assumed) var(txn.aws_new_account) if aws_new_account",
      ),
    ).toBe(true);
    expect(
      rules.includes("http-request set-header Accept-Encoding identity if { ssl_fc } aws_sts_host"),
    ).toBe(true);
    expect(rules.includes("aws_fed")).toBe(false);
    expect(rules.includes("aws_role_account")).toBe(false);
  });

  it("lets no static CodeCommit credential through on its account", () => {
    expect(rules.includes("aws_git_account")).toBe(false);
    expect(rules.includes("-m str -f")).toBe(false);
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
  it("refuses in restrict, and only names what restrict would refuse in audit", () => {
    const restrict = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(restrict.includes("http-request deny deny_status 403 if aws_refused")).toBe(true);
    const audit = awsKeyRequestRules(CHECK, "audit").join("\n");
    expect(audit.includes("txn.would_refuse")).toBe(true);
    expect(audit.includes("deny")).toBe(false);
  });

  it("orders the verdicts from the least decisive to the most, each one overriding those above", () => {
    const verdicts = awsKeyRequestRules(CHECK, "restrict")
      .map((l) => /set-var\(txn\.aws\) str\(([a-z-]+)\)/.exec(l)?.[1])
      .filter((v) => v !== undefined);
    expect([...new Set(verdicts)]).toStrictEqual([
      "allowed",
      "role-not-allowed",
      "key-not-allowed",
      "no-credential",
      "ambiguous-credential",
      "unsupported-credential",
      "unreadable",
    ]);
  });

  it("matches each host pattern once", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    for (const pattern of [
      AWS_API_HOST,
      AWS_RESOURCE_HOST,
      AWS_PUBLIC_HOST,
      CODECOMMIT_HOST,
      STS_HOST,
    ]) {
      expect(rules.split(`-m reg ${pattern} }`).length).toBe(2);
    }
  });

  it("matches SigV4's and SigV4a's header as SDKs spell it, and no other scheme", () => {
    const sigv4 = new RegExp(SIGV4_HEADER);
    for (const header of [
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261008/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=a",
      "AWS4-ECDSA-P256-SHA256 Credential=AKIDEXAMPLE/20261008/sts/aws4_request, SignedHeaders=host, Signature=a",
    ]) {
      expect(sigv4.test(header)).toBe(true);
    }
    for (const header of [
      "aws4-hmac-sha256 Credential=AKIDEXAMPLE/20261008/us-east-1/sts/aws4_request",
      "AWS4-HMAC-SHA256 SignedHeaders=host, Credential=AKIDEXAMPLE/20261008/us-east-1/sts/aws4_request",
      "AWS4-HMAC-SHA512 Credential=AKIDEXAMPLE/20261008/us-east-1/sts/aws4_request",
      "AWS AKIDEXAMPLE:c2lnbmF0dXJl",
      "Bearer token",
    ]) {
      expect(sigv4.test(header)).toBe(false);
    }
  });

  it("reads CodeCommit's static Git user name as <user>-at-<account>, and nothing more", () => {
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

  it("asks STS for a body it can read, unless the client signed Accept-Encoding", () => {
    // The pattern the signed-header test reads, against real SignedHeaders lists.
    const signed = new RegExp("signedheaders=[^,]*accept-encoding", "i");
    expect(
      signed.test("Credential=K/x, SignedHeaders=accept-encoding;host;x-amz-date, Signature=a"),
    ).toBe(true);
    expect(signed.test("Credential=K/x, SignedHeaders=host;x-amz-date, Signature=a")).toBe(false);
  });
});

describe("the traffic record", () => {
  it("names a field for each value the record's aws object holds", () => {
    expect(awsKeyExtension(CHECK).logFields).toStrictEqual({
      name: "aws",
      fields: {
        key: "txn.aws_log_key",
        accountId: "txn.aws_log_account",
        assumedAccount: "txn.aws_log_assumed",
        keyRef: "txn.aws_log_key_ref",
        issuedKeyRef: "txn.aws_log_issued_ref",
      },
    });
  });

  it("says which kind of known key signed a request", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict");
    for (const kind of ["env", "assumed", "issued"]) {
      expect(rules.some((l) => l.includes(`set-var(txn.aws_log_key) str(${kind}) if`))).toBe(true);
    }
  });

  it("is filled in only for a request the check let through", () => {
    for (const rules of [
      awsKeyRequestRules(CHECK, "audit"),
      awsKeyRequestRules({ keyMapFile: "/rules/keys.map", refSecret: REF_SECRET }, "restrict"),
    ]) {
      const filled = rules.filter(
        (l) => l.includes("set-var(txn.aws_log_") && !l.includes("txn.aws_log_key_ref"),
      );
      for (const line of filled) {
        expect(/ if aws_allowed( |$)/.test(line) || line.includes("{ var(txn.aws_key_owner)")).toBe(
          true,
        );
      }
      expect(
        rules
          .filter((l) => l.includes("set-var(txn.aws_key_owner)"))
          .every((l) => / if aws_allowed( |$)/.test(l)),
      ).toBe(true);
    }
  });

  it("references the key of every request signed with one, whatever the verdict", () => {
    const ref = `'var(txn.aws_key),hmac(sha256,${REF_SECRET}),bytes(0,8),hex,lower'`;
    for (const mode of ["restrict", "audit"] as const) {
      expect(
        awsKeyRequestRules(CHECK, mode).includes(
          `    http-request set-var(txn.aws_log_key_ref) ${ref} if { var(txn.aws_key) -m reg ^[A-Za-z0-9]+$ }`,
        ),
      ).toBe(true);
    }
  });

  it("references the key an STS answer or an ECR redirect issues, allowed or not", () => {
    const response = awsKeyResponseRules({ keyMapFile: "/rules/keys.map", refSecret: REF_SECRET });
    for (const [variable, acl] of [
      ["txn.aws_new_key", "aws_new_key"],
      ["txn.aws_issued_key", "aws_issued_key"],
    ]) {
      expect(
        response.includes(
          `    http-response set-var(txn.aws_log_issued_ref) 'var(${variable}),hmac(sha256,${REF_SECRET}),bytes(0,8),hex,lower' if ${acl}`,
        ),
      ).toBe(true);
    }
  });

  it("takes only a secret HAProxy reads as one base64 argument", () => {
    for (const refSecret of ["", `${REF_SECRET}=`, `${REF_SECRET.slice(1)},`]) {
      expect(() => awsKeyRequestRules({ ...CHECK, refSecret }, "restrict")).toThrow(
        "invalid AWS key reference secret",
      );
    }
  });

  it("names the account of the role an STS answer hands a key for, allowed or not", () => {
    expect(
      awsKeyResponseRules(CHECK).includes(
        "    http-response set-var(txn.aws_log_assumed) var(txn.aws_new_account) if aws_new_account",
      ),
    ).toBe(true);
  });
});

describe("learning a key", () => {
  it("learns only over TLS from an STS host that names no resource, after a request it let through, but reads the account and the key from any answer over TLS", () => {
    const rules = awsKeyRequestRules(CHECK, "audit").join("\n");
    expect(
      rules.includes("set-var(txn.aws_sts_host) bool(true) if aws_host !aws_resource_host"),
    ).toBe(true);
    expect(
      rules.includes(
        "set-var(txn.aws_learn) bool(true) if { ssl_fc } aws_sts_host { var(txn.aws) -m str allowed }",
      ),
    ).toBe(true);
    // S3 takes a bucket named sts, whose host STS_HOST alone would match.
    expect(stsHost.test("sts.s3.amazonaws.com")).toBe(true);
    expect(resourceHost.test("sts.s3.amazonaws.com")).toBe(true);
    expect(
      rules.includes("set-var(txn.aws_sts_read) bool(true) if { ssl_fc } aws_sts_host\n"),
    ).toBe(true);
    const response = awsKeyResponseRules(CHECK);
    const line = (variable: string) => response.find((l) => l.includes(variable))!;
    expect(line("set-var(txn.aws_new_key)").includes(" if aws_sts_read ")).toBe(true);
    expect(line("%[var(txn.aws_new_key)]").includes(" if aws_learn ")).toBe(true);
    expect(line("set-var(txn.aws_new_account)").includes(" if aws_sts_read ")).toBe(true);
  });

  it("adds a key only for a role in an allowed account, from an answer naming one key and role", () => {
    expect(
      awsKeyResponseRules(CHECK).includes(
        "    http-response set-map(/rules/keys.map) %[var(txn.aws_new_key)] %[var(txn.aws_new_account)] if aws_learn aws_new_key aws_new_account aws_new_account_allowed",
      ),
    ).toBe(true);
    expect(
      awsKeyResponseRules(CHECK).filter((l) =>
        l.includes("aws_assume_role !aws_many_keys !aws_many_arns"),
      ).length,
    ).toBe(2);
  });
});

describe("a key ECR issues", () => {
  const request = awsKeyRequestRules(CHECK, "restrict");
  const response = awsKeyResponseRules(CHECK);

  it("is learned only from a registry the check let a request through to", () => {
    const registry = new RegExp(ECR_REGISTRY_HOST);
    for (const host of [
      "111111111111.dkr.ecr.us-east-1.amazonaws.com",
      "111111111111.dkr.ecr-fips.us-east-1.amazonaws.com",
      "111111111111.dkr.ecr.cn-north-1.amazonaws.com.cn",
      "111111111111.dkr-ecr.us-east-1.on.aws",
    ]) {
      expect(registry.test(host)).toBe(true);
    }
    for (const host of [
      "api.ecr.us-east-1.amazonaws.com",
      "bucket.s3.us-east-1.amazonaws.com",
      "b123abcde4.execute-api.us-east-1.amazonaws.com",
      "abcdefghij.lambda-url.us-east-1.on.aws",
    ]) {
      expect(registry.test(host)).toBe(false);
    }
    expect(
      request.includes(
        `    http-request set-var(txn.aws_ecr_learn) bool(true) if { ssl_fc } !aws_refused { var(txn.host) -m reg ${ECR_REGISTRY_HOST} }`,
      ),
    ).toBe(true);
    const learning = response.filter((l) => l.includes("set-var(txn.aws_issued_key)"));
    expect(learning.length).toBe(1);
    for (const line of learning) {
      expect(
        line.includes(
          " if aws_ecr_learn { status 300:399 } { res.fhdr_cnt(location) eq 1 } !aws_location_many",
        ),
      ).toBe(true);
    }
  });

  it("reads the key ID from a Location's query credential", () => {
    const credential = new RegExp(LOCATION_CREDENTIAL, "i");
    const key = (location: string) => location.replace(credential, "$2");
    const AS = "AS";
    const issued = `${AS}IATESTISSUEDKEY01`;
    expect(
      key(
        `https://prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com/a/b?X-Amz-Security-Token=T&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${issued}%2F20261010%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=ab`,
      ),
    ).toBe(issued);
    expect(
      key(
        `https://b.s3.amazonaws.com/x?X-Amz-Credential=${issued}/20261010/us-east-1/s3/aws4_request`,
      ),
    ).toBe(issued);
    expect(key(`https://b.s3.amazonaws.com/x?x-amz-credential=${issued}%2F20261010`)).toBe(issued);
    // Not a parameter of its own: left whole, which no key ID matches.
    const hidden = `https://b.s3.amazonaws.com/x?a=1%26X-Amz-Credential=${issued}%2F`;
    expect(key(hidden)).toBe(hidden);
    const inPath = `https://b.s3.amazonaws.com/X-Amz-Credential=${issued}/`;
    expect(key(inPath)).toBe(inPath);
  });

  it("never replaces what a known key was learned as", () => {
    expect(
      response.some((l) =>
        l.endsWith(
          "%[var(txn.aws_issued_key)] issued if aws_issued_key !{ var(txn.aws_issued_key),map(/rules/keys.map) -m found }",
        ),
      ),
    ).toBe(true);
  });

  it("signs only a presigned URL to S3", () => {
    expect(
      request.includes(
        `    http-request set-var(txn.aws) str(key-not-allowed) if aws_issued !aws_query or aws_issued !{ var(txn.host) -m reg ${S3_HOST} }`,
      ),
    ).toBe(true);
  });
});

reportResults();
