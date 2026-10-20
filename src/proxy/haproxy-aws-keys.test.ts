import { describe, it, expect, reportResults } from "#core/lib/test/test-shim.ts";

import {
  AWS_API_SUFFIXES,
  AWS_PUBLIC_HOST,
  AWS_RESOURCE_HOST,
  CODECOMMIT_HOST,
  EC2_HOST,
  ECR_DUALSTACK_REGISTRY_HOST,
  ECR_REGISTRY_HOST,
  S3_HOST,
  STS_HOST,
} from "./aws-hosts.ts";
import {
  LOCATION_CREDENTIAL,
  SIGV4_HEADER,
  awsKeyRequestRules,
  awsKeyResponseRules,
  awsKeyExtension,
} from "./haproxy-aws-keys.ts";

const REF_SECRET = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
const CHECK = {
  accountFile: "/rules/accounts.lst",
  keyMapFile: "/rules/keys.map",
  refSecret: REF_SECRET,
};

describe("EC2's API host", () => {
  it("blocks a non-form Content-Type POST to EC2", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
    const rule =
      rules
        .split("\n")
        .find((l) => l.includes(EC2_HOST) && l.includes("set-var(txn.aws_unsupported)")) ?? "";
    expect(rule.includes("METH_POST")).toBe(true);
    expect(
      rule.includes("!{ req.hdr(content-type) -m beg -i application/x-www-form-urlencoded }"),
    ).toBe(true);
  });
});

describe("AssumeRoleWithWebIdentity", () => {
  const rules = awsKeyRequestRules(CHECK, "restrict").join("\n");
  const acl = (name: string) => {
    const line = rules.split("\n").find((l) => l.startsWith(`    acl ${name} `))!;
    const source = line.replace(/^.* -m reg -i /, "");
    return new RegExp(source.replace("(?s)", ""), source.startsWith("(?s)") ? "is" : "i");
  };

  it("matches Action undecoded, so a name hidden in another value does not count", () => {
    const named = acl("aws_fed_action");
    expect(named.test("Action=AssumeRoleWithWebIdentity&RoleArn=x")).toBe(true);
    expect(named.test("Action=GetFederationToken&Name=%26Action%3DAssumeRoleWithWebIdentity")).toBe(
      false,
    );
  });

  // STS decodes a parameter's name, so R%6FleArn is RoleArn to it.
  it("counts Action and RoleArn under a percent-encoded name", () => {
    expect(acl("aws_fed_action").test("%41ction=AssumeRoleWithWebIdentity&RoleArn=x")).toBe(true);
    expect(acl("aws_fed_action_many").test("Action=AssumeRoleWithWebIdentity&%41ction=X")).toBe(
      true,
    );
    expect(acl("aws_role_body_many").test("Action=X&R%6FleArn=evil&RoleArn=ok")).toBe(true);
    expect(acl("aws_role_body_many").test("Action=X&RoleArn=ok&RoleSessionName=gh")).toBe(false);
  });

  it("counts Action and RoleArn in the query under any spelling, as STS takes it over the body", () => {
    const inQuery = acl("aws_fed_in_query");
    for (const query of ["R%6FleArn=evil", "Version=1&RoleArn=evil", "%41ction=X"]) {
      expect(inQuery.test(query)).toBe(true);
    }
    expect(inQuery.test("Version=2011-06-15")).toBe(false);
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
    // A web identity call is read for the record, but nothing judges it by account.
    expect(rules.includes("str(role-not-allowed)")).toBe(false);
    expect(rules.includes("!aws_role_account")).toBe(false);
    expect(rules.includes("set-var(txn.aws_log_role)")).toBe(true);
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
  it("blocks in restrict, and only names what restrict would block in audit", () => {
    const restrict = awsKeyRequestRules(CHECK, "restrict").join("\n");
    expect(restrict.includes("http-request deny deny_status 403 if aws_blocked")).toBe(true);
    const audit = awsKeyRequestRules(CHECK, "audit").join("\n");
    expect(audit.includes("txn.would_block")).toBe(true);
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
    expect(rules.split(`-m end ${AWS_API_SUFFIXES.join(" ")} }`).length).toBe(2);
    for (const pattern of [AWS_RESOURCE_HOST, AWS_PUBLIC_HOST, CODECOMMIT_HOST, STS_HOST]) {
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
});

describe("the key's map entry", () => {
  it("is looked up after every key is read and the body waited for, and before any line reads it", () => {
    for (const rules of [
      awsKeyRequestRules(CHECK, "restrict"),
      awsKeyRequestRules({ keyMapFile: "/rules/keys.map", refSecret: REF_SECRET }, "audit"),
    ]) {
      const lookups = rules.flatMap((l, i) =>
        l.includes("set-var(txn.aws_key_entry)") ? [i] : [],
      );
      expect(lookups.length).toBe(1);
      const lookup = lookups[0]!;
      rules.forEach((l, i) => {
        if (l.includes("set-var(txn.aws_key) ") || l.includes("wait-for-body")) {
          expect(i < lookup).toBe(true);
        }
        if (/\baws_key_known\b|var\(txn\.aws_key_entry\)/.test(l) && i !== lookup) {
          expect(i > lookup).toBe(true);
        }
      });
    }
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
        roleAccount: "txn.aws_log_role",
      },
    });
  });

  it("says which kind of known key signed a request", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict");
    for (const kind of ["env", "assumed", "issued"]) {
      expect(rules.some((l) => l.includes(`set-var(txn.aws_log_key) str(${kind}) if`))).toBe(true);
    }
  });

  it("names the key a request was signed with whatever the verdict, and the rest only for one let through", () => {
    for (const rules of [
      awsKeyRequestRules(CHECK, "audit"),
      awsKeyRequestRules({ keyMapFile: "/rules/keys.map", refSecret: REF_SECRET }, "restrict"),
    ]) {
      const filled = rules.filter(
        (l) =>
          l.includes("set-var(txn.aws_log_") &&
          !l.includes("txn.aws_log_key_ref") &&
          !l.includes("txn.aws_log_role"),
      );
      for (const line of filled) {
        expect(/ if aws_allowed( |$)/.test(line) || line.includes("{ var(txn.aws_key_owner)")).toBe(
          true,
        );
      }
      expect(rules.filter((l) => l.includes("set-var(txn.aws_key_owner)"))).toStrictEqual([
        "    http-request set-var(txn.aws_key_owner) var(txn.aws_key_entry) if aws_key_known",
      ]);
    }
  });

  it("records a request before restrict blocks it, which ends its rules", () => {
    const rules = awsKeyRequestRules(CHECK, "restrict");
    const deny = rules.indexOf("    http-request deny deny_status 403 if aws_blocked");
    expect(deny > 0).toBe(true);
    const logged = rules.flatMap((l, i) => (l.includes("set-var(txn.aws_log_") ? [i] : []));
    expect(logged.length > 0).toBe(true);
    expect(logged.every((i) => i < deny)).toBe(true);
  });

  it("names the account a web identity call is judged by, whatever the verdict", () => {
    for (const check of [CHECK, { keyMapFile: "/rules/keys.map", refSecret: REF_SECRET }]) {
      for (const mode of ["restrict", "audit"] as const) {
        expect(
          awsKeyRequestRules(check, mode).includes(
            "    http-request set-var(txn.aws_log_role) var(txn.aws_role_account) if aws_role_account !aws_fed_ambiguous",
          ),
        ).toBe(true);
      }
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
    expect(new RegExp(STS_HOST).test("sts.s3.amazonaws.com")).toBe(true);
    expect(new RegExp(AWS_RESOURCE_HOST).test("sts.s3.amazonaws.com")).toBe(true);
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

  it("is read from any registry's answer over TLS, and learned only when the check let the request through", () => {
    const registry = new RegExp(`${ECR_REGISTRY_HOST}|${ECR_DUALSTACK_REGISTRY_HOST}`);
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
        `    http-request set-var(txn.aws_ecr_read) bool(true) if { ssl_fc } aws_resource_host { var(txn.host) -m reg ${ECR_REGISTRY_HOST} }`,
      ),
    ).toBe(true);
    expect(
      request.includes(
        `    http-request set-var(txn.aws_ecr_read) bool(true) if { ssl_fc } { var(txn.host) -m end .on.aws } { var(txn.host) -m reg ${ECR_DUALSTACK_REGISTRY_HOST} }`,
      ),
    ).toBe(true);
    expect(
      request.includes(
        "    http-request set-var(txn.aws_ecr_learn) bool(true) if { var(txn.aws_ecr_read) -m bool } !aws_blocked",
      ),
    ).toBe(true);
    // The on.aws name's regex runs only behind a suffix test that every
    // dual-stack registry passes.
    const gate = request
      .find((l) => l.includes(ECR_DUALSTACK_REGISTRY_HOST))!
      .match(/\{ var\(txn\.host\) -m end (\S+) \}/)![1]!;
    expect("111111111111.dkr-ecr.us-east-1.on.aws".endsWith(gate)).toBe(true);
    expect("111111111111.dkr-ecr.us-east-1.on.aws.example".endsWith(gate)).toBe(false);
    const learning = response.filter((l) => l.includes("set-var(txn.aws_issued_key)"));
    expect(learning.length).toBe(1);
    for (const line of learning) {
      expect(
        line.includes(
          " if aws_ecr_read { status 300:399 } { res.fhdr_cnt(location) eq 1 } !aws_location_many",
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
          "%[var(txn.aws_issued_key)] issued if aws_ecr_learn aws_issued_key !{ var(txn.aws_issued_key),map(/rules/keys.map) -m found }",
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
