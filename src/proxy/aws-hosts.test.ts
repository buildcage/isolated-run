import { describe, it, expect, reportResults } from "#core/lib/test/test-shim.ts";

import {
  AWS_API_SUFFIXES,
  AWS_DOMAINS,
  AWS_PUBLIC_HOST,
  AWS_RESOURCE_HOST,
  EC2_HOST,
  SIGV2_PARAM,
  SIGV4_PARAM,
  STS_HOST,
} from "./aws-hosts.ts";

// What the config writes is also what reaches the regex engine: HAProxy's
// word parser leaves `\.` alone. See escapeForHaproxy.
const stsHost = new RegExp(STS_HOST);
const resourceHost = new RegExp(AWS_RESOURCE_HOST);
const publicHost = new RegExp(AWS_PUBLIC_HOST);
// HAProxy's `-m end`, which txn.host is tested with.
const apiHost = { test: (host: string) => AWS_API_SUFFIXES.some((s) => host.endsWith(s)) };

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

  it("agrees with the domains the other host patterns are built on", () => {
    const domain = new RegExp(`\\.${AWS_DOMAINS}$`);
    for (const host of [
      "x.amazonaws.com",
      "x.amazonaws.com.cn",
      "x.amazonaws.eu",
      "x.api.aws",
      "x.api.amazonwebservices.com.cn",
      "x.api.amazonwebservices.eu",
      ...AWS_API_SUFFIXES.map((s) => s.slice(1)),
      "x.amazonaws.org",
      "x.amazonaws.cn",
      "x.api.amazonwebservices.com",
      "x.aws",
      "x.amazonaws.com.evil",
    ]) {
      expect(apiHost.test(host)).toBe(domain.test(host));
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

describe("EC2's API host", () => {
  const ec2Host = new RegExp(EC2_HOST);

  it("names EC2 by its regional, region-less, FIPS, dual-stack, pre-regional and VPC-endpoint names", () => {
    for (const host of [
      "ec2.us-east-1.amazonaws.com",
      "ec2.amazonaws.com",
      "ec2-fips.us-east-1.amazonaws.com",
      "ec2.cn-north-1.amazonaws.com.cn",
      "ec2.us-east-1.api.aws",
      "ec2-fips.us-east-1.api.aws",
      "us-west-2.ec2.amazonaws.com",
      "eu-west-1.ec2.amazonaws.com",
      "vpce-0123456789abcdef0-abcdefgh.ec2.us-east-1.vpce.amazonaws.com",
    ]) {
      expect(ec2Host.test(host)).toBe(true);
    }
  });

  it("leaves out an EC2 instance's public name and other ec2-prefixed services", () => {
    for (const host of [
      "ec2-54-12-3-4.compute-1.amazonaws.com",
      "ec2messages.us-east-1.amazonaws.com",
      "ec2instanceconnect.us-east-1.amazonaws.com",
      "ec2.amazonaws.com.evil",
      // The pre-regional name is the commercial partition's alone.
      "cn-north-1.ec2.amazonaws.com.cn",
    ]) {
      expect(ec2Host.test(host)).toBe(false);
    }
  });
});

describe("hosts that name the resource", () => {
  it("covers every form AWS documents for them", () => {
    for (const host of [
      // S3: virtual-hosted, legacy, path style, dual-stack, FIPS, access
      // points, control, Outposts, Object Lambda, VPC endpoints, website,
      // acceleration, China.
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
      "111111111111.s3-control-fips.dualstack.us-east-1.amazonaws.com",
      "my-ap-111111111111.op-01ac5d28a6a232904.s3-outposts.us-west-2.amazonaws.com",
      "my-ap-111111111111.s3-object-lambda.us-east-1.amazonaws.com",
      "bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com",
      "my-bucket.bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com",
      "my-ap-111111111111.accesspoint.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com",
      "111111111111.control.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com",
      "bucket.s3-website-us-east-1.amazonaws.com",
      "bucket.s3-website.eu-central-1.amazonaws.com",
      "bucket.s3-accelerate.amazonaws.com",
      "bucket.s3-accelerate.dualstack.amazonaws.com",
      "bucket.s3.cn-north-1.amazonaws.com.cn",
      "bucket.s3.eusc-de-east-1.amazonaws.eu",
      // A bucket named like a service-only endpoint.
      "s3-control.s3.us-east-1.amazonaws.com",
      "s3-control.s3.amazonaws.com",
      "s3-accesspoint-fips.s3-us-west-2.amazonaws.com",
      "s3-object-lambda.s3.dualstack.us-east-1.amazonaws.com",
      "s3-outposts.example.s3-website-us-east-1.amazonaws.com",
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
      "s3-control.us-east-1.amazonaws.com",
      "s3-control.dualstack.us-east-1.amazonaws.com",
      "s3-control-fips.us-east-1.amazonaws.com",
      "s3-outposts.us-west-2.amazonaws.com",
      "s3-outposts-fips.us-east-1.amazonaws.com",
      "s3-outposts.dualstack.us-west-2.amazonaws.com",
      "s3-accesspoint.us-east-1.amazonaws.com",
      "s3-accesspoint-fips.dualstack.us-east-1.amazonaws.com",
      "s3-object-lambda.us-east-1.amazonaws.com",
      "s3-control.amazonaws.com",
      "s3-control.dualstack.amazonaws.com",
      "s3-control-fips.us-gov-west-1.amazonaws.com",
      "s3-control.cn-north-1.amazonaws.com.cn",
      "s3-outposts.eusc-de-east-1.amazonaws.eu",
      "control.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com",
      "accesspoint.vpce-1a2b3c4d-5e6f.s3-fips.us-east-1.vpce.amazonaws.com",
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
  const credential = new RegExp(`(^|[&;])${SIGV2_PARAM}=`, "i");

  it("counts the name in any case, with any letter percent-encoded, after & or ;", () => {
    for (const body of [
      "AWSAccessKeyId=K&Action=X",
      "Action=X&AWSAccessKeyId=K",
      "Action=X&awsaccesskeyid=K",
      "Action=X&AWSAccessK%65yId=K",
      "Action=X&%41%57%53AccessKeyId=K",
      // EC2 splits a body on ; too.
      "Action=X;AWSAccessKeyId=K",
    ]) {
      expect(credential.test(body)).toBe(true);
    }
  });

  it("does not count the name inside a value, whose &, = and ; are encoded", () => {
    for (const body of [
      "Action=Publish&Message=https%3A%2F%2Fb.s3.amazonaws.com%2Fk%3FExpires%3D1%26AWSAccessKeyId%3DK",
      "Action=X&MyAWSAccessKeyId=K",
      "Action=X&M=a%3BAWSAccessKeyId%3DK",
    ]) {
      expect(credential.test(body)).toBe(false);
    }
  });
});

describe("SigV4's credential in a form body", () => {
  const credential = new RegExp(`(^|[&;])${SIGV4_PARAM}=`, "i");

  it("counts the name in any case, with any character percent-encoded, after & or ;", () => {
    for (const body of [
      "X-Amz-Credential=K",
      "Action=X&x-amz-credential=K",
      "Action=X&X%2DAmz-Cr%65dential=K",
      "Action=X;X-Amz-Credential=K",
    ]) {
      expect(credential.test(body)).toBe(true);
    }
    expect(credential.test("Action=X&Message=a%26X-Amz-Credential%3DK")).toBe(false);
  });
});

reportResults();
