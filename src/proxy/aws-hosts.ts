/**
 * The AWS hosts and parameter names the access key check matches requests
 * against, as regular expressions.
 */

// API endpoints only: the commercial, China and European Sovereign Cloud
// domains, and the dual-stack ones, written as regexes.
const AMAZONAWS_TLDS = ["com", "com\\.cn", "eu"];
const DUALSTACK_NAMES = [
  "api\\.aws",
  "api\\.amazonwebservices\\.com\\.cn",
  "api\\.amazonwebservices\\.eu",
];
const AMAZONAWS_DOMAINS = `amazonaws\\.(${AMAZONAWS_TLDS.join("|")})`;
const DUALSTACK_DOMAINS = `(${DUALSTACK_NAMES.join("|")})`;
export const AWS_DOMAINS = `(${AMAZONAWS_DOMAINS}|${DUALSTACK_DOMAINS})`;
// The same domains as suffixes, which HAProxy tests without a regex. Matched
// against txn.host, which is lowercased, has no port and holds only
// [A-Za-z0-9._-]. Any name under these domains, whatever its labels hold, so
// one with a `_` is checked.
export const AWS_API_SUFFIXES = [
  ...AMAZONAWS_TLDS.map((tld) => `amazonaws\\.${tld}`),
  ...DUALSTACK_NAMES,
].map((domain) => `.${domain.replaceAll("\\.", ".")}`);
// The names an interface VPC endpoint gives a service.
const vpceHost = (service: string) =>
  `^([a-z0-9-]+\\.)*vpce-[a-z0-9-]+\\.${service}\\.[a-z0-9-]+\\.vpce\\.amazonaws\\.com$`;
// A service's API host: its regional, region-less and dual-stack names and its
// interface VPC endpoint. vpceService lets the VPC-endpoint name differ, as
// EC2's does in carrying `-fips`.
const apiHost = (service: string, vpceService = service) =>
  `^${service}(-fips)?(\\.[a-z0-9-]+)?\\.${AWS_DOMAINS}$|${vpceHost(vpceService)}`;
export const STS_HOST = apiHost("sts");
// EC2's API. It reads the request body as a Query form whatever the
// Content-Type says; as of 2026-10-12 it was the only Query service that does.
// `<region>.ec2.amazonaws.com` is its pre-regional endpoint name, still
// resolved (us-east-1's as a CNAME to ec2.amazonaws.com) and reaching the same
// API, in the commercial partition alone. The `ec2-<ip>.compute` public names
// are a resource host, not this.
export const EC2_HOST = `${apiHost("ec2", "ec2(-fips)?")}|^[a-z0-9-]+\\.ec2\\.amazonaws\\.com$`;
// Hosts that name the resource a request is for, in the host or (S3's path
// style, an EKS OIDC issuer) the path, so the URL rules can pin it and an
// unsigned request is left to them: S3 in every form, ECR registries,
// CodeArtifact repositories, API Gateway, AppSync, Managed Grafana
// workspaces, Amazon MQ brokers, OpenSearch domains, EKS clusters and OIDC
// issuers, load balancers and EC2 public names. Every other API host names
// only a service and a region, as S3's control, access point, Object Lambda
// and Outposts endpoints do with no account or access point in front, public
// or behind a VPC endpoint. Those are matched whole, so a bucket that shares
// one's first label, as s3-control.s3.us-east-1.amazonaws.com does, still
// names a resource: a bucket's next label starts with s3, a region's does not.
const S3_SERVICE_HOST = `s3-(accesspoint|control|object-lambda|outposts)(-fips)?(\\.dualstack)?(\\.(?!s3)[a-z0-9-]+)?\\.${AMAZONAWS_DOMAINS}$`;
export const S3_HOST = `^(?!${S3_SERVICE_HOST}|(accesspoint|control)\\.vpce-)(.*\\.)?s3(-[a-z0-9-]+)?(\\.[a-z0-9-]+)*\\.${AMAZONAWS_DOMAINS}$`;
export const AWS_RESOURCE_HOST =
  S3_HOST +
  `|\\.(dkr\\.ecr(-fips)?|d\\.codeartifact|execute-api|appsync-api|appsync-realtime-api)\\.[a-z0-9-]+\\.${AMAZONAWS_DOMAINS}$` +
  `|^g-[a-z0-9]+\\.grafana-workspace\\.[a-z0-9-]+\\.${AMAZONAWS_DOMAINS}$` +
  `|^b-[a-z0-9-]+\\.mq\\.[a-z0-9-]+\\.${AMAZONAWS_DOMAINS}$` +
  `|^(search|vpc)-[a-z0-9-]+\\.[a-z0-9-]+\\.es\\.${AMAZONAWS_DOMAINS}$` +
  `|^[0-9a-f]{32}\\.[a-z0-9]+\\.[a-z0-9-]+\\.eks\\.${AMAZONAWS_DOMAINS}$` +
  `|^[0-9a-f]{32}\\.[a-z0-9-]+\\.${DUALSTACK_DOMAINS}$` +
  `|^oidc\\.eks\\.[a-z0-9-]+\\.${AMAZONAWS_DOMAINS}$` +
  `|^oidc-eks\\.[a-z0-9-]+\\.${DUALSTACK_DOMAINS}$` +
  `|\\.elb(\\.[a-z0-9-]+)?\\.${AMAZONAWS_DOMAINS}$` +
  `|\\.compute(-1)?\\.${AMAZONAWS_DOMAINS}$`;
// Public hosts that reach no account, so an unsigned request to them is left
// to the URL rules too.
export const AWS_PUBLIC_HOST =
  "^(awscli|checkip|ip-ranges|pricing\\.us-east-1)\\.amazonaws\\.com$|^pricing\\.cn-northwest-1\\.amazonaws\\.com\\.cn$";
// An ECR registry, whose redirect to a layer's presigned URL teaches its key:
// its AWS API names, and below, its dual-stack name under on.aws, which the
// check otherwise leaves to the URL rules.
export const ECR_REGISTRY_HOST = `\\.dkr\\.ecr(-fips)?\\.[a-z0-9-]+\\.${AMAZONAWS_DOMAINS}$`;
export const ECR_DUALSTACK_REGISTRY_HOST = "^[0-9]{12}\\.dkr-ecr\\.[a-z0-9-]+\\.on\\.aws$";
export const CODECOMMIT_HOST =
  `^git-codecommit(-fips)?\\.[a-z0-9-]+\\.${AMAZONAWS_DOMAINS}$|` +
  vpceHost("git-codecommit(-fips)?");
// A parameter name as a query or a form body may spell it, any letter
// percent-encoded.
export const formName = (name: string) =>
  name
    .split("")
    .map((c) => {
      const codes = new Set([c, c.toUpperCase()].map((l) => `%${l.charCodeAt(0).toString(16)}`));
      return `(${[c, ...codes].join("|")})`;
    })
    .join("");
export const SIGV2_PARAM = formName("awsaccesskeyid");
export const SIGV4_PARAM = formName("x-amz-credential");
