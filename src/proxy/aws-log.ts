/** What the AWS access key check logs: why it blocked a request, and what it saw in one. */

import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";

/** Starts every reason the check blocks with. */
export const AWS_REASON_PREFIX = "aws-";

/** The verdicts restrict mode blocks on, each logged as `reason=aws-<verdict>`. */
export const AWS_BLOCKED_VERDICTS = [
  "no-credential",
  "ambiguous-credential",
  "unsupported-credential",
  "unreadable",
  "key-not-allowed",
  "role-not-allowed",
] as const;

/** A reason the check blocks with. */
export type AwsBlockedReason =
  `${typeof AWS_REASON_PREFIX}${(typeof AWS_BLOCKED_VERDICTS)[number]}`;

/** What the traffic record says of a request the check let through; see
 *  docs/aws.md#in-the-traffic-artifact. */
export type AwsTrafficFields = {
  aws: {
    key?: "env" | "assumed" | "issued" | "none";
    accountId?: string;
    assumedAccount?: string;
    keyRef?: string;
    issuedKeyRef?: string;
    roleAccount?: string;
  };
};

/** What the check logged for a request. */
export function awsFieldsOf(e: TrafficEvent): AwsTrafficFields["aws"] {
  return e.extensions?.aws ?? {};
}
