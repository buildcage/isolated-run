/** What the AWS access key check logs with each request. */

import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";

/** What the traffic record says of a request the check let through; see
 *  docs/aws.md#in-the-traffic-artifact. */
export type AwsTrafficFields = {
  aws: {
    key?: "env" | "assumed" | "issued" | "none";
    accountId?: string;
    assumedAccount?: string;
    keyRef?: string;
    issuedKeyRef?: string;
  };
};

/** What the check logged for a request. */
export function awsFieldsOf(e: TrafficEvent): AwsTrafficFields["aws"] {
  return e.extensions?.aws ?? {};
}
