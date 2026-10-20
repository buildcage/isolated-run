/** The AWS access keys a run used, numbered once for every part of its report. */

import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import type { LineNote } from "#core/lib/report/render/communication-details.ts";
import type { SummaryBlock } from "#core/lib/report/render/fit-step-summary.ts";
import { codeCell, markdownTable } from "#core/lib/report/render/markdown-table.ts";
import { trafficTableBlock, type PartFit } from "#core/lib/report/render/traffic-parts.ts";

import { ECR_DUALSTACK_REGISTRY_HOST, ECR_REGISTRY_HOST } from "../proxy/aws-hosts.ts";
import { isAwsAccountId } from "../proxy/aws-keys.ts";
import { AWS_REASON_PREFIX, awsFieldsOf, type AwsBlockedReason } from "../proxy/aws-log.ts";

export const KEY_NOT_ALLOWED = "aws-key-not-allowed" satisfies AwsBlockedReason;
const ECR_REGISTRY = new RegExp(`${ECR_REGISTRY_HOST}|${ECR_DUALSTACK_REGISTRY_HOST}`);

export function isEcrRegistry(host: string): boolean {
  return ECR_REGISTRY.test(host);
}

export interface AwsKey {
  keyRef: string;
  /** "key 1", "key 2" and so on, in the order each first signed a request or was issued. */
  name: string;
  /** What the check knew the key as when it let a request signed with it through. */
  known?: "env" | "assumed" | "issued";
  /** The account of the role whose AssumeRole answer in the run issued the key. */
  account?: string;
  /** The requests whose answers issued the key, the first first: ECR hands
   *  one key out on many redirects. */
  issuers: TrafficEvent[];
  /** The first reason the check blocked a request signed with it for, or in
   *  audit would. */
  blocked?: string;
  wouldBlock?: string;
  /** The hosts of the requests signed with it, in the order each first appeared, and how many. */
  hosts: Set<string>;
  count: number;
}

/** Every key a request in `timeline` was signed with or issued, by keyRef. */
export function awsKeys(timeline: TrafficEvent[]): Map<string, AwsKey> {
  const keys = new Map<string, AwsKey>();
  const keyOf = (keyRef: string): AwsKey => {
    let key = keys.get(keyRef);
    if (!key) {
      key = {
        keyRef,
        name: `key ${keys.size + 1}`,
        issuers: [],
        hosts: new Set(),
        count: 0,
      };
      keys.set(keyRef, key);
    }
    return key;
  };
  for (const e of timeline) {
    const { key: known, keyRef, issuedKeyRef, assumedAccount } = awsFieldsOf(e);
    if (keyRef) {
      const key = keyOf(keyRef);
      key.hosts.add(e.host);
      key.count++;
      if (known && known !== "none") key.known ??= known;
      if (e.action === "block" && e.reason?.startsWith(AWS_REASON_PREFIX)) key.blocked ??= e.reason;
      if (e.wouldBlock?.startsWith(AWS_REASON_PREFIX)) key.wouldBlock ??= e.wouldBlock;
    }
    if (issuedKeyRef) {
      const key = keyOf(issuedKeyRef);
      key.issuers.push(e);
      if (assumedAccount && isAwsAccountId(assumedAccount)) key.account ??= assumedAccount;
    }
  }
  return keys;
}

/** How many hosts a key's row names before counting the rest. */
const KEY_HOSTS_SHOWN = 3;

/** A key's hosts as one cell: the first few, then how many more. */
export function keyHostsCell(hosts: Set<string>): string {
  const rest = hosts.size - KEY_HOSTS_SHOWN;
  const shown = [...hosts].slice(0, KEY_HOSTS_SHOWN).map(codeCell).join(", ");
  return rest > 0 ? `${shown} and ${rest} more` : shown;
}

/** The end of each line in Communication details that a key signed or that issued one. */
export function awsKeyLineNote(keys: Map<string, AwsKey>): LineNote {
  const name = (keyRef: string | undefined) => (keyRef ? keys.get(keyRef)?.name : undefined);
  return (e) => {
    const { keyRef, issuedKeyRef } = awsFieldsOf(e);
    const signer = name(keyRef);
    const issued = name(issuedKeyRef);
    if (!signer) return issued && `[issued aws ${issued}]`;
    return issued ? `[aws ${signer} → issued ${issued}]` : `[aws ${signer}]`;
  };
}

/** Names the summary block of AWS Keys. */
const AWS_KEYS_ID = "traffic-aws-keys";

/** What the report says where the Job Summary's size limit cut AWS Keys. */
export function awsKeysTruncationNote(artifactAvailable: boolean): string {
  const rest = artifactAvailable
    ? "the buildcage-traffic artifact uploaded for this run has every request's keyRef"
    : "set upload_traffic_artifact: true to get every request's keyRef as a downloadable artifact";
  return `_…truncated: the AWS keys exceeded GitHub's Job Summary size limit; ${rest}._\n`;
}

function checkCell(key: AwsKey): string {
  if (key.blocked) return `🚫 ${key.blocked}`;
  if (key.wouldBlock) return `⚠️ restrict would block (${key.wouldBlock})`;
  return key.known ? "✅ known" : "not checked";
}

function sourceCell(key: AwsKey, keys: Map<string, AwsKey>): string {
  if (key.known === "env") return "starting key";
  const [issuer] = key.issuers;
  if (!issuer) return "unknown";
  const ecr = isEcrRegistry(issuer.host);
  // An unsigned call that issues a key: a web identity to STS, a registry
  // token to ECR.
  const from =
    keys.get(awsFieldsOf(issuer).keyRef ?? "")?.name ??
    (ecr ? "a registry token" : "a web identity");
  if (key.account) return `role in ${key.account} (from ${from})`;
  return ecr ? `ECR layer URL (from ${from})` : `STS (from ${from})`;
}

/**
 * AWS Keys: one row per key the run used, so a run shows what the AWS access
 * key check made of each, blocked or not. The numbers are the ones
 * Communication details ends each signed line with.
 */
export function awsKeysBlocks(keys: Map<string, AwsKey>, fit: PartFit): SummaryBlock[] {
  if (keys.size === 0) return [];
  const table = markdownTable(
    [
      { key: "key", title: "Key" },
      { key: "check", title: "Check" },
      { key: "source", title: "Source" },
      { key: "count", title: "Requests", align: "right" },
      // Already a code span per host, as a request chooses its Host header.
      { key: "hosts", title: "Hosts", cell: String },
      { key: "keyRef", title: "keyRef", cell: codeCell },
    ],
    [...keys.values()].map((key) => ({
      key: key.name,
      check: checkCell(key),
      source: sourceCell(key, keys),
      count: key.count,
      hosts: keyHostsCell(key.hosts),
      keyRef: key.keyRef,
    })),
  );
  return [
    trafficTableBlock(
      AWS_KEYS_ID,
      fit.priority,
      awsKeysTruncationNote(fit.artifactAvailable),
      "### 🔑 AWS Keys\n\n",
      table,
      "\n",
    ),
  ];
}
