import type { HostTableRow } from "./render/host-table.ts";
import type { AnnotatedBlockedRow } from "./build/aggregate.ts";

/** Echoed back verbatim rather than re-derived — only the container's own
 *  env (or, for run, its own action input) reflects what was configured. */
export interface GenReportParameters {
  mode: string;
  allowedHttpsRules: string[];
  allowedHttpRules: string[];
  allowedIpRules: string[];
  /** Also drives whether the "Expected" column is shown (length > 0). */
  knownBlockedRules: string[];
}

export interface ReportDataCommon {
  parameters: GenReportParameters;

  /** restrict mode's allowed traffic or audit mode's audited traffic —
   *  which heading applies is decided from parameters.mode. */
  passed: HostTableRow[];

  /** Aggregated blocked-domain rows, already annotated against
   *  knownBlockedRules. Can be non-empty even in audit mode. */
  blocked: AnnotatedBlockedRow[];

  /** Raw blocked-event count — can differ from blocked.length for the
   *  transparent engine (pre-aggregation log line count). */
  blockedCount: number;

  /** False iff the log looks structurally implausible for a real run (no
   *  non-buildcage/non-denial content at all) — see haproxy.ts's
   *  hasNonBuildcageContent.
   *  Used to fail closed on a suspiciously empty log instead of treating it
   *  as "nothing was blocked". */
  logLooksPlausible: boolean;
}

/** isolated-run's proxy image only ever produces transparent-shaped data
 *  (no buildkitd/vertex logs) — unlike dash14/buildcage, there's no
 *  discriminated union with an explicit-engine variant here. */
export interface TransparentReportData extends ReportDataCommon {
  engine: "transparent";
}

export type ReportData = TransparentReportData;
