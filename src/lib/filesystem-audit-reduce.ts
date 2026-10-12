import { createStripper } from "./filesystem-audit-strip.ts";
import {
  createAuditSummary,
  parseLine,
  type AuditSummary,
  type SummaryOptions,
} from "./filesystem-audit-summary.ts";

export interface ReducedRecording {
  /** Undefined when summarizing failed, for summaryError. */
  summary: AuditSummary | undefined;
  summaryError?: unknown;
}

/**
 * Two passes over the recording: the first finds buildcage's machinery and
 * what each process loaded, the second hands the step's lines to the sink and
 * builds the summary. A failed summary comes back as summaryError, so the sink
 * still gets every line.
 */
export function reduceRecording(
  forEachLine: (onLine: (line: string) => void) => void,
  scratchBase: string,
  options: SummaryOptions,
  /** Opened between the two passes; takes each line the step keeps. */
  openSink?: () => (line: string) => void,
  createSummary: typeof createAuditSummary = createAuditSummary,
): ReducedRecording {
  const stripper = createStripper(scratchBase);
  const summary = createSummary(options);
  let summaryError: unknown;
  let failedSummary = false;
  const summarize = (step: () => void): void => {
    if (failedSummary) return;
    try {
      step();
    } catch (e) {
      [failedSummary, summaryError] = [true, e];
    }
  };

  let lines = 0;
  let length = 0;
  forEachLine((line) => {
    lines++;
    length += line.length;
    const r = parseLine(line);
    stripper.observe(r);
    summarize(() => summary.observe(r));
  });

  const sink = openSink?.();
  let again = 0;
  let lengthAgain = 0;
  forEachLine((line) => {
    again++;
    lengthAgain += line.length;
    const r = parseLine(line);
    const kept = stripper.filter(line, r);
    summarize(() => summary.add(kept ? kept.record : r, kept !== undefined));
    if (kept) sink?.(kept.line);
  });
  // The tracer has stopped, so the two reads see the same lines, which the
  // line positions the first pass found depend on.
  if (again !== lines || lengthAgain !== length)
    throw new Error("the recording changed while it was being read");

  let result: AuditSummary | undefined;
  summarize(() => (result = summary.finish()));
  return { summary: result, summaryError };
}
