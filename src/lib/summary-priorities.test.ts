import { describe, it, expect } from "vitest";

import { TRAFFIC_BLOCK } from "#core/lib/report/render/render-report-markdown.ts";

import { FILESYSTEM_BLOCK } from "./filesystem-audit-summary.ts";
import { FILESYSTEM_PRIORITIES, TRAFFIC_PRIORITIES } from "./summary-priorities.ts";

describe("summary priorities", () => {
  it("keeps room for the traffic tables, then the audit's tables, then the two logs", () => {
    const order = [
      TRAFFIC_PRIORITIES[TRAFFIC_BLOCK.example],
      TRAFFIC_PRIORITIES[TRAFFIC_BLOCK.wouldRefuse],
      TRAFFIC_PRIORITIES[TRAFFIC_BLOCK.blocked],
      TRAFFIC_PRIORITIES[TRAFFIC_BLOCK.failed],
      TRAFFIC_PRIORITIES[TRAFFIC_BLOCK.passed],
      FILESYSTEM_PRIORITIES[FILESYSTEM_BLOCK.executed],
      FILESYSTEM_PRIORITIES[FILESYSTEM_BLOCK.paths],
      TRAFFIC_PRIORITIES[TRAFFIC_BLOCK.log],
      FILESYSTEM_PRIORITIES[FILESYSTEM_BLOCK.log],
    ];
    expect(order).toEqual(order.toSorted((a, b) => a - b));
    expect(new Set(order).size).toBe(order.length);
  });
});
