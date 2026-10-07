/**
 * The order the Job Summary's parts are given room in when the step's summary
 * would pass GitHub's size limit, lowest first: the traffic report's example
 * and host tables, the filesystem audit's tables, then the communication log
 * and the filesystem audit's full record. The frames (headings, notes,
 * footers) are always kept.
 */

import {
  TRAFFIC_BLOCK,
  type TrafficPriorities,
} from "#core/lib/report/render/render-report-markdown.ts";

import { FILESYSTEM_BLOCK, type FilesystemPriorities } from "./filesystem-audit-summary.ts";

export const TRAFFIC_PRIORITIES: TrafficPriorities = {
  [TRAFFIC_BLOCK.example]: 1,
  [TRAFFIC_BLOCK.blocked]: 2,
  [TRAFFIC_BLOCK.failed]: 3,
  [TRAFFIC_BLOCK.passed]: 4,
  [TRAFFIC_BLOCK.log]: 7,
};

export const FILESYSTEM_PRIORITIES: FilesystemPriorities = {
  [FILESYSTEM_BLOCK.executed]: 5,
  [FILESYSTEM_BLOCK.paths]: 6,
  [FILESYSTEM_BLOCK.log]: 8,
};
