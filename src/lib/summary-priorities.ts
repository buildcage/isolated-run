/**
 * The order the Job Summary's parts are given room in when the step's summary
 * would pass GitHub's size limit, lowest first: the traffic report's example,
 * its list of requests restrict would refuse and its host tables, the
 * filesystem audit's tables, then the communication log
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
  [TRAFFIC_BLOCK.wouldRefuse]: 2,
  [TRAFFIC_BLOCK.blocked]: 3,
  [TRAFFIC_BLOCK.failed]: 4,
  [TRAFFIC_BLOCK.passed]: 5,
  [TRAFFIC_BLOCK.log]: 8,
};

export const FILESYSTEM_PRIORITIES: FilesystemPriorities = {
  [FILESYSTEM_BLOCK.executed]: 6,
  [FILESYSTEM_BLOCK.paths]: 7,
  [FILESYSTEM_BLOCK.log]: 9,
};
