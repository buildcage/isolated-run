import { readFileSync } from "node:fs";

import type { HostMount } from "./types.ts";

/**
 * Pure: extract {mountPoint, fsType} for every line of raw
 * /proc/self/mountinfo content. Format (space-separated fields):
 *   ID PARENT-ID MAJOR:MINOR ROOT MOUNT-POINT OPTIONS [OPT-FIELDS...] - FSTYPE SOURCE SUPER-OPTIONS
 * The mount point is always field 5 (index 4); the filesystem type is
 * always the field right after the literal "-" separator, regardless of
 * how many optional fields precede it.
 */
export function parseMountinfo(mountinfoContent: string): HostMount[] {
  return mountinfoContent
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const fields = line.split(" ");
      const dashIndex = fields.indexOf("-");
      return { mountPoint: unescapeField(fields[4]), fsType: unescapeField(fields[dashIndex + 1]) };
    });
}

/**
 * Undo the octal escapes the kernel writes for the four characters that
 * would otherwise be unreadable in a space-separated table: space (\040),
 * tab (\011), newline (\012) and backslash (\134). A mount point left
 * escaped names a path that does not exist, so runc ignores the
 * readonlyPaths entry built from it and that mount stays writable.
 *
 * One left-to-right pass, which is what keeps a path that really contains a
 * backslash correct: the kernel writes it as \134, so the text following an
 * escape is never rescanned as one.
 */
function unescapeField(field: string | undefined): string {
  return (field ?? "").replace(/\\([0-7]{3})/g, (_, octal: string) =>
    String.fromCharCode(parseInt(octal, 8)),
  );
}

/**
 * Reads the real host mount table. Node runs directly on the runner host,
 * not inside any namespace, so this is exactly the mount table
 * run-isolated.sh's `mount --rbind /` will duplicate into rootfsBindDir a
 * moment later (see buildOciConfig's readonlyPaths handling for why this
 * matters).
 */
// Untested by design: parseMountinfo holds the logic and is tested directly.
/* v8 ignore start */
export function listHostMounts(): HostMount[] {
  return parseMountinfo(readFileSync("/proc/self/mountinfo", "utf8"));
}
/* v8 ignore stop */
