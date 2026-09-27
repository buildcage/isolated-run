import { describe, it, expect } from "vitest";

import { parseMountinfo } from "./mountinfo.ts";

// Realistic /proc/self/mountinfo lines (see parseMountinfo's doc comment
// for the field layout). Each has one optional field ("shared:N") before
// the "-" separator, matching what a systemd-managed host typically shows.
const SAMPLE_MOUNTINFO = [
  "1 0 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw",
  "2 1 0:2 / /proc rw,relatime shared:2 - proc proc rw",
  "3 1 0:3 / /run rw,nosuid,relatime shared:3 - tmpfs tmpfs rw,size=100k",
  "4 3 0:4 / /run/user/1000 rw,nosuid,relatime shared:4 - tmpfs tmpfs rw",
  "5 1 0:5 / /mnt rw,relatime shared:5 - ext4 /dev/sdb1 rw",
].join("\n");

describe("parseMountinfo", () => {
  // No "-" separator, so the fsType lookup lands on fields[0].
  it("yields empty strings for a line too malformed to have the fields", () => {
    expect(parseMountinfo("1 0 0:1 /")).toStrictEqual([{ mountPoint: "", fsType: "1" }]);
  });

  it("extracts the mount point and filesystem type of every line", () => {
    expect(parseMountinfo(SAMPLE_MOUNTINFO)).toStrictEqual([
      { mountPoint: "/", fsType: "ext4" },
      { mountPoint: "/proc", fsType: "proc" },
      { mountPoint: "/run", fsType: "tmpfs" },
      { mountPoint: "/run/user/1000", fsType: "tmpfs" },
      { mountPoint: "/mnt", fsType: "ext4" },
    ]);
  });

  it("undoes the octal escapes a path with a space, a tab or a newline arrives in", () => {
    expect(
      parseMountinfo(
        [
          "6 1 0:6 / /mnt/my\\040disk rw,relatime shared:6 - ext4 /dev/sdc1 rw",
          "7 1 0:7 / /mnt/tab\\011here rw,relatime shared:7 - ext4 /dev/sdd1 rw",
          "8 1 0:8 / /mnt/new\\012line rw,relatime shared:8 - ext4 /dev/sde1 rw",
        ].join("\n"),
      ).map(({ mountPoint }) => mountPoint),
    ).toStrictEqual(["/mnt/my disk", "/mnt/tab\there", "/mnt/new\nline"]);
  });

  it("leaves a path that really contains a backslash alone, rather than rescanning it", () => {
    // The kernel writes a literal backslash as \134, so "\134040" is the
    // four characters \, 0, 4, 0, not an escaped space.
    expect(
      parseMountinfo("9 1 0:9 / /mnt/\\134040 rw,relatime shared:9 - ext4 /dev/sdf1 rw")[0]
        .mountPoint,
    ).toStrictEqual("/mnt/\\040");
  });

  it("ignores trailing/blank lines", () => {
    expect(parseMountinfo(`${SAMPLE_MOUNTINFO}\n\n`).length).toStrictEqual(5);
  });
});
