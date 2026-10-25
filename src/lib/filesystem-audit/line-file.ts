import { closeSync, openSync, readSync, writeSync } from "node:fs";

const CHUNK_BYTES = 1 << 20;

/**
 * Calls onLine with each line of the file, as split("\n") would give them,
 * reading it a chunk at a time so no file is too large to read.
 */
export function readLines(
  path: string,
  onLine: (line: string) => void,
  chunkBytes = CHUNK_BYTES,
): void {
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.alloc(chunkBytes);
    // The start of a line no chunk has ended yet, joined once it does.
    let carry: Buffer[] = [];
    for (let n; (n = readSync(fd, buf, 0, buf.length, null)) > 0;) {
      const chunk = buf.subarray(0, n);
      let start = 0;
      for (let nl; (nl = chunk.indexOf(10, start)) !== -1; start = nl + 1) {
        if (carry.length === 0) onLine(chunk.toString("utf8", start, nl));
        else onLine(Buffer.concat([...carry, chunk.subarray(start, nl)]).toString("utf8"));
        carry = [];
      }
      if (start < n) carry.push(Buffer.from(chunk.subarray(start)));
    }
    onLine(Buffer.concat(carry).toString("utf8"));
  } finally {
    closeSync(fd);
  }
}

/** Writes lines to a new file, joined by newlines, a chunk at a time. */
export function openWriter(
  path: string,
  chunkBytes = CHUNK_BYTES,
): { write: (line: string) => void; close: () => void } {
  const fd = openSync(path, "w");
  let pending: string[] = [];
  let size = 0;
  let first = true;
  const flush = (): void => {
    // writeSync may write less than it is given.
    const data = Buffer.from(pending.join(""));
    for (let off = 0; off < data.length;) off += writeSync(fd, data, off);
    pending = [];
    size = 0;
  };
  return {
    write: (line) => {
      pending.push(first ? line : `\n${line}`);
      first = false;
      size += line.length + 1; // UTF-16 units, close enough to bytes to pace the flushes
      if (size >= chunkBytes) flush();
    },
    close: () => {
      try {
        flush();
      } finally {
        closeSync(fd);
      }
    },
  };
}
