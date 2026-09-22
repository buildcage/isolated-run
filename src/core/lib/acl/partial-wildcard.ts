/**
 * Domain pattern compiler for the `inspect` engine, which allows a wildcard
 * inside a label: `abc*.amazonaws.com`.
 *
 * The shared compiler in wildcard-rules.ts rejects that, requiring a label
 * containing `*` to be exactly `*` or `**`. For `universal` that is only
 * a restriction on how a rule can be phrased. For `inspect` it would be a
 * hazard, because the resolver's scope is generated from these same patterns:
 * a rule unable to say "only names beginning with abc" forces the author to
 * write `*.amazonaws.com` instead, widening what is allowed to resolve and
 * therefore what can leak through a DNS query alone.
 *
 * The wildcard vocabulary is otherwise unchanged, and keeps the same meaning
 * wherever it appears in a label:
 *
 *   `**`: one or more characters, dots included
 *   `*` : one or more characters, dots excluded
 *   `?` : a single character, dots excluded
 *
 * Kept separate from wildcard-rules.ts rather than added to it, so widening
 * this grammar cannot change what the `universal` engine accepts.
 */

/** Characters that must be escaped to appear literally in a regex. */
const REGEX_META = /[.+^$()[\]{}|\\]/g;

/** How a wildcard is spelled for one kind of separator. */
interface Vocabulary {
  across: string;
  within: string;
  single: string;
}

const DOMAIN: Vocabulary = { across: ".+", within: "[^.]+", single: "[^.]" };
// A path's `**` is zero or more, so `/pkg/**` also covers `/pkg/` itself.
const PATH: Vocabulary = { across: ".*", within: "[^/]+", single: "[^/]" };

/**
 * Compile one atom (a domain label or a path segment), allowing wildcards to
 * sit among literal text.
 */
function atomToRegex(atom: string, vocab: Vocabulary): string {
  let out = "";
  for (let i = 0; i < atom.length; i++) {
    if (atom[i] === "*") {
      // Longest match first: `**` spans the separator; a single `*` does not.
      if (atom[i + 1] === "*") {
        out += vocab.across;
        i++;
      } else {
        out += vocab.within;
      }
      continue;
    }
    if (atom[i] === "?") {
      out += vocab.single;
      continue;
    }
    out += atom[i].replace(REGEX_META, "\\$&");
  }
  return out;
}

/**
 * Convert a domain pattern to a regex string, without anchors or port.
 *
 * @throws {Error} if a label is empty
 */
export function domainToRegexPartial(domain: string): string {
  return domain
    .split(".")
    .map((label) => {
      if (label === "") throw new Error(`Invalid domain "${domain}": empty label`);
      return atomToRegex(label, DOMAIN);
    })
    .join("\\.");
}

/**
 * Convert a path pattern to a regex fragment, without anchors and keeping the
 * leading `/`.
 *
 * Empty segments are allowed, unlike domain labels: a path begins with `/`, so
 * splitting always yields one.
 */
export function pathToRegexPartial(path: string): string {
  if (path === "") return "";
  return path
    .split("/")
    .map((segment) => atomToRegex(segment, PATH))
    .join("/");
}

/**
 * Convert a `<domain>:<port|*>` pattern to a regex string, without anchors.
 *
 * Mirrors wildcardToRegex's shape so callers can split the result on the last
 * colon to recover the host and port halves.
 *
 * @throws {Error} if the pattern is malformed
 */
export function wildcardToRegexPartial(pattern: string): string {
  if (!/^[^:]+:(?:\d+|\*)$/.test(pattern)) {
    throw new Error(`Invalid pattern "${pattern}"`);
  }
  const colonIndex = pattern.lastIndexOf(":");
  const domain = pattern.slice(0, colonIndex);
  const port = pattern.slice(colonIndex + 1);
  return `${domainToRegexPartial(domain)}:${port === "*" ? "\\d+" : port}`;
}

/** True if `regex` carries a `|` outside every group and character class. */
function hasTopLevelAlternation(regex: string): boolean {
  let depth = 0;
  let inClass = false;
  for (let i = 0; i < regex.length; i++) {
    const c = regex[i];
    if (c === "\\") {
      i++;
    } else if (inClass) {
      if (c === "]") inClass = false;
    } else if (c === "[") {
      inClass = true;
    } else if (c === "(") {
      depth++;
    } else if (c === ")") {
      depth--;
    } else if (c === "|" && depth === 0) {
      return true;
    }
  }
  return false;
}

/**
 * A bracket written as a literal. One in the half taken for the host means
 * the `:` the split chose was not the port separator, an IPv6 authority
 * (`\[::1\]:443`) above all. A character class keeps its `[` unescaped, so
 * `web[0-9]\.example\.com` is unaffected.
 */
const HOST_LITERAL_ILLEGAL = /\\[[\]]/;

/**
 * Check part of a `~` rule against what the rule syntax can represent.
 *
 * @throws {Error} if the text carries a top-level `|`, or a host half holds
 *   a character no hostname can
 */
export function checkRawRegexHalf(
  text: string,
  label: string,
  rule: string,
  hostHalf: boolean,
): void {
  if (hasTopLevelAlternation(text)) {
    throw new Error(
      `Invalid regex in rule "${rule}": the ${label} "${text}" has a top-level "|". Anchors bind ` +
        `to its first and last branch rather than to the whole ${label}, so write one rule per ` +
        `alternative, or put the "|" inside a group, as in "(a|b)\\.example\\.com"`,
    );
  }
  if (hostHalf && HOST_LITERAL_ILLEGAL.test(text)) {
    throw new Error(
      `Invalid regex in rule "${rule}": the ${label} "${text}" holds a character no hostname can, ` +
        `so the ":" this rule was split at is not its port separator. An IPv6 address is not ` +
        `supported here, in a "~" rule any more than in a literal one`,
    );
  }
}

/** True if `regex` ends in a `$` that is an anchor rather than a literal. */
export function endsAnchored(regex: string): boolean {
  if (!regex.endsWith("$")) return false;
  let backslashes = 0;
  for (let i = regex.length - 2; i >= 0 && regex[i] === "\\"; i--) backslashes++;
  return backslashes % 2 === 0;
}

/**
 * Anchor a `~` rule's host half at both ends.
 *
 * Both engines match a `~` rule as a search rather than a full match
 * (HAProxy's `-m reg`, CEL's `matches`), so an unanchored `~example\.com:443`
 * would also admit `evil-example.com:4430`. A URL rule's author cannot write
 * the anchors themselves: the host half's `^` goes to the scheme and its `$`
 * to the path, and a host rule is treated the same way.
 *
 * Concatenation suffices because checkRawRegexHalf has already refused a
 * top-level `|`, the one construct it would bind to only half of.
 */
export function anchorRawRegex(regex: string): string {
  return `${regex.startsWith("^") ? "" : "^"}${regex}${endsAnchored(regex) ? "" : "$"}`;
}

/**
 * Where a port pattern starts in a `<host>[:<port>]` regex fragment written
 * by a user: a bare `:`, or the `(` of a group opening right at the colon
 * (`(:8443)?`, `(:443|:8443)`). Splitting there, rather than at the last `:`
 * in the whole fragment, keeps a port group's own `(` out of the host half
 * so both halves stay balanced regexes on their own.
 */
const PORT_PATTERN_START = /\(:|:/;

/**
 * Split a `<host>[:<port>]` regex fragment (a `~` rule's own text, minus any
 * scheme or path around it) into its domain-only prefix and the port
 * pattern (including its own leading `:` or `(`). `portPattern` is `null`
 * when the fragment names no port at all.
 */
export function splitDomainFromPortPattern(hostPlusPort: string): {
  domain: string;
  portPattern: string | null;
} {
  const match = PORT_PATTERN_START.exec(hostPlusPort);
  if (!match) return { domain: hostPlusPort, portPattern: null };
  return {
    domain: hostPlusPort.slice(0, match.index),
    portPattern: hostPlusPort.slice(match.index),
  };
}

/**
 * Extract the host-only fragment from a `~` host rule's raw regex, for the
 * resolver's allowlist: a DNS query carries no port, so whatever names a port
 * is dropped here regardless of its shape. Enforcement uses the raw regex
 * directly instead (see haproxy-rules.ts), matched as one expression against
 * the connection, so this function exists only for coredns-config.ts.
 *
 * @throws {Error} if the regex is invalid, it carries a top-level `|`, it
 *   names no port at all (a port is always required), or the host half does
 *   not compile as a regex on its own or holds a character no hostname can
 */
export function splitRawRegexHost(pattern: string): { host: string } {
  const regex = pattern.slice(1);
  try {
    new RegExp(regex);
  } catch (e) {
    throw new Error(`Invalid regex in rule "${pattern}": ${(e as Error).message}`);
  }
  // Over the whole expression: the split cuts at the first ":", leaving the
  // "|" of `a\.com:443|b\.com:443` where a host-half check would not see it.
  checkRawRegexHalf(regex, "expression", pattern, false);

  const { domain, portPattern } = splitDomainFromPortPattern(regex);
  if (portPattern === null) {
    throw new Error(
      `Invalid regex in rule "${pattern}": expected ":" separating the host from a port; a port ` +
        `is always required`,
    );
  }
  let host = domain;
  if (host.startsWith("^")) host = host.slice(1);
  checkRawRegexHalf(host, "host half", pattern, true);

  try {
    new RegExp(host);
  } catch (e) {
    throw new Error(
      `Invalid regex in rule "${pattern}": the host part "${host}" does not compile on its own: ` +
        `${(e as Error).message}`,
    );
  }
  return { host };
}
