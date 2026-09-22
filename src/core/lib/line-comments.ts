/**
 * The `#` comment rule shared by every newline-separated input the action
 * takes: the rule lists (allowed_*_rules, known_blocked_rules) and, in
 * isolated-run, write_through. A comment starts at a `#` that is at the start
 * of a line or preceded by whitespace, and runs to the end of the line.
 */

/**
 * Drop a trailing `#` comment from a single line. The leading whitespace is
 * kept so the tokens before it stay separated. A `#` with no whitespace before
 * it is left in place, which is what write_through wants: a path may contain a
 * literal `#`.
 */
export function stripLineComment(line: string): string {
  return line.replace(/(^|\s)#.*$/, "$1");
}

/**
 * As stripLineComment, but for the rule inputs, where a `#` with no space
 * before it is rejected rather than left in place. A `#` is never a legitimate
 * part of a rule: it appears in no host or address, a URL fragment is dropped
 * before the request is ever sent, and it is not a regex metacharacter. So a
 * glued `#` is a mistake, a comment written without its leading space or a
 * stray fragment, and reporting it keeps the rule from silently becoming one
 * that matches nothing.
 */
export function stripRuleComment(line: string): string {
  const content = stripLineComment(line);
  if (content.includes("#")) {
    throw new Error(
      `Invalid rule ${JSON.stringify(line.trim())}: a "#" starts a comment only with a space ` +
        `before it, and "#" is never part of a host or URL, so a rule cannot contain one.`,
    );
  }
  return content;
}
