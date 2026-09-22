/**
 * One comment rule shared by every newline-separated input the action takes:
 * the rule lists (allowed_*_rules, known_blocked_rules) and, in isolated-run,
 * write_through.
 */

/**
 * Drop a trailing `#` comment from a single line: a `#` at the start of the
 * line, or one preceded by whitespace, begins a comment that runs to the end
 * of the line. The leading whitespace is kept so the tokens before it stay
 * separated.
 *
 * The whitespace requirement leaves a `#` that sits mid-token alone, so a `~`
 * regex rule (a host character class, or a literal `#` written as `~...#...`)
 * is not truncated by its own `#`.
 */
export function stripLineComment(line: string): string {
  return line.replace(/(^|\s)#.*$/, "$1");
}
