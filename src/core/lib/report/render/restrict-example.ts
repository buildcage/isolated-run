/**
 * The parts every "Switch to restrict mode" snippet shares, whichever engine
 * built it: the `uses:` line and the <details> block the YAML sits in.
 *
 * Shared rather than written out per renderer, so STEP_INDENT's own comment
 * cannot be fixed in one copy and missed in the other.
 */

/**
 * GitHub Actions' own indentation convention (jobs: -> <id>: -> steps: ->
 * "- name:") always puts a step 6 spaces in, so the generated snippet can be
 * pasted directly into an existing steps: list without re-indenting it.
 */
const STEP_INDENT = "      ";

/** The `uses:` line, with the resolved version as a trailing comment when known. */
export function usesLine(actionRepo: string, actionRef?: string, actionVersion?: string): string {
  return `  uses: ${actionRepo}@${actionRef}${actionVersion ? ` # ${actionVersion}` : ""}\n`;
}

export interface RestrictExampleBlockOptions {
  /** Markdown rendered right under the snippet, ahead of the footnote. */
  appendix?: string;
  /** Rendered under the snippet as small print, when the engine has a caveat
   *  worth attaching to it. */
  footnote?: string;
}

export function restrictExampleBlock(
  yaml: string,
  { appendix, footnote }: RestrictExampleBlockOptions = {},
): string {
  const indented = yaml
    .split("\n")
    .map((line) => (line ? STEP_INDENT + line : line))
    .join("\n");

  let md = "\n<details>\n";
  md += "<summary>🛡️ Switch to restrict mode</summary>\n\n";
  md += "```yaml\n";
  md += indented;
  md += "```\n\n";
  if (appendix) md += appendix;
  if (footnote) md += `<sub>*${footnote}*</sub>\n\n`;
  md += "</details>\n";
  return md;
}
