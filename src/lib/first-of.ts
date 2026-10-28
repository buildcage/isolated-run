/**
 * Every name if there are at most `shown`, else one fewer and how many more
 * there are, so the count never stands for a single name.
 */
export function firstOf(names: string[], shown: number): string {
  if (names.length <= shown) return names.join(", ");
  return `${names.slice(0, shown - 1).join(", ")} and ${names.length - shown + 1} more`;
}
