import type { Annotation } from "#core/lib/actions/annotation.ts";

/**
 * Fails the step under restrict with fail_on_blocked (`failClosed`), and only
 * warns otherwise: what a report that cannot be trusted does to the step.
 */
export function failOrWarn(annotation: Annotation, failClosed: boolean): (message: string) => void {
  return (message) => {
    if (failClosed) {
      annotation.error(`${message}; failing the step under restrict with fail_on_blocked`);
      process.exitCode = 1;
    } else {
      annotation.warning(message);
    }
  };
}
