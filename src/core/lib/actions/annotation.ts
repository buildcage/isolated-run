/** Declared as properties, not methods, so a caller can pass one on its own:
 *  nothing here reads `this`. */
export interface Annotation {
  notice: (message: string) => void;
  warning: (message: string) => void;
  error: (message: string) => void;
}

/** Escaped as @actions/core does, so a newline cannot start a workflow command. */
function escapeData(message: string): string {
  return message.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

/**
 * Build a GitHub Actions annotation emitter. When `enabled` is false, every
 * method is a no-op, to suppress annotations when this script isn't
 * running as the real action.
 */
export function createAnnotation(enabled: boolean): Annotation {
  if (!enabled) {
    return { notice() {}, warning() {}, error() {} };
  }
  return {
    notice(message: string) {
      console.log(`::notice::${escapeData(message)}`);
    },
    warning(message: string) {
      console.log(`::warning::${escapeData(message)}`);
    },
    error(message: string) {
      console.log(`::error::${escapeData(message)}`);
    },
  };
}

/**
 * The always-on emitter, for the messages that are printed whether or not this
 * is a real action run: a deprecated input's migration notice, a fatal error on
 * the way out.
 *
 * Only the module that assembles an action's steps (its entry point, or
 * wherever that body was extracted to) and `fatal.ts` may name it. The modules
 * they call don't choose where a message goes: they take the sink as an
 * argument, an `Annotation` for what the caller can suppress and one of
 * `annotate`'s methods for what it can't. `vite.config.ts` lists the files the
 * lint rule lets past.
 */
export const annotate: Annotation = createAnnotation(true);
