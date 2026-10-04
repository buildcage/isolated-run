import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { exitOnFatalError } from "#core/lib/actions/fatal.ts";

import { runSandboxStep } from "./lib/sandbox-step.ts";

// Untested by design, down to the end of the file: the self-invocation guard a
// test can never be inside, and handing the step's exit code to the process.
// The step itself is sandbox-step.ts, tested there.
/* v8 ignore start */
// Node resolves symlinks in import.meta.url but not in argv, and the runner
// may reach the checkout through one.
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runSandboxStep(process.env)
    .then((exitCode) => {
      if (exitCode !== 0) process.exitCode = exitCode;
    })
    .catch(exitOnFatalError("sandbox"));
}
/* v8 ignore stop */
