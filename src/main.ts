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
  let settled = false;
  // Node exits with status 0 when a wait is left with nothing holding it
  // open, which would pass a step that never ran its command.
  process.on("beforeExit", () => {
    if (settled) return;
    process.stdout.write("::error::The step stopped partway through; failing it.\n");
    process.exitCode = 1;
  });
  runSandboxStep(process.env)
    .then((exitCode) => {
      if (exitCode !== 0) process.exitCode = exitCode;
    })
    .catch(exitOnFatalError("sandbox"))
    .finally(() => {
      settled = true;
    });
}
/* v8 ignore stop */
