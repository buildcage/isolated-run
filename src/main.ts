import { fileURLToPath } from "node:url";

import { exitOnFatalError } from "#core/lib/actions/fatal.ts";

import { runSandboxStep } from "./lib/sandbox-step.ts";

// Untested by design, down to the end of the file: the self-invocation guard a
// test can never be inside, and handing the step's exit code to the process.
// The step itself is sandbox-step.ts, tested there.
/* v8 ignore start */
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runSandboxStep(process.env)
    .then((exitCode) => {
      if (exitCode !== 0) process.exitCode = exitCode;
    })
    .catch(exitOnFatalError("sandbox"));
}
/* v8 ignore stop */
