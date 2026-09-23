/**
 * The three files buildOciConfig's output refers to but does not contain: the
 * step's own script, the sandbox's resolv.conf, and the config itself.
 *
 * Separated from the spec builder because that is a pure function of its
 * arguments and these are the only writes in the bundle's setup.
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Write the user-supplied `run:` input to an executable script file.
 * Routing through a file (rather than passing the command inline to a
 * shell) avoids any shell-injection surface from the input string.
 *
 * Goes in `execDir` because the sandbox has to exec it; buildOciConfig
 * hides the rest of the scratch dir from other runs, and this file needs
 * the same protection: Actions expands a `${{ secrets.X }}` written inline
 * in `run:` before the input ever reaches here.
 *
 * `bash -e` like a native `run:` step: under dash, `if [[ ... ]]` silently
 * skips its branch. bash is present, as the rootfs is the runner's own `/`.
 */
export function writeRunScript(runInput: string, execDir: string): string {
  const scriptPath = join(execDir, "run-script.sh");
  const content = runInput.startsWith("#!") ? runInput : `#!/bin/bash\nset -e\n${runInput}\n`;
  writeFileSync(scriptPath, content, { mode: 0o700 });
  return scriptPath;
}

/**
 * Write the final OCI config to `bundleDir/config.json` (overwriting the
 * `runc spec` placeholder generateBaseOciSpec left there). 0600: it describes
 * this sandbox's whole isolation policy, and only runc reads it.
 */
export function writeOciConfig(config: unknown, bundleDir: string): string {
  const configPath = join(bundleDir, "config.json");
  writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
  return configPath;
}

/** Write the resolv.conf bind-mount source referenced by buildOciConfig. */
export function writeResolvConf(dns: string, dir: string): string {
  const resolvConfPath = join(dir, "resolv.conf");
  writeFileSync(resolvConfPath, `nameserver ${dns}\n`, { mode: 0o644 });
  return resolvConfPath;
}
