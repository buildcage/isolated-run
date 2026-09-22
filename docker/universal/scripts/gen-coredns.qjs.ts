/**
 * Generate the `universal` engine's CoreDNS Corefile from the same host rules
 * the HAProxy allowlist is built from, so a name CoreDNS logs as allowed is one
 * HAProxy would also let through. CoreDNS never resolves a name for real: every
 * name is answered with the proxy's own address, and HAProxy makes the only
 * outbound connection, once a request has already passed these same rules.
 *
 * `inspect` generates its haproxy.cfg and Corefile from one script
 * (gen-configs). `universal` keeps its haproxy.cfg on an envsubst template (see
 * init-haproxy-cfg), so only the Corefile is generated here; the same rule
 * strings feed both, so the two views cannot drift.
 *
 * Usage:
 *   qjs --std -m gen-coredns.js <corefile_out> <proxy_address> <mode> \
 *     <https_rules> <http_rules>
 *
 * Host rules are whitespace separated. `universal` supports neither url nor tls
 * rules, so those inputs do not exist.
 */
import * as std from "qjs:std";
import { generateCorednsConfig } from "#core/lib/acl/coredns-config.js";
import { compileRuleSet } from "#core/lib/acl/haproxy-rules.js";
import { splitRuleTokens } from "#core/lib/acl/wildcard-rules.js";

const [corefileOut, proxyAddress, mode, httpsInput, httpInput] = scriptArgs.slice(1);

function writeFile(path: string, content: string): void {
  const file = std.open(path, "w");
  if (!file) throw new Error(`cannot write ${path}`);
  file.puts(content);
  file.close();
}

try {
  if (!proxyAddress) throw new Error("no proxy address given");

  const httpsRules = splitRuleTokens(httpsInput);
  const httpRules = splitRuleTokens(httpInput);

  const coredns = generateCorednsConfig(compileRuleSet({ httpsRules, httpRules }), {
    proxyAddress,
    mode: mode === "audit" ? "audit" : "restrict",
  });

  // A warning here means a rule cannot be honoured in full, so it has to be
  // visible in the build log rather than only in a file nobody reads.
  for (const warning of coredns.warnings) {
    std.err.puts(`buildcage: warning: ${warning}\n`);
  }

  writeFile(corefileOut, coredns.config);
} catch (e) {
  // Failing closed: without the Corefile CoreDNS would not start, taking the
  // container down rather than answering names off an empty allowlist.
  std.err.puts(`buildcage: ${(e as Error).message}\n`);
  std.exit(1);
}
