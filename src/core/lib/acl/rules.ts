import { ActionError, errorMessage } from "../errors.ts";
import { generateCorednsConfig } from "./coredns-config.ts";
import { generateHaproxyConfig } from "./haproxy-config.ts";
import { compileRuleSet, type RuleInputs } from "./haproxy-rules.ts";
import { buildUrlRules, type UrlRule } from "./url-rules.ts";
import { parseAndValidateKnownBlockedRules, parseAndValidateRules } from "./wildcard-rules.ts";

/**
 * Thrown when an ACL rule input (allowed_https_rules/allowed_http_rules/
 * allowed_ip_rules/known_blocked_rules) fails to parse. Shared by the setup
 * and run actions, which both accept the same rule syntax.
 */
export class InvalidRulesError extends ActionError<"INVALID_RULES"> {}

/**
 * Rethrow a rule-parser's syntax errors as an InvalidRulesError.
 */
export function parseRulesOrThrow(rulesInput: string | undefined): string[] {
  try {
    return parseAndValidateRules(rulesInput);
  } catch (e) {
    throw new InvalidRulesError(errorMessage(e), "INVALID_RULES");
  }
}

/**
 * Same, for `known_blocked_rules`, whose missing ports are completed rather
 * than rejected; see completeRulePort.
 */
export function parseKnownBlockedRulesOrThrow(rulesInput: string | undefined): string[] {
  try {
    return parseAndValidateKnownBlockedRules(rulesInput);
  } catch (e) {
    throw new InvalidRulesError(errorMessage(e), "INVALID_RULES");
  }
}

/**
 * buildUrlRules, rethrowing its syntax errors as an InvalidRulesError.
 */
export function buildUrlRulesOrThrow(rulesInput: string | undefined): UrlRule[] {
  try {
    return buildUrlRules(rulesInput);
  } catch (e) {
    throw new InvalidRulesError(errorMessage(e), "INVALID_RULES");
  }
}

/**
 * Stand-in for the proxy's own address, which only the container knows. The
 * generators only interpolate it, so any address compiles the same.
 */
const PLACEHOLDER_PROXY_ADDRESS = "192.0.2.1";

/**
 * Compile already-parsed rules the way the proxy does when it starts, so a
 * rule its compilers refuse is refused here rather than stopping the
 * container. Every engine's compilation is run whatever the engine, the
 * rules being the same syntax on both.
 *
 * @throws {InvalidRulesError} if any compiler refuses a rule
 */
export function checkRulesCompileOrThrow(inputs: RuleInputs): void {
  try {
    generateHaproxyConfig(inputs);
    generateCorednsConfig(compileRuleSet(inputs), { proxyAddress: PLACEHOLDER_PROXY_ADDRESS });
  } catch (e) {
    throw new InvalidRulesError(errorMessage(e), "INVALID_RULES");
  }
}

/**
 * An IP rule's host half, for a rule not written as a `~` regex: digits, dots
 * and wildcards, plus the `/` of a CIDR block. Anything else names a host,
 * and the IP path matches only the address a connection goes to.
 */
const IP_RULE_HOST = /^[0-9.*?/]+$/;

/**
 * parseRulesOrThrow for `allowed_ip_rules`, which also refuses a rule that
 * names a host rather than an address.
 */
export function parseIpRulesOrThrow(rulesInput: string | undefined): string[] {
  const rules = parseRulesOrThrow(rulesInput);
  for (const rule of rules) {
    if (rule.startsWith("~")) continue;
    if (!IP_RULE_HOST.test(rule.slice(0, rule.lastIndexOf(":")))) {
      throw new InvalidRulesError(
        `IP rule "${rule}" names a host, not an address. allowed_ip_rules is matched against ` +
          `the address a connection goes to; allow a name with allowed_https_rules or ` +
          `allowed_http_rules instead.`,
        "INVALID_RULES",
      );
    }
  }
  return rules;
}

export interface BuildACLRulesInput {
  httpsRulesInput: string | undefined;
  httpRulesInput: string | undefined;
  ipRulesInput: string | undefined;
}

export interface ACLRules {
  httpsRules: string[];
  httpRules: string[];
  ipRules: string[];
}

/**
 * Rules are kept as written (wildcard format) and validated eagerly.
 */
export function buildACLRules({
  httpsRulesInput,
  httpRulesInput,
  ipRulesInput,
}: BuildACLRulesInput): ACLRules {
  return {
    httpsRules: parseRulesOrThrow(httpsRulesInput),
    httpRules: parseRulesOrThrow(httpRulesInput),
    ipRules: parseIpRulesOrThrow(ipRulesInput),
  };
}
