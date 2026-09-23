/**
 * The gateway the build reaches the proxy and its resolver through. CoreDNS
 * answers every name with it, so a connection sent there was named rather than
 * addressed, and its destination says nothing about which name.
 *
 * Written into both engines' s6 scripts and haproxy.cfg.template, which cannot
 * import this, so a change here is a change there.
 */
export const PROXY_ADDRESS = "172.20.0.1";
