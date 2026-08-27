# Inspect Proxy Engine (experimental)

> [!WARNING]
> `inspect` is an **experimental** engine. It terminates TLS inside the sandbox, so a tool that pins
> a certificate or ships its own trust store will not work under it. Read this page before relying
> on it. `universal` remains the default and recommended engine.

`inspect` terminates TLS inside the sandbox and re-signs it with a CA the isolated command is made
to trust. That is what lets it enforce on the method, path and query of a request rather than only
on its destination.

|                    | `universal` (default) | `inspect`                     |
| ------------------ | --------------------- | ----------------------------- |
| Interception       | network level         | network level                 |
| Visible to policy  | destination           | method, full URL, path, query |
| CA trusted by step | not needed            | **required**                  |

Nothing about `universal` changes when this engine is used, and it stays the default.

```yaml
- name: Start isolated-run
  uses: buildcage/isolated-run@d9c6a461166ef1489d43ecc9eca1cada10abf122 # v1.0.4
  with:
    proxy_mode: restrict
    proxy_engine: inspect
    allowed_url_rules: |
      GET|HEAD https://registry.npmjs.org/**
    run: npm ci
```

## Why this engine exists

Domain-level rules cannot separate fetching a package from publishing one. A step allowed to reach
a package registry to install dependencies is, under a host rule, equally allowed to publish to it
with a stolen token. Enforcing on the method and the path requires seeing inside the request, which
requires terminating TLS.

## Architecture

Two components, plus a CA-trust mount.

**HAProxy** does the inspecting, and the engine depends on three of its behaviours:

1. **It tells a TLS handshake from a plain request by its first bytes** (`req.ssl_hello_type`), so
   one listener takes both and no port has to be declared as plaintext or TLS in advance. That is
   what lets an audit run record everything without being configured for it first.
2. **It resolves the requested name itself and connects there**, only once a request has already
   passed the rules (`do-resolve` then `set-dst`), so where a connection ends up is never the
   command's choice, and a name a request would be refused for never triggers a real DNS query.
3. **It resolves `..` in the path before the rules see it** (`normalize-uri`), so a rule cannot be
   walked out of.

**CoreDNS** never resolves a name for real, allowed or not; it only decides what gets logged as
allowed or denied, which still has to match the rules exactly, on a regex rather than a domain
suffix; see [DNS](#dns).

**CA trust** is delivered differently here than in `buildcage/docker`'s own `inspect` engine.
There, a wrapper around `runc` writes the CA into the BuildKit worker's own disposable rootfs
layer for the life of one `RUN` step, then deletes it again before the layer is committed as a
snapshot — safe there because that rootfs is thrown away regardless. This action's sandbox rootfs
is instead a `mount --rbind /` of the **real host root** (see
[Isolation Mechanisms](./security.md#isolation-mechanisms)), so writing the CA the same way would
mean writing it onto the runner's own filesystem. Instead, the CA (and, where relevant, an
augmented copy of the system CA store) is written into this run's own scratch directory and
mounted _over_ the sandbox's view of the relevant paths in its OCI `config.json` — a
mount-namespace-scoped overlay, not a host write. Nothing needs to be undone afterward:
`run-isolated.sh`'s teardown removes it along with the rest of the sandbox's mount namespace when
the step ends, and the real host files those paths would otherwise resolve to are never touched.

## Rule syntax

A rule is a method list, a space, then a URL pattern. Because a rule contains a space, this input is
newline separated.

```yaml
allowed_url_rules: |
  GET https://registry.npmjs.org/@myorg/**
  GET|HEAD https://example.com/public/*
  POST,PUT https://api.internal.example.com/v1/*
  * https://internal.example.com
```

Methods are separated by `|` or `,`, and `*` means any method. **The method is required.** There is
no default, so a rule always states what it permits and nobody has to guess what omitting it means.

| Pattern | In a domain                 | In a path              |
| ------- | --------------------------- | ---------------------- |
| `**`    | crosses dots                | crosses `/`            |
| `*`     | one or more characters      | one or more characters |
| `?`     | one character               | one character          |
| `~`     | raw regex for the whole URL |                        |

**A wildcard may sit among literal text here**, in a path segment as in a domain label:
`abc*.amazonaws.com`, `/pkg-*/**`. `universal`'s own rule syntax requires a label containing `*`
to be exactly `*` or `**`, and for it that is only a restriction on phrasing. For `inspect` it would
be a hazard, because an author who cannot write `abc*` has to widen the rule to `*.amazonaws.com`
instead — and CoreDNS's allow/deny decision is generated from the same host pattern the HTTP rule
is, so a wider host is a wider grant on both sides at once, not just a less precise log line. The
grammar lives in its own compiler, so relaxing it cannot change what `universal` accepts.

**A path or method never narrows what a wildcard host resolves.** DNS has no notion of a path: a
rule of `GET https://*.example.com/release/**` still makes CoreDNS log any name under
`*.example.com` as allowed, `SECRET-DATA.example.com` included, because the allow/deny decision is
host-only by construction — the path is only enforced afterward, by HAProxy. This is not a gap: it
is exactly why CoreDNS never resolves anything for real (see [DNS](#dns)) — the query itself cannot
leak a path that was never sent, and the request that follows is refused all the same, before it
ever reaches an origin. Writing the host half as narrowly as the name actually needs is what
narrows the DNS-layer exposure; the path half narrows only the HTTP-layer one.

`allowed_https_rules` and `allowed_http_rules` keep their existing `host:port` syntax and meaning,
and are equivalent to a URL rule with any method and any path.

A rule may name an address rather than a name, in `allowed_url_rules` or the host rules. The proxy
resolves the Host header to decide where to connect, and no resolver can answer an address, so one
is taken as it stands instead of being asked about. Nothing is loosened by that: the rules are
matched against the same Host header and still decide, and what the command connected to is
discarded either way. The pattern is strict about its octets, because whatever it admits is used
unresolved; `999.1.2.3`, `010.0.0.1` and `1.2.3.4.evil.example` all fail it and are refused.

Unlike `allowed_ip_rules`, which tunnels without looking, an address reached this way stays
inspected, so method and path rules apply to it. Over HTTPS the origin's certificate still has to be
valid for the address, which means an IP SAN; most are not, so an address is usually a plaintext or
a passthrough destination in practice.

`allow_tls_rules` takes the same `host:port` syntax and covers TLS that is not HTTPS: the SNI and
the destination port are checked and the connection is passed through undecrypted, so the isolated
command validates the origin's own certificate. The name is still resolved here, so a passthrough
goes where we resolved it and not where the command aimed. `allowed_ip_rules` covers the same for a
destination with no name at all.

## How a request is handled

```
                        ┌─────────────────────────────────────────┐
   run: ──redirect──▶   │ detect (mode tcp)                       │
                        │   first bytes: handshake or plain?      │
                        └───┬──────────────┬──────────────┬───────┘
                            │              │              │
              ip/tls rule   │      TLS     │    plaintext │
                            ▼              ▼              ▼
                     ┌────────────┐  ┌──────────┐  ┌──────────┐
                     │ passthrough│  │ https_in │  │ http_in  │
                     │  mode tcp  │  │ TLS ter- │  │          │
                     │  undecryp- │  │ minated, │  │          │
                     │  ted       │  │ cert per │  │          │
                     └─────┬──────┘  │ SNI      │  └────┬─────┘
                           │         └────┬─────┘       │
                           │              │             │
                           │      normalize the path    │
                           │      resolve the name here │
                           │      match host/path/method│
                           │              │             │
                           ▼              ▼             ▼
                        origin      origin (TLS,   origin
                                    cert checked)
```

A certificate is generated from the SNI alone, so **a refused destination is never contacted**: the
only path that reaches an origin is the backend, and a request that no rule allows never gets there.
The origin's certificate is checked on that same connection, which is why the check applies exactly
where it matters.

## Expected behaviour

Everything below was verified against HAProxy rather than reasoned about.

### Per rule kind

| Rule                  | What it permits                            | Decided by           | Decrypted |
| --------------------- | ------------------------------------------ | -------------------- | --------- |
| `allowed_https_rules` | any method and path on the host, over TLS  | Host header          | yes       |
| `allowed_http_rules`  | any method and path on the host, plaintext | Host header          | n/a       |
| `allowed_url_rules`   | the named methods on matching URLs         | Host header and path | yes       |
| `allow_tls_rules`     | TLS to the named host and port             | SNI and port         | **no**    |
| `allowed_ip_rules`    | TCP to the address and port, any protocol  | address and port     | **no**    |

### Attempts to get around the rules

| What the isolated command does                         | What happens                                                                                                             |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| Asks for any name, on or off the allowlist             | Answered locally with the proxy's own address; the query is never forwarded, allowed or not                              |
| Requests a host no rule covers                         | **403**, recorded with its full URL, origin never contacted                                                              |
| Requests a path or method no rule covers               | **403**, recorded with its full URL                                                                                      |
| Walks out of an allowed path with `..`                 | **403**: the path is normalised before the rules see it                                                                  |
| Encodes the traversal as `%2e%2e` or `..%2f`           | **403**: decoding happens first, and what no normaliser can strip is refused outright                                    |
| Uses a backslash, raw or `%5c`, to climb               | **403**: the URL standard treats `\` as `/` for http(s), so a raw backslash is refused outright and `..%5c` like `..%2f` |
| Sends an allowed name while aiming elsewhere           | Reaches the address **we** resolved, not the one it chose                                                                |
| Puts an address in the Host header                     | Taken as the destination only if a rule names it; the rules decide either way                                            |
| Points `/etc/hosts` at an address of its choosing      | Same: the command's address is discarded                                                                                 |
| Allowlists a name that resolves to an internal address | **403**: the resolved address is refused if it is loopback, link-local, the proxy itself, or another never-public range  |
| Reaches an allowed host presenting a wrong certificate | **503**: the origin certificate is checked when HAProxy connects                                                         |
| Speaks a protocol that is not TLS on any port          | Classified by its first bytes, so it is parsed as HTTP if it is HTTP                                                     |
| Ignores the proxy variables entirely                   | No effect: interception is at the network level                                                                          |

Destination spoofing is **removed rather than detected**. HAProxy discards the address the command
picked and connects to the one it resolved itself, so there is no mismatch to catch and a legitimate
request still works.

### Audit mode

`proxy_mode: audit` records without enforcing: the rule ACLs are not emitted, so nothing is refused
on either listener, while the method and full URL of every request are still recorded. `set-dst` and
the origin certificate check stay in place, because neither can be dropped honestly.

Because one listener classifies by content, **audit needs no configuration to record everything**,
including plaintext on a port nobody declared. That is the point of the engine: a step's traffic
can be learned before any rule is written.

**The resolver still answers every query locally, even under audit.** It never forwards, in either
mode; forwarding would make it a live exfiltration channel for any name the step only looks up,
never connecting to. Audit's own let-everything-through policy is HAProxy's job: with no ACL to deny
it, `do-resolve` runs for every request and reaches the real address directly, so the mode whose
whole purpose is to observe real traffic still does. Every query CoreDNS sees is still logged as
allowed, so a name that was only looked up still appears in the report.

**Audit is not a passive observer.** TLS is still terminated, so a tool that pins a certificate, or
that consults a trust store the sandbox cannot reach, fails under `audit` exactly as under
`restrict`. That differs from `universal`, whose audit mode inspects nothing and breaks nothing.

### The resolved address, not just the name

The rules check the name; nothing about the name says where it resolves. An attacker who controls
DNS for an allowlisted domain, or a dependency's own domain that has been pointed inward, can make an
allowed name resolve to an internal address. The isolated command itself cannot reach that address
(it resolves the same name inside its own network namespace), but the **proxy** connecting on its
behalf sits directly on the runner, with whatever the runner can see. The loudest case is a cloud
metadata endpoint at `169.254.169.254` handing back credentials.

So a **resolved** destination is refused if it lands in a range that is never a legitimate public
origin: loopback, link-local (all of AWS/GCP/Azure IMDS), CGNAT (Alibaba IMDS), the IETF protocol
block (Oracle IMDS), their IPv6 equivalents, and the proxy's own address. An allowlisted name
pointing at `169.254.169.254` is refused with 403, before anything connects to it.

RFC1918 is deliberately **not** in that set: a name pointing at an internal mirror is a real, intended
setup. To reach one of these ranges on purpose, name the **address** in a rule rather than a name that
resolves to it. An explicitly named address is exempt, having been asked for rather than arrived at.

## Network isolation

The same boundary `universal` uses, unaffected by the choice of engine — see
[Isolation Mechanisms](./security.md#isolation-mechanisms). In short: a dedicated veth pair (fixed
addressing, `172.20.0.1` for the proxy/gateway, `172.20.0.101` for the isolated command — no bridge,
since it is always a 1:1 connection) puts every step's traffic through a single proxy container; the
proxy's `sandbox0`-facing `iptables` redirects all TCP to the one listener above and drops
everything else, including `FORWARD`, so a packet that escaped redirection goes nowhere. Only TCP is
redirected, so this also stops UDP and ICMP: the isolated command has no way out over either, and
IPv6 is dropped outright the same way `universal` drops it.

## DNS

**Every name is answered locally with the proxy's own address, allowed or not.** CoreDNS never
forwards a query anywhere: a step can exfiltrate through the query itself
(`SECRET-DATA.amazonaws.com` would reach an attacker's own authoritative nameserver the moment it is
forwarded, no connection ever needed), and closing that off unconditionally is simpler, and safer,
than closing it off only for the names a rule happens to deny. All the resolver decides is what gets
logged as `allowed` or `denied`, which still has to match the rules exactly, on a regex rather than a
domain suffix — `universal`'s own resolver can only express `/amazonaws.com/`, which covers
everything beneath it, so a rule of `abc*.amazonaws.com` would be logged as allowed for names it
never meant to grant. That precision is why this engine uses **CoreDNS** in place of
`universal`'s resolver.

```
# Allowlisted names are logged as allowed, but answered exactly like a denied
# one below: this resolver never gets a request any closer to a real address.
. {
    view allowlist {
      expr name() matches '^(abc[^.]*\\.amazonaws\\.com|registry\\.npmjs\\.org)\\.$'
    }
    template IN A   { answer "{{ .Name }} 60 IN A <proxy-ip>" }
    template IN AAAA { }
    log . "buildcage dns allowed name={name}"
}

# Everything else: the same answer, logged as denied instead.
. {
    template IN A   { answer "{{ .Name }} 60 IN A <proxy-ip>" }
    template IN AAAA { }
    log . "buildcage dns denied name={name}"
}
```

The query never leaves either way, so the exfiltration channel stays shut regardless of how wide a
rule turns out to be — a name outside the allowlist is **answered locally with the proxy's own
address**, not NXDOMAIN, so the step connects there and the full URL including its query string is
recorded before the request is decided on. NXDOMAIN would close the channel just as well but leave
only a bare name in the log.

**Real resolution happens exactly once, in HAProxy, strictly after a request has already passed the
full rule check** (host, path and method) — never through CoreDNS, and never before that check. This
ordering is a security invariant, not an optimisation: getting it backwards would make HAProxy's own
`do-resolve` a live exfiltration channel of exactly the kind CoreDNS was built to avoid being, for
any request the rules were always going to refuse. It is also why a wildcard host is never made safer
by pairing it with a path or method restriction: DNS has no notion of a path, so `SECRET-DATA` under
an allowed `*.example.com` is logged as allowed the moment it is looked up, before any path is even
known — see [Rule syntax](#rule-syntax). The request that follows is still refused, and still never
reaches an origin; only the log line, not the outcome, reflects the host-only nature of this
resolver's decision.

## What the report reads

Job Summary generation reads **two** logs from the throwaway proxy container, not one, right before
it is stopped at the end of the step.

| Log                        | What only it holds                                               |
| -------------------------- | ---------------------------------------------------------------- |
| `/var/log/haproxy/current` | Every request, with its method, full URL, status and size        |
| `/var/log/coredns/current` | Names the resolver refused, which never reached the proxy at all |

Leaving the resolver's log out would let a step exfiltrate through a DNS query alone and have the
report show nothing, since no connection is ever made in that case.

Refused requests carry their full URL, which is what this engine has and `universal` does not: the
request is read before it is decided on, and the origin is never contacted. A blocked entry
therefore names the exact URL that was attempted, query string included, rather than a bare host.

### One timeline

Everything the step did appears in order, refusals interleaved with the rest.

```
✅ 00:00.512: GET https://registry.npmjs.org/express -> 200 (99.9KB)
🚫 00:01.048: DNS secret-data.attacker.example -> dns-not-allowed
🚫 00:01.390: POST https://registry.npmjs.org/express/-rev/1-abc -> not-allowed
✅ 00:02.115: TLS db.example.com:5432 -> (12.3KB)
🚫 00:02.601: GET https://absent.example.com/ -> dns-failed
```

Every time is relative to when the proxy itself started, not an absolute clock reading: `MM:SS.mmm`,
widening to `HH:MM:SS.mmm` only once a run passes an hour.

A refusal names its reason rather than a status: 403, 502 and 503 mean a rule, a name that would not
resolve, and an origin that could not be reached or verified, and the number does not say which.

An undecrypted passthrough is here too, with the byte count and nothing else, because that is all
there is to know about it. Without it the traffic a step was explicitly allowed to tunnel would be
the only thing the report could not show.

Names that merely resolved are left out. The request that followed already says the name resolved,
and listing both doubles every line.

The proxy prints one guaranteed line at startup. An empty log is otherwise ambiguous between "saw
nothing" and "never ran", and reporting "nothing was blocked" for a proxy that never started is the
dangerous reading of the two.

## From audit to restrict

An `audit` report ends with the `allowed_url_rules` that would have permitted exactly what the step
did, ready to paste into a `restrict` run. Generating them is the engine's reason for existing: a
workflow author cannot know in advance which URLs `npm install` reaches, so the rules have to be
learned from a real run.

A real `npm ci`, audited, produces something like this:

```yaml
allowed_url_rules: |
  GET https://registry.npmjs.org/**
  POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk
```

Which is the whole argument for the engine in three lines. npm does POST to the registry, for the
advisory check. `allowed_https_rules: registry.npmjs.org:443` permits that POST and every other one
on the same host, publishing included; these rules permit the one endpoint npm actually used.

A generated rule must never permit more than was observed, so:

- **Hosts are enumerated, never generalised.** `a.example.com` and `b.example.com` never become
  `*.example.com`. HAProxy's own rule check is generated from these same patterns, so a widened host
  is a wider grant there too, not only a less precise one in the DNS log.
- **Methods are listed exactly**, never `*`.
- **A path keeps its longest unchanging prefix**, and only what varied becomes `**`. A single
  observed path stays exact.

Grouping is by origin and method before paths are compared, so a path only a `POST` reached cannot
become reachable by `GET`. Groups that end up with the same pattern are merged back into one rule,
which is what keeps `GET|HEAD` on one line.

A host reached at many unrelated paths therefore collapses to `/**`. That is the honest answer: the
alternatives are listing every URL, which nobody can maintain, or clustering them, which invents
permissions nobody observed. Such a rule still constrains the method, which no host-level rule can.

The rules are a starting point, not an answer. A URL carrying a version or a date will not match the
next run, and anything reached through `allow_tls_rules` or `allowed_ip_rules` is absent, having
never been inspected.

A `~` regex rule cannot be split into a host and a path, so it cannot be matched by an engine that
matches the two separately. The generator warns and emits nothing for it; such a rule needs an
`allowed_https_rules` entry for the host it targets.

## Limitations

- **TLS is terminated.** A tool that ships its own trust store, or that pins a certificate, will not
  work. The mounted CA-trust files point the common CA-trust environment variables (below) at a
  store carrying the CA, but a tool that consults none of them cannot be reached. The JVM (Java,
  Kotlin, Scala, ...) is one such case: it only reads its own `cacerts` file, which nothing here
  points anywhere, so it is not supported yet.
- **A variable already pointing somewhere is left alone, not appended to.** If a step's own
  environment already sets one of the variables below to some path, this action leaves it exactly
  as it is rather than appending the CA to whatever it already points at — doing that safely needs
  resolving that path against the sandbox rootfs without a host-escape via a symlink, which this
  initial support does not implement yet. Only an unset variable is pointed at the CA.
- **The CA is added to a store that already exists, not created.** A step whose environment has
  nothing resembling a system CA bundle at any of the well-known paths has nothing for this action
  to add to. This only matters to a tool that needs TLS trust for something.
- **`allow_tls_rules` and `allowed_ip_rules` are uninspected by design.** They are recorded, with a
  byte count, but nothing inside them is.
- **Query strings are kept in the log**, so a credential passed as a query parameter is recorded
  there as well. They are kept because that is also where an exfiltration payload goes.
- **No content digests, and no SLSA-style materials** for what was fetched — nothing here attests to
  what a request actually returned, only that it was made and to what.
- **A rule cannot narrow a destination reached by address.** `allowed_ip_rules` takes an address or
  a CIDR block; a pattern is refused rather than approximated.
- **UDP is dropped**, so anything using QUIC or HTTP/3 falls back to TCP or fails. Port 53 to the
  gateway is the sole exception, which is the resolver. ICMP is dropped too.

### CA-trust environment variables

Where a variable below is unset, this action points it at the CA depending on what the variable
means to the tool that reads it: some add to a built-in set, so pointing them at a file holding only
this CA leaves everything else trusted; others replace the bundle outright, so those are pointed at
the (augmented) system store instead. If the variable is already set, it is left untouched — see
[Limitations](#limitations) above.

| Variable              | Read by                                                                                                 | If unset                                          |
| --------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `NODE_EXTRA_CA_CERTS` | Node.js                                                                                                 | Additive — pointed at a file holding only this CA |
| `DENO_CERT`           | Deno                                                                                                    | Additive — pointed at a file holding only this CA |
| `CURL_CA_BUNDLE`      | curl                                                                                                    | Left unset — curl already reads the system store  |
| `REQUESTS_CA_BUNDLE`  | Python `requests`                                                                                       | Replaces the bundle — pointed at the system store |
| `PIP_CERT`            | pip                                                                                                     | Replaces the bundle — pointed at the system store |
| `SSL_CERT_FILE`       | OpenSSL, and anything reading it (Go's `crypto/x509` on Unix, Ruby, wget, Rust's `rustls-native-certs`) | Replaces the bundle — pointed at the system store |
