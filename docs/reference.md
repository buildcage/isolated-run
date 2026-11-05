# Reference

This page holds every input and output of the action, the rule grammar in full, what the report and
the traffic artifact contain, and how a `write-through:` entry is resolved. The
[README](../README.md) covers what Buildcage does and how to adopt it, and links here for the
details.

## Contents

- [Action inputs](#action-inputs)
  - [General inputs](#general-inputs)
  - [Network inputs](#network-inputs)
    - [Rule inputs](#rule-inputs)
  - [AWS key check inputs](#aws-key-check-inputs)
  - [Filesystem inputs](#filesystem-inputs)
  - [Filesystem audit inputs](#filesystem-audit-inputs)
  - [Spellings and values](#spellings-and-values)
- [Config file](#config-file)
- [Outputs](#outputs)
- [Operation modes](#operation-modes)
- [Rule syntax](#rule-syntax)
- [Report details](#report-details)
- [Blocked service names](#blocked-service-names)
- [Requests that never arrived whole](#requests-that-never-arrived-whole)
- [Connections that failed](#connections-that-failed)
- [AWS access key check](#aws-access-key-check)
- [Hidden query parameters](#hidden-query-parameters)
- [Traffic artifact](#traffic-artifact)
- [Filesystem audit](#filesystem-audit)
- [Working directory](#working-directory)
- [CA trust variables](#ca-trust-variables)
- [`ephemeral` overlays](#ephemeral-overlays)
- [`write-through` paths](#write-through-paths)

## Action inputs

### General inputs

| Input               | Default   | Description                                                                                                                                                                 |
| ------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `run`               | required  | Command(s) to run inside the isolated sandbox under `bash -e`. See [How `run` is executed](../README.md#how-run-is-executed).                                               |
| `working-directory` | workspace | The directory `run` starts in, relative to the workspace. Relative `write-through` paths and `config-file` resolve against it. See [Working directory](#working-directory). |
| `config-file`       | empty     | A YAML file in the workspace, relative to the working directory or absolute, that sets the other inputs. See [Config file](#config-file).                                   |
| `label`             | empty     | Label appended to this step's Job Summary heading, e.g. `npm ci`, to tell repeated steps apart.                                                                             |

### Network inputs

| Input                             | Default    | Description                                                                                                          |
| --------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------- |
| `proxy-mode`                      | `restrict` | `audit` or `restrict`. See [Operation modes](#operation-modes).                                                      |
| `proxy-engine`                    | `inspect`  | `inspect` or `universal`. See [Engines](../README.md#engines).                                                       |
| `fail-on-blocked`                 | `true`     | Fail the step when a connection was blocked; ignored in `audit` mode.                                                |
| `fail-on-ca-residue`              | `true`     | `inspect` only. `false` turns a copy of the CA in Chromium's NSS database into a warning. See [Chromium](#chromium). |
| `upload-traffic-artifact`         | `false`    | Upload the observed traffic as a JSON artifact. See [Traffic artifact](#traffic-artifact).                           |
| `traffic-artifact-retention-days` | empty      | How long to keep that artifact, in days. See [Spellings and values](#spellings-and-values).                          |

#### Rule inputs

All of these are empty by default. The `allowed-*` inputs are additive: a connection is allowed
when any rule in any of them matches. `known-blocked-rules` allows nothing; it marks blocks you
expect. Which ones apply depends on the engine.

| Input                                  | `inspect` | `universal` | What one rule matches                                                                           |
| -------------------------------------- | :-------: | :---------: | ----------------------------------------------------------------------------------------------- |
| [`allowed-url-rules`][url-rules]       |    ✅     |      -      | A method and a URL: `GET https://registry.npmjs.org/**`                                         |
| [`allowed-https-rules`][host-rules]    |    ✅     |     ✅      | A host and port reached over HTTPS: `registry.npmjs.org:443`                                    |
| [`allowed-http-rules`][host-rules]     |    ✅     |     ✅      | A host and port reached over plain HTTP: `deb.debian.org:80`                                    |
| [`allowed-ip-rules`][ip-rules]         |    ✅     |     ✅      | An address and port, for connections made without DNS: `192.168.1.1:443`                        |
| [`allowed-tls-rules`][tls-rules]       |    ✅     |      -      | A TLS destination to pass through undecrypted, judged on SNI: `db.example.com:5432`             |
| [`known-blocked-rules`][blocked-rules] |    ✅     |     ✅      | A host, or (on `inspect`) a method and URL, expected to be blocked, so it doesn't fail the step |

[url-rules]: #url-rules-allowed-url-rules
[host-rules]: #host-rules-allowed-https-rules-allowed-http-rules-allowed-ip-rules-known-blocked-rules
[ip-rules]: #ip-addresses-allowed-ip-rules
[tls-rules]: #tls-passthrough-allowed-tls-rules
[blocked-rules]: #blocked-rules-known-blocked-rules

Under `inspect`, `allowed-https-rules` and `allowed-http-rules` still work and are kept for
compatibility, but `allowed-url-rules` covers them: a host rule is the same as a URL rule with any
method and any path.

Setting a rule the engine can't act on is caught before the command starts. `restrict` fails, since
the step would otherwise run without a protection its rules appear to give it. `audit` warns and
ignores the rule.

Each `allowed-*` input can hold about 128 KiB of rules, the most Linux passes in one environment
variable. Only the rules count, not comments or blank lines. A larger input fails the step before
the command starts; write fewer, broader rules, such as [wildcards](#wildcards). This only matters
with `config-file`, since a value set in the workflow already has to fit for the runner to start the
step.

### AWS key check inputs

Both are `inspect` only and **experimental**. See [AWS access key check](#aws-access-key-check).

| Input                       | Default | Description                                                                                                                                                                            |
| --------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `aws-key-check`             | `false` | Block AWS API requests signed with any key but the step's own `AWS_ACCESS_KEY_ID`.                                                                                                     |
| `allowed-aws-role-accounts` | empty   | AWS accounts whose roles the step may assume; the keys those roles issue, and static CodeCommit Git credentials of these accounts, pass the check too. Requires `aws-key-check: true`. |

### Filesystem inputs

| Input             | Default      | Description                                                                                              |
| ----------------- | ------------ | -------------------------------------------------------------------------------------------------------- |
| `write-through`   | empty        | Paths whose writes reach the real host filesystem. See [`write-through` paths](#write-through-paths).    |
| `filesystem-mode` | `persistent` | `persistent` or `ephemeral` (**experimental**). See [Filesystem access](../README.md#filesystem-access). |

### Filesystem audit inputs

All of these are **experimental**. See [Filesystem audit](#filesystem-audit).

| Input                              | Default | Description                                                                                                                                                                                             |
| ---------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `filesystem-audit`                 | `off`   | `off` or `record`; `record` logs the step's file accesses.                                                                                                                                              |
| `expected-filesystem-rules`        | empty   | The file accesses the step is expected to make; the summary then lists only those outside them. Requires `filesystem-audit: record`.                                                                    |
| `fail-on-unexpected-file-access`   | `false` | Fail the step when an access fell outside `expected-filesystem-rules` (every access, when none are set) or could not be checked against them, in `audit` mode too. Requires `filesystem-audit: record`. |
| `upload-filesystem-audit-artifact` | `false` | Upload the filesystem audit's full record as an artifact.                                                                                                                                               |
| `filesystem-audit-retention-days`  | empty   | How long to keep that artifact, in days. See [Spellings and values](#spellings-and-values).                                                                                                             |

### Spellings and values

Each input named with hyphens also takes its name spelled with underscores (`proxy_mode` for
`proxy-mode`), as earlier versions named it. When a workflow sets both spellings, a list input (the
rule inputs, `write-through`, `expected-filesystem-rules`) takes the lines of both, and any other
input takes the hyphenated value, warning when the two differ.

Each input takes only the values below. Any other value fails the step before the sandbox is set
up.

- An input whose default is `true` or `false` takes only those two values.
- `filesystem-mode` and `filesystem-audit` take only the two values their rows name.
- A `-retention-days` input takes a whole number of days above zero. A value above the
  repository's maximum is lowered to it, with a warning.
- An input left empty takes its default. For a `-retention-days` input, that is the repository's
  own default.

## Config file

`config-file` names a YAML file in the repository that sets any input but `run`, `working-directory`
and the deprecated `writable` ([The former input names](#the-former-input-names)), so the policy can
sit beside the code that needs it:

```yaml
# path/to/buildcage-config.yml
proxy-engine: inspect
allowed-url-rules: |
  GET https://registry.npmjs.org/**
known-blocked-rules: |
  telemetry.example.com
```

```yaml
- uses: actions/checkout@<sha>
- uses: buildcage/isolated-run@<sha>
  with:
    config-file: path/to/buildcage-config.yml
    run: npm ci
```

- Each key is an input name, in either spelling, and each value is written as it would be under
  `with:`. The step fails on a key that is not an input, on `writable` (use `write-through`), on a
  value that is a list or a nested mapping, and on an input set under both spellings. The exception
  is an input whose other spelling comes in through a merge key (`<<`): the file's own key then
  wins.
- An input the workflow sets wins over the file. The rule inputs, `expected-filesystem-rules`
  among them, and `write-through` are the exception: the file's lines are added to the workflow's.
- A relative path is relative to the [working directory](#working-directory), `$GITHUB_WORKSPACE`
  unless `working-directory` is set. An absolute path, such as
  `${{ github.workspace }}/buildcage.yml`, is taken as it is. Either way the file, with its
  symlinks resolved, must be inside `$GITHUB_WORKSPACE`, and a `..` may only start a relative
  path. The repository has to be checked out by an earlier step.
- `config-file` fails the step on `pull_request_target`, and on `workflow_run` triggered by a pull
  request event: the workspace there can hold the pull request's own code, which could rewrite the
  file. Set the inputs in the workflow on those events.
- On any other event the file is read as the workflow checked it out, so whoever can write that
  copy sets its rules. A workflow that checks out a pull request's code on `issue_comment`, for
  example, takes the rules from the pull request.

## Outputs

| Output                           | Description                                                                                                                                              |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `traffic-artifact-name`          | Name of the uploaded traffic artifact, when `upload-traffic-artifact` produced one. Empty otherwise, including when the upload failed.                   |
| `filesystem-audit-artifact-name` | Name of the uploaded filesystem audit artifact, when `upload-filesystem-audit-artifact` produced one. Empty otherwise, including when the upload failed. |

Each is also set under its name spelled with underscores, `traffic_artifact_name` and
`filesystem_audit_artifact_name`.

## Operation modes

| `proxy-mode` | What it does                                                      | When to use it                                            |
| ------------ | ----------------------------------------------------------------- | --------------------------------------------------------- |
| `audit`      | Logs every destination the command reaches and enforces no rules  | First setup, adding a dependency, investigating a failure |
| `restrict`   | Allows only what the rules match, blocks and logs everything else | Everyday workflows, security-critical steps               |

`audit` allows what the active engine can classify. A connection it cannot classify, such as an HTTP
request carrying no `Host` header, is still blocked, on each engine's own terms.

Because `audit` enforces nothing, the `allowed-*-rules` have no effect in it; you write them when
you move to `restrict`. Any other `proxy-mode` value, a differently cased one included, fails the
step.

Under `inspect`, `audit` still terminates TLS, so a tool that pins a certificate fails there as it
would under `restrict`. `universal` decrypts nothing in either mode.

If you forget a domain the command needs, `restrict` blocks it and the step fails with the
destination named. Run `audit` first to find those domains.

## Rule syntax

`allowed-url-rules` and `allowed-tls-rules` need `proxy-engine: inspect`. The host rules work with
every engine.

<a id="url-rules-allowed_url_rules"></a>

### URL rules: `allowed-url-rules`

A rule is a method list, a space, then a URL pattern. Because a rule contains a space, this input is
newline-separated. The method is required, so a rule always states what it permits. A `#` at the
start of a line, or after whitespace, begins a comment that runs to the end of the line, and a blank
line is ignored, so a long list can be split into groups. A `#` with no whitespace before it does
not start a comment. Setup reports it as a mistake instead of trimming it, since `#` is part of no
host or URL and a fragment never travels with a request.

```yaml
allowed-url-rules: |
  # npm: fetch packages, and the audit endpoint it posts to
  GET https://registry.npmjs.org/**
  POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk

  # pip: one registry, two domains
  GET https://pypi.org/simple/**
  GET https://files.pythonhosted.org/packages/**

  # apt
  GET http://deb.debian.org/**

  # an internal service, on a non-default port
  GET|HEAD https://api.internal.example.com:8443/v1/*

  # anything at all on one internal host
  * https://tools.internal.example.com
```

Methods are separated by `|` or `,`, and `*` means any method. The port may be left out when it is
the scheme's default, and a pattern with no path allows any path on that host. A pattern may not
carry:

- a `#` fragment, which never travels with a request, so a rule carrying one would match nothing
- a query string (a `?` followed by text holding `=` or `&`), since a rule matches the path alone
  and the query is never compared
- a user name before an `@` in the host, which no request's `Host` carries

| Pattern | In a domain                                       | In a path                     |
| ------- | ------------------------------------------------- | ----------------------------- |
| `**`    | crosses dots                                      | crosses `/`                   |
| `*`     | one or more, not crossing a dot                   | one or more, not crossing `/` |
| `?`     | one character                                     | one character                 |
| `~`     | raw regex, split into a host half and a path half |                               |

In a URL rule a wildcard may sit among literal text, inside a domain label or a path segment. Host
rules don't allow that:

```yaml
allowed-url-rules: |
  GET https://abc*.amazonaws.com/**
  GET https://example.com/pkg-*/**
```

A path or method never narrows what a wildcard _host_ resolves. See
[Inspect Proxy Engine](./security.md#inspect-proxy-engine) for why, and for how to write a host
pattern that doesn't widen more than intended.

A URL rule may name an address instead of a host, but it works only for plain `http`. Over HTTPS, a
client connecting to an address sends no SNI, so the proxy answers with a default certificate valid
for no name, and the proxy's own check of the origin's certificate never accepts an IP SAN either.
Pass TLS to an address through with `allowed-ip-rules` instead. Naming an address loosens nothing:
the rules still match against the `Host` header, and a request reached this way is still
inspected, so its method and path rules apply.

<a id="host-rules-allowed_https_rules-allowed_http_rules-allowed_ip_rules-known_blocked_rules"></a>

### Host rules: `allowed-https-rules`, `allowed-http-rules`, `allowed-ip-rules`, `known-blocked-rules`

`allowed-https-rules`, `allowed-http-rules` and `allowed-ip-rules` share one syntax; rules are
separated by whitespace, so one per line reads best, and comments work as in
[`allowed-url-rules`](#url-rules-allowed-url-rules). A host rule is equivalent to a URL rule with
any method and any path. `known-blocked-rules` extends this syntax and is newline-separated, since a
line there can also be a URL rule; see [Blocked rules](#blocked-rules-known-blocked-rules).

```yaml
allowed-https-rules: |
  registry.npmjs.org:443
  repo.maven.apache.org:443
  *.internal.example.com:443
  registry.internal.example.com:8443

allowed-http-rules: |
  deb.debian.org:80
```

#### Wildcards

| Pattern | Matches                                                     | Example                                                                  |
| ------- | ----------------------------------------------------------- | ------------------------------------------------------------------------ |
| `*`     | One or more characters **excluding** dots (single label)    | `*.example.com` matches `sub.example.com` but not `deep.sub.example.com` |
| `**`    | One or more characters **including** dots (multiple labels) | `**.example.com` matches `sub.example.com` and `deep.sub.example.com`    |
| `?`     | A single character excluding dots                           | `exampl?.com` matches `example.com`, `examplx.com`                       |

A label that contains `*` has to be exactly `*` or `**`. `abc*.example.com` is refused here; only
[`allowed-url-rules`](#url-rules-allowed-url-rules) takes a wildcard in the middle of a label.

Besides the wildcards, a label holds letters, digits, `-` and `_`, and nothing else. Write an
internationalized name in its punycode form (`xn--mnchen-3ya.de`, not `münchen.de`), the form a
connection carries. A leading, trailing or doubled dot is refused.

A `Host` header ending in a dot (`example.com.`) matches as the name without the dot. An SNI may not
end in a dot (RFC 6066), so one that does keeps it. Some rules are judged on the SNI:
`allowed-tls-rules`, `allowed-https-rules` under `universal`, and
[`sni-not-allowed`](#the-ones-buildcage-blocked). For those, a name ending in a dot matches only a
rule whose `**` can take in the dot (`example.**` or `**`, not `example.com.**`), or a `~` rule
written to allow the dot.

`**` alone matches an address too. Under `**:443`, a request sent to the proxy through any name but
carrying `Host: 10.0.0.5` is forwarded to that private address (see
[A name may not resolve inward](./security.md#a-name-may-not-resolve-inward)). A connection made
straight to an address is judged by `allowed-ip-rules` only.

#### Ports

Every host, IP and TLS rule must name a port. It is a decimal from 1 to 65535 without a leading zero
(`443`, not `0443`), or `*` for any port. A URL rule may leave its port out, and takes the same form
when it names one. A `~` rule's port is part of its regex and is not checked.

| Rule                 | Matches                                                       |
| -------------------- | ------------------------------------------------------------- |
| `example.com:443`    | `example.com` on port 443 only                                |
| `*.example.com:8443` | Any single-level subdomain of `example.com` on port 8443 only |
| `example.com:*`      | `example.com` on any port                                     |

`known-blocked-rules` is the exception: a host rule there that names no port is read as `:*`. It is
matched against rows of the report rather than against connections, and a row for a name the
resolver blocked has no port at all, since nothing was connected to. `telemetry.example.com` and
`telemetry.example.com:*` are the same rule.

<a id="blocked-rules-known_blocked_rules"></a>

### Blocked rules: `known-blocked-rules`

`known-blocked-rules` lists traffic that is expected to be blocked, so a run isn't failed over a
block you already know about. It does not allow anything: the traffic stays blocked. Use it for a
telemetry endpoint you want blocked but not treated as an error, where an allow rule would let the
request through.

Unlike the allow inputs it is newline-separated, one rule per line, because a line can be either
form:

- a **host rule** (`host:port`, the syntax above), which works on every engine; and
- a **URL rule** (a method and a URL, the [`allowed-url-rules`](#url-rules-allowed-url-rules)
  syntax), which needs `proxy-engine: inspect`, the only engine that sees a method or a path.

```yaml
known-blocked-rules: |
  # host rules: acknowledge every port on a name, or a specific one
  telemetry.example.com
  *.metrics.example.com:443

  # URL rules (inspect only): acknowledge one endpoint on an otherwise-allowed host
  POST https://api.example.com/telemetry
  * https://noisy.example.com/health
```

A URL rule marks only requests that carry the method and path it names, so it acknowledges one
endpoint on a host while any other blocked request to the same host still fails the step. A
host-level block (a name the resolver blocked, or a connection blocked before any request was
read) carries no method or path, so it is matched by a host rule, never a URL rule. Port handling
follows each form: a host rule with no port reads as `:*`, a URL rule with no port as the scheme's
default (`443`/`80`), exactly as in the allow inputs.

Under `proxy-engine: universal`, which never sees a method or a path, a URL line is handled like any
other [rule the engine can't act on](#rule-inputs): `restrict` refuses it and `audit` warns.

> **Migrating from v1.** `known_blocked_rules` was whitespace-separated, so several host rules could
> share a line. It is now newline-separated: put each rule on its own line.

<a id="ip-addresses-allowed_ip_rules"></a>

### IP addresses: `allowed-ip-rules`

Connections made straight to an address never go through DNS, so they are allowed separately from
any domain. IPv4 only, in decimal without leading zeros (`10.0.0.1`, not `010.0.0.1`, which HAProxy
reads as octal) and with a prefix length of 0 to 32; setup refuses anything else. A rule can be an
address, a CIDR block, a wildcard or a `~` regex, the same on every engine:

```yaml
allowed-ip-rules: |
  192.168.1.10:443
  10.0.0.0/8:443
  192.168.1.*:443
  ~^172\.16\.\d+\.\d+:5432$
```

A rule is matched against the address the connection goes to, not against a name the connection
carries, so setup refuses a rule that names a host. A `~` rule is not checked for this. Write it
against the address and port as digits, since a `~` rule that names a host matches nothing.

Inside the sandbox, every name resolves to the proxy's own address. An IP rule whose range covers
that address still does not allow a connection made through a name; the domain rules judge it.

A connection an IP rule allows is tunnelled without inspection: once an `ip:port` pair is allowed,
any TCP-based protocol can use that path. The proxy connects upstream as soon as the connection
arrives, without waiting for the client to send anything, so a protocol where the server speaks
first (SMTP, MySQL) works too. The connection goes to the address the client connected to, even
when it carries a name (under `inspect`, even a name an `allowed-tls-rules` entry lists). The
report lists it under the `IP` rule type. Prefer a domain rule where the destination has a stable
name.

A connection passed through this way or by `allowed-tls-rules`, any allowed HTTPS connection under
`universal`, and an upgraded WebSocket are closed after an hour in which nothing is sent either way.
An idle ssh session or pooled database connection stays open up to that limit.

<a id="tls-passthrough-allowed_tls_rules"></a>

### TLS passthrough: `allowed-tls-rules`

Use this for TLS traffic that isn't HTTPS, and for HTTPS whose client requires HTTP/2, such as gRPC:
`inspect` answers no ALPN, so such a client fails there. The SNI and port are checked and the
connection passes through undecrypted, so the command validates the origin's own certificate. The
name is still resolved by the proxy, so a passthrough goes where the proxy resolved it and not where
the command aimed:

```yaml
allowed-tls-rules: |
  db.example.com:5432
  repo.maven.apache.org:443
```

The second rule above is the shape to use for a JVM build whose keystore Buildcage cannot inject
into (a keystore under a non-default password, or a runner with no `keytool` outside the writable
paths). A JVM already on the runner otherwise trusts the injected CA without a passthrough.

The rules take the [host rule][host-rules] syntax: they are separated by whitespace, and comments
work as in [`allowed-url-rules`](#url-rules-allowed-url-rules).

### Regular expressions

Prefix a rule with `~` to use a regular expression. A host rule's pattern is matched against
`domain:port` as one expression, so the port is part of the pattern and can be a regex itself. The
port is required, since the text a pattern is matched against always carries one, so a `~` host rule
with no `:` in it is refused. `known-blocked-rules` is the exception: it reads such a rule as any
port.

| Rule                              | Effect                                                     |
| --------------------------------- | ---------------------------------------------------------- |
| `~^example\.com:443$`             | Matches `example.com` on port 443 only                     |
| `~^example\.com:\d+$`             | Matches `example.com` on any port                          |
| `~^.*\.example\.com:(443\|8443)$` | Matches any subdomain of `example.com` on port 443 or 8443 |
| `~^192\.168\.1\.\d+:80$`          | Matches a range of IP addresses (in `allowed-ip-rules`)    |

`^` and `$` are added where they are missing, so a pattern always covers the whole `domain:port`. An
IPv6 address is refused here as everywhere else in the rule syntax. A host name matches in any case,
as it does in a wildcard rule. The host part may not contain `'`, a backtick, `{$` or `{%`: no host
name does, and the resolver's configuration has no way to quote them.

The host part of a pattern also decides which names the resolver answers as allowed, and the
resolver matches it with RE2. Lookaround (`(?=`, `(?!`, `(?<=`, `(?<!`) and backreferences are
therefore refused there, in a URL rule's host half as well.

Setup checks a pattern with JavaScript's regular expressions, but the proxy runs it with PCRE2,
which reads some syntax differently or refuses it. Setup therefore refuses that syntax up front:

- A backslash may precede only punctuation, as in `\.`, one of
  `\d \D \w \W \s \S \b \B \n \r \t \f`, or a single-digit backreference such as `\1`. Any other
  letter or digit after a backslash is refused.
- A backreference must point to a group the pattern has. In a URL rule, the group must be in the
  same half.
- `\B` is refused inside a character class.
- A `]` right after `[` or `[^` is refused, and so is a POSIX class such as `[:alpha:]`. Escape the
  bracket (`[\]a]`) or write a range (`[a-z]`) instead.
- A `{` must open a quantifier such as `{2}` or `{1,3}`, since PCRE2 reads `{,3}` and `{ 1,3}` as
  quantifiers where JavaScript and RE2 read text. Write a literal brace as `\{`.
- A flag modifier such as `(?i:`, and one group name used in two alternatives, are refused: the
  proxy's configuration generator cannot compile them. A host needs no `(?i:`, since it matches in
  any case; in a path, spell each case as a class, as in `[Aa]`.

Other syntax that only JavaScript accepts, such as `[\d-z]`, passes setup and then stops the proxy
from starting.

In `allowed-url-rules` a `~` expression covers the URL, and is split at the first `/` after `://`:
everything before that `/` is matched against the host, everything from it onward against the path.
The scheme before `://` must be written `https`, `http` or `https?`, the last covering both; any
other spelling is refused, since the scheme decides which listener the rule is enforced on.

```yaml
allowed-url-rules: |
  # host half: example\.com   path half: /pub/.*$
  GET ~^https://example\.com/pub/.*$

  # the host half's port pattern can be any regex
  GET ~^https://example\.com:(443|8443)/.*$
  GET ~^https://example\.com:\d+/.*$

  # either scheme, each on its own default port
  GET ~^https?://example\.com/pub/.*$
```

Leave the port out and the rule matches the scheme's default port only, 443 for `https` and 80 for
`http`; there is no implicit any-port, so write `example\.com:\d+` to allow more. An SNI or `Host`
with anything but letters, digits, `.`, `_` and `-` in it never reaches a rule, even in `audit`
(see [security.md](security.md#the-proxy-chooses-the-destination-not-the-command)).

A top-level `|` is not supported in either a host rule or a URL rule. The anchors would bind to one
branch each, and a URL rule's two halves are compiled separately, so a choice spanning them has no
meaning. Keep the `|` inside a group, or write one rule per alternative:

```yaml
# not supported
allowed-url-rules: |
  GET ~^https://a\.example\.com/x$|^https://b\.example\.com/y$

# supported
allowed-url-rules: |
  GET ~^https://(a|b)\.example\.com/x$
  GET ~^https://a\.example\.com/x$
  GET ~^https://b\.example\.com/y$
```

A group cannot straddle the `/` the rule is split at either. A rule the split cannot handle is
refused with an error naming what to write instead.

## Report details

An alert under the report's title counts what needs a look: requests blocked, requests `restrict`
would block, connections that failed and requests nothing acted on. It is a CAUTION when a request
was blocked unexpectedly or the report is incomplete, and a WARNING otherwise. With nothing to
count, or only requests blocked as expected, there is no alert. In the tables that follow, blocked
requests are marked 🚫 and failed connections ⚠️.

A report that is not a full record of the step fails it under `restrict` with
`fail-on-blocked: true`, even when the rows it does hold are all allowed or matched by
`known-blocked-rules`, since what is missing could have been blocked. The report is not a full
record when:

- the log does not begin where the step did
- the log holds a line the report cannot read
- the proxy lost lines it could not write
- the proxy or the resolver restarted during the step, since a connection still open when the proxy
  stopped never gets its line
- the proxy's or the resolver's log writer died during the step, losing the lines it had not yet
  written
- the report could not confirm that the proxy lost no lines, or that no log writer died

In `audit` mode, or with `fail-on-blocked: false`, an incomplete report is a notice instead.

A proxy or resolver that does not answer the report, because it stopped during the step and stayed
down or because it hung, fails the step in both modes, regardless of `fail-on-blocked`. Requests and
lookups made while it was down failed instead of going around it, but nothing recorded them.

A log the report cannot fetch at all fails the step in both modes too, even while the proxy and the
resolver answer, since there is then no report. So does a report that cannot be built from logs it
did read.

Matching is per request, so a row that counts several requests to one host counts as expected only
when a rule accounts for every one of them: a URL rule that names one endpoint leaves the host's
other blocked requests to fail the step. The matched rows go under **Known Blocked Hosts**,
collapsed below the allowed hosts, instead of Blocked Hosts. Those rows are also folded into one row
per rule, named after the rule and counting the hosts behind it (`*.example.com:* (12 hosts)`). A
rule covering noisy traffic then costs the table one line however many hosts it names, which matters
most when the noise puts its payload in the name itself and every request brings a new long
hostname. The individual hosts stay in **Communication details**.

A name the step looked up and never connected to gets a row of its own, with `DNS` as the rule kind
and no port (folded like any other row when a `known-blocked-rules` rule matches it). Under
`inspect`, that row is the only trace of a name the step looked up and did not use, so it is where a
rule wider than the step needs shows up. A name that was connected to has no such row, since the
connection's own row already names it. A name whose every connection ended before a request keeps
the row, since [connections the client ended](#connections-the-client-ended) are in neither host
table.

### The Job Summary size cap

GitHub caps a Job Summary at 1 MiB per step, counting what the command itself wrote there, and drops
the whole summary rather than truncating it. The report is written first; what the command wrote
follows it, cut at a line boundary with a note and a warning when it does not fit in what is left.
A note and a warning replace what the command wrote when it is over 1 MiB on its own, as GitHub
would drop it whole; the step does not fail.

When the report itself, with its Filesystem Activity section if the filesystem audit was on, would
pass the limit, its parts give way in this order:

1. the file access details
2. the Communication details timeline
3. the known blocked hosts table
4. the Filesystem Activity table
5. the AWS keys table
6. the allowed table
7. the blocked and failed table
8. the ⚠️ tables of requests `restrict` would block
9. the `restrict` example

A part that does not fit is cut at a line boundary, with a note after what is kept. When nothing of
it fits, the note replaces it. The known blocked hosts table, the Filesystem Activity section's
accessed paths table and the example are never cut partway: each is kept whole or replaced by its
note. Once one of the other traffic tables is cut, the Communication details timeline and the known
blocked hosts table are left out under the same note. Likewise, once the Filesystem Activity table
is cut, the file access details are left out under its note.

The report is written to the Job Summary only, so what was cut is recovered from the
[traffic artifact](#traffic-artifact), or the filesystem audit's own artifact for its section; when
neither was uploaded, it is not kept anywhere.

## Blocked service names

A row whose reason is `dns-service-not-allowed` is a service-discovery name,
`_mongodb._tcp.cluster0.x.mongodb.net` and the like. Neither way of clearing it makes the record
resolve. Buildcage's resolver serves no discovery record at all (see
[Service discovery](../README.md#service-discovery)), so the answer stays empty either way. Only
whether the row fails the step changes.

1. **Allow the host the name belongs to** (`cluster0.x.mongodb.net`). The lookup is then reported as
   `discovery` instead and leaves the table, and the step may connect to that host. This is the
   useful one whenever the step was trying to reach the service.
2. **List the service name in `known-blocked-rules`** (`_mongodb._tcp.cluster0.x.mongodb.net:*`).
   The row moves to Known Blocked Hosts, folded under that rule, and stops failing the step. Nothing
   else changes, and the host stays unreachable.

Naming the service name in an `allowed-*` rule also clears the row, but it is the misleading option:
it reads as permission to reach something that nothing can connect to, and the record still does not
resolve.

## Requests that never arrived whole

A connection can end before a whole request has arrived. What the report does with one depends on
who ended it. If the client ended it, no rule decided it, and the report lists it as a
[connection the client ended](#connections-the-client-ended). If Buildcage would not read the bytes
as a request, the connection is [blocked](#the-ones-buildcage-blocked) like any other.

Under `universal`, only a plaintext connection made through a name gets this far. Its name would
have come from the request, which never arrived, so its host reads `(unknown)`. Under `inspect`,
the host is the name from the TLS handshake's SNI. When there is no SNI, the host is the address the
connection was sent to, and the row's rule type reads `IP`, since a connection to an address the
step wrote out itself could only have been passed by `allowed-ip-rules`. The exception is
Buildcage's own address, where every connection made through a name lands, because the resolver
answers each name with it. That address names nothing, so the host reads `(unknown)`. The address
is recorded either way, in the `destination` field of the [traffic artifact](#traffic-artifact).

A row carries no method or URL where no request line ever parsed. `missing-host-header` is the
exception: that one did parse, so it keeps the method and the path it asked for. Its URL is built
around the same host as the row, as HTTP itself does for a request with no `Host` (RFC 9112 §3.3),
with the port where it is not the scheme's default.

### Connections the client ended

A connection the client ended before it sent a whole request reached no rule and no origin, so it is
in neither host table. **Communication details** shows it with ⚠️ and how it ended. Under `inspect`,
one sent straight to an address is blocked instead, as
[`ip-not-allowed`](#the-ones-buildcage-blocked), or as `sni-not-allowed` where its SNI names a host
no rule allows.

```
⚠️ 00:09.123: HTTPS untrusted-ca.example.com:443 -> client-aborted
⚠️ 00:10.250: HTTPS untrusted-ca.example.com:443 -> client-tls-failed
⚠️ 00:11.407: HTTPS untrusted-ca.example.com:443 -> client-timeout
```

| Reason              | What happened                                                                           |
| ------------------- | --------------------------------------------------------------------------------------- |
| `client-aborted`    | the client closed without sending a request, after the TLS handshake if there was one   |
| `client-tls-failed` | the TLS handshake with the client failed (`inspect` only)                               |
| `client-timeout`    | the client held the connection open without sending a request until the timeout expired |

The commonest cause is a container with no `ca-certificates`: the client cannot verify the
certificate the `inspect` engine signs with, so every HTTPS request to that host ends at the
handshake, as `client-tls-failed`, or as `client-aborted` from a client that closes just after it.
The step's own output says so first, as a certificate verification error; installing
`ca-certificates`, or otherwise letting the client trust the CA, is what lets the requests through.
An `allowed-https-rules` entry changes nothing: the host has already resolved and been dialled.

A `client-aborted` or `client-timeout` is shown only where its host completed no other connection.
Where the same host also completed one, the close is a keepalive pool cleaning up after its work
rather than a failure, so it is left out of Communication details as noise. A `client-tls-failed` is
always shown, since another client reaching the host says nothing of whether this one trusts the CA.
The raw [traffic artifact](#traffic-artifact) keeps every one either way. None of them fails the
step, not even with `fail-on-blocked: true`. No rule blocked them, so `known-blocked-rules` has
nothing to match, and nothing reached an origin. A `::warning::` annotation gives the count of those
shown.

A protocol where the server speaks first (SMTP, MySQL, FTP) ends here too once it reaches the
plain-HTTP stage: the client waits for a greeting and the proxy waits for a request, so no rule is
ever reached. Every such connection through a name gets there, and is ⚠️ rather than 🚫 even where
nothing allows the destination, so it does not fail the step. With no TLS handshake it never matches
`allowed-tls-rules`; connecting to the address under an `allowed-ip-rules` entry is what passes it
through.

### The ones Buildcage blocked

Buildcage blocked these: they are 🚫 rows in **Blocked Hosts**, counted in the blocked-connections
annotation, and they fail the step under `fail-on-blocked: true` like any other blocked connection.

```
🚫 00:14.002: GET http://10.0.0.9/pkg.tgz?token=*** -> missing-host-header
🚫 00:15.880: HTTP (unknown):5432 -> bad-request
🚫 00:16.204: TCP 10.0.0.9:5432 -> bad-request
🚫 00:17.031: TCP 203.0.113.9:8443 -> ip-not-allowed
```

| Reason                | What happened                                                                                               |
| --------------------- | ----------------------------------------------------------------------------------------------------------- |
| `bad-request`         | the step sent bytes that could not be read as an HTTP request at all                                        |
| `missing-host-header` | a request parsed, and carried no `Host` for a rule to match or resolve                                      |
| `ip-not-allowed`      | a connection straight to an address no `allowed-ip-rules` entry covers ended before its request (`inspect`) |
| `sni-not-allowed`     | the same, with an SNI naming a host no rule allows (`inspect`, `restrict` only)                             |

`bad-request` is most often a protocol that is not HTTP at all and where the client speaks first,
such as PostgreSQL or `git://`, on a port no `allowed-ip-rules` or `allowed-tls-rules` entry covers:
anything that is not a TLS handshake is handed to the plain-HTTP stage, which reads it as a request
and blocks it. `bad-request` and `missing-host-header` are blocked in `audit` mode too, as the same
check is under `universal`, since a request naming no host has nothing to connect to.

`ip-not-allowed` is a connection to an address such as `203.0.113.9:8443` that ended before its
request: a client that does not trust the CA, or one waiting for the server to speak first. A client
sends no SNI to an address, so the certificate the proxy answers with matches no name, and a client
that checks it goes no further, in `audit` too. `universal` in `restrict` blocks the same connection
on arrival.

A keepalive client also closes a connection after its requests, and that close is logged the same
way. It is left out of the report when a request to the same address and port was read. Plain HTTP
sent to an address with a `Host` naming some other host is the exception: the log records that
request under the address it was forwarded to, not the one the client connected to, so its
keepalive close is counted here.

A host rule does not clear a `bad-request` or `ip-not-allowed` row. For traffic that is not HTTP,
add the address and port to `allowed-ip-rules`, or the name to `allowed-tls-rules`, and the
connection is passed through undecrypted instead of being read as a request. `known-blocked-rules`
can mark a row whose host is a name from the SNI or an address. A row reading `(unknown)` names
nothing a rule can be written against, so the passthrough rule is the only way to clear it.

`sni-not-allowed` is the same kind of connection, sent straight to an address, but carrying an SNI.
The name is judged the way the resolver judges a name looked up through DNS: against the host of
every rule except `allowed-ip-rules`, on any port. The one difference is that a trailing dot is
kept. The same attempt made through DNS is blocked as `dns-not-allowed`. If the rules allow the
name, the connection stays a [connection the client ended](#connections-the-client-ended), as it
would through DNS. That is usually a client that does not trust the CA, pointed at an address by
`/etc/hosts` or `curl --resolve`. `audit` blocks no name, so it blocks no SNI. A rule allowing the
host clears the row, and so does a `known-blocked-rules` entry.

Under `universal`, a connection through a name that is not a TLS handshake is also read as HTTP. ssh
or `git://` to a name is blocked as `bad-request`, in `audit` too. A client waiting for the server
to speak first (SMTP, FTP) ends as a [connection the client ended](#connections-the-client-ended).
No rule on the name clears either. `universal` has no `allowed-tls-rules`, so the step has to
connect to the address, under an `allowed-ip-rules` entry.

## Connections that failed

A request no rule blocked can still come to nothing: the origin answers nothing usable, breaks off
mid-transfer, or its name resolves nowhere. The report lists them as ⚠️ rows in the table of blocked
hosts, headed **Blocked / Failed Hosts** when it holds both and **Failed Hosts** when it holds only
them. They follow the blocked rows and stay in that table, as `known-blocked-rules` never matches
a failure. **Communication details** shows each with ⚠️ too:

```
⚠️ 00:12.004: GET https://registry.npmjs.org/big.tgz -> origin-aborted
⚠️ 00:13.771: GET https://mirror.example.com/index -> origin-no-response
```

| Reason               | What happened                                                                  |
| -------------------- | ------------------------------------------------------------------------------ |
| `origin-no-response` | the connection was made, and no usable response headers came back              |
| `origin-aborted`     | the response started and the transfer was cut short                            |
| `dns-failed`         | the name resolved nowhere upstream; no rule blocked it                         |
| `origin-unreachable` | a connection on which Buildcage checks no origin certificate could not be made |

None of the four hides an origin Buildcage failed to authenticate, which is why they are failures
and not blocks. The first two happen on a connection that completed, which is where the origin's
certificate was checked, so what went wrong afterwards went wrong with an origin Buildcage had
authenticated. `dns-failed` never reached a connection. `origin-unreachable` is a plaintext request
or a passthrough, and Buildcage checks the origin certificate of neither. A plaintext request is
carried as it was sent, and a passthrough is relayed undecrypted for the step to judge.

`universal` writes its decision before the connection is made and never sees what became of it, so
`dns-failed` is the only one of the four it can report. `audit` reports them the same way, though no
rule allowed anything there either: the table says only that the rules did not stop these. The rules
`audit` suggests for `restrict` include these hosts too, since the next run will ask for them again.

None of the four fails the step, not even with `fail-on-blocked: true`, and a `::notice::` gives the
count. No rule blocked them, so no rule can clear them either. `known-blocked-rules` has nothing to
match, and an `allowed-*` entry changes nothing. What clears one is the origin coming back, or the
command reaching for something that is up.

A blocked `DNS` row for the same name is different. That one is Buildcage's own resolver saying no
rule allows the name, and it does fail the step.

A connection Buildcage never completed is not one of these. It is blocked, listed in Blocked Hosts,
and fails the step:

| Reason                  | What happened                                                            |
| ----------------------- | ------------------------------------------------------------------------ |
| `origin-untrusted`      | the origin's certificate was presented and Buildcage would not accept it |
| `origin-connect-failed` | the connection never completed, so no certificate was ever accepted      |

`origin-untrusted` is the plain case: a forged certificate, an expired one, or an origin speaking no
TLS at all. `origin-connect-failed` can look like an outage, and the report cannot tell it apart
from one. HAProxy retries a failed connection, and the TLS error it reports belongs to the last
attempt alone, so an impostor blocked for its certificate on one attempt leaves no trace once a
later attempt fails at TCP. The report therefore counts it as blocked: a connection it never
completed is one whose origin it never authenticated. See
[Attempts to get around it](./security.md#attempts-to-get-around-it).

An `origin-connect-failed` row from a host you know to be flaky rather than hostile is cleared the
way any expected block is, by listing the host in `known-blocked-rules`.

## AWS access key check

`aws-key-check` and `allowed-aws-role-accounts` are **experimental**: their behavior and error
messages may still change without following semver. [AWS access key check](./aws.md) covers why the
check exists, how to set it up, what it does not stop, and the IAM settings that close the rest.

- With `aws-key-check: true`, a request to an AWS API host must be signed with the step's own
  `AWS_ACCESS_KEY_ID`, taken as given without checking its account. If that variable is unset or is
  not an access key ID, the step fails before the sandbox is set up, in `audit` too.
- `allowed-aws-role-accounts` takes 12-digit AWS account IDs, separated by commas, whitespace or
  newlines, with `#` comments as in the rule inputs. A key STS issues through `AssumeRole` or
  `AssumeRoleWithWebIdentity` for a role in one of these accounts passes too, and with no account
  named no such key does. Quote an account ID that begins with `0`, which YAML otherwise reads as a
  number.
- Any account named needs `aws-key-check: true`, from the workflow or a config file. If the check
  is unset or `false`, the step fails, in `audit` too. Set in the workflow,
  `allowed-aws-role-accounts` replaces a config file's value. Left empty in the workflow, it counts
  as unset, and the file's accounts still apply. So when the config file names accounts,
  `aws-key-check: false` in the workflow fails the step. To run without the check, point
  `config-file` at a file that names no accounts.
- An unsigned request is left to the URL rules in these cases:
  - where the host names the resource it is for, such as an S3 bucket or an ECR registry
  - on a public host that reaches no account, such as `checkip.amazonaws.com`
  - on CodeCommit, which Git asks before it logs in

  Everywhere else an unsigned request is blocked. The one exception is an
  `AssumeRoleWithWebIdentity` call sent as a form, as the SDKs send it, for a role in one of these
  accounts. See [Which hosts](./aws.md#which-hosts).

The check blocks after the URL rules have allowed a request, with a reason that starts with `aws-`:
`aws-key-not-allowed`, `aws-no-credential`, `aws-role-not-allowed`, `aws-unsupported-credential`,
`aws-unreadable` or `aws-ambiguous-credential`. [Troubleshooting](./aws.md#troubleshooting) gives
each one's usual causes and what to do.

Like `not-allowed`, these are 🚫 rows in **Blocked Hosts** and fail the step under
`fail-on-blocked: true`. `known-blocked-rules` marks them as expected the same way, matching the
host or URL whatever the reason, and in `restrict` the report links to
[Troubleshooting](./aws.md#troubleshooting) only while one is not expected. In `audit` mode nothing
is blocked: a warning annotation counts the requests `restrict` would have blocked, and the report
counts them under **⚠️ Restrict Would Block** for each host and reason, or for each key under
`aws-key-not-allowed`. This preview does not apply `known-blocked-rules`: it counts, warns about and
links for every request `restrict`'s rules would block, including ones a rule would then mark
expected, which the `restrict` run itself would not fail on. **Communication details** lists each
among the other requests, marked `(restrict would block: <reason>)`, and the traffic artifact has
them too.

## Hidden query parameters

**Communication details** replaces the value of a query parameter named `access_key`,
`access_token`, `api_key`, `api_token`, `auth`, `authorization`, `auth_token`, `client_secret`,
`code`, `credential`, `credentials`, `id_token`, `jwt`, `key`, `passwd`, `password`, `pat`,
`private_token`, `pwd`, `refresh_token`, `secret`, `session`, `session_token`, `sig`, `signature`,
`subscription-key`, `token`, `x-amz-security-token`, `x-amz-signature`, `x-api-key` or
`x-goog-signature`. The name is matched ignoring case, `-`, `_`, `.` and any trailing `[...]`, so
`api_key`, `api-key`, `api.key`, `apiKey`, `APIKEY` and `api_key[0][]` are one name. What the
brackets hold is not looked at, so `user[password]` keeps its value. A parameter starts after `&`,
`;` or any `?`, so one in a URL carried inside another's value is replaced too. The replaced value
runs to the next `&`, so a `;` or `?` inside a secret does not leave the rest of it showing:

```
✅ 00:04.212: GET https://cdn.example.com/x.tar.gz?X-Amz-Signature=***&X-Amz-Expires=3600 -> 200 (4.1MB)
🚫 00:05.003: POST https://evil.example.com/?d=BASE64PAYLOAD -> not-allowed
```

The [traffic artifact](#traffic-artifact) keeps every value as it was sent.
[Credentials in a URL](./security.md#credentials-in-a-url) explains why the summary hides these
and what it still shows.

## Traffic artifact

`upload-traffic-artifact: true` uploads the report's timeline as a `traffic.json` inside an artifact
named `buildcage-traffic-<id>`. `<id>` is eight random hexadecimal characters drawn for each step,
so the artifacts of several steps in one job get different names. It carries every name lookup,
including the ones the summary folds into the request that followed them, and service-discovery
lookups with the record type that was asked for. `universal` sees neither the request nor where a
name resolved, so under it `method`, `url`, `status` and `destination` are absent and the rows are
name lookups and a connection-level view (host, port and bytes).

Where the report has to serve as an audit record, keep this artifact, not the Job Summary. In
`filesystem-mode: persistent`, a later step can add to the Job Summary, but it cannot add to an
artifact already uploaded. See
[What the sandbox does not stop](./security.md#what-the-sandbox-does-not-stop).

| Field         | Always | Notes                                                                                                               |
| ------------- | ------ | ------------------------------------------------------------------------------------------------------------------- |
| `time`        | yes    | ISO 8601 UTC                                                                                                        |
| `elapsed`     |        | since the proxy started, fixed `HH:MM:SS.mmm`                                                                       |
| `action`      | yes    | `allow`, `block`, `audit` when nothing was enforced, `discovery`, `incomplete`, `failed`                            |
| `protocol`    | yes    | `https`, `http`, `tls`, `tcp`, `dns`                                                                                |
| `host`        | yes    | the name asked for, the address when there was none, or `(unknown)`                                                 |
| `port`        |        | absent for `dns`, which connects to nothing                                                                         |
| `queryType`   |        | the record asked for; `discovery` rows and blocked service names                                                    |
| `method`      |        | `http` and `https`, and `tcp` for a request with no `Host` sent to an address                                       |
| `url`         |        | as `method`; verbatim, unlike the summary's                                                                         |
| `status`      |        | only when something answered                                                                                        |
| `bytes`       |        | absent for a blocked request and for `dns`                                                                          |
| `reason`      |        | only when `action` is `block`, `incomplete` or `failed`                                                             |
| `destination` |        | the address it actually resolved to; `inspect` only, and absent for `dns`                                           |
| `wouldBlock`  |        | `audit` only: the reason `restrict` would have blocked it for, from the AWS access key check                        |
| `aws`         |        | a request to an AWS API host the AWS access key check judged; see [the AWS check](./aws.md#in-the-traffic-artifact) |

A `dns` row's `host` is the name as the resolver logged it: lowercased, with escapes such as `\ `
and `\DDD` kept.

A field is absent because it does not apply, never because it was zero: a blocked request has no
status because nothing answered, and a passthrough none because nothing was decrypted. Filter on
`action`. The artifact is uploaded even when the step fails, since a failing run is when it is most
wanted.

```json
[
  {
    "time": "2026-09-02T04:11:07.512Z",
    "elapsed": "00:00:00.512",
    "action": "allow",
    "protocol": "https",
    "host": "registry.npmjs.org",
    "port": 443,
    "method": "GET",
    "url": "https://registry.npmjs.org/express",
    "status": 200,
    "bytes": 102300,
    "destination": "104.16.0.35"
  },
  {
    "time": "2026-09-02T04:11:08.048Z",
    "elapsed": "00:00:01.048",
    "action": "block",
    "protocol": "dns",
    "host": "secret-data.attacker.example",
    "reason": "dns-not-allowed"
  },
  {
    "time": "2026-09-02T04:11:08.390Z",
    "elapsed": "00:00:01.390",
    "action": "block",
    "protocol": "https",
    "host": "registry.npmjs.org",
    "port": 443,
    "method": "POST",
    "url": "https://registry.npmjs.org/express/-rev/1-abc",
    "reason": "not-allowed"
  }
]
```

Query strings are kept verbatim here, since that is also where an exfiltration payload would go. The
Job Summary is the exception: it replaces credential query parameters, see
[Credentials in a URL](./security.md#credentials-in-a-url).

Treat the artifact as sensitive: it keeps any credential a build put in a query or a path. A later
job in the same run can fetch it with `actions/download-artifact`, and anyone who can read the
repository can fetch it through the API, until it expires.

## Filesystem audit

`filesystem-audit` is **experimental**: its behavior, inputs and output format may still change
without following semver. The guide is [Filesystem audit](./filesystem-audit.md); what follows is
the short form.

- `filesystem-audit: record` records the step's file accesses from the kernel and never blocks one.
  It needs a cgroup v2 host on Linux 6.1 or newer (6.4 on arm64) with kernel BTF; elsewhere the step
  fails before the command runs. A 32-bit system call in the step kills the thread that made it,
  with `SIGSYS`.
- The step's Job Summary gets a **Filesystem Activity Report** section after the traffic report: the
  programs the step ran and how often, every path each program touched with a flag for each action,
  and, folded below them, one row per command and path.
- `upload-filesystem-audit-artifact: true` uploads the full record as JSON lines in an artifact
  named `buildcage-filesystem-audit-<id>`, whose name the `filesystem-audit-artifact-name` output
  carries; `filesystem-audit-retention-days` sets how long it is kept. It leaves out each program's
  arguments but holds every path the step touched; treat it as sensitive.
- `expected-filesystem-rules` lists the accesses the step is expected to make, one
  `<program> <access> <path>` rule per line, and is combined with a config file's as the other rule
  inputs are. With it, the section lists only the accesses outside the rules, the verdict counts
  them, and a warning names them; `fail-on-unexpected-file-access: true` fails the step instead, in
  `audit` mode too. The artifact marks each line with the rule that took it or as unexpected, and,
  where a recorded access fell outside the rules, holds `expected-filesystem-rules-to-add.txt`, a
  rule for each such access. See
  [Expected accesses](./filesystem-audit.md#expected-accesses).

## Working directory

`working-directory` sets the directory `run` starts in, as the workflow's own `working-directory:`
does for a `run:` step, which does not apply to a `uses:` step. A relative path resolves against
`$GITHUB_WORKSPACE`, and an absolute one is taken as it is. Neither `~` nor a `$NAME` is expanded;
use an expression such as `${{ runner.temp }}` instead. A `..` may only start the path:
`../shared` works, and `current/..` fails the step.

```yaml
- uses: buildcage/isolated-run@<sha>
  with:
    working-directory: packages/web
    config-file: buildcage.yml # packages/web/buildcage.yml
    write-through: dist # packages/web/dist
    run: npm ci && npm run build
```

- The step fails before the command runs when the directory does not exist, is not a directory, is
  covered by a mount of the sandbox's own (as under `/dev/shm` or `/run`), or cannot be entered by
  the step's user without its supplementary groups, which the sandbox drops. Under
  `filesystem-mode: ephemeral` it fails too when the directory is in a host mount the overlay cannot
  take, which the step warns of and the command would see as an empty directory.
- Relative `write-through` paths and the `config-file` path resolve against it. `config-file` cannot
  set `working-directory` itself, and the file must still be in `$GITHUB_WORKSPACE`. Adding
  `working-directory` to a step changes where its relative `write-through` paths point: with
  `working-directory: app`, `write-through: app/dist` becomes `app/app/dist`.
- The directory's symlinks are resolved once, when the step starts, and the command and every
  relative path start from where they lead, as after `cd -P`. With `current` linking to
  `releases/v2`, `working-directory: current` starts the command in `releases/v2`,
  `write-through: dist` is `releases/v2/dist`, and `write-through: ../out` and
  `config-file: ../x.yml` are in `releases`, where the command's own `cd ..` goes.
- In the [filesystem audit](./filesystem-audit.md#paths), `./` is the working directory, and the
  rest of the workspace shows as `$GITHUB_WORKSPACE/`. An `expected-filesystem-rules` rule may name
  a path in the working directory with `./` or without it, from the workspace, `$HOME` or `/`, such
  as `$GITHUB_WORKSPACE/app/dist/**`. `./` itself always starts at the working directory: under
  `working-directory: app`, `./app/dist/**` names `app/app/dist`.
- The directory is writable only when it is somewhere the step can write anyway: the workspace,
  `$HOME`, `$RUNNER_TEMP`, `/tmp` or a `write-through` path. A command starting elsewhere can read
  there but not write.
- `PWD` is the directory's real path. Without `working-directory` it is the workspace's real path,
  which differs from `$GITHUB_WORKSPACE` when that goes through a symlink.

## CA trust variables

`proxy-engine: inspect` terminates TLS and re-signs it with a CA generated for the step, so the
command has to trust that CA. The CA is valid for two days from when it is generated and carries a
random `serialNumber` in its subject, so no two runs share one. The CA is mounted into the sandbox
at `/dev/buildcage-ca.pem`, a file holding only this CA. A copy of the runner's system CA store with
the CA added is mounted over the store's own path, whichever of the well-known store paths this
runner has, since that is the path a tool with a compiled-in store path reads. Some tools read a
directory of certificates rather than the bundle, so each of these directories the runner has is
covered by a copy holding the CA too:

- `/etc/pki/ca-trust/source/anchors`, p11-kit's anchors on RHEL and Fedora, read by GnuTLS there
  through p11-kit
- `/etc/pki/trust/anchors`, p11-kit's anchors on SUSE, read by what uses p11-kit directly
- `/var/lib/ca-certificates/pem`, read by GnuTLS on SUSE

The directory is copied as the runner user, so one holding an entry the runner cannot read is left
uncovered: the step warns and goes on, and a tool reading that directory fails TLS.

Nothing is written to the runner's filesystem, and the mount goes away with the sandbox when the
step ends.

The variables below are set only when the command's environment leaves them unset, and where each
one points depends on what it means to the tool that reads it:

| Variable              | Read by                                                                                                                                                      | If unset                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| `NODE_EXTRA_CA_CERTS` | Node.js                                                                                                                                                      | Additive: pointed at `/dev/buildcage-ca.pem`, a file holding only this CA |
| `DENO_CERT`           | Deno                                                                                                                                                         | Additive: pointed at `/dev/buildcage-ca.pem`, a file holding only this CA |
| `CURL_CA_BUNDLE`      | curl                                                                                                                                                         | Left unset; curl already reads the system store                           |
| `REQUESTS_CA_BUNDLE`  | Python `requests`                                                                                                                                            | Replaces the bundle: pointed at the system store                          |
| `PIP_CERT`            | pip                                                                                                                                                          | Replaces the bundle: pointed at the system store                          |
| `SSL_CERT_FILE`       | OpenSSL, and anything linked against it (Go's `crypto/x509` on Unix, Ruby, Rust's `rustls-native-certs`). Not GnuTLS, so Debian's wget and git never read it | Replaces the bundle: pointed at the system store                          |

A variable that is already set is left alone, not appended to, and the step warns about it unless
it points at the system store. `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `npm_config_cafile` (in any
case), `AWS_CA_BUNDLE`, `CARGO_HTTP_CAINFO` and `BUNDLE_SSL_CA_CERT` are never set, but the step
warns about them the same way when they are set. The CA goes only into a store that already exists;
none is created. [Limitations](../README.md#limitations) covers both of these, a variable that is
already set and a missing store, with what each means for a command that needs TLS trust.

### JVM keystores

A JVM reads none of these variables, only its own keystore. The CA is added, with the runner's own
`keytool`, to a copy of the `cacerts` (and `jssecacerts` when present) of the `java` on `PATH` and
of `$JAVA_HOME`, and the copy is mounted over it. Any other JDK keeps its own keystore. Bazel can be
pointed at an injected copy with
`bazel --host_jvm_args=-Djavax.net.ssl.trustStore=$JAVA_HOME/lib/security/cacerts ...`.

The `keytool` that injects the CA runs outside the sandbox, so it must live outside `$HOME`,
`$GITHUB_WORKSPACE`, `/tmp`, `$RUNNER_TEMP` and `write-through:`. GitHub-hosted runners have one in
`/usr/lib/jvm`. A self-hosted runner whose only JDKs are under `$HOME` (mise, sdkman, coursier, or
`setup-java` with the runner in a home directory) needs a system JDK or a `RUNNER_TOOL_CACHE`
outside `$HOME`. Without one, or with a keystore sealed under a non-default password, the step
warns and a JVM build needs `proxy-engine: universal`.

### Chromium

Chromium reads none of these, only its compiled-in root store and the NSS database in `$HOME`.
Every Chromium reads `~/.pki/nssdb` when it exists, and M146 and later read
`~/.local/share/pki/nssdb` when it does not, so the database is the first of those that exists, or a
new `~/.pki/nssdb` when neither does. For the step, the database's `pkcs11.txt` gains a second,
read-only slot on a database holding only this CA, so Chromium trusts the CA while the runner's own
certificates, keys and writes stay in its own database. `$HOME` is the step's, read before the
command starts: a `HOME` the command changes gets no slot.

What the command writes to the database is kept where `filesystem-mode` keeps writes to that path:
always under `persistent`, and under `ephemeral` only below a `write-through:` entry. Elsewhere it
is discarded. The slot itself is never kept. If the command copies the CA into the database itself,
for example by changing the CA's trust with `certutil -M` or by exporting it and importing it back,
the database is not written back. The step fails, naming the database and pointing at
`fail-on-ca-residue`. Under `fail-on-ca-residue: false` the step only warns and writes the database
back. When parallel steps change the same database, the one that ends later replaces the other's
changes as a whole, as it does whatever else wrote to the database while the step ran.

A database the runner user cannot write, one too large to copy (over 512 files or 20 MiB), or a
symlink or non-directory on the path leaves the database as it is, with a warning: Chromium in that
step does not trust the CA and fails TLS through the proxy, so use `proxy-engine: universal` for it.
Chromium opens nothing it cannot open read-write, so an unwritable database cannot take the slot.

Missing directories are created 0700 and removed, if still empty, once no step of the same runner
user uses them, including steps in other jobs. A database Chromium has filled is not empty, so it
stays, as it would had Chromium created it. On a filesystem without file birth times (some NFS
mounts), created directories are always left in place. If something else, such as a parallel step
outside any sandbox, removes the directory while a step runs, that step's Chromium stops trusting
the proxy CA; the step warns, naming the database, and writes nothing back to it. Under
`filesystem-mode: ephemeral`, when `$HOME` is an overlay of its own and `~/.pki/nssdb` is not
written through, a missing `~/.pki/nssdb` is made in that overlay, not on the runner.

What the command changed is written back after the step, with the slot taken back out first. A
file that already matches is not touched, and a write-back that fails partway leaves entries
behind rather than losing them, except an entry whose type the command changed, which is removed
just before its replacement goes in. Write-backs to the same database take turns, so a step never
copies the database halfway through another's write-back.

## `ephemeral` overlays

Under `filesystem-mode: ephemeral`, each writable path is an overlay whose writes are discarded when
the step ends. A separate host mount below one of them gets an overlay of its own, so its contents
stay visible, except in two cases:

- A FUSE mount without `allow_other`, one the runner cannot stat, or one whose path holds `,` or `:`
  shows as an empty directory, and the step warns.
- A mount of a single file stays hidden without a warning: the command sees the file beneath the
  mount point.

<a id="write_through-paths"></a>

## `write-through` paths

`write-through:` names the paths whose writes reach the real host filesystem, in either
[filesystem mode](../README.md#filesystem-access). It is one path per line. Entries resolve like
this:

- A line whose first non-space character is `#` is a comment, and a blank line is skipped, so a
  group of paths can carry a heading. Unlike the rule inputs, only a whole-line `#` counts: a `#`
  anywhere else stays part of the path, since a path may legitimately contain one (or a space before
  one) and an inline comment could not be told apart from it.
- `$NAME` / `${NAME}` expand only for `HOME`, `GITHUB_WORKSPACE`, `RUNNER_TEMP`, `GITHUB_OUTPUT`,
  `GITHUB_ENV`, `GITHUB_PATH`, and `GITHUB_STEP_SUMMARY`, not arbitrary env, so a value smuggled in
  through the step's own `env:` block can't redirect where a listed path resolves. Any other `$NAME`
  is refused.
- A leading `~/` expands to `$HOME`.
- A relative path (`./dist`) resolves against the [working directory](#working-directory)'s real
  path, `$GITHUB_WORKSPACE` unless `working-directory` is set.
- A `..` may only start a relative path: `../out` climbs from the working directory, as the
  command's own `..` does. A `..` anywhere else, as in `a/../b`, `~/../x` or
  `$GITHUB_WORKSPACE/..`, fails the step.
- Symlinks are not followed. A path that is a symlink, or goes through one anywhere along it, fails
  the step, and the error names the path it leads to, which you can write instead. Following one
  would make the place it leads to writable, and an earlier step could have pointed it at a path the
  sandbox keeps read-only, such as a tool installed under `/opt/hostedtoolcache`. The part of a path
  that is `$HOME`, `$GITHUB_WORKSPACE` or `$RUNNER_TEMP` is taken at its real path, as persistent
  mode does, so only what the entry adds below one is checked: `~/.cache` works where `/home` links
  to `/var/home`.
- A path that doesn't already exist is created before the step runs, always as a directory, the same
  convention Docker itself uses for a bind mount whose host source doesn't exist yet
  (`docker run -v`/`--mount`), never as a file. `$GITHUB_OUTPUT`, `$GITHUB_ENV`, `$GITHUB_PATH`, and
  `$GITHUB_STEP_SUMMARY` are the runner's own generated files and must already exist: a missing one
  fails the step instead of being created. Anything else missing (`./dist`, say) is created as a
  directory by the runner user, parents included, which needs the nearest existing parent to be
  writable by it (a tree it owns, or `/tmp`). Under any other parent the step fails before your
  command runs, since the command couldn't write there either. Create such a path in an earlier,
  non-isolated step and give it to the runner user:
  `sudo install -d -o "$(id -u)" -g "$(id -g)" /etc/something`.
- A created directory stays after the step, as with `docker run -v`, even if the step fails.
  Buildcage never removes one. A directory removed on the runner while a step runs, by a parallel
  step outside any sandbox or a `persistent` sandbox that can write its parent, is detached from
  every sandbox binding it, and that step's later writes there may not reach the runner.
- `write-through:` accepts files as well as directories, but only a path that is already a file when
  the step starts, since a missing one is created as a directory. A file entry is bind-mounted
  file-to-file (as the `inspect` engine mounts its CA), so an append or a truncating write goes
  through, but a tool that replaces the file outright (`mv`, or unlink plus recreate) does not. If
  you need a file that doesn't exist yet to persist, either have an earlier step create it first, or
  list its (already-existing) parent directory instead.
- A directory entry is a mount point inside the sandbox. A tool that refreshes its output directory
  by removing it and recreating it, rather than clearing its contents, fails at the final `rmdir`
  with `EBUSY`, the same way removing a `docker run -v` target does: a mount point can't be removed
  from inside. Writes inside the directory still go through; only removing the directory itself does
  not.
- `$GITHUB_ENV` and `$GITHUB_PATH` are read-only inside the sandbox until named here, even under a
  writable parent such as `$RUNNER_TEMP` or `write-through: /`, since what they set reaches every
  later step and post step. `$GITHUB_STATE` stays read-only, named or not.

`write-through:` changes how a path is mounted, not who owns it, so pointing it at a system
directory the runner user cannot write (`/usr`, most of `/etc`) gains nothing. It is meant for paths
outside `$HOME` that the workflow has already arranged for the runner user to write, in an earlier,
non-isolated step.

### `$GITHUB_OUTPUT` and `$GITHUB_STEP_SUMMARY`

The command writes these two freely, so wherever its writes would reach the runner, this action
mediates them. The command writes to backing copies the action owns, bound into the sandbox, and
cannot reach the real files, not even at another path a bind mount shows them at. After the step,
the action reads the copies back and writes the real files itself. A real file that is not already
a regular file fails the step (GitHub's runner creates both before the step).

Every step in `persistent` mode is mediated this way. In `ephemeral` mode the two are discarded with
the overlay like any other write, unless `write-through` names the file or a directory it is in
(`$RUNNER_TEMP`, say), by any of the paths it is shown at. Only then are they mediated and written
back, without a bind of their own.

A copy the command replaced with a symlink, FIFO or directory, or made unreadable, is read back as
empty and fails the step; it is never followed or blocked on. The
backing copies sit under `/var/tmp/buildcage-<uid>`, which the sandbox cannot see, so the command
reaches them only through the bind and cannot move them aside.

`$GITHUB_OUTPUT` is written back trimmed to the entries the runner can read (a dropped entry fails
the step). `$GITHUB_STEP_SUMMARY` is written back as the command left it, after the report, cut to
what the report leaves of GitHub's limit, or replaced by a note when it is over 1 MiB on its own
(see [The Job Summary size cap](#the-job-summary-size-cap)). `$GITHUB_ENV`,
`$GITHUB_PATH` and `$GITHUB_STATE` are not mediated: they stay read-only in the sandbox.

### Paths under `/run`

The sandbox covers the host's `/run` with an empty tmpfs to keep host service sockets out of reach.
Naming a path under `/run`, or `/run` itself, re-exposes it, for a service socket a later step
needs, say. That reopens an outbound path through the daemon behind it. Naming all of `/run`
reopens one through every daemon there, so do it deliberately. See
[Isolation mechanisms](./security.md#isolation-mechanisms).

### Runner directories

The runner's install directory, the runner's `_actions` directory holding every action's checkout,
and the docker CLI's config directory (`$DOCKER_CONFIG`, else `~/.docker`) stay read-only, since
the runner and this action run code from them after the command exits. The exceptions are a
`write-through:` entry naming the directory itself, and `uses: ./`, whose checkout is the
workspace. On a self-hosted runner whose work directory is inside its install directory, as `_work`
is by default, the rest of `_work`, such as the tool cache in `_work/_tool`, is read-only too; the
workspace, `$RUNNER_TEMP` and `write-through:` entries stay writable. A directory reached through a
symlink the command could replace, such as a `~/.docker` that links elsewhere, fails the step
before the command runs; point `DOCKER_CONFIG` or the runner's work directory at the real path
instead.

### Reserved paths

`/etc/resolv.conf` is mounted by the sandbox itself to reach the proxy's DNS, and the runner's own
CA store to carry the proxy's CA. Which path that store is depends on the runner, so every path a CA
store is looked for at is reserved, whether or not this runner keeps one there:
`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem`,
`/etc/pki/tls/cacert.pem` and `/etc/ssl/cert.pem`. An entry naming one is then refused on every
runner, instead of working on one runner and failing on the next. The file a candidate is a symlink
to is reserved as well, since that is where the mount lands
(`/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` on RHEL, say).

Under `inspect`, a CA directory the step covers (`/etc/pki/ca-trust/source/anchors`,
`/etc/pki/trust/anchors` or `/var/lib/ca-certificates/pem`) and anything in it, a JVM keystore the
step covers with its CA-carrying copy, and anything inside the NSS database it covers
(`~/.pki/nssdb/cert9.db`) are refused too. Which of them exist depends on the runner and the JDKs
installed, so only the ones the step actually mounts count. A CA directory that is a symlink is
reserved where it leads as well, as a CA store is. Naming a keystore's directory, or the
parent of a CA directory, is fine, and naming `~/.pki/nssdb` itself has the command's changes to it
written back.

Naming a reserved path, or anything under one, fails the step before the proxy starts; it is not
quietly ignored. So does naming `/proc`, `/dev` or `/sys`, which the sandbox mounts fresh, or
anything under one.
Naming a directory that contains reserved paths (`write-through: /etc`) is fine: writes elsewhere
under it reach the host, and only the reserved paths themselves stay read-only.

An entry naming the sandbox's scratch directory, `/var/tmp/buildcage-<uid>`, a path inside it, or
an ancestor of it is refused outright. That directory holds the sandbox's view of the host's `/`,
and a `write-through:` entry is mounted with everything below it, so allowing one there would
expose a second, writable copy of the whole host `/`.
Entries are normalized first, so `/var/tmp/./buildcage-<uid>` is caught by the same check. This
guards against an operator's `write-through:` value, not against the command itself. The literal `/`
is [the opt-out below](#the--opt-out) and skips the guard by design.

### The `/` opt-out

`write-through: /` makes every path writable but those that stay read-only under any writable
parent: `$GITHUB_ENV`, `$GITHUB_PATH`, `$GITHUB_STATE`, the docker CLI's config directory, the
runner's install directory, its `_actions` directory and the reserved paths above. It only means
anything under `persistent` and is refused under `ephemeral`, since that mode discards writes and
`/` would persist every one. The sentinel is the literal `/` only: an entry that merely _resolves_
to `/` (a miscounted `../`, say) is refused rather than read as the opt-out.

> [!WARNING]
> Use `write-through: /` only for code you trust. Against a compromised command it removes more
> than the read-only restriction:
>
> - All of `/run` is reachable again, which reopens an outbound path through every daemon there. A
>   `systemd --user` bus there (`/run/user/<uid>/bus`) starts a unit outside the sandbox with all
>   of the runner's groups. On a GitHub-hosted runner the command cannot open the Docker socket
>   itself, since `docker` is only a supplementary group there, but such a unit can, and it reaches
>   the network past the proxy, directly or from a container on the host network.
> - `docker`, `sudo` and, under `inspect`, `keytool` are taken from the first match on `$PATH` even
>   where the command can write, so the host may later run a copy the command replaced. `docker`
>   also looks for its `docker-credential-*` helpers on the whole `$PATH`, where the command can
>   plant one.
> - `$XDG_RUNTIME_DIR` is no longer masked where it sits outside `/run`, so a `systemd --user` bus
>   there is reachable too.
> - Symlinks are refused only in the paths that are always writable (the workspace, `$HOME`,
>   `$RUNNER_TEMP` and `/tmp`) and in other `write-through:` entries, though the command could
>   replace one anywhere.
>
> The read-only paths named at the start of this section, the `/proc` masks and the command's own
> network namespace still hold. The step warns about all this when `write-through: /` is set.

### The former input names

`write-through:` was called `writable:` before it covered both filesystem modes, and `allow_write:`
was its `filesystem-mode: ephemeral`-only counterpart. `writable:` still works and means the same
thing, except that its entries go through the resolution above, so a relative entry resolves against
the working directory rather than being passed through as-is, and a `$NAME` outside the seven
supported variables is refused instead of being treated as a literal path. Setting both joins their
lines. `allow_write:` has been removed, and a step still passing it fails with a message saying so
rather than silently discarding the writes it asked to keep.
