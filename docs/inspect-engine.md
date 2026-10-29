# Inspect Proxy Engine

This page holds no content of its own. The `inspect` engine is documented in the
[README](../README.md) and the guides below, and what follows is a set of links into them.

- [Engines](../README.md#engines): what it enforces on, and when to use `universal` instead
- [Rules for the inspect engine](../README.md#rules-for-the-inspect-engine): `allowed-url-rules`, `allowed-tls-rules` and `allowed-ip-rules` by example
- [Rule syntax](./reference.md#rule-syntax): the grammar those rules are written in
- [CA trust and compatibility](../README.md#ca-trust-and-compatibility) and [Limitations](../README.md#limitations): the CA it mounts, and what it cannot work with
- [CA trust variables](./reference.md#ca-trust-variables): each variable it sets and what it points at
- [AWS access key check](./aws.md): `aws-key-check` and `allowed-aws-role-accounts`, what they stop, and what IAM has to close instead
- [The report](../README.md#the-report): what the Job Summary shows, and what the traffic artifact holds
- [Inspect Proxy Engine](./security.md#inspect-proxy-engine): architecture, threat model, attack resistance
