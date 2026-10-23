---
description: "Configure private client certificate authentication for Redis/Valkey persistence and execution locks."
---
# Redis/Valkey client mTLS

Client certificate authentication is disabled by default. The SaaS Galaxy deployment can enable it for Valkey without changing existing plaintext or server-authenticated TLS configurations.

## Configuration

The following properties are available under **both** `conductor.redis` and `conductor.redis-lock`. Configure both clients when persistence and Redis execution locks connect to a server that requires client certificates.

| Property | Default | Meaning |
| --- | --- | --- |
| `mtlsEnabled` | `false` | Enable client certificate authentication. |
| `tlsKeyStorePath` | unset | Absolute path to a readable JKS store containing the client private key and X.509 certificate chain. |
| `tlsTrustStorePath` | unset | Absolute path to a readable JKS store containing trusted X.509 CA certificates. |
| `tlsPasswordFilePath` | unset | Absolute path to a readable, nonempty password file. The same password protects both stores and the private key. |

For persistence, `conductor.redis.mtlsEnabled=true` enables TLS and client certificate authentication together. No separate `conductor.redis.ssl=true` setting is needed. `conductor.redis.ignoreSsl` must remain `false`. The host availability pinger and the persistence client both receive the private identity and trust material. Cluster, standalone and sentinel clients apply these settings.

For execution locks, `conductor.redis-lock.mtlsEnabled=true` requires every configured `serverAddress` to use `rediss://`. Redisson receives explicit key and trust manager factories; setting only JVM-wide key store properties does not configure its client identity.

The client leaf must be currently valid, must not be a CA certificate, and must explicitly include the `clientAuth` extended key usage. Missing files, invalid stores or invalid client certificates cause startup to fail when mTLS is enabled. CA trust stores may retain overlapping issuers during rotation; they must contain only CA certificates.

Both transports use TLS 1.2/1.3 and verify server hostnames. Server certificate SANs must cover the configured seed hostname and the node hostnames or IP addresses advertised by the cluster. Disabling hostname or CA verification is not supported in mTLS mode. Existing Redis password/ACL authentication remains configured independently.

## Renewal and rollout

The stores, key managers and trust managers are loaded as startup snapshots. There is no automatic certificate reload. For SaaS Galaxy, after Vault Agent refreshes the mounted certificate/key or CA bundle, rebuild the private stores and perform a controlled Galaxy rolling restart before the previous certificate expires. Replacing a JKS file alone does not refresh existing clients or pooled connections.

Deploy client certificate support before requiring certificates on the Valkey TLS listener. Requiring client certificates affects every client of that listener, including TLS readiness probes. A separate plaintext listener, the cluster bus and replication links are controlled by Valkey's server configuration and are not changed by these client properties.

