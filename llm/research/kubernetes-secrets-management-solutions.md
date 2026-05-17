---
title: "Kubernetes Secrets Management Solutions — Domain Research"
date: "2026-03-02"
depth: "standard-research"
request: "standalone"
---

## Executive Summary

The Kubernetes secrets management landscape in 2026 has settled into a clear tiered structure. At the foundation layer, **External Secrets Operator (ESO)** has become the de facto standard for synchronizing secrets from any external vault into K8s — it's a CNCF project with multi-provider support and is essentially table stakes. Above that, the choice of **vault backend** is the real architectural decision: **OpenBao** (the Linux Foundation fork of HashiCorp Vault) is the strongest option for teams that need open-source guarantees and already use the Vault API surface, while **HashiCorp Vault Enterprise** remains the choice for organizations that need DR replication and commercial support. For teams that want a simpler, developer-friendly experience, **Infisical** and **Doppler** offer managed platforms with Kubernetes operators. **Sealed Secrets** and **SOPS** serve the GitOps-specific niche of encrypting secrets in Git.

For the OpenClaw/credential-proxy context specifically, **OpenBao + ESO** is the natural fit — OpenBao is already the chosen vault backend, and ESO would bridge it into K8s if the system ever runs on K8s infrastructure.

---

## 1. Vault Backends (Where Secrets Live)

### HashiCorp Vault

The industry standard for secrets management since 2015. Provides:
- Dynamic secret generation (database creds, cloud IAM, PKI certificates with TTL)
- 50+ secret engines for different backends
- Fine-grained ACL policies
- Comprehensive audit logging
- HA clustering with Raft or Consul storage

**License change**: In 2023, HashiCorp switched from MPL 2.0 to BSL 1.1. You cannot offer Vault as a hosted service competing with HashiCorp's commercial offerings. Now under IBM ownership (2024).

**Strengths**: Mature, battle-tested, largest ecosystem, best Enterprise features (DR replication, namespaces, performance standbys).

**Weaknesses**: Operational complexity (3-5 node HA cluster), steep learning curve, BSL license restrictions, $2,000-5,000/month operational cost for production.

### OpenBao

Linux Foundation/OpenSSF fork of Vault's last MPL 2.0 release (v1.14.0). As of February 2026, at version 2.5.0.

**Key advantages over Vault**:
- True open-source (MPL 2.0, OSI-approved, no commercial restrictions)
- Namespaces available in open-source edition (Vault Enterprise-only feature)
- Community governance (not corporate-controlled roadmap)
- IBM engineers among key contributors
- API-compatible with Vault (drop-in replacement for most use cases)

**What's missing vs Vault Enterprise**:
- No native Disaster Recovery Replication (biggest gap)
- Smaller ecosystem of integrations (growing rapidly)
- Less commercial support infrastructure

**Current status**: No longer experimental — production-ready, Linux Foundation-governed, active development.

### Infisical

Open-source (MIT core) secrets management platform focused on developer experience:
- Cloud-managed or self-hosted
- Native K8s operator (Helm chart, ~10-15 min setup)
- CSI driver for file-based injection
- Secret versioning, rotation, and automatic sync
- Built-in secret scanning

**Strengths**: Best DX, fastest setup, MIT license for core.

**Weaknesses**: Usage limits on service accounts can create hidden costs at scale. Less mature than Vault/OpenBao for complex dynamic secret scenarios.

### Doppler

SaaS-first secrets management:
- Project-based organization with environment branching (dev/staging/prod)
- Native K8s operator (single Helm chart, ~5 min setup)
- Integrates with nearly every CI/CD tool and cloud platform
- Unlimited service accounts (charges per developer)

**Strengths**: Simplest setup, best for teams that want zero operational overhead.

**Weaknesses**: SaaS-only (no self-hosted option), vendor lock-in, not open-source.

### CyberArk Conjur

Enterprise-grade secrets management purpose-built for DevOps and containerized environments:
- Fine-grained RBAC and policy-as-code
- Native K8s authenticator
- Automatic credential rotation
- Detailed audit trails

**Strengths**: Deep enterprise security features, compliance certifications.

**Weaknesses**: Opaque pricing, significant operational expertise required, overkill for most teams.

### Assessment

| Aspect | Vault (BSL) | OpenBao | Infisical | Doppler | Conjur |
|--------|------------|---------|-----------|---------|--------|
| License | BSL 1.1 | MPL 2.0 | MIT (core) | Proprietary | LGPL (OSS) / Proprietary (Enterprise) |
| Dynamic secrets | 50+ engines | 50+ engines | Limited | No | Yes |
| Self-hosted | Yes | Yes | Yes | No | Yes |
| K8s operator | VSO | Compatible | Yes | Yes | Yes |
| Operational complexity | High | High | Medium | Low | High |
| Setup time | Hours-days | Hours-days | 10-15 min | 5-10 min | Days |
| Cost | $2-5K/mo (ops) | Free + ops | Free tier + per-seat | Per developer | Opaque enterprise |
| Maturity | 10+ years | 2+ years (on Vault base) | 3+ years | 4+ years | 8+ years |

**Recommendation for OpenClaw**: **OpenBao** — already chosen as the vault backend, API-compatible with Vault, open-source, and provides all the features credential-proxy needs (KV v2, AppRole auth, ACL policies).

---

## 2. Kubernetes Integration Layer (How Secrets Get Into Pods)

### External Secrets Operator (ESO)

CNCF project. The industry-standard bridge between external vaults and K8s:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: api-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: api-credentials
  data:
    - secretKey: api-key
      remoteRef:
        key: secret/data/openclaw/credentials/anthropic
        property: key
```

**How it works**: ESO watches ExternalSecret CRDs, fetches values from the configured backend (Vault, OpenBao, AWS SM, GCP SM, Azure KV, etc.), and creates/updates standard K8s Secrets. Pods consume them normally via volume mounts or env vars.

**Strengths**:
- Multi-provider (one operator, many backends)
- Configurable refresh intervals (automatic rotation sync)
- ClusterSecretStore for cross-namespace sharing
- PushSecret CRD for bidirectional sync
- CNCF project with strong community

**Weaknesses**:
- Creates K8s Secrets in etcd (must enable encryption at rest)
- Secrets are materialized (exist in cluster even when pods aren't running)
- No dynamic secret generation (delegates to backend)

### Secrets Store CSI Driver

Mounts secrets directly as files in pods via the Container Storage Interface, **without creating K8s Secret objects**:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: vault-secrets
spec:
  provider: vault
  parameters:
    vaultAddress: "https://vault:8200"
    roleName: "credproxy"
    objects: |
      - objectName: "api-key"
        secretPath: "secret/data/openclaw/credentials/anthropic"
        secretKey: "key"
```

**How it works**: At pod startup, kubelet calls the CSI driver, which fetches secrets from the vault and mounts them as files. Secrets exist only in the pod's tmpfs, never in etcd.

**Strengths**:
- Secrets never stored in etcd
- Pod-level scoping (secrets exist only while pod runs)
- Provider plugins for Vault, AWS, Azure, GCP

**Weaknesses**:
- No automatic refresh after pod startup (must restart pod or use sidecar)
- Less flexible than ESO for complex scenarios
- Provider ecosystem smaller than ESO

### Vault Agent Sidecar Injector

Deploys a Vault Agent sidecar into pods via mutating admission webhook:

```yaml
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/role: "credproxy"
  vault.hashicorp.com/agent-inject-secret-api-key: "secret/data/openclaw/credentials/anthropic"
```

**How it works**: Webhook intercepts pod creation, injects an init container (pre-populates secrets) and a sidecar container (manages lifecycle). Secrets written to shared in-memory volume at `/vault/secrets/`.

**Strengths**:
- Automatic token renewal and secret refresh
- Template rendering (Go templates for secret formatting)
- No code changes needed in application
- Dynamic secrets stay fresh

**Weaknesses**:
- Extra container per pod (resource overhead)
- Vault-specific (no multi-provider)
- Shared volume readable by any container in the pod

### Vault Secrets Operator (VSO)

HashiCorp's newer, Kubernetes-native approach (replaces sidecar for many use cases):

```yaml
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultStaticSecret
metadata:
  name: api-credentials
spec:
  vaultAuthRef: default
  mount: secret
  path: openclaw/credentials/anthropic
  destination:
    name: api-credentials
    create: true
  refreshAfter: 30s
```

**How it works**: Operator watches VaultStaticSecret/VaultDynamicSecret CRDs, syncs to K8s Secrets. Similar to ESO but Vault-specific with tighter integration.

**Strengths**:
- Native VaultDynamicSecret support (ESO can't generate dynamic secrets)
- Automatic rollout-restart on secret change
- Transit encryption for Secret data

**Weaknesses**:
- Vault-only (no multi-provider)
- Creates K8s Secrets in etcd (same as ESO)

### Sealed Secrets (Bitnami)

GitOps-specific: encrypts secrets for safe Git storage.

```bash
kubeseal --format yaml < secret.yaml > sealed-secret.yaml
git add sealed-secret.yaml && git commit
```

**How it works**: Controller generates asymmetric key pair. You encrypt secrets client-side with the public key, commit the SealedSecret to Git. Controller decrypts with private key and creates a standard K8s Secret.

**Strengths**: Enables GitOps for secrets (encrypted in repo, decrypted in cluster).

**Weaknesses**: Static secrets only, no rotation, no multi-provider, private key compromise = all secrets compromised.

### SOPS (Mozilla/CNCF Sandbox)

File-level encryption for secrets in Git:

```bash
sops --encrypt --age age1... secrets.yaml > secrets.enc.yaml
```

Integrates with age, AWS KMS, GCP KMS, Azure KV, HashiCorp Vault for key management. Used with Flux (SOPS integration built-in) or the sops-secrets-operator for K8s.

**Strengths**: Flexible key management, works with any KMS, CNCF project.

**Weaknesses**: File-oriented (not API-oriented), no dynamic secrets, operational overhead for key rotation.

### Assessment

| Aspect | ESO | CSI Driver | Vault Sidecar | VSO | Sealed Secrets | SOPS |
|--------|-----|-----------|---------------|-----|----------------|------|
| Multi-provider | Yes (20+) | Yes (4) | No (Vault only) | No (Vault only) | No | Yes (5 KMS) |
| Secrets in etcd | Yes | No | No | Yes | Yes | Yes |
| Auto-refresh | Yes (interval) | No | Yes (continuous) | Yes (interval) | No | No |
| Dynamic secrets | No (delegates) | No | Yes | Yes | No | No |
| GitOps-native | No | No | No | No | Yes | Yes |
| Resource overhead | Operator only | Driver DaemonSet | Sidecar per pod | Operator only | Controller only | Operator only |
| CNCF | Yes (Incubating) | Yes (part of K8s SIG) | No | No | No | Sandbox |

**Recommendation for OpenClaw**: **ESO + OpenBao provider** if deploying to K8s. ESO is the broadest, most future-proof integration layer. If dynamic secret refresh is needed, supplement with **Vault Sidecar** for the credential-proxy pod specifically.

---

## 3. Architecture Patterns

### Pattern A: ESO + External Vault (Industry Standard)

```
┌─────────────────────────────────────────┐
│  Kubernetes Cluster                     │
│                                         │
│  ExternalSecret ──► ESO ──► K8s Secret  │
│                      │          │       │
│                      │     Volume Mount  │
│                      │          │       │
│                      │     ┌────▼────┐  │
│                      │     │   Pod   │  │
│                      │     └─────────┘  │
│                      │                  │
└──────────────────────┼──────────────────┘
                       │
                 ┌─────▼─────┐
                 │ OpenBao / │
                 │   Vault   │
                 └───────────┘
```

**Pros**: Simple, well-understood, works with any provider.
**Cons**: Secrets materialized in etcd, pod has plaintext access.

### Pattern B: CSI Driver Direct Mount (No etcd)

```
┌─────────────────────────────────────────┐
│  Kubernetes Cluster                     │
│                                         │
│  SecretProviderClass                    │
│        │                                │
│   CSI Driver ──────────────┐            │
│        │              tmpfs mount       │
│        │              ┌────▼────┐       │
│        │              │   Pod   │       │
│        │              └─────────┘       │
│        │                                │
└────────┼────────────────────────────────┘
         │
    ┌────▼─────┐
    │ OpenBao  │
    └──────────┘
```

**Pros**: Secrets never in etcd, exist only while pod runs.
**Cons**: No auto-refresh, provider-specific, secrets still readable by pod.

### Pattern C: Sidecar + Dynamic Secrets (Maximum Security)

```
┌──────────────────────────────────────────────┐
│  Kubernetes Cluster                          │
│                                              │
│  ┌──────────────────────────────┐            │
│  │  Pod                         │            │
│  │  ┌──────────┐  ┌──────────┐ │            │
│  │  │  Vault   │  │   App    │ │            │
│  │  │ Sidecar  │──│Container │ │            │
│  │  │          │  │          │ │            │
│  │  └────┬─────┘  └──────────┘ │            │
│  │       │    shared tmpfs     │            │
│  └───────┼─────────────────────┘            │
│          │                                   │
└──────────┼───────────────────────────────────┘
           │
      ┌────▼─────┐
      │ OpenBao  │
      └──────────┘
```

**Pros**: Dynamic secrets with auto-refresh, short-lived credentials.
**Cons**: Resource overhead per pod, Vault-specific, pod still reads plaintext.

### Pattern D: credential-proxy (Zero-Knowledge)

```
┌─────────────────────────────────────────────────┐
│  MicroVM                                        │
│                                                 │
│  ┌──────────┐  placeholder   ┌───────────────┐ │
│  │  Agent   │───────────────►│ credential-   │ │
│  │ (LLM)   │◄───────────────│   proxy       │ │
│  └──────────┘  scrubbed resp │  (MITM + OPA  │ │
│                              │   + Temporal)  │ │
│                              └───────┬────────┘ │
│                                      │ VSOCK    │
└──────────────────────────────────────┼──────────┘
                                       │
                          ┌────────────▼─────────┐
                          │  Host                │
                          │  ┌──────────┐        │
                          │  │ OpenBao  │        │
                          │  └──────────┘        │
                          │  ┌──────────┐        │
                          │  │ Temporal │        │
                          │  └──────────┘        │
                          └──────────────────────┘
```

**Pros**: Zero-knowledge (agent never sees real secrets), response scrubbing, per-request audit, formally verified, hardware isolation.
**Cons**: Most complex, requires MITM proxy infrastructure.

### Assessment

| Aspect | Pattern A | Pattern B | Pattern C | Pattern D |
|--------|-----------|-----------|-----------|-----------|
| Workload trust | Trusted | Trusted | Trusted | **Untrusted** |
| Secret exposure to workload | Yes | Yes | Yes | **No** |
| Response scrubbing | No | No | No | **Yes** |
| Per-request authz | No | No | No | **Yes** |
| Dynamic secrets | Via backend | No | Yes | JIT fetch |
| Operational complexity | Low | Low | Medium | High |
| Industry adoption | Very high | High | High | Niche (emerging) |

---

## 4. Emerging Trends (2025-2026)

### Dynamic Secrets as Default
The industry is moving from static, long-lived credentials to dynamic, short-lived ones. 75% faster K8s adoption is reported when eliminating static secret management bottlenecks. Dynamic secrets reduce the damage window from months to minutes.

### Zero-Trust Secrets
Every secret access is treated as untrusted: authenticated, authorized, and audited individually. This aligns closely with credential-proxy's per-request model.

### License Shifts
HashiCorp's BSL change is pushing the industry toward OpenBao, Infisical, and other open-source alternatives. GitLab has invested in OpenBao. NASA is evaluating OpenBao as a Vault replacement.

### Operator Pattern Dominance
K8s operators (ESO, VSO, Infisical Operator, Doppler Operator) have become the standard integration pattern, replacing sidecars for most static/semi-dynamic secret use cases.

---

## Summary

| Solution | Best For | Skip If |
|----------|---------|---------|
| **OpenBao** | Open-source Vault replacement, dynamic secrets, full control | You need DR replication or commercial support |
| **Vault Enterprise** | Large enterprise, compliance requirements, DR replication | BSL license is a concern, budget-constrained |
| **ESO** | Multi-provider K8s secret sync, GitOps-friendly | You only use one provider and prefer tighter integration |
| **CSI Driver** | Secrets that should never touch etcd | You need auto-refresh or multi-provider |
| **Vault Sidecar** | Dynamic secrets with continuous refresh | Resource overhead is a concern |
| **Infisical** | Developer-friendly, fast setup, MIT core | Complex dynamic secret scenarios |
| **Doppler** | Zero operational overhead, SaaS-friendly teams | Self-hosted requirement, open-source requirement |
| **Sealed Secrets** | GitOps with encrypted secrets in repo | You need rotation or dynamic secrets |
| **SOPS** | File-level encryption, Flux integration | You need API-oriented secret management |
| **credential-proxy** | Untrusted workloads, zero-knowledge delivery | Workloads are trusted and you don't need response scrubbing |

## Key Takeaways

### Adopt
- **External Secrets Operator** — Industry standard K8s integration layer; use regardless of vault backend choice
- **OpenBao** — Already chosen for credential-proxy; best open-source vault with Vault API compatibility

### Adapt
- **ESO + OpenBao** as K8s deployment path — If credential-proxy ever runs on K8s, ESO provides the bridge for non-agent secrets (TLS certs, service configs). Agent-facing credentials still flow through credential-proxy's zero-knowledge path
- **Dynamic secrets pattern** — OpenBao's dynamic secret engines (database, cloud IAM) could generate short-lived credentials per-agent-session instead of static KV secrets

### Defer
- **Vault Enterprise** — Only if DR replication or commercial support becomes a hard requirement
- **Infisical/Doppler** — Simpler alternatives if OpenBao operational complexity becomes a burden for the team

### Skip
- **Sealed Secrets** — credential-proxy already uses sops-nix for encrypted secrets in the Nix config; Sealed Secrets adds no value
- **CSI Driver alone** — ESO is strictly more capable for the OpenClaw use case
- **CyberArk Conjur** — Enterprise-oriented, opaque pricing, overkill for current scale
