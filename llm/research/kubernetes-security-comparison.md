---
title: "Kubernetes Security vs. credential-proxy — Domain Research"
date: "2026-03-02"
depth: "standard-research"
request: "standalone"
---

## Executive Summary

Kubernetes provides a rich set of security primitives — Secrets, RBAC, Network Policies, Service Account Token Projection, CSI Secret Store Driver, and OPA Gatekeeper — that collectively address many of the same *axes* as credential-proxy. However, Kubernetes was designed for **trusted workloads operated by trusted humans**, whereas credential-proxy was designed for **untrusted LLM-generated code that may actively attempt credential exfiltration**. This fundamental threat model difference means Kubernetes provides the *building blocks* but not the *assembled security guarantees* that credential-proxy delivers. In particular, Kubernetes has no native equivalent for response scrubbing, zero-knowledge credential delivery, per-request domain binding, or formally verified concurrency protocols.

The short answer: **Kubernetes gives you the ingredients, but you'd still need to build the recipe** — and that recipe is essentially what credential-proxy is.

---

## 1. Secret Storage and Delivery

### Kubernetes Secrets (`data` field)

Kubernetes Secrets store sensitive data (API keys, passwords, TLS certs) as base64-encoded values in the `data` field. They can be consumed by pods as:

- **Volume mounts**: Files appear on disk at a path in the container
- **Environment variables**: Values injected into the container's env
- **Projected volumes**: Multiple Secrets, ConfigMaps, and service account tokens combined into a single mount

**Critical limitation**: Base64 is encoding, not encryption. Secrets are stored **unencrypted in etcd by default**. Anyone with API access or direct etcd access can read them. Encryption at rest is available (AESCBC, Secretbox, or KMS provider) but must be explicitly configured.

**Exposure model**: Once a Secret is mounted into a pod, **the workload has full access to the plaintext value**. There is no mechanism to prevent the workload from reading, logging, or exfiltrating the secret content. The pod is trusted to handle secrets responsibly.

### Secrets Store CSI Driver

The [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/) mounts secrets from external stores (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) as files in pods — bypassing etcd entirely. Secrets are fetched JIT at pod startup.

**Benefits over native Secrets:**
- Secrets never stored in etcd
- Central secret management with rotation
- Audit logging in the external vault
- Pod-level access control via service account binding

**Same fundamental limitation**: The pod still receives the **real secret value** as a file on disk. An exfiltration-capable workload can read it.

### Vault Agent Sidecar Injector

HashiCorp's [Vault Agent Injector](https://developer.hashicorp.com/vault/docs/deploy/kubernetes/injector) deploys a sidecar container that authenticates to Vault using the pod's service account, fetches secrets, and writes them to a shared in-memory volume (`/vault/secrets/`).

**Benefits:**
- Dynamic secret generation (e.g., database credentials with TTL)
- Automatic token renewal and secret refresh
- No Vault client library needed in the application

**Same limitation**: The application pod reads real secret values from the shared volume. The sidecar pattern is a **delivery mechanism**, not a **zero-knowledge mechanism**.

### credential-proxy: Placeholder Substitution

credential-proxy takes a fundamentally different approach:

1. Agent uses opaque placeholder tokens (`agent-vault-<uuid>`) in requests
2. Proxy intercepts the request, fetches real credentials from OpenBao
3. Proxy substitutes placeholders with real values **after the request leaves the agent**
4. Proxy scrubs real values back to placeholders in the response **before the agent sees it**

**The agent never possesses the real credential.** This is the core distinction.

### Assessment

| Aspect | K8s Secrets | CSI Driver | Vault Sidecar | credential-proxy |
|--------|------------|------------|---------------|-----------------|
| Secret storage | etcd (base64) | External vault | External vault | OpenBao (KV v2) |
| Delivery mechanism | Volume mount / env var | Volume mount | Shared volume | Placeholder substitution |
| Workload sees real secret | **Yes** | **Yes** | **Yes** | **No** |
| JIT fetch | No (pod startup) | Pod startup | Pod startup + refresh | Per-request |
| Response scrubbing | N/A | N/A | N/A | Yes (real -> placeholder) |
| Encryption at rest | Optional (KMS) | In external vault | In Vault | In OpenBao |
| Formally verified | No | No | No | TLA+ model |

**Adoption recommendation: Skip** — Kubernetes secret delivery mechanisms fundamentally trust the workload to handle secrets responsibly. This is the wrong trust model for untrusted LLM-generated code. credential-proxy's zero-knowledge design is specifically built for this threat.

---

## 2. Authentication and Identity

### Kubernetes Service Account Tokens

Since v1.20, Kubernetes uses **bound service account tokens** by default:
- Time-limited (configurable expiry)
- Audience-bound (specific API server or external service)
- Object-bound (tied to specific pod)
- OIDC-compatible (external services can validate via OIDC Discovery)

Projected service account token volumes allow pods to obtain tokens scoped to a specific audience, enabling **workload identity federation** with cloud providers (GCP Workload Identity, Azure AD Workload Identity, AWS IRSA).

### credential-proxy: OIDC per-request verification

credential-proxy validates a Keycloak-issued JWT on **every proxied request** (inline, before any Temporal workflow starts):
- Subject = agent identity
- Roles extracted from `realm_access.roles`
- Groups from `groups` claim
- Token expiry enforced with sentinel errors
- Raw JWT stripped (`Proxy-Authorization` header deleted) before upstream forwarding
- JWT never enters Temporal history — only extracted `IdentityClaims` are serialized

### Assessment

| Aspect | K8s Service Accounts | credential-proxy OIDC |
|--------|---------------------|----------------------|
| Token type | JWT (bound, projected) | JWT (Keycloak OIDC) |
| Scope | Pod-level | Per-request |
| External validation | Yes (OIDC Discovery) | Yes (JWKS endpoint) |
| Token stripped from forwarded requests | No (pod handles own auth) | Yes (Proxy-Authorization deleted) |
| Audit per request | No (pod lifecycle events) | Yes (Temporal search attributes per request) |

**Adoption recommendation: Adapt** — K8s service account tokens could serve as the identity source for agents running in pods (agent authenticates to proxy using a projected SA token instead of a Keycloak JWT). However, K8s tokens don't provide per-request validation, role extraction, or JWT stripping — those would still need credential-proxy.

---

## 3. Authorization and Policy

### Kubernetes RBAC

RBAC controls **who can create/read/update/delete Kubernetes resources**. It answers: "Can service account X read Secret Y in namespace Z?"

RBAC does **not** control:
- What the workload does with the secret once it has it
- Which external domains the workload sends the secret to
- Per-request authorization decisions

### OPA Gatekeeper (Admission Controller)

[OPA Gatekeeper](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/) enforces policies at **admission time** (when K8s resources are created/modified). It answers: "Is this Pod spec allowed to exist?"

Examples:
- Block pods running as root
- Enforce resource limits
- Require specific labels
- Restrict image registries

Gatekeeper complements RBAC: RBAC controls **who**, Gatekeeper controls **what the resource looks like**.

### credential-proxy: OPA per-request policy

credential-proxy uses OPA with Rego policies evaluated **per proxied HTTP request**:

```rego
allow if {
    has_roles                    # identity has realm_access.roles
    all_credentials_bound        # every credential's bound_domain == target_domain
}
```

This answers: "Can agent X use credential Y to call domain Z right now?"

**Domain binding enforcement**: Each credential is bound to a specific target domain. An agent with access to an Anthropic API key **cannot use it to call a different domain** — even if the agent has the placeholder token. This is not something Kubernetes provides at any level.

### Assessment

| Aspect | K8s RBAC | OPA Gatekeeper | credential-proxy OPA |
|--------|---------|---------------|---------------------|
| Enforcement point | API server | Admission controller | Per HTTP request |
| Scope | K8s resources | K8s resource specs | HTTP requests to external APIs |
| Domain binding | N/A | N/A | Per-credential domain enforcement |
| Default deny | No (depends on config) | Per-constraint | Yes (`allow := false`) |
| Fail-closed | Depends on config | Yes | Yes (403 with denial reason) |
| Audit trail | K8s audit log | Audit violations | Temporal workflow per decision |

**Adoption recommendation: Skip** — K8s RBAC and Gatekeeper operate at the wrong abstraction level. They govern K8s resource access, not per-HTTP-request credential usage. credential-proxy's OPA policies are purpose-built for the "can this agent use this credential against this domain" question.

---

## 4. Network Isolation

### Kubernetes Network Policies

K8s NetworkPolicy resources control pod-to-pod and pod-to-external traffic at the IP/port level:

- **Egress policies**: Restrict which IPs/ports a pod can connect to
- **Ingress policies**: Restrict which pods can connect to a service
- **DNS-based policies** (with Calico/Cilium): Filter by domain name

A well-configured egress policy can prevent a compromised pod from calling arbitrary external services.

### credential-proxy: nftables + VSOCK

credential-proxy's network model is more restrictive:

```
VM outbound: BLOCKED except DNS (UDP 53) and Tailscale (UDP 41641)
HTTP(S) traffic: FORCED through credential proxy (HTTP_PROXY=localhost:18790)
VSOCK: Not TCP/IP; bypasses guest network stack entirely
```

**Key difference**: VSOCK is not a network interface. It's a virtio transport between VM guest and host that is immune to nftables rules, network sniffing, and guest-side firewall manipulation. A compromised agent cannot modify iptables/nftables to bypass the proxy because the proxy communicates over a hardware-level channel the guest OS cannot intercept.

### Assessment

| Aspect | K8s Network Policies | credential-proxy nftables + VSOCK |
|--------|---------------------|----------------------------------|
| Enforcement | CNI plugin (Calico, Cilium) | Kernel nftables + KVM/virtio |
| Bypass by compromised workload | Possible (container escape → host netns) | Extremely difficult (requires KVM escape) |
| Domain-level filtering | With Cilium L7 policies | Domain allowlist in proxy |
| Proxy enforcement | Not guaranteed | All HTTP forced through proxy |
| Transport security | mTLS (service mesh) | VSOCK (hardware isolation) |

**Adoption recommendation: Adapt** — K8s Network Policies provide useful defense-in-depth for the outer boundary (which external IPs the VM's pod can reach). However, they cannot replace VSOCK's hardware-level isolation guarantee or the mandatory proxy routing. Use both: K8s policies for pod-level egress control, credential-proxy for in-VM request-level control.

---

## 5. Audit and Observability

### Kubernetes Audit Logging

K8s API server audit logging records who accessed which resources when, at configurable verbosity levels (Metadata, Request, RequestResponse). Events are written to log files or webhook backends.

**Limitations:**
- Records K8s API operations, not application-level HTTP requests
- Does not track which external APIs a workload called or which credentials it used
- No per-request correlation of identity → credential → target domain → response

### credential-proxy: Temporal Workflow Audit Trail

Each proxied request creates a Temporal workflow with queryable search attributes:

```
CredProxyAgentID:           (agent subject from JWT)
CredProxyTargetDomain:      (e.g., "api.anthropic.com")
CredProxyCredentialRefHash: (comma-separated placeholder list)
CredProxyStatus:            (in_progress, success, denied, error, timeout)
```

This provides a **tamper-resistant, per-request audit trail** with full lifecycle tracking: authentication → authorization → credential injection → upstream response → response scrubbing.

### Assessment

| Aspect | K8s Audit Logging | credential-proxy Temporal |
|--------|-------------------|--------------------------|
| Granularity | K8s API operations | Per-HTTP-request lifecycle |
| Tracks credential usage | No | Yes (which credential, which domain) |
| Tamper resistance | Log file (rotatable) | Temporal event history (append-only) |
| Queryable | Via log aggregation | Native search attributes |
| Real-time | Near-real-time | Real-time (workflow visibility) |

**Adoption recommendation: Skip** — K8s audit logging is complementary but does not replace per-request credential usage auditing. credential-proxy's Temporal-backed audit trail is specifically designed for the "who used what credential where" question.

---

## 6. Response Scrubbing (No K8s Equivalent)

This is the clearest gap. Kubernetes has **no mechanism** to inspect and scrub API responses flowing back to workloads. Once a workload makes an HTTP request (even through a service mesh), the full response is returned to it.

credential-proxy's response scrubbing replaces real credential values with placeholders in upstream responses before they reach the agent. This prevents:
- Upstream APIs echoing back credentials in response bodies
- Error messages containing credential fragments
- Debug/diagnostic responses revealing secrets

**This is architecturally impossible in Kubernetes** without a MITM proxy layer — which is exactly what credential-proxy is.

**Adoption recommendation: Skip** — No K8s feature addresses this. It requires an interception proxy by design.

---

## 7. Formal Verification (No K8s Equivalent)

credential-proxy's concurrency protocol is modeled in TLA+/PlusCal and verified to have:
- No deadlocks
- No race conditions
- No double-writes on decision channels
- Guaranteed handler termination
- Guaranteed registry cleanup

Kubernetes does not formally verify its internal protocols. While K8s is extensively tested, there is no mathematical proof of properties like "a pod's secret access is always cleaned up" or "admission webhooks always terminate."

**Adoption recommendation: Skip** — This is a methodology, not a feature. It's unique to credential-proxy's design approach.

---

## Summary

| Security Axis | K8s Feature | credential-proxy | Gap |
|--------------|------------|-----------------|-----|
| Secret storage | Secrets (etcd), CSI Driver | OpenBao (KV v2) | Comparable |
| Secret delivery | Volume mount, env var, sidecar | Placeholder substitution | **Fundamental** — K8s exposes real secrets |
| Identity | Service Account tokens (OIDC) | Keycloak OIDC per-request | Comparable (K8s tokens adaptable) |
| Authorization | RBAC + Gatekeeper | OPA per-request + domain binding | **Significant** — K8s operates at wrong level |
| Network isolation | Network Policies | nftables + VSOCK | **Significant** — K8s lacks hardware isolation |
| Audit | API audit log | Temporal per-request trail | **Significant** — K8s lacks credential-usage tracking |
| Response scrubbing | None | Real → placeholder | **No K8s equivalent** |
| Formal verification | None | TLA+ model | **No K8s equivalent** |
| Threat model | Trusted workloads | Untrusted LLM code | **Fundamental mismatch** |

## Key Takeaways

### Adopt
- **K8s Network Policies as outer boundary**: Use egress policies to restrict which external IPs the VM pod can reach, as defense-in-depth layered with credential-proxy's internal controls.

### Adapt
- **K8s Service Account tokens as agent identity**: Could replace or complement Keycloak if agents run in K8s pods. The projected SA token provides OIDC-compatible identity that credential-proxy could validate.
- **CSI Driver for OpenBao delivery to credential-proxy itself**: Use CSI to mount the OpenBao AppRole credentials into the credential-proxy pod (not the agent pod), keeping vault credentials out of etcd.

### Defer
- **K8s audit logging integration**: Could correlate K8s pod events with Temporal workflow events for a unified audit view, but not needed for MVP.

### Skip
- **K8s Secrets as replacement for OpenBao**: Wrong trust model — K8s Secrets expose plaintext to the workload.
- **K8s RBAC/Gatekeeper as replacement for per-request OPA**: Wrong abstraction level — governs resource access, not HTTP request authorization.
- **Any K8s feature as replacement for response scrubbing**: Architecturally impossible without a MITM proxy layer.
- **K8s network isolation as replacement for VSOCK**: Container namespaces are escapable; KVM/VSOCK provides hardware boundary.
