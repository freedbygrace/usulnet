# usulnet Licensing & Editions

This document defines the three usulnet editions, their feature sets, resource
limits, and how the license system works at a technical level.

---

## Editions Overview

| Edition | Price Model | Target |
|---------|-------------|--------|
| **Community (CE)** | Free (AGPLv3) | Homelab, personal projects, small teams |
| **Business** | Per-node subscription | SMBs, growing teams, multi-node clusters |
| **Enterprise** | Custom pricing | Large organizations, compliance, unlimited |

---

## Feature Matrix

### Core Features (all editions)

| Feature | CE | Business | Enterprise |
|---------|:--:|:--------:|:----------:|
| Container management (create, start, stop, remove) | Yes | Yes | Yes |
| Image management (pull, build, tag, push) | Yes | Yes | Yes |
| Volume & network management | Yes | Yes | Yes |
| Stack/Compose deployment | Yes | Yes | Yes |
| Basic dashboard & metrics | Yes | Yes | Yes |
| Single-node Docker management | Yes | Yes | Yes |
| Web terminal (single session) | Yes | Yes | Yes |
| Basic RBAC (admin/user) | Yes | Yes | Yes |
| Webhook notifications (1 channel) | Yes | Yes | Yes |

### Business Features

| Feature | Code | CE | Business | Enterprise |
|---------|------|:--:|:--------:|:----------:|
| Custom Roles | `custom_roles` | - | Yes | Yes |
| OAuth Authentication | `oauth` | - | Yes | Yes |
| LDAP/Active Directory | `ldap` | - | Yes | Yes |
| Multi-channel Notifications | `multi_notification` | - | Yes | Yes |
| Audit Log Export | `audit_export` | - | Yes | Yes |
| Multiple Backup Destinations | `multi_backup` | - | Yes | Yes |
| API Keys | `api_keys` | - | Yes | Yes |
| Priority Support | `priority_support` | - | Yes | Yes |
| Docker Swarm Management | `swarm` | - | Yes | Yes |
| Git Sync (GitOps) | `git_sync` | - | Yes | Yes |

### Enterprise-Only Features

| Feature | Code | CE | Business | Enterprise |
|---------|------|:--:|:--------:|:----------:|
| SSO/SAML | `sso_saml` | - | - | Yes |
| High Availability Mode | `ha_mode` | - | - | Yes |
| Shared Terminals | `shared_terminals` | - | - | Yes |
| White-Label Branding | `white_label` | - | - | Yes |
| Compliance (SOC2, HIPAA) | `compliance` | - | - | Yes |
| OPA Policy Engine | `opa_policies` | - | - | Yes |
| Image Signing & Verification | `image_signing` | - | - | Yes |
| Runtime Security | `runtime_security` | - | - | Yes |
| Log Aggregation | `log_aggregation` | - | - | Yes |
| Custom Dashboards | `custom_dashboards` | - | - | Yes |
| Ephemeral Environments | `ephemeral_envs` | - | - | Yes |
| Manifest Builder | `manifest_builder` | - | - | Yes |

---

## Resource Limits

| Resource | CE | Business | Enterprise |
|----------|---:|--------:|-----------:|
| **Max Nodes** | 1 (local only) | From license + 1 | Unlimited |
| **Max Users** | 3 | From license | Unlimited |
| **Max Teams** | 1 | 5 | Unlimited |
| **Max Custom Roles** | 1 | Unlimited | Unlimited |
| **Max LDAP Servers** | 1 | 3 | Unlimited |
| **Max OAuth Providers** | Disabled | 3 | Unlimited |
| **Max API Keys** | 3 | 25 | Unlimited |
| **Max Git Connections** | 1 | 5 | Unlimited |
| **Max S3 Connections** | 1 | 5 | Unlimited |
| **Max Backup Destinations** | 1 | 5 | Unlimited |
| **Max Notification Channels** | 1 | Unlimited | Unlimited |

> **Note:** A limit value of 0 in the code means "unlimited". For CE,
> LDAP is capped at 1 server and OAuth is disabled entirely (0 = disabled,
> gated by the `FeatureLDAP` / `FeatureOAuth` feature flags).

### Business Node Counting

Business licenses specify purchased nodes in the JWT (`nod` claim). The
total allowed nodes are calculated as:

```
total_nodes = purchased_nodes + CEBaseNodes (1)
```

So a customer who buys 3 nodes gets 4 total (3 purchased + 1 base/master).

---

## License Keys (JWT)

License keys are JSON Web Tokens (JWT) signed with **RSA-4096 (RS512)**.

### Token Structure

```json
{
  "lid": "USN-xxxx-xxxx",
  "eml": "<sha256 of customer email>",
  "edition": "biz",
  "nod": 3,
  "usr": 15,
  "features": ["custom_roles", "oauth", "ldap", ...],
  "exp": 1735689600,
  "iat": 1704067200
}
```

| Field | Description |
|-------|-------------|
| `lid` | License ID (must start with `USN-`) |
| `eml` | SHA-256 hash of the customer email |
| `edition` | `biz` (Business) or `ee` (Enterprise) |
| `nod` | Purchased node count (Business only) |
| `usr` | Allowed user count (Business only) |
| `features` | Array of enabled feature flags |
| `exp` | Expiration timestamp (required) |
| `iat` | Issued-at timestamp (required) |

### Security

- **Algorithm**: Only RS512 is accepted (alg=none and HS256 confusion attacks are rejected)
- **Key size**: RSA-4096 minimum enforced
- **Public key**: Embedded in the binary (`internal/license/keys/public.pem`)
- **Private key**: Only exists on the Cloudflare Worker that issues licenses
- **Instance binding**: Licenses are tied to an instance fingerprint (machine ID + hostname + salt)

---

## License Lifecycle

### Activation

1. Admin submits license key via `POST /api/v1/license`
2. JWT is cryptographically verified (RS512 signature, expiration, claims)
3. On success: license state is applied in-memory and persisted to disk
4. Audit log records the activation with edition, license ID, and user info

### Deactivation

1. Admin calls `DELETE /api/v1/license`
2. License is removed from memory and disk
3. System reverts to Community Edition
4. Audit log records the deactivation

### Background Revalidation

A background goroutine re-validates the stored license every **6 hours**:

- If the license has expired, `info.Valid` is set to `false`
- The edition marker is preserved so the UI shows "expired" rather than "CE"
- Features are disabled but data is preserved

### Expiration Notifications

The system sends notifications at configurable thresholds before expiration:

| Days Remaining | Notification Type | Priority |
|---------------:|-------------------|----------|
| 30 | `license_expiry` | High |
| 15 | `license_expiry` | High |
| 7 | `license_expiry` | High |
| 3 | `license_expiry` | High |
| 1 | `license_expiry` | High |
| 0 (expired) | `license_expired` | Critical |

Duplicate notifications are suppressed with a 24-hour cooldown per threshold.

---

## Graceful Degradation

When a paid license expires, the system does **not** crash or lock out users.
Instead, it gracefully degrades:

1. **Features**: All paid features are disabled (return HTTP 402)
2. **Limits**: Resource limits revert to Community Edition values
3. **Data**: All existing data is preserved and accessible
4. **Status endpoint**: `GET /api/v1/license/status` reports degradation state
5. **UI**: Shows "License expired" banner with renewal instructions

### Degradation States

| State | Edition Shown | Limits Applied | Features |
|-------|---------------|----------------|----------|
| Active license | Business/Enterprise | License limits | All licensed features |
| Expired license | Business/Enterprise (expired) | CE limits | None (402 on access) |
| No license | Community Edition | CE limits | None |

---

## API Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | `/api/v1/license` | Get current license info | Admin |
| `POST` | `/api/v1/license` | Activate license key | Admin |
| `DELETE` | `/api/v1/license` | Deactivate license | Admin |
| `GET` | `/api/v1/license/status` | Detailed status with degradation | Admin |

---

## Middleware Enforcement

The license system provides several middleware functions for route protection:

| Middleware | Behavior | HTTP Status |
|-----------|----------|:-----------:|
| `RequireFeature(feature)` | Blocks if feature not in license | 402 |
| `RequirePaid()` | Blocks CE and expired licenses | 402 |
| `RequireEnterprise()` | Blocks non-Enterprise editions | 402 |
| `RequireValidLicense()` | Blocks expired licenses | 402 |
| `RequireLimit(resource, currentFn, limitFn)` | Blocks when resource limit reached | 402 |

All license-related denials return **HTTP 402 Payment Required** with a JSON
error body containing the error code (`LICENSE_REQUIRED`, `LICENSE_EXPIRED`,
or `LIMIT_EXCEEDED`) and upgrade guidance.

---

## Implementation Files

| File | Purpose |
|------|---------|
| `internal/license/license.go` | Editions, features, limits, Info struct |
| `internal/license/validator.go` | JWT parsing and verification |
| `internal/license/provider.go` | Runtime state management |
| `internal/license/store.go` | Disk persistence |
| `internal/license/fingerprint.go` | Instance identification |
| `internal/license/expiration.go` | Expiration checker and graceful degradation |
| `internal/license/notification_adapter.go` | Bridge to notification service |
| `internal/api/handlers/license.go` | REST API endpoints |
| `internal/api/middleware/license.go` | HTTP middleware functions |
