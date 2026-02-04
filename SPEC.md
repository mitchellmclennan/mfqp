# Metalogue Federated Query Protocol (MFQP) v1.0

**Status:** Draft  
**Version:** 1.0.0  
**Date:** 2026-02-04  
**Authors:** Metalogue Protocol Team  
**License:** Apache 2.0

---

## Abstract

The Metalogue Federated Query Protocol (MFQP) defines a standard for privacy-preserving, cryptographically attested queries between AI systems operated by different organizations. MFQP enables "Ghost Queries" — intent-only transmissions that reveal the purpose of a query without exposing raw data.

MFQP is designed for:
- Enterprise B2B AI intelligence sharing
- Cross-organizational RAG federation
- Compliance-friendly knowledge exchange
- Metered intelligence settlement (pay-per-query)

---

## 1. Introduction

### 1.1 Motivation

Modern enterprises deploy AI systems that could benefit from querying external knowledge bases. However, direct federation of RAG systems raises significant privacy, compliance, and trust concerns:

1. **Privacy**: Raw queries may reveal sensitive business information
2. **Compliance**: Data residency and access controls must be enforced
3. **Trust**: Responses must be verifiable and non-repudiable
4. **Settlement**: Intelligence exchange should be metered and billable

MFQP addresses these concerns through:
- **Intent-only queries** ("Ghost Queries") that transmit purpose, not content
- **Policy-based access control** at the responder
- **Cryptographic attestation** of all responses
- **Transaction metering** via the "Truth Tax" model

### 1.2 Terminology

| Term | Definition |
|------|------------|
| **Ghost Query** | An intent-only query that reveals purpose without transmitting raw content |
| **Requester** | The organization sending a query |
| **Responder** | The organization processing a query and returning a response |
| **Attestation** | Cryptographic proof of response authenticity using Ed25519 signatures |
| **Truth Tax** | Per-query transaction fee for verified intelligence exchange |
| **Redaction** | Policy-based removal of sensitive fields from responses |
| **Shredding** | Cryptographic destruction of ephemeral context after query completion |

### 1.3 Protocol Overview

```
┌─────────────┐         Ghost Query         ┌─────────────┐
│  Requester  │ ──────────────────────────► │  Responder  │
│    (Org A)  │                             │    (Org B)  │
│             │       Attested Response     │             │
│             │ ◄────────────────────────── │             │
└─────────────┘                             └─────────────┘
       │                                           │
       └────────── Metalogue Gateway ──────────────┘
                  (routing, billing, audit)
```

---

## 2. Message Formats

### 2.1 Ghost Query

A Ghost Query is the fundamental request message in MFQP. It transmits intent rather than raw query content.

#### 2.1.1 Wire Format (JSON)

```json
{
  "mfqp_version": "1.0",
  "message_type": "ghost_query",
  "query_id": "550e8400-e29b-41d4-a716-446655440000",
  "source_company": "acme-corp",
  "target_company": "globex-inc",
  "intent": "What is the current inventory status for SKU-12345?",
  "intent_class": "inventory.status",
  "auth_level": "verified",
  "freshness_required_seconds": 300,
  "timestamp": "2026-02-04T10:30:00.000Z",
  "signature": "base64-encoded-ed25519-signature"
}
```

#### 2.1.2 Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mfqp_version` | string | Yes | Protocol version (semver format) |
| `message_type` | string | Yes | Must be `"ghost_query"` |
| `query_id` | string (UUID v4) | Yes | Globally unique query identifier |
| `source_company` | string | Yes | Requester organization slug |
| `target_company` | string | Yes | Responder organization slug |
| `intent` | string | Yes | Natural language description of query intent |
| `intent_class` | string | Yes | Classified intent category (hierarchical, dot-separated) |
| `auth_level` | string | Yes | Authentication level: `"pending"`, `"verified"`, `"trusted"` |
| `freshness_required_seconds` | integer | No | Maximum age of response data (default: 300) |
| `timestamp` | string (ISO 8601) | Yes | Query creation timestamp in UTC |
| `signature` | string (Base64) | Yes | Ed25519 signature of canonical message bytes |

#### 2.1.3 Intent Classes

Intent classes are hierarchical identifiers that enable policy matching without exposing query content:

```
contract.terms           - Contract term inquiries
contract.pricing         - Pricing information requests
inventory.status         - Inventory level queries
inventory.forecast       - Demand forecasting requests
personnel.org_chart      - Organizational structure queries
personnel.contact        - Contact information requests
legal.compliance         - Compliance status checks
financial.metrics        - Financial performance queries
```

### 2.2 Query Response

A Query Response is the attested answer to a Ghost Query.

#### 2.2.1 Wire Format (JSON)

```json
{
  "mfqp_version": "1.0",
  "message_type": "query_response",
  "query_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "success",
  "payload": {
    "encrypted": true,
    "algorithm": "AES-256-GCM",
    "ciphertext": "base64-encoded-encrypted-payload",
    "nonce": "base64-encoded-nonce"
  },
  "redactions": ["field.salary", "field.ssn"],
  "results_count": 3,
  "freshness_timestamp": "2026-02-04T10:30:00.500Z",
  "attestation": {
    "attestation_id": "660e8400-e29b-41d4-a716-446655440001",
    "response_hash": "sha256-hash-of-response",
    "signer_key_id": "sha256-fingerprint-of-public-key",
    "policy_snapshot": {
      "policy_id": "770e8400-e29b-41d4-a716-446655440002",
      "allowed_intent": "inventory.status",
      "redacted_fields": ["field.cost"]
    },
    "signature": "base64-encoded-ed25519-signature"
  },
  "timestamp": "2026-02-04T10:30:01.000Z"
}
```

#### 2.2.2 Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mfqp_version` | string | Yes | Protocol version |
| `message_type` | string | Yes | Must be `"query_response"` |
| `query_id` | string (UUID) | Yes | Matching query identifier |
| `status` | string | Yes | `"success"`, `"denied"`, `"error"`, `"timeout"` |
| `payload` | object | Conditional | Required if status is `"success"` |
| `payload.encrypted` | boolean | Yes | Whether payload is encrypted |
| `payload.algorithm` | string | Conditional | Encryption algorithm (if encrypted) |
| `payload.ciphertext` | string (Base64) | Conditional | Encrypted response content |
| `payload.nonce` | string (Base64) | Conditional | Encryption nonce |
| `redactions` | array[string] | Yes | List of redacted field paths |
| `results_count` | integer | Yes | Number of results returned |
| `freshness_timestamp` | string (ISO 8601) | Yes | When data was fetched |
| `attestation` | object | Yes | Cryptographic attestation |
| `attestation.attestation_id` | string (UUID) | Yes | Unique attestation identifier |
| `attestation.response_hash` | string | Yes | SHA-256 hash of unencrypted response |
| `attestation.signer_key_id` | string | Yes | SHA-256 fingerprint of signing key |
| `attestation.policy_snapshot` | object | Yes | Policy applied at response time |
| `attestation.signature` | string (Base64) | Yes | Ed25519 signature |
| `timestamp` | string (ISO 8601) | Yes | Response creation timestamp |

---

## 3. Cryptographic Requirements

### 3.1 Signing Algorithm

MFQP uses **Ed25519** (Edwards-curve Digital Signature Algorithm) as specified in [RFC 8032](https://tools.ietf.org/html/rfc8032).

#### 3.1.1 Key Characteristics

| Property | Value |
|----------|-------|
| Algorithm | Ed25519 |
| Private Key Size | 32 bytes |
| Public Key Size | 32 bytes |
| Signature Size | 64 bytes |
| Security Level | ~128-bit |

#### 3.1.2 Why Ed25519?

- **Fast**: Sub-millisecond signing and verification
- **Secure**: No known practical attacks
- **Small**: 64-byte signatures vs 256+ for RSA
- **Standard**: Widely adopted (SSH, Signal, TLS 1.3)
- **Deterministic**: Same message + key = same signature

### 3.2 Message Canonicalization

Before signing, messages MUST be canonicalized to ensure consistent signatures.

#### 3.2.1 Ghost Query Canonicalization

```
canonical_bytes = 
    version_byte (0x01)                   # 1 byte
    + mfqp_version (UTF-8, length-prefixed)
    + query_id (UUID bytes, 16 bytes)
    + source_company (UTF-8, length-prefixed)
    + target_company (UTF-8, length-prefixed)
    + intent (UTF-8, length-prefixed)
    + intent_class (UTF-8, length-prefixed)
    + auth_level (UTF-8, length-prefixed)
    + freshness_required_seconds (big-endian uint32)
    + timestamp_microseconds (big-endian uint64)
```

#### 3.2.2 Response Canonicalization

```
canonical_bytes =
    version_byte (0x01)                   # 1 byte
    + response_hash (32 bytes, SHA-256)
    + timestamp_microseconds (big-endian uint64)
    + policy_hash (32 bytes, SHA-256 of JSON-encoded policy)
```

### 3.3 Signature Generation

```python
# Python example using cryptography library
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def sign_message(message_bytes: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """Sign canonical message bytes with Ed25519."""
    return private_key.sign(message_bytes)  # Returns 64-byte signature
```

### 3.4 Signature Verification

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def verify_signature(
    message_bytes: bytes, 
    signature: bytes, 
    public_key: Ed25519PublicKey
) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    try:
        public_key.verify(signature, message_bytes)
        return True
    except InvalidSignature:
        return False
```

### 3.5 Public Key Registration

Organizations MUST register their Ed25519 public keys with the Metalogue Gateway before sending queries.

#### 3.5.1 Key Fingerprint

```python
import hashlib

def compute_key_fingerprint(public_key_bytes: bytes) -> str:
    """Compute SHA-256 fingerprint of public key."""
    return hashlib.sha256(public_key_bytes).hexdigest()
```

---

## 4. Protocol Semantics

### 4.1 Query Lifecycle

```
1. SUBMIT      Requester creates and signs Ghost Query
       │
       ▼
2. ROUTE       Gateway validates signature and routes to Responder
       │
       ▼
3. PROCESS     Responder evaluates policy and executes query
       │
       ▼
4. RESPOND     Responder creates attested response
       │
       ▼
5. VERIFY      Gateway verifies attestation
       │
       ▼
6. SETTLE      Gateway records transaction and calculates fee
       │
       ▼
7. SHRED       Context is cryptographically destroyed
```

### 4.2 Policy Evaluation

Responders MUST evaluate incoming queries against their federation policies before processing.

#### 4.2.1 Policy Matching

1. Check if `intent_class` matches any `allowed_intents` pattern
2. Check if `intent_class` matches any `denied_intents` pattern (deny wins)
3. Apply `max_results_per_query` limit
4. Apply `redacted_fields` to response

### 4.3 Response Status Codes

| Status | Description |
|--------|-------------|
| `success` | Query processed successfully |
| `denied` | Query denied by policy |
| `timeout` | Query processing exceeded time limit |
| `error` | Internal error during processing |
| `rate_limited` | Rate limit exceeded |

---

## 5. Error Codes

### 5.1 Transport Errors

| Code | Name | Description |
|------|------|-------------|
| `E001` | `INVALID_SIGNATURE` | Ed25519 signature verification failed |
| `E002` | `UNKNOWN_SENDER` | Source company not registered |
| `E003` | `UNKNOWN_TARGET` | Target company not found |
| `E004` | `PARTNER_SUSPENDED` | Partner relationship is suspended |
| `E005` | `RATE_LIMITED` | Rate limit exceeded |
| `E006` | `TIMEOUT` | Request timed out |

### 5.2 Policy Errors

| Code | Name | Description |
|------|------|-------------|
| `P001` | `INTENT_NOT_ALLOWED` | Intent class not in allowed list |
| `P002` | `INTENT_DENIED` | Intent class explicitly denied |
| `P003` | `FRESHNESS_UNAVAILABLE` | Cannot meet freshness requirement |

### 5.3 Processing Errors

| Code | Name | Description |
|------|------|-------------|
| `X001` | `INTERNAL_ERROR` | Internal processing error |
| `X002` | `NO_RESULTS` | Query returned no results |
| `X003` | `ATTESTATION_FAILED` | Failed to generate attestation |

---

## 6. Versioning

### 6.1 Version Format

MFQP uses [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH
```

- **MAJOR**: Breaking changes to wire format or semantics
- **MINOR**: Backward-compatible additions
- **PATCH**: Bug fixes and clarifications

### 6.2 Version Negotiation

Implementations MUST:
1. Include `mfqp_version` in all messages
2. Reject messages with unsupported MAJOR versions
3. Accept messages with higher MINOR versions (forward-compatible)

### 6.3 Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-02-04 | Initial release |

---

## 7. Security Considerations

### 7.1 Key Management

- Private keys MUST be stored encrypted at rest
- Key rotation SHOULD occur every 90 days
- Compromised keys MUST be revoked immediately

### 7.2 Replay Prevention

- Each `query_id` MUST be globally unique (UUID v4)
- Responders SHOULD reject duplicate `query_id` values
- Timestamps MUST be within 5 minutes of server time

### 7.3 Privacy Preservation

- Ghost Queries transmit intent, not raw data
- Responders MAY redact sensitive fields
- Context MUST be shredded after completion

### 7.4 Rate Limiting

Implementations SHOULD enforce:
- Per-partner daily query limits
- Per-partner per-minute query limits
- Global rate limits for DDoS protection

---

## 8. Wire Format Examples

### 8.1 Complete Ghost Query

```json
{
  "mfqp_version": "1.0",
  "message_type": "ghost_query",
  "query_id": "550e8400-e29b-41d4-a716-446655440000",
  "source_company": "boeing",
  "target_company": "ge-aviation",
  "intent": "What is the current lead time for CFM LEAP-1B engine parts?",
  "intent_class": "supply_chain.lead_time",
  "auth_level": "trusted",
  "freshness_required_seconds": 600,
  "timestamp": "2026-02-04T10:30:00.000Z",
  "signature": "d2VyZW5vdGdvaW5ndG9wdWJsaXNoYXJlYWxzaWduYXR1cmVoZXJlLi4u"
}
```

### 8.2 Complete Query Response

```json
{
  "mfqp_version": "1.0",
  "message_type": "query_response",
  "query_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "success",
  "payload": {
    "encrypted": false,
    "content": {
      "results": [
        {
          "part_family": "CFM LEAP-1B",
          "lead_time_days": 45,
          "availability": "in_stock"
        }
      ]
    }
  },
  "redactions": ["unit_cost", "supplier_margin"],
  "results_count": 1,
  "freshness_timestamp": "2026-02-04T10:30:00.500Z",
  "attestation": {
    "attestation_id": "660e8400-e29b-41d4-a716-446655440001",
    "response_hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
    "signer_key_id": "b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567",
    "policy_snapshot": {
      "policy_id": "770e8400-e29b-41d4-a716-446655440002",
      "allowed_intent": "supply_chain.*",
      "redacted_fields": ["unit_cost", "supplier_margin"]
    },
    "signature": "YW5vdGhlcmZha2VzaWduYXR1cmVmb3JkZW1vcHVycG9zZXM="
  },
  "timestamp": "2026-02-04T10:30:01.000Z"
}
```

---

## 9. Reference Implementations

Reference implementations are provided in:

- **Python**: `sdks/python/metalogue/protocol/mfqp.py`
- **TypeScript**: `sdks/typescript/src/protocol/mfqp.ts`

These implementations demonstrate correct message format, signing, and verification.

---

## 10. Conformance

An implementation conforms to MFQP v1.0 if it:

1. **Messages**: Produces and consumes messages matching the wire formats in Section 2
2. **Signing**: Uses Ed25519 signatures as specified in Section 3
3. **Verification**: Correctly verifies signatures before processing
4. **Lifecycle**: Implements the query lifecycle in Section 4.1
5. **Errors**: Returns appropriate error codes from Section 5

---

## Appendix A: JSON Schema

### A.1 Ghost Query Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://metalogue.xyz/schemas/mfqp/ghost-query.json",
  "title": "MFQP Ghost Query",
  "type": "object",
  "required": ["mfqp_version", "message_type", "query_id", "source_company", 
               "target_company", "intent", "intent_class", "auth_level", 
               "timestamp", "signature"],
  "properties": {
    "mfqp_version": { "type": "string", "pattern": "^\\d+\\.\\d+$" },
    "message_type": { "const": "ghost_query" },
    "query_id": { "type": "string", "format": "uuid" },
    "source_company": { "type": "string", "minLength": 1 },
    "target_company": { "type": "string", "minLength": 1 },
    "intent": { "type": "string", "minLength": 1 },
    "intent_class": { "type": "string", "pattern": "^[a-z_]+(?:\\.[a-z_]+)*$" },
    "auth_level": { "enum": ["pending", "verified", "trusted"] },
    "freshness_required_seconds": { "type": "integer", "minimum": 0, "default": 300 },
    "timestamp": { "type": "string", "format": "date-time" },
    "signature": { "type": "string", "contentEncoding": "base64" }
  }
}
```

---

## Appendix B: Contributing

MFQP is an open protocol. Contributions are welcome via:

- GitHub Issues: Report bugs or propose enhancements
- Pull Requests: Submit specification changes
- Mailing List: Discuss protocol design

---

## Appendix C: License

This specification is released under the Apache License 2.0.

```
Copyright 2026 Metalogue, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
