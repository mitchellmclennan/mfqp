# MFQP: Metalogue Federated Query Protocol

**The open standard for secure AI-to-AI communication between enterprises.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/Version-1.0.0-green.svg)](./SPEC.md)

---

## The Problem

Your company's AI needs information from another company's AI.

**Without a standard protocol:**
- 🔓 Raw API calls expose what you're searching for
- 🤝 Point-to-point integrations don't scale
- ❓ No way to verify responses are authentic
- 💸 No standard way to bill for intelligence

**Example:** Boeing's AI asks GE's AI about engine part availability.

| Without MFQP | With MFQP |
|--------------|-----------|
| Boeing sends: `GET /inventory?part=titanium-alloy` | Boeing sends: "What parts have lead time under 30 days?" |
| GE sees Boeing's exact needs → adjusts pricing | GE sees classified intent, not raw query |
| Response is just JSON — can be disputed | Response has Ed25519 attestation — legal proof |
| Custom integration for each partner | Standard protocol works with any partner |

---

## What is MFQP?

MFQP is the **SWIFT for AI cognition** — a standard way for AI systems to:

1. **Query across organizational boundaries** — Your AI talks to their AI
2. **Preserve privacy** — Send intent, not raw data ("Ghost Queries")
3. **Prove authenticity** — Every response is cryptographically signed
4. **Enable billing** — Metered queries with tiered pricing

### How It Works

```
┌─────────────────┐                                    ┌─────────────────┐
│   BOEING AI     │                                    │     GE AI       │
│                 │                                    │                 │
│  "I need to     │      Ghost Query (Intent Only)     │  "Boeing wants  │
│   know engine   │ ──────────────────────────────────►│   lead time     │
│   lead times"   │    • Intent: inventory.lead_time   │   info"         │
│                 │    • Ed25519 signature             │                 │
│                 │                                    │  [Checks policy]│
│                 │      Attested Response             │  [Queries data] │
│  "45 days,      │ ◄──────────────────────────────────│  [Signs result] │
│   verified ✓"   │    • Actual data (lead_time: 45)   │                 │
│                 │    • Ed25519 attestation           │                 │
│                 │    • Policy snapshot               │                 │
└─────────────────┘                                    └─────────────────┘
                              │
                     Metalogue Gateway
                   (routing, billing, trust)
```

---

## Key Concepts

### Ghost Queries

A Ghost Query transmits **intent**, not raw content.

| Traditional API | Ghost Query |
|-----------------|-------------|
| `SELECT * FROM inventory WHERE sku = 'T-5000'` | "What's the lead time for premium alloys?" |
| Exposes exact product codes | Exposes only classified intent |
| Partner learns your roadmap | Partner learns nothing sensitive |

### Intent Classes

Queries are classified into hierarchical categories for policy matching:

```
inventory.status        → "Do you have X in stock?"
inventory.lead_time     → "How long until X is available?"
contract.pricing        → "What's the price for X?"
supply_chain.capacity   → "Can you produce N units by date Y?"
```

Partners define policies: "Allow `inventory.*` but deny `contract.pricing`"

### Cryptographic Attestation

Every response includes an **Ed25519 signature** proving:

1. **Who responded** — Public key fingerprint identifies the signer
2. **What was sent** — SHA-256 hash of response content
3. **When it was sent** — Timestamp prevents replay attacks
4. **What policy applied** — Snapshot of access rules at response time

**This is legal proof.** If GE says "We never said 45 days lead time" — you have the signed attestation.

### Truth Tax (Transaction Fees)

Queries are metered and billed per transaction:

| Intent Class | Fee | Example |
|--------------|-----|---------|
| Simple (public data) | $0.25 | "What are your office hours?" |
| Standard (business data) | $0.50 | "What's the lead time for part X?" |
| Proprietary (competitive data) | $2-5 | "What's your production capacity?" |
| Financial (high-value data) | $10-100 | "What's your margin on product Y?" |

---

## Quick Start

### Python

```bash
pip install mfqp
```

```python
from mfqp import GhostQuery, sign_message, verify_signature
from mfqp.crypto import generate_keypair

# Generate Ed25519 keypair (do this once, store securely)
private_key, public_key = generate_keypair()

# Create a Ghost Query
query = GhostQuery(
    source_company="boeing",
    target_company="ge-aviation",
    intent="What is the current lead time for CFM LEAP-1B engine parts?",
    intent_class="inventory.lead_time",
    auth_level="trusted"
)

# Sign the query
signature = sign_message(query, private_key)
print(f"Query ID: {query.query_id}")
print(f"Signature: {signature.hex()[:32]}...")

# Send via Metalogue Gateway (or directly to partner)
# response = gateway.send(query, signature)

# Verify the response attestation
# is_valid = verify_signature(response.attestation, partner_public_key)
```

### TypeScript

```bash
npm install @metalogue/mfqp
```

```typescript
import { GhostQuery, signMessage, verifySignature, generateKeypair } from '@metalogue/mfqp';

// Generate keypair
const { privateKey, publicKey } = await generateKeypair();

// Create query
const query = new GhostQuery({
  sourceCompany: 'boeing',
  targetCompany: 'ge-aviation',
  intent: 'What is the current lead time for CFM LEAP-1B engine parts?',
  intentClass: 'inventory.lead_time',
  authLevel: 'trusted'
});

// Sign
const signature = await signMessage(query, privateKey);

// Verify response (after receiving)
const isValid = await verifySignature(response.attestation, signature, partnerPublicKey);
```

### Go

```bash
go get github.com/mitchellmclennan/mfqp-go
```

```go
import "github.com/mitchellmclennan/mfqp-go/protocol"

query, _ := protocol.NewGhostQuery(protocol.GhostQueryParams{
    SourceCompany: "boeing",
    TargetCompany: "ge-aviation",
    Intent:        "What is the current lead time for CFM LEAP-1B engine parts?",
    IntentClass:   "inventory.lead_time",
    AuthLevel:     "trusted",
})

signature, _ := protocol.SignMessage(query, privateKey)
```

---

## Protocol Features

### Security

| Feature | Description |
|---------|-------------|
| **Ed25519 Signatures** | 128-bit security, sub-millisecond signing |
| **Replay Protection** | Unique query IDs + 5-minute timestamp window |
| **Key Fingerprints** | SHA-256 fingerprints for key identification |
| **Message Canonicalization** | Deterministic byte order for consistent signatures |

### Privacy

| Feature | Description |
|---------|-------------|
| **Intent-Only Queries** | Send purpose, not raw data |
| **Policy-Based Redaction** | Partners control what fields are returned |
| **Context Shredding** | Ephemeral data destroyed after query |

### Enterprise

| Feature | Description |
|---------|-------------|
| **Hierarchical Intent Classes** | Fine-grained access control |
| **Attestation Certificates** | Non-repudiable response proof |
| **Transaction Metering** | Per-query billing hooks |
| **Rate Limiting** | DDoS protection built into spec |

---

## Specification

See [SPEC.md](./SPEC.md) for the complete protocol specification:

- **Section 2**: Message formats (Ghost Query, Response, Attestation)
- **Section 3**: Cryptographic requirements (Ed25519, canonicalization)
- **Section 4**: Protocol semantics (lifecycle, policy evaluation)
- **Section 5**: Error codes (E001-E006, P001-P003, X001-X003)
- **Section 6**: Versioning and compatibility
- **Section 7**: Security considerations

---

## Reference Implementations

| Language | Package | Source | Status |
|----------|---------|--------|--------|
| Python 3.9+ | `pip install mfqp` | [/python](./python) | ✅ Production |
| TypeScript | `npm install @metalogue/mfqp` | [/typescript](./typescript) | ✅ Production |
| Go 1.21+ | `go get github.com/mitchellmclennan/mfqp-go` | [/go](./go) | ✅ Production |

All implementations include:
- Input validation (regex patterns, size limits)
- Replay protection (sliding window cache)
- Timestamp drift tolerance (±5 minutes)
- Comprehensive error types

---

## What's Open vs. Proprietary

### Open (This Repository)

✅ Message formats (Ghost Query, Response, Attestation)  
✅ Cryptographic scheme (Ed25519 signing/verification)  
✅ Error codes and handling  
✅ Reference implementations  
✅ Protocol specification  

Anyone can implement MFQP. That's the point.

### Proprietary (Metalogue Network)

🔒 **Partner Registry** — Trusted database of verified enterprises  
🔒 **Query Routing** — Gateway that routes queries to correct partner  
🔒 **Transaction Billing** — Metering, invoicing, settlement  
🔒 **Trust Attestation** — Third-party verification service  

Think of it like HTTP:
- HTTP spec is open — anyone can implement a browser
- But you still need servers, DNS, CDNs, load balancers

MFQP spec is open. **Metalogue provides the network.**

---

## Use Cases

### Defense & Aerospace
Boeing's AI queries Lockheed's AI about component availability without revealing production schedules.

### Financial Services
Goldman's AI queries Bloomberg's AI for market data with cryptographic proof of response authenticity.

### Healthcare
Pfizer's AI queries Mayo Clinic's AI about clinical trial compatibility with HIPAA-compliant attestation.

### Supply Chain
Ford's AI queries Bosch's AI about sensor capacity without exposing demand forecasts.

---

## Comparison

| Feature | MFQP | Direct API | GraphQL Federation |
|---------|------|-----------|-------------------|
| Intent privacy | ✅ Ghost Queries | ❌ Raw queries exposed | ❌ Field selection visible |
| Response attestation | ✅ Ed25519 signatures | ❌ Trust-on-faith | ❌ No cryptographic proof |
| Standardized billing | ✅ Truth Tax model | ❌ Custom per-partner | ❌ Not addressed |
| Policy-based access | ✅ Intent class matching | ❌ Custom auth | ⚠️ Partial |
| Cross-org federation | ✅ Designed for B2B | ❌ Point-to-point | ⚠️ Same-org focused |

---

## FAQ

**Q: Why not just use REST APIs?**
> REST exposes your exact queries. If you ask for "titanium alloy inventory," suppliers know you need titanium. With MFQP, you send an intent class (`inventory.status`) — they know you want inventory info, not what specific materials.

**Q: How is this different from GraphQL?**
> GraphQL focuses on flexible data fetching within an organization. MFQP focuses on trust, privacy, and billing between organizations.

**Q: What if I don't want to use Metalogue's network?**
> You can implement MFQP peer-to-peer. The spec is fully open. But you'll need to solve routing, trust, and billing yourself.

**Q: Is Ed25519 quantum-safe?**
> No. When post-quantum cryptography standards mature, MFQP 2.0 will adopt them. For now, Ed25519 provides 128-bit classical security.

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for:
- How to report issues
- Pull request guidelines
- Code style requirements
- Specification change process

---

## License

Apache 2.0 — See [LICENSE](./LICENSE) for details.

You may use this specification and reference implementations for any purpose, including commercial use, without royalties.

---

## Links

- **Specification**: [SPEC.md](./SPEC.md)
- **Metalogue Network**: [metalogue.xyz](https://metalogue.xyz)
- **Issues**: [GitHub Issues](https://github.com/mitchellmclennan/mfqp/issues)

---

Built with ❤️ by [Metalogue](https://metalogue.xyz) — The SWIFT for AI Cognition
