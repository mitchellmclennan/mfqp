# MFQP: Metalogue Federated Query Protocol

The open standard for secure AI-to-AI communication between enterprises.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview

MFQP (Metalogue Federated Query Protocol) enables secure, authenticated communication between AI agents across organizational boundaries. It provides:

- **Ghost Queries** — Intent-only queries that don't expose underlying data
- **Ed25519 Signatures** — Cryptographic authentication for all messages
- **Attestation** — Verifiable proof of query processing and response integrity
- **Replay Protection** — Built-in defense against replay attacks

## Quick Start

### Python
```bash
pip install mfqp
```

```python
from mfqp import GhostQuery, sign_message, verify_signature
from mfqp.crypto import generate_keypair

# Generate keys
private_key, public_key = generate_keypair()

# Create a signed query
query = GhostQuery(
    source_company="acme-corp",
    target_company="globex-inc",
    intent="What is the current inventory status for part #12345?",
    intent_class="inventory.status"
)
signature = sign_message(query, private_key)

# Verify on receiving end
is_valid = verify_signature(query, signature, public_key)
```

### TypeScript
```bash
npm install @metalogue/mfqp
```

```typescript
import { GhostQuery, signMessage, verifySignature } from '@metalogue/mfqp';

const query = new GhostQuery({
  sourceCompany: 'acme-corp',
  targetCompany: 'globex-inc',
  intent: 'What is the current inventory status for part #12345?',
  intentClass: 'inventory.status'
});

const signature = await signMessage(query, privateKey);
const isValid = await verifySignature(query, signature, publicKey);
```

### Go
```bash
go get github.com/mitchellmclennan/mfqp-go
```

```go
import "github.com/mitchellmclennan/mfqp-go/protocol"

query, _ := protocol.NewGhostQuery(protocol.GhostQueryParams{
    SourceCompany: "acme-corp",
    TargetCompany: "globex-inc",
    Intent:        "What is the current inventory status?",
    IntentClass:   "inventory.status",
})
signature, _ := protocol.SignMessage(query, privateKey)
```

## Specification

See [SPEC.md](./SPEC.md) for the full protocol specification including:

- Message formats (Ghost Query, Response, Attestation)
- Cryptographic requirements (Ed25519, key registration)
- Error codes (E001-E006, P001-P003, X001-X003)
- Versioning and compatibility guarantees

## Reference Implementations

| Language | Package | Directory |
|----------|---------|-----------|
| Python | `pip install mfqp` | [/python](./python) |
| TypeScript | `npm install @metalogue/mfqp` | [/typescript](./typescript) |
| Go | `go get github.com/mitchellmclennan/mfqp-go` | [/go](./go) |

All reference implementations are production-ready with:
- Input validation (regex patterns, size limits)
- Replay protection (sliding window cache)
- Timestamp drift tolerance (±5 minutes)

## What's Included (Open)

- ✅ Ghost Query message format
- ✅ Ed25519 signature scheme
- ✅ Error codes and handling
- ✅ Reference implementations
- ✅ Protocol specification

## What's NOT Included (Metalogue Network)

The following are proprietary services provided by [Metalogue](https://metalogue.xyz):

- 🔒 Partner registry & vetting
- 🔒 Query routing infrastructure  
- 🔒 Transaction billing
- 🔒 Trust attestation service

For enterprise federation, visit [metalogue.xyz](https://metalogue.xyz).

## Examples

See the [/examples](./examples) directory for:
- `sign_query.py` — Python query signing
- `verify_attestation.ts` — TypeScript attestation verification
- `full_flow.go` — Go end-to-end example

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

Apache 2.0 — See [LICENSE](./LICENSE) for details.

---

Built with ❤️ by [Metalogue](https://metalogue.xyz) — The SWIFT for AI Cognition
