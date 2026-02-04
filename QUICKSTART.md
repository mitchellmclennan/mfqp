# MFQP Quickstart Guide

Get up and running with MFQP in 5 minutes.

---

## Step 1: Install

Choose your language:

```bash
# Python
pip install mfqp

# TypeScript/JavaScript
npm install @metalogue/mfqp

# Go
go get github.com/mitchellmclennan/mfqp-go
```

---

## Step 2: Generate Keys

You need an Ed25519 keypair. Generate once, store securely.

### Python

```python
from mfqp.crypto import generate_keypair, save_keypair

# Generate new keypair
private_key, public_key = generate_keypair()

# Save to files (private key should be encrypted in production)
save_keypair(private_key, public_key, "myorg")
# Creates: myorg.private.pem, myorg.public.pem

print(f"Public key fingerprint: {public_key.fingerprint()}")
```

### TypeScript

```typescript
import { generateKeypair, saveKeypair } from '@metalogue/mfqp';

const { privateKey, publicKey } = await generateKeypair();
await saveKeypair(privateKey, publicKey, 'myorg');

console.log(`Fingerprint: ${publicKey.fingerprint()}`);
```

### Go

```go
import "github.com/mitchellmclennan/mfqp-go/crypto"

privateKey, publicKey, _ := crypto.GenerateKeypair()
crypto.SaveKeypair(privateKey, publicKey, "myorg")

fmt.Printf("Fingerprint: %s\n", publicKey.Fingerprint())
```

---

## Step 3: Create a Ghost Query

A Ghost Query sends your intent to another organization.

### Python

```python
from mfqp import GhostQuery

query = GhostQuery(
    source_company="your-company",     # Your org identifier
    target_company="partner-company",   # Who you're querying
    intent="What is the lead time for premium components?",
    intent_class="inventory.lead_time", # Classified intent category
    auth_level="verified"               # Your trust level
)

print(f"Query ID: {query.query_id}")
print(f"Created at: {query.timestamp}")
```

### TypeScript

```typescript
import { GhostQuery } from '@metalogue/mfqp';

const query = new GhostQuery({
  sourceCompany: 'your-company',
  targetCompany: 'partner-company',
  intent: 'What is the lead time for premium components?',
  intentClass: 'inventory.lead_time',
  authLevel: 'verified'
});

console.log(`Query ID: ${query.queryId}`);
```

---

## Step 4: Sign the Query

All queries must be signed with your private key.

### Python

```python
from mfqp import sign_message
from mfqp.crypto import load_private_key

private_key = load_private_key("myorg.private.pem")
signature = sign_message(query, private_key)

print(f"Signature: {signature.hex()[:32]}...")
```

### TypeScript

```typescript
import { signMessage, loadPrivateKey } from '@metalogue/mfqp';

const privateKey = await loadPrivateKey('myorg.private.pem');
const signature = await signMessage(query, privateKey);

console.log(`Signature: ${Buffer.from(signature).toString('hex').slice(0, 32)}...`);
```

---

## Step 5: Send the Query

### Option A: Via Metalogue Gateway (Recommended)

```python
from mfqp.gateway import MetalogueGateway

gateway = MetalogueGateway(api_key="your-api-key")
response = gateway.send(query, signature)

print(f"Status: {response.status}")
print(f"Results: {response.payload}")
```

### Option B: Direct to Partner (Peer-to-Peer)

```python
import requests

# You need the partner's MFQP endpoint
partner_endpoint = "https://api.partner.com/mfqp/v1/query"

response = requests.post(partner_endpoint, json={
    "query": query.to_dict(),
    "signature": signature.hex()
})
```

---

## Step 6: Verify the Response

Always verify the attestation before trusting the response.

### Python

```python
from mfqp import verify_signature
from mfqp.registry import get_partner_public_key

# Get partner's registered public key
partner_key = get_partner_public_key("partner-company")

# Verify attestation signature
is_valid = verify_signature(
    response.attestation,
    response.attestation.signature,
    partner_key
)

if is_valid:
    print("✅ Response verified! Data is authentic.")
    print(f"Lead time: {response.payload['lead_time_days']} days")
else:
    print("❌ Attestation invalid! Do not trust this response.")
```

### TypeScript

```typescript
import { verifySignature, getPartnerPublicKey } from '@metalogue/mfqp';

const partnerKey = await getPartnerPublicKey('partner-company');
const isValid = await verifySignature(
  response.attestation,
  response.attestation.signature,
  partnerKey
);

if (isValid) {
  console.log('✅ Response verified!');
  console.log(`Lead time: ${response.payload.leadTimeDays} days`);
}
```

---

## Complete Example

### Python

```python
from mfqp import GhostQuery, sign_message, verify_signature
from mfqp.crypto import generate_keypair
from mfqp.gateway import MetalogueGateway
from mfqp.registry import get_partner_public_key

# 1. Setup (done once)
private_key, public_key = generate_keypair()

# 2. Create query
query = GhostQuery(
    source_company="boeing",
    target_company="ge-aviation",
    intent="What is the current lead time for CFM LEAP-1B engine parts?",
    intent_class="inventory.lead_time",
    auth_level="trusted"
)

# 3. Sign
signature = sign_message(query, private_key)

# 4. Send
gateway = MetalogueGateway(api_key="...")
response = gateway.send(query, signature)

# 5. Verify
partner_key = get_partner_public_key("ge-aviation")
if verify_signature(response.attestation, response.attestation.signature, partner_key):
    print(f"Lead time: {response.payload['lead_time_days']} days")
    print(f"Availability: {response.payload['availability']}")
    print(f"Attested by: {response.attestation.signer_key_id}")
```

---

## Common Intent Classes

Use these standard intent classes for policy matching:

| Class | Description | Example Intent |
|-------|-------------|----------------|
| `inventory.status` | Check availability | "Is part X in stock?" |
| `inventory.lead_time` | Check lead times | "When can you deliver X?" |
| `contract.pricing` | Get pricing info | "What's the price for X?" |
| `supply_chain.capacity` | Check capacity | "Can you produce N units?" |
| `personnel.contact` | Get contact info | "Who handles X?" |
| `legal.compliance` | Check compliance | "Are you SOC 2 certified?" |

---

## Error Handling

```python
from mfqp.errors import MFQPError, SignatureError, PolicyDeniedError

try:
    response = gateway.send(query, signature)
except SignatureError as e:
    print(f"Signature invalid: {e.code}")  # E001
except PolicyDeniedError as e:
    print(f"Query denied: {e.code}")  # P001 or P002
except MFQPError as e:
    print(f"MFQP error: {e.code} - {e.message}")
```

---

## Next Steps

1. **Register with Metalogue** — Get your public key verified
2. **Read the full spec** — [SPEC.md](./SPEC.md)
3. **Understand the why** — [WHY.md](./WHY.md)
4. **See examples** — [/examples](./examples)

---

[← Back to README](./README.md)
