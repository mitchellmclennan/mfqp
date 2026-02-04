# Why MFQP?

## The $150 Trillion Problem

Every day, enterprises make decisions based on information from other enterprises:

- **Boeing** needs to know if GE has engine parts in stock
- **Goldman Sachs** needs real-time data from Bloomberg
- **Ford** needs capacity info from Bosch
- **Anduril** needs compute availability from Oracle

Today, this happens through:
- 📧 Emails and phone calls
- 📊 Portal logins and spreadsheets
- 🔗 Point-to-point API integrations
- 🤝 Relationship managers

**None of these scale for AI.**

When AI agents need to query across company boundaries, there's no standard. Every integration is custom. Every response is trusted on faith.

---

## The Vision: SWIFT for AI Cognition

### What is SWIFT?

SWIFT processes **$150 trillion** in cross-border payments annually. It works because:

1. **Open message format** — Any bank can implement SWIFT messages
2. **Trusted network** — Banks are vetted and registered
3. **Cryptographic verification** — Messages are authenticated
4. **Transaction fees** — Per-message billing

### What is MFQP?

MFQP is the same model for AI queries:

1. **Open message format** — Any enterprise can implement MFQP
2. **Trusted network** — Partners are vetted and registered
3. **Cryptographic verification** — Ed25519 attestation
4. **Transaction fees** — Per-query billing ("Truth Tax")

---

## Why Intent-Only Queries?

Traditional APIs expose what you're looking for:

```
GET /api/inventory?sku=TITANIUM-ALLOY-5000&quantity=50000
```

This tells the supplier:
- You need titanium alloy (material intelligence)
- SKU 5000 specifically (product roadmap)
- 50,000 units (demand forecast)

**That's valuable competitive intelligence you just gave away for free.**

### Ghost Queries

MFQP uses "Ghost Queries" — you send the **intent**, not the raw query:

```json
{
  "intent": "What materials have lead time under 30 days?",
  "intent_class": "inventory.lead_time"
}
```

The responder knows you want lead time info. They don't know:
- Which specific materials
- How much quantity
- Why you need it

**Your query is a ghost. It reveals purpose, not content.**

---

## Why Cryptographic Attestation?

### The Dispute Problem

Without attestation:

> **Ford:** "Bosch, you said you could deliver 100K sensors by March!"
> **Bosch:** "We never said that."
> **Ford:** "We have the API response!"
> **Bosch:** "Could be modified. Can you prove we sent it?"

### With MFQP Attestation

Every response includes:

```json
{
  "attestation": {
    "response_hash": "sha256:abc123...",
    "signer_key_id": "sha256:def456...",
    "timestamp": "2026-02-04T10:30:01Z",
    "signature": "base64:Ed25519signature..."
  }
}
```

This proves:
- **Who signed it** — Bosch's registered public key
- **What was said** — SHA-256 hash of exact response
- **When** — Timestamp within 5-minute window
- **Verifiable** — Anyone with Bosch's public key can verify

**This is cryptographic, legally admissible proof.**

---

## Why Transaction Fees?

### The Free API Problem

If queries are free:
- No incentive to respond quickly
- No incentive to provide quality data
- No sustainable business model
- Partners become data hoarders

### The Truth Tax Model

Every query has a cost based on value:

| Query Type | Fee | Why |
|------------|-----|-----|
| Public data | $0.25 | Low effort, widely available |
| Business data | $0.50 | Curated, maintained data |
| Proprietary data | $2-5 | Competitive advantage |
| Financial data | $10-100 | High-value, liability-bearing |

**This creates a market.** Companies are incentized to:
- Respond quickly (time = money)
- Provide accurate data (reputation = money)
- Make more data available (data = revenue)

---

## The Network Effect

### Why Open Protocol?

Visa didn't keep card formats proprietary. They published standards and built the network.

MFQP is open so that:
1. **Enterprises adopt faster** — "It's not vendor lock-in"
2. **Competitors are compatible** — They play by our rules
3. **Standard wins before fragmentation** — First mover advantage

### What's Proprietary?

The **network** is the business:

| Open (Free) | Proprietary (Metalogue) |
|-------------|------------------------|
| Message format | Partner registry |
| Signing scheme | Query routing |
| Error codes | Transaction billing |
| Reference code | Trust attestation |

You can implement MFQP yourself. But then:

> "Great, I built an MFQP client. Who do I send queries to?"

**Answer:** Metalogue's network of 500+ verified partners.

> "How do I know GE's response is from GE?"

**Answer:** Metalogue's partner registry with verified public keys.

> "How do I pay/get paid?"

**Answer:** Metalogue's billing and settlement service.

---

## Market Opportunity

### The Numbers

| Metric | Value |
|--------|-------|
| B2B data exchange market | $12.7B (2024) |
| Enterprise AI spending | $154B (2024) |
| SWIFT transaction volume | 45M messages/day |
| Visa transaction volume | 700M transactions/day |

### The Play

If MFQP becomes the standard for AI federation:

- **Year 1:** 500 enterprises, 1M queries/month → $6M ARR
- **Year 2:** 2,000 enterprises, 50M queries/month → $300M ARR
- **Year 3:** 5,000 enterprises, 500M queries/month → $3B ARR

At 15-20x ARR multiples, this is a **$45-60B** outcome.

---

## Get Started

### Use the Protocol

```bash
pip install mfqp
# or
npm install @metalogue/mfqp
```

### Join the Network

Contact [sales@metalogue.xyz](mailto:sales@metalogue.xyz) to:
- Register as a federation partner
- Get your Ed25519 public key verified
- Start sending and receiving queries

---

[← Back to README](./README.md)
