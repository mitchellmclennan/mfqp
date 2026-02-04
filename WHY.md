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

### The Information Asymmetry Problem

In B2B relationships, **information is leverage**. The more your partner knows about your situation, the less negotiating power you have.

Traditional APIs expose everything:

```
GET /api/inventory?sku=TITANIUM-ALLOY-5000&quantity=50000
```

This tells the supplier:
- You need titanium alloy (material intelligence)
- SKU 5000 specifically (product roadmap)
- 50,000 units (demand forecast)

**That's valuable competitive intelligence you just gave away for free.**

### A Concrete Example: The Desperate Buyer

**Scenario:** Boeing's AI needs to check GE's engine availability.

**❌ Raw Query Approach:**

```
"We need 500 LEAP-1B engines for the 737 MAX production ramp-up in Q3. 
Our current supplier Safran is 6 weeks behind schedule. What's your capacity and pricing?"
```

**What GE learns:**
| Intelligence | Value to GE |
|-------------|-------------|
| Boeing is scaling 737 MAX | Product roadmap intel |
| They need 500 units | Exact demand forecast |
| Safran is behind schedule | Competitor weakness |
| They're asking about capacity | They're desperate |
| Q3 timeline | Deadline pressure |

**Result:** GE now knows Boeing has no negotiating leverage. They can raise prices 15–20% and Boeing has to accept.

---

**✅ Ghost Query Approach (MFQP):**

```json
{
  "intent": "What is current production capacity for commercial aviation engines?",
  "intent_class": "inventory.capacity_check"
}
```

**What GE learns:**
| Intelligence | Value to GE |
|-------------|-------------|
| Boeing is checking capacity | Generic interest signal |
| ...that's it | — |

**GE responds:**
```json
{
  "content": "Current LEAP-1B capacity: 650 units/quarter. Lead time: 45 days.",
  "attestation": { "signature": "..." }
}
```

**Result:** Boeing gets actionable data. GE doesn't know:
- Why Boeing is asking
- How urgent the need is
- What happened with Safran
- Boeing's exact quantity requirements

**Boeing preserves negotiating leverage.**

---

### Intent Classification Categories

MFQP uses standardized intent classes that reveal *purpose* without exposing *specifics*:

| Intent Class | What Responder Sees | What Responder Doesn't See |
|-------------|---------------------|---------------------------|
| `inventory.availability` | "Checking stock levels" | Which SKUs, quantities, urgency |
| `pricing.quote_request` | "Requesting pricing" | Budget, competing quotes, deadline |
| `logistics.lead_time` | "Checking delivery times" | Production schedule, dependencies |
| `financial.credit_check` | "Assessing creditworthiness" | Deal size, terms, alternatives |
| `legal.compliance_query` | "Compliance question" | Specific regulation, exposure risk |

The responder's AI matches the intent class to their data policies and returns appropriate information—without knowing the sensitive context.

---

### Real-World Use Cases

| Scenario | Raw Query Exposes | Ghost Query Protects |
|----------|-------------------|---------------------|
| **Supply chain check** | Urgency, volumes, competitor issues | Just "capacity inquiry" |
| **M&A due diligence** | Acquisition target identity | Just "financial health query" |
| **Competitive intelligence** | Exactly what you're building | Just "market sizing request" |
| **Legal discovery** | Creates detailed liability trail | Minimal exposure |
| **Pricing negotiation** | Your budget and alternatives | Just "quote request" |

---

### The Bottom Line

Ghost Queries aren't just about privacy—they're about **preserving negotiating leverage** in adversarial business relationships.

Your AI gets the answers it needs. Your partners don't learn why you're asking.

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
