# MFQP vs MCP: Understanding the Difference

Two protocols, two different purposes. Here's how they work together.

---

## Quick Comparison

| Aspect | MCP | MFQP |
|--------|-----|------|
| **Full Name** | Model Context Protocol | Metalogue Federated Query Protocol |
| **Created By** | Anthropic | Metalogue |
| **Purpose** | Connect AI to tools/data | Connect AI across organizations |
| **Scope** | Within one organization | Between organizations |
| **Trust Model** | Implicit (same org) | Explicit (Ed25519 signatures) |
| **Billing** | N/A | Per-query transaction fees |

---

## What is MCP?

**MCP (Model Context Protocol)** is Anthropic's standard for connecting AI assistants to external tools and data sources.

```
┌─────────────┐      MCP       ┌─────────────┐
│   Claude    │ ───────────────►│  Your DB    │
│  (AI Agent) │                 │  Your APIs  │
│             │ ◄───────────────│  Your Files │
└─────────────┘                 └─────────────┘
```

**MCP answers:** "How does my AI access my company's internal tools?"

**Examples:**
- Claude Desktop reading your local files
- ChatGPT calling your company's Slack API
- VS Code Copilot querying your internal docs

**Key traits:**
- Same organization (trust is implicit)
- JSON-RPC 2.0 transport
- Tools, resources, prompts
- No authentication required (local execution)

---

## What is MFQP?

**MFQP (Metalogue Federated Query Protocol)** is a standard for AI-to-AI communication *between* organizations.

```
┌─────────────┐      MFQP      ┌─────────────┐
│  Boeing AI  │ ───────────────►│    GE AI    │
│  (Org A)    │                 │   (Org B)   │
│             │ ◄───────────────│             │
└─────────────┘                 └─────────────┘
        │                               │
        └───── Metalogue Gateway ───────┘
             (routing, trust, billing)
```

**MFQP answers:** "How does my AI query another company's AI?"

**Examples:**
- Boeing's AI asking GE's AI about engine part availability
- Goldman's AI querying Bloomberg's AI for market data
- Ford's AI checking Bosch's AI for sensor capacity

**Key traits:**
- Different organizations (trust must be established)
- Ed25519 cryptographic signatures
- Intent-only queries (privacy-preserving)
- Per-query transaction fees

---

## How They Work Together

The **Metalogue MCP Server** bridges these two worlds:

```
┌─────────────────────────────────────────────────────────────────┐
│                         YOUR ORGANIZATION                        │
│                                                                  │
│  ┌─────────┐     MCP      ┌───────────────────┐                 │
│  │ Claude  │ ────────────►│ Metalogue MCP     │                 │
│  │ Desktop │              │ Server            │                 │
│  └─────────┘              └─────────┬─────────┘                 │
│                                     │                            │
└─────────────────────────────────────┼────────────────────────────┘
                                      │ MFQP
                                      ▼
                          ┌─────────────────────┐
                          │  Metalogue Gateway  │
                          │  (Federation Hub)   │
                          └─────────┬───────────┘
                                    │ MFQP
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                       PARTNER ORGANIZATION                       │
│                                                                  │
│  ┌───────────────────┐     Internal     ┌─────────────┐         │
│  │ Partner's MFQP    │ ────────────────►│ Partner's   │         │
│  │ Endpoint          │                  │ Data/AI     │         │
│  └───────────────────┘                  └─────────────┘         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### The Flow

1. **You ask Claude:** "What's the lead time for GE engine parts?"
2. **Claude calls MCP tool:** `federated_query(target="ge-aviation", query="...")`
3. **MCP Server creates MFQP Ghost Query:** Signs with your Ed25519 key
4. **Metalogue Gateway routes:** Validates signature, routes to GE
5. **GE's AI processes:** Checks policy, queries data, signs response
6. **Response flows back:** With cryptographic attestation
7. **Claude shows you:** "Lead time is 45 days (verified ✓)"

---

## MCP Tools Provided

The Metalogue MCP Server exposes these tools to AI assistants:

| Tool | Purpose | MFQP Equivalent |
|------|---------|-----------------|
| `federated_query` | Query partner org | Ghost Query |
| `list_partners` | List registered partners | Partner Registry |
| `verify_attestation` | Verify response signature | Attestation Verification |
| `get_audit_trail` | Get query audit log | Transaction History |

### Example: Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "metalogue": {
      "command": "python",
      "args": ["-m", "metalogue.mcp_server"],
      "env": {
        "METALOGUE_API_KEY": "your-api-key"
      }
    }
  }
}
```

Then ask Claude:
> "What's the current inventory status at our partner Globex?"

Claude will use the `federated_query` tool to send an MFQP Ghost Query through the Metalogue network.

---

## When to Use Each

### Use MCP When:
- Connecting AI to **your own** tools and data
- Building internal AI assistants
- No cross-organization trust needed
- Local execution (Claude Desktop, VS Code)

### Use MFQP When:
- Querying **another company's** AI/data
- Need cryptographic proof of responses
- Privacy-preserving queries required
- Per-query billing needed

### Use Both When:
- Your AI needs to query external partners
- Install Metalogue MCP Server
- MCP handles the local tool interface
- MFQP handles the cross-org federation

---

## Protocol Comparison

### Message Format

**MCP Request (JSON-RPC 2.0):**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "federated_query",
    "arguments": {
      "target_company": "ge-aviation",
      "query": "What's the lead time for LEAP engines?"
    }
  },
  "id": 1
}
```

**MFQP Ghost Query:**
```json
{
  "mfqp_version": "1.0",
  "message_type": "ghost_query",
  "query_id": "550e8400-e29b-41d4-a716-446655440000",
  "source_company": "boeing",
  "target_company": "ge-aviation",
  "intent": "What's the lead time for LEAP engines?",
  "intent_class": "inventory.lead_time",
  "auth_level": "trusted",
  "timestamp": "2026-02-04T10:30:00Z",
  "signature": "Ed25519-base64-signature..."
}
```

### Security Model

| Aspect | MCP | MFQP |
|--------|-----|------|
| Authentication | None (local trust) | Ed25519 signatures |
| Authorization | App-level | Intent class policies |
| Audit | Optional | Mandatory attestation |
| Non-repudiation | No | Yes (cryptographic) |

---

## Summary

| Protocol | Analogy | One Sentence |
|----------|---------|--------------|
| **MCP** | USB for AI | Plugs your AI into your tools |
| **MFQP** | SWIFT for AI | Connects your AI to other companies' AI |

They're **complementary**:
- MCP is the interface for AI tools
- MFQP is the protocol for cross-org federation
- Metalogue MCP Server bridges them

---

## Links

- **MCP Specification**: [modelcontextprotocol.io](https://modelcontextprotocol.io)
- **MFQP Specification**: [SPEC.md](./SPEC.md)
- **Metalogue Network**: [metalogue.xyz](https://metalogue.xyz)

---

[← Back to README](./README.md)
