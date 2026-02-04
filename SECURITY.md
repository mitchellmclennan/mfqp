# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in MFQP, please report it responsibly:

1. **Do NOT** open a public issue
2. Email: security@metalogue.xyz
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Your suggested fix (optional)

We will respond within 48 hours and work with you on a fix.

## Security Considerations

MFQP involves cryptographic operations. Key security notes:

- **Private keys** must be stored encrypted at rest
- **Timestamps** are validated within 5-minute windows to prevent replay
- **Query IDs** must be unique (UUIDv4) to prevent replay
- **Ed25519** is used for all signatures
- **Key rotation** should follow your organization's policy

See [SPEC.md](./SPEC.md) for full security considerations.
