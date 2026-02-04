# Contributing to MFQP

Thank you for your interest in contributing to the Metalogue Federated Query Protocol!

## How to Contribute

### Reporting Issues
- Check existing issues before creating a new one
- Include reproduction steps, expected behavior, and actual behavior
- For security issues, email security@metalogue.xyz instead

### Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Run the test suite
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Code Style
- **Python**: Follow PEP 8, use type hints
- **TypeScript**: Use strict mode, ESM exports
- **Go**: Follow standard Go conventions (`gofmt`)

### Specification Changes
Changes to SPEC.md require extra scrutiny:
- Must maintain backward compatibility (or be a major version bump)
- Need review from core maintainers
- Should include reference implementation updates

## Development Setup

### Python
```bash
cd python
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest
```

### TypeScript
```bash
cd typescript
npm install
npm test
```

### Go
```bash
cd go
go test ./...
```

## License
By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
