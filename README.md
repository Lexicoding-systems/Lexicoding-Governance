# Lexicoding Governance Protocol

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**Protocol-level Governance for AI Reasoning & Output Authorization**

The Lexicoding Governance Protocol (VARX) provides a cryptographically-verified governance framework for AI systems, enabling secure decision-making with immutable audit trails.

## Overview

The Lexicoding Governance Protocol implements a three-node architecture that ensures:

- **Authenticity**: All messages are cryptographically signed with Ed25519
- **Integrity**: Tamper-evident hash chains protect audit records
- **Non-Repudiation**: Digital signatures prevent denial of actions
- **Replay Protection**: Secure nonces prevent message replay attacks

## Architecture

```
┌─────────────┐         ┌─────────────┐         ┌──────────────┐
│  ModelNode  │         │  VARXNode   │         │ AuditorNode  │
└──────┬──────┘         └──────┬──────┘         └──────┬───────┘
       │                       │                        │
       │ 1. Signed Request     │                        │
       ├──────────────────────>│                        │
       │                       │ 2. Evaluate π_varx     │
       │                       │ 3. Apply Rules         │
       │ 4. Signed Decision    │                        │
       │<──────────────────────┤                        │
       │                       │ 5. Audit Record        │
       │                       ├───────────────────────>│
       │                       │                        │ 6. Add to Chain
```

### Components

| Node | Purpose |
|------|---------|
| **ModelNode** | AI system interface - generates signed governance requests |
| **VARXNode** | Decision engine - evaluates reasoning with π_varx semantic analysis |
| **AuditorNode** | Audit trail - maintains cryptographic hash chain of all decisions |

## Features

-  **Ed25519 Digital Signatures** - 128-bit security for message authentication
-  **SHA256 Hash Chains** - Tamper-evident audit trails
-  **π_varx Semantic Engine** - AI reasoning pathway analysis
-  **Configurable Rule Bundles** - Flexible governance policies
- **HKDF Key Derivation** - Secure key management
-  **Replay Protection** - Secure nonces prevent attacks

## Installation

### Requirements

- Python 3.9 or higher
- pip (Python package installer)

### Install from source

```bash
# Clone the repository
git clone https://github.com/Lexicoding-systems/Lexicoding-Governance.git
cd Lexicoding-Governance

# Install the package
pip install -e .
```

### Install dependencies only

```bash
pip install -r requirements.txt
```

### Development installation

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from core.crypto import generate_keypair, sign_message, verify_signature

# Generate node identity
private_key, public_key = generate_keypair()

# Sign a governance request
request = {
    "type": "governance_request",
    "action": "data_access",
    "reasoning": {"steps": [{"step": 1, "reasoning": "User consent obtained"}]}
}
signature = sign_message(request, private_key)

# Verify the signature
is_valid = verify_signature(request, signature, public_key)
print(f"Signature valid: {is_valid}")
```

## Project Structure

```
lexicoding-governance/
├── src/
│   ├── audit/          # Audit trail and hash chain
│   ├── core/           # Cryptographic primitives
│   ├── engine/         # π_varx semantic engine & SAT solver
│   ├── nodes/          # ModelNode, VARXNode, AuditorNode
│   └── utils/          # Utility functions
├── tests/              # Test suite
├── docs/               # Documentation
│   ├── architecture.md
│   ├── cryptography.md
│   ├── api-specification.md
│   └── regulatory-compliance.md
├── pyproject.toml      # Project configuration
└── requirements.txt    # Dependencies
```

## Documentation

- [Architecture Overview](docs/architecture.md) - Detailed system architecture
- [Cryptography](docs/cryptography.md) - Cryptographic primitives and security
- [API Specification](docs/api-specification.md) - Protocol API documentation
- [Regulatory Compliance](docs/regulatory-compliance.md) - Compliance guidelines

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_crypto.py
```

### Code Quality

```bash
# Format code
black src tests

# Sort imports
isort src tests

# Lint code
ruff check src tests

# Type checking
mypy src
```

## Security

The VARX Protocol employs industry-standard cryptographic primitives:

| Primitive | Algorithm | Security Level |
|-----------|-----------|----------------|
| Digital Signatures | Ed25519 | 128-bit |
| Hash Functions | SHA256 | 128-bit collision resistance |
| Key Derivation | HKDF-SHA256 | 256-bit |
| Nonces | CSPRNG | 128-bit randomness |

### Reporting Security Issues

Please report security vulnerabilities by opening an issue or contacting the maintainers directly.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Organization**: Lexicoding Systems
- **Email**: Jacobporter@Lexicoding.tech
- **GitHub**: [Lexicoding-systems](https://github.com/Lexicoding-systems)

---

*Built with ❤️ by Lexicoding Systems*
