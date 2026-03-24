# TOR Demo (RSA + AES)

This project is an educational TOR-style demo: a public-key directory, an encrypted echo client/server, and early onion-routing socket experiments.

## Goals
- Illustrate RSA-OAEP to protect an ephemeral AES key.
- Illustrate AES-256-GCM for message confidentiality and integrity.
- Show a simplified PKI annuaire with SHA-256 fingerprints.

## Prerequisites
- Python 3.x
- Python package: `cryptography`

Quick install:
```bash
pip install cryptography
```

## Quick start
Examples using the launcher:
```bash
# 1) Demo mode (server + client in one process)
python main.py demo "Hello" "Test" "QUIT"

# 2) Server only (writes annuaire.json)
python main.py server --annuaire-out annuaire.json

# 3) Client only (reads annuaire.json)
python main.py client --annuaire-in annuaire.json "Hi" "QUIT"
```

For details:
- Usage: [docs/usage.en.md](docs/usage.en.md)
- Architecture: [docs/architecture.en.md](docs/architecture.en.md)
- Module index: [docs/modules.en.md](docs/modules.en.md)
- Known limitations: [docs/limitations.en.md](docs/limitations.en.md)

## Notes
This repository targets learning and demonstration. Security is simplified for clarity.

## Evaluation rubric (suggested)
- Functional correctness: demo flow runs and encrypted exchange is consistent.
- Crypto justification: RSA-OAEP, AES-GCM, role of SHA-256 fingerprints.
- Software structure: separation of client/server/annuaire, readability.
- Reproducibility: clear run commands and expected behavior.
- Known limitations: stated constraints and simplifications.
