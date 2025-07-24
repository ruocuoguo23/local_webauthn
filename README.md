# Local WebAuthn

A lightweight Flask service that simulates WebAuthn/Passkey authentication and signing for development and testing.

## Features

- **WebAuthn Credential Management**: Creates/loads EC keypairs compatible with WebAuthn
- **Multiple Key Formats**: COSE, raw 64-byte, compressed 33-byte, hex string
- **WebAuthn Protocol Signing**: Full authentication flow implementation
- **REST API**: Simple HTTP endpoints for testing
- **Persistent Storage**: Saves credentials locally

## Requirements

- Python 3.7+
- Dependencies: `cryptography`, `fido2`, `Flask`, `cbor`

## Quick Start

```bash
./start.sh                           # Auto-setup and run in test mode             # Test mode (default)
python webauthn_local.py --server    # HTTP server mode
```

## API Endpoints

### GET /pubkey
Returns credential ID and public key in hex format.

```bash
curl http://127.0.0.1:8000/pubkey
```

Response:
```json
{
  "credential_id": "base64_credential_id",
  "pubkey_hex": "128_char_hex_string",
  "success": true
}
```

### POST /sign
Signs data using WebAuthn protocol.

```bash
curl -X POST http://127.0.0.1:8000/sign \
  -H "Content-Type: application/json" \
  -d '{"data":"Hello, WebAuthn!", "origin":"https://example.com"}'
```

Request:
```json
{
  "data": "data_to_sign",
  "origin": "http://localhost:8000"  // optional
}
```

Response:
```json
{
  "result": {
    "signature": "base64url_signature",
    "authenticator_data": "base64url_auth_data", 
    "client_data_json": "base64url_client_data",
    "credential_id": "base64url_credential_id"
  },
  "success": true
}
```

## Technical Details

- **Cryptography**: SECP256R1 (P-256) with ES256 (ECDSA + SHA-256)
- **Storage**: Local `webauthn_credentials.json` file
- **Protocol**: Implements WebAuthn client data, authenticator data, and signature generation

## Options

```bash
python webauthn_local.py [--server] [--host HOST] [--port PORT]
```

- `--server`: Start HTTP server mode
- `--host`: Server host (default: 127.0.0.1)  
- `--port`: Server port (default: 8000)

⚠️ **For development/testing only** - not production ready.
