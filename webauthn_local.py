from cryptography.hazmat.primitives import serialization, hashes
from fido2.cose import ES256
from fido2.utils import sha256
from fido2.webauthn import AttestedCredentialData
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import os
import json
import base64
from flask import Flask, request, jsonify
import argparse

# Key storage path
KEY_PATH = "webauthn_credentials.json"

# Create Flask application
app = Flask(__name__)


def create_or_load_keypair():
    """Create or load WebAuthn key pair"""
    if os.path.exists(KEY_PATH):
        # Load existing keys from file
        with open(KEY_PATH, "r") as f:
            data = json.load(f)
            credential_data = base64.b64decode(data["credential_data"])
            credential = AttestedCredentialData(credential_data)

            # Load private key
            private_key = serialization.load_pem_private_key(
                data["private_key_pem"].encode("utf-8"),
                password=None,
                backend=default_backend()
            )
            return credential, private_key
    else:
        # Generate EC key pair using cryptography library
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Convert to COSE format public key
        cose_public_key = ES256.from_cryptography_key(public_key)

        # Create credential ID
        credential_id = os.urandom(16)

        # Create AAGUID (16 bytes random UUID)
        aaguid = os.urandom(16)

        # Create credential data - correct parameter order
        credential = AttestedCredentialData.create(
            aaguid,  # First parameter should be aaguid
            credential_id,  # Second parameter is credential ID
            cose_public_key  # Third parameter is COSE public key
        )

        # Save credential data and private key information
        with open(KEY_PATH, "w") as f:
            json.dump({
                "credential_data": base64.b64encode(credential).decode("utf-8"),
                "credential_id": base64.b64encode(credential_id).decode("utf-8"),
                "aaguid": base64.b64encode(aaguid).decode("utf-8"),
                "private_key_pem": private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode("utf-8")
            }, f)

        return credential, private_key


def get_public_key_in_cose_format():
    """Get public key in COSE format"""
    credential, _ = create_or_load_keypair()
    return credential.public_key


def get_public_key_bytes():
    """Get public key bytes"""
    credential, _ = create_or_load_keypair()
    # Convert COSE format public key to bytes
    # Here we use the raw form with CBOR encoding
    import cbor
    return cbor.dumps(credential.public_key)


def get_credential_id():
    """Get credential ID"""
    credential, _ = create_or_load_keypair()
    return credential.credential_id


def get_webauthn_raw_pubkey_bytes():
    """Get WebAuthn public key in 64-byte format (x,y coordinates)
    Suitable for Rust WebAuthn([u8; 64]) format
    """
    credential, _ = create_or_load_keypair()
    cose_key = credential.public_key

    # Extract x and y coordinates from COSE key
    # In ES256 keys, -2 and -3 keys correspond to x and y coordinates (32 bytes each)
    x = cose_key[-2]
    y = cose_key[-3]

    # Directly connect x and y coordinates to form a 64-byte public key
    raw_pubkey = x + y

    return raw_pubkey


def get_webauthn_pubkey_hex():
    """Get WebAuthn public key in hexadecimal string representation"""
    raw_pubkey = get_webauthn_raw_pubkey_bytes()
    return raw_pubkey.hex()


def get_compressed_pubkey_bytes(pubkey_bytes=None):
    """Get WebAuthn public key in compressed 33-byte format
    This format is:
    - 0x02 + x-coordinate (if y is even)
    - 0x03 + x-coordinate (if y is odd)

    Args:
        pubkey_bytes (bytes, optional): Raw 64-byte public key. If None, gets from local key.

    Returns:
        bytes: 33-byte compressed public key
    """
    if pubkey_bytes is None:
        raw_pubkey = get_webauthn_raw_pubkey_bytes()
    else:
        raw_pubkey = pubkey_bytes

    # Split into x and y coordinates
    x = raw_pubkey[:32]
    y = raw_pubkey[32:]
    # Check if y is odd or even (check the last bit)
    prefix = b'\x03' if y[-1] & 1 else b'\x02'
    # Create compressed format: prefix + x coordinate
    compressed_pubkey = prefix + x
    return compressed_pubkey


def sign_data(data_string, origin="http://localhost:8000"):
    """Sign data using WebAuthn"""
    credential, private_key = create_or_load_keypair()

    # Handle hex string format coming from Rust with hex::encode(&message_hash_bytes)
    if isinstance(data_string, str):
        try:
            # Try to decode as hex string
            challenge = bytes.fromhex(data_string)
        except ValueError:
            # Fall back to UTF-8 encoding if not valid hex
            challenge = data_string.encode('utf-8')
    else:
        challenge = data_string

    # Create proper ClientData JSON structure according to WebAuthn spec
    client_data = {
        "type": "webauthn.get",  # For authentication
        "challenge": base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('='),
        "origin": origin,
        "crossOrigin": False
    }

    # Convert to JSON string
    client_data_json = json.dumps(client_data, separators=(',', ':'))
    # print the client data JSON for debugging
    print("Client Data JSON:", client_data_json)
    client_data_bytes = client_data_json.encode('utf-8')

    # Generate client data hash from the JSON bytes (not directly from input data)
    client_data_hash = sha256(client_data_bytes)

    # Create AuthenticatorData
    # In a real WebAuthn flow, this would be structured data with RP ID hash,
    # flags, counter, etc. Here we're using a simplified version
    rp_id_hash = os.urandom(32)  # In real implementation this would be SHA-256 hash of RP ID
    flags = bytes([0x01])  # Example flag - User Present bit set
    counter = (0).to_bytes(4, byteorder='big')
    auth_data = rp_id_hash + flags + counter

    # Combine data to be signed
    message = auth_data + client_data_hash

    # print the message to be signed for debugging, in hex format
    print("Message to be signed (hex):", message.hex())

    # Sign with private key
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    # print the signature for debugging, print the length of the signature
    print("Signature Length:", len(signature))

    # signature should be in r, s format for WebAuthn
    # Convert signature to bytes in DER format
    signature_in_rs_format = get_raw_signature_64_bytes(signature)

    # print the signature in r,s format for debugging
    print("Signature in r,s format (hex):", signature_in_rs_format.hex())

    return {
        "signature": base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('='),
        "authenticator_data": base64.urlsafe_b64encode(auth_data).decode('utf-8').rstrip('='),
        "client_data_json": base64.urlsafe_b64encode(client_data_bytes).decode('utf-8').rstrip('='),
        "credential_id": base64.urlsafe_b64encode(credential.credential_id).decode('utf-8').rstrip('=')
    }


# Get raw r, s values (32 bytes each)
def get_signature_rs_components(signature_der):
    """Convert DER-encoded signature to r,s components"""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(signature_der)

    # Convert to 32-byte byte strings
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    # Normalize s value (ensure s < n/2) - some platforms require low S values
    if s > n // 2:
        s = n - s

    # Convert to strict 32-byte format, handling potential overflow
    try:
        r_bytes = r.to_bytes(32, byteorder='big')
    except OverflowError:
        # If r exceeds 32 bytes (rare case), take the lowest 32 bytes
        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')[-32:]

    try:
        s_bytes = s.to_bytes(32, byteorder='big')
    except OverflowError:
        # If s exceeds 32 bytes (rare case), take the lowest 32 bytes
        s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')[-32:]

    return r_bytes, s_bytes


# Get 64-byte raw signature format
def get_raw_signature_64_bytes(signature_der):
    """Get r||s format 64-byte signature"""
    r_bytes, s_bytes = get_signature_rs_components(signature_der)
    return r_bytes + s_bytes


# Flask route definitions
@app.route('/pubkey', methods=['GET'])
def get_pubkey():
    """API endpoint for getting public key information"""
    try:
        return jsonify({
            'credential_id': base64.b64encode(get_credential_id()).decode('utf-8'),
            'pubkey_hex': get_webauthn_pubkey_hex(),
            'success': True
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


@app.route('/sign', methods=['POST'])
def sign_api():
    """API endpoint for data signing"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON', 'success': False}), 400

        data = request.json.get('data')
        if not data:
            return jsonify({'error': 'Missing data field', 'success': False}), 400

        # Get origin if provided, otherwise use default
        origin = request.json.get('origin', "http://localhost:8000")

        signature_result = sign_data(data, origin)
        return jsonify({
            'result': signature_result,
            'success': True
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


"""
Usage Instructions:
------------------
This program provides WebAuthn key management and signature capabilities through both
a command-line interface and an HTTP API server.

Requirements:
- Install dependencies: pip install cryptography fido2 flask cbor

Running modes:
1. Test mode (default):
   python webauthn_local.py
   This will create/load keys and run various test operations.

2. HTTP server mode:
   python webauthn_local.py --server
   This starts an HTTP server on 127.0.0.1:8000 with the following endpoints:

   - GET /pubkey: Returns credential ID and public key in hex format
     curl http://127.0.0.1:8000/pubkey

   - POST /sign: Signs provided data and returns signature components
     curl -X POST http://127.0.0.1:8000/sign -H "Content-Type: application/json" -d '{"data":"Hello, WebAuthn!"}'

   Custom host/port:
   python webauthn_local.py --server --host 0.0.0.0 --port 9000
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='WebAuthn Local Server')
    parser.add_argument('--server', action='store_true', help='Start the HTTP server')
    parser.add_argument('--host', default='127.0.0.1', help='Server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8000, help='Server port (default: 8000)')

    args = parser.parse_args()

    if args.server:
        print(f"Starting WebAuthn HTTP server on {args.host}:{args.port}")
        print("Available endpoints:")
        print("  - GET /pubkey: Get public key information")
        print("  - POST /sign: Sign data (JSON body with 'data' field)")
        app.run(host=args.host, port=args.port)
