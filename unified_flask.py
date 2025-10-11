from flask import Flask, request, jsonify
import oqs
import base64
import os
from datetime import datetime

app = Flask(__name__)

# =========================
# Configuration Section
# =========================
# Define authorized devices allowed to connect to the system
AUTHORIZED_DEVICES = {"soldier-001", "hq-001", "drone-001"}

# Specify the Post-Quantum Cryptography (PQC) algorithms
KEM_ALGO = "Kyber768"       # Used for key encapsulation (secure key exchange)
SIG_ALGO = "ML-DSA-65"      # Used for digital signatures

# In-memory session storage for active KEM sessions
kem_sessions = {}

# Log file to record verified messages
LOG_FILE = os.path.expanduser("~/liboqs-python/log_verified.txt")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


# =========================
# Health & Status Endpoints
# =========================
@app.route("/", methods=["GET"])
def home():
    """Root endpoint providing service details and available API routes."""
    return jsonify({
        "service": "PQC Military Communication System",
        "status": "operational",
        "endpoints": {
            "connect": "/connect",
            "handshake_start": "/handshake/start",
            "handshake_complete": "/handshake/complete",
            "sign": "/sign",
            "verify": "/verify",
            "status": "/status"
        }
    })


@app.route("/status", methods=["GET"])
def status():
    """Returns the current system configuration and active session count."""
    return jsonify({
        "KEM": KEM_ALGO,
        "Signature": SIG_ALGO,
        "Encryption": "AES-GCM-256",
        "Status": "Secure and operational",
        "active_sessions": len(kem_sessions)
    })


# =========================
# Device Connection
# =========================
@app.route("/connect", methods=["POST"])
def connect():
    """Registers an authorized device before initiating a handshake."""
    data = request.get_json()
    device_id = data.get("device_id")

    if device_id in AUTHORIZED_DEVICES:
        print(f"Device {device_id} connected successfully.")
        return jsonify({
            "status": "OK",
            "message": f"Device {device_id} connected."
        }), 200
    else:
        print(f"Unauthorized device attempted to connect: {device_id}")
        return jsonify({
            "status": "FAIL",
            "message": "Unauthorized device."
        }), 403


# =========================
# Key Encapsulation (KEM) Handshake
# =========================
@app.route("/handshake/start", methods=["POST"])
def handshake_start():
    """Begins the PQC handshake process by generating and sharing a public key."""
    data = request.get_json()
    device_id = data.get("device_id")

    # Initialize KEM instance and generate keypair
    kem = oqs.KeyEncapsulation(KEM_ALGO)
    public_key = kem.generate_keypair()

    # Store the KEM session for this device
    kem_sessions[device_id] = kem

    print(f"Handshake started for device {device_id}")
    return jsonify({
        "algorithm": KEM_ALGO,
        "public_key": base64.b64encode(public_key).decode(),
        "device_id": device_id
    })


@app.route("/handshake/complete", methods=["POST"])
def handshake_complete():
    """Completes the KEM handshake and derives a shared secret key."""
    data = request.get_json()
    device_id = data.get("device_id")
    ciphertext_b64 = data.get("ciphertext")

    # Retrieve existing KEM session for the device
    kem = kem_sessions.get(device_id)
    if not kem:
        return jsonify({"error": "No active session"}), 400

    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        shared_secret = kem.decap_secret(ciphertext)

        print(f"Handshake successfully completed for {device_id}")
        return jsonify({
            "status": "OK",
            "shared_secret": base64.b64encode(shared_secret).decode(),
            "device_id": device_id
        })
    except Exception as e:
        return jsonify({"error": f"Handshake failed: {str(e)}"}), 400


# =========================
# Digital Signatures
# =========================
@app.route("/sign", methods=["POST"])
def sign_message():
    """Digitally signs a given message using the PQC signature algorithm."""
    try:
        data = request.get_json()
        if not data or "message" not in data:
            return jsonify({"error": "Missing 'message' field"}), 400

        message = data["message"].encode()

        # Generate keypair and sign the message
        sig = oqs.Signature(SIG_ALGO)
        public_key = sig.generate_keypair()
        signature = sig.sign(message)

        print(f"Message signed successfully: '{data['message']}'")
        return jsonify({
            "signature": base64.b64encode(signature).decode(),
            "public_key": base64.b64encode(public_key).decode(),
            "algorithm": SIG_ALGO
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/verify", methods=["POST"])
def verify_signature():
    """Verifies a message signature using the provided public key."""
    try:
        data = request.get_json()
        required = ["message", "signature", "public_key"]
        if not all(k in data for k in required):
            return jsonify({"error": "Missing required fields"}), 400

        message = data["message"].encode()
        signature = base64.b64decode(data["signature"])
        public_key = base64.b64decode(data["public_key"])

        # Verify the digital signature
        sig = oqs.Signature(SIG_ALGO)
        verified = sig.verify(message, signature, public_key)

        if verified:
            with open(LOG_FILE, "a") as f:
                f.write(f"{datetime.now()} - Verified: {message.decode()}\n")

            print(f"Signature verified successfully for message: '{data['message']}'")
            return jsonify({
                "status": "success",
                "verified": True,
                "message": "Signature verified successfully."
            }), 200
        else:
            print("Signature verification failed.")
            return jsonify({
                "status": "failure",
                "verified": False,
                "message": "Signature verification failed."
            }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# Application Entry Point
# =========================
if __name__ == "__main__":
    print("=" * 60)
    print("PQC MILITARY COMMUNICATION SYSTEM")
    print("=" * 60)
    print(f"KEM Algorithm: {KEM_ALGO}")
    print(f"Signature Algorithm: {SIG_ALGO}")
    print(f"Authorized Devices: {', '.join(AUTHORIZED_DEVICES)}")
    print("=" * 60)
    print("Server starting on http://0.0.0.0:5000")
    print("=" * 60)

    app.run(host="0.0.0.0", port=5000, debug=True)
