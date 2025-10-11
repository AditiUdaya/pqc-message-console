from flask import Flask, request, jsonify
import oqs
import base64
import os
from datetime import datetime

app = Flask(__name__)

# ===== Configuration =====
AUTHORIZED_DEVICES = {"soldier-001", "hq-001", "drone-001"}
KEM_ALGO = "Kyber768"
SIG_ALGO = "ML-DSA-65"

# In-memory storage
kem_sessions = {}
message_inbox = {"hq-001": [], "soldier-001": [], "drone-001": []}
LOG_FILE = os.path.expanduser("~/liboqs-python/log_verified.txt")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# ===== Health & Status =====
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": "PQC Military Communication System",
        "status": "operational",
        "endpoints": {
            "connect": "/connect",
            "status": "/status",
            "chat_send": "/send",
            "chat_receive": "/receive",
            "visualizer_handshake_start": "/handshake/start",
            "visualizer_handshake_complete": "/handshake/complete",
            "visualizer_sign": "/sign",
            "visualizer_verify": "/verify"
        }
    })

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "KEM": KEM_ALGO,
        "Signature": SIG_ALGO,
        "Status": "Secure and operational",
        "active_sessions": len(kem_sessions)
    })

# ===== Device Connection =====
@app.route("/connect", methods=["POST"])
def connect():
    data = request.get_json()
    device_id = data.get("device_id")
    if device_id in AUTHORIZED_DEVICES:
        # Create a KEM session on connect to count active devices accurately
        kem = oqs.KeyEncapsulation(KEM_ALGO)
        kem.generate_keypair()
        kem_sessions[device_id] = kem
        print(f"Device {device_id} connected. Active sessions: {len(kem_sessions)}")
        return jsonify({"status": "OK", "message": f"Device {device_id} connected."}), 200
    else:
        print(f"Unauthorized device: {device_id}")
        return jsonify({"status": "FAIL", "message": "Unauthorized device."}), 403

# ===== Automated Chat Endpoints =====
@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json()
    sender, receiver, message_text = data.get("sender_id"), data.get("receiver_id"), data.get("message")
    if not all([sender, receiver, message_text]):
        return jsonify({"error": "Missing required fields"}), 400
    
    sig = oqs.Signature(SIG_ALGO)
    public_key = sig.generate_keypair()
    signature = sig.sign(message_text.encode())
    
    message_bundle = {
        "message": message_text,
        "signature": base64.b64encode(signature).decode(),
        "public_key": base64.b64encode(public_key).decode(),
        "sender_id": sender
    }
    message_inbox[receiver].append(message_bundle)
    return jsonify({"status": "success", "message": "Message sent successfully"}), 200

@app.route("/receive", methods=["POST"])
def receive_messages():
    receiver_id = request.get_json().get("receiver_id")
    if not receiver_id: return jsonify({"error": "Missing 'receiver_id'"}), 400

    messages_to_process = message_inbox[receiver_id]
    message_inbox[receiver_id] = []  # Clear inbox
    
    verified_messages = []
    sig = oqs.Signature(SIG_ALGO)
    for bundle in messages_to_process:
        is_verified = sig.verify(
            bundle["message"].encode(),
            base64.b64decode(bundle["signature"]),
            base64.b64decode(bundle["public_key"])
        )
        if is_verified:
            verified_messages.append({"sender_id": bundle["sender_id"], "message": bundle["message"]})
    return jsonify({"status": "success", "messages": verified_messages}), 200

# ===== Visualization Endpoints =====
@app.route("/handshake/start", methods=["POST"])
def handshake_start():
    device_id = request.get_json().get("device_id")
    kem = oqs.KeyEncapsulation(KEM_ALGO)
    public_key = kem.generate_keypair()
    kem_sessions[f"viz_{device_id}"] = kem # Use a separate session for visualization
    return jsonify({"public_key": base64.b64encode(public_key).decode(), "device_id": device_id})

@app.route("/handshake/complete", methods=["POST"])
def handshake_complete():
    data = request.get_json()
    device_id, ciphertext_b64 = data.get("device_id"), data.get("ciphertext")
    kem = kem_sessions.get(f"viz_{device_id}")
    if not kem: return jsonify({"error": "No active handshake visualization session"}), 400
    shared_secret = kem.decap_secret(base64.b64decode(ciphertext_b64))
    return jsonify({"shared_secret": base64.b64encode(shared_secret).decode()})

@app.route("/sign", methods=["POST"])
def sign_message():
    message = request.get_json().get("message", "").encode()
    sig = oqs.Signature(SIG_ALGO)
    public_key = sig.generate_keypair()
    signature = sig.sign(message)
    return jsonify({
        "signature": base64.b64encode(signature).decode(),
        "public_key": base64.b64encode(public_key).decode()
    })

@app.route("/verify", methods=["POST"])
def verify_signature():
    data = request.get_json()
    message = data.get("message", "").encode()
    signature = base64.b64decode(data.get("signature"))
    public_key = base64.b64decode(data.get("public_key"))
    sig = oqs.Signature(SIG_ALGO)
    verified = sig.verify(message, signature, public_key)
    return jsonify({"verified": verified})

if __name__ == "__main__":
    print("=" * 60)
    print("PQC MILITARY COMMUNICATION SYSTEM (COMBINED)")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
