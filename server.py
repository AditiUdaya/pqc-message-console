# server.py
from flask import Flask, request, jsonify
import oqs
import base64
import os
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# ===== Configuration =====
AUTHORIZED_DEVICES = {"soldier-001", "hq-001"}
KEM_ALGO = "Kyber768"
SIG_ALGO = "ML-DSA-65"
SHARED_AES_KEY = AESGCM.generate_key(bit_length=256)

# --- Message Storage ---
message_store = []
kem_sessions = {}

# ===== Health & Status =====
@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "Signature": SIG_ALGO, "KEM": KEM_ALGO, "Symmetric Encryption": "AES-256-GCM",
        "active_sessions": len(kem_sessions), "messages_in_store": len(message_store)
    })

# ===== Device Connection =====
@app.route("/connect", methods=["POST"])
def connect():
    device_id = request.get_json().get("device_id")
    if device_id in AUTHORIZED_DEVICES:
        kem = oqs.KeyEncapsulation(KEM_ALGO); kem.generate_keypair()
        kem_sessions[device_id] = kem
        return jsonify({"status": "OK"}), 200
    return jsonify({"status": "FAIL", "message": "Unauthorized device."}), 403

# ===== Chat Endpoints =====
@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json()
    sender, receiver, msg_text = data.get("sender_id"), data.get("receiver_id"), data.get("message")
    aes_gcm = AESGCM(SHARED_AES_KEY)
    nonce = os.urandom(12)
    ciphertext = aes_gcm.encrypt(nonce, msg_text.encode('utf-8'), None)
    message_id = str(uuid.uuid4())
    message_bundle = {
        "id": message_id, "sender_id": sender, "receiver_id": receiver,
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "status": "sent"
    }
    message_store.append(message_bundle)
    return jsonify({"status": "success", "message_id": message_id})

@app.route("/receive", methods=["POST"])
def receive_messages():
    client_id = request.get_json().get("client_id")
    aes_gcm = AESGCM(SHARED_AES_KEY)
    full_conversation = []
    for bundle in message_store:
        try:
            nonce = base64.b64decode(bundle["nonce_b64"])
            ciphertext = base64.b64decode(bundle["ciphertext_b64"])
            decrypted_text = aes_gcm.decrypt(nonce, ciphertext, None).decode('utf-8')
            if bundle["receiver_id"] == client_id and bundle["status"] == "sent":
                bundle["status"] = "read"
            full_conversation.append({
                "id": bundle["id"], "sender_id": bundle["sender_id"],
                "message": decrypted_text, "status": bundle["status"]
            })
        except Exception as e:
            print(f"Server error during decryption for client {client_id}: {e}")
    return jsonify({"status": "success", "messages": full_conversation})

# --- NEW: RECALL MESSAGE LOGIC ---
@app.route("/recall_message", methods=["POST"])
def recall_message():
    message_id = request.get_json().get("message_id")
    for msg in message_store:
        if msg['id'] == message_id:
            msg['status'] = 'recalled'
            break
    return jsonify({"status": "success"})


# ===== Visualization Endpoints (Unchanged) =====
@app.route("/handshake/start", methods=["POST"])
def handshake_start():
    device_id = request.get_json().get("device_id")
    kem = oqs.KeyEncapsulation(KEM_ALGO)
    public_key = kem.generate_keypair()
    kem_sessions[f"viz_{device_id}"] = kem
    return jsonify({"public_key": base64.b64encode(public_key).decode()})

@app.route("/handshake/complete", methods=["POST"])
def handshake_complete():
    data = request.get_json()
    device_id, ciphertext_b64 = data.get("device_id"), data.get("ciphertext")
    kem = kem_sessions.get(f"viz_{device_id}")
    if not kem: return jsonify({"error": "No active viz session"}), 400
    shared_secret = kem.decap_secret(base64.b64decode(ciphertext_b64))
    return jsonify({"shared_secret": base64.b64encode(shared_secret).decode()})

@app.route("/sign", methods=["POST"])
def sign_message():
    message = request.get_json().get("message", "").encode()
    sig = oqs.Signature(SIG_ALGO)
    public_key = sig.generate_keypair()
    signature = sig.sign(message)
    return jsonify({"signature": base64.b64encode(signature).decode(), "public_key": base64.b64encode(public_key).decode()})

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
    print("PQC MILITARY COMMUNICATION SYSTEM (Recall Feature)")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
