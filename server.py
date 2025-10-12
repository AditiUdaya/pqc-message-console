# server.py
from flask import Flask, request, jsonify, send_file
import oqs
import base64
import os
import uuid
import io
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# ===== Configuration =====
AUTHORIZED_DEVICES = {"soldier-001", "hq-001", "drone-001"}
KEM_ALGO = "Kyber768"
SIG_ALGO = "ML-DSA-65"
SHARED_AES_KEY = AESGCM.generate_key(bit_length=256)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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

# ===== Chat & File Endpoints =====
@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json()
    sender, receiver, msg_text = data.get("sender_id"), data.get("receiver_id"), data.get("message")
    message_bundle = {
        "id": str(uuid.uuid4()), "sender_id": sender, "receiver_id": receiver,
        "type": "text", "message": msg_text, "status": "sent"
    }
    message_store.append(message_bundle)
    return jsonify({"status": "success"})

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files: return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({"error": "No selected file"}), 400
    
    sender = request.form.get('sender_id')
    receiver = request.form.get('receiver_id')
    file_contents = file.read()

    aes_gcm = AESGCM(SHARED_AES_KEY)
    nonce = os.urandom(12)
    encrypted_contents = aes_gcm.encrypt(nonce, file_contents, None)
    
    file_id = str(uuid.uuid4())
    encrypted_filename = f"{file_id}.enc"
    encrypted_filepath = os.path.join(UPLOAD_FOLDER, encrypted_filename)

    with open(encrypted_filepath, 'wb') as f:
        f.write(base64.b64encode(nonce) + b':' + base64.b64encode(encrypted_contents))

    file_message_bundle = {
        "id": file_id, "sender_id": sender, "receiver_id": receiver,
        "type": "file", "filename": file.filename,
        "encrypted_path": encrypted_filename, "status": "sent"
    }
    message_store.append(file_message_bundle)
    return jsonify({"status": "success"})

@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    file_bundle = next((msg for msg in message_store if msg['id'] == file_id and msg.get('type') == 'file'), None)
    if not file_bundle: return "File not found.", 404
    encrypted_filepath = os.path.join(UPLOAD_FOLDER, file_bundle['encrypted_path'])
    
    try:
        with open(encrypted_filepath, 'rb') as f:
            nonce_b64, encrypted_contents_b64 = f.read().split(b':')
        nonce, encrypted_contents = base64.b64decode(nonce_b64), base64.b64decode(encrypted_contents_b64)
        aes_gcm = AESGCM(SHARED_AES_KEY)
        decrypted_contents = aes_gcm.decrypt(nonce, encrypted_contents, None)
        return send_file(io.BytesIO(decrypted_contents), as_attachment=True, download_name=file_bundle['filename'])
    except Exception as e:
        return f"Could not process file: {e}", 500

@app.route("/receive", methods=["POST"])
def receive_messages():
    client_id = request.get_json().get("client_id")
    for bundle in message_store:
        if bundle.get("receiver_id") == client_id and bundle.get("status") == "sent":
            bundle["status"] = "read"
    return jsonify({"status": "success", "messages": message_store})

@app.route("/recall_message", methods=["POST"])
def recall_message():
    message_id = request.get_json().get("message_id")
    for msg in message_store:
        if msg['id'] == message_id: msg['status'] = 'recalled'; break
    return jsonify({"status": "success"})

# ===== Visualization Endpoints =====
@app.route("/handshake/start", methods=["POST"])
def handshake_start():
    kem = oqs.KeyEncapsulation(KEM_ALGO)
    public_key = kem.generate_keypair()
    kem_sessions["viz_session"] = kem
    return jsonify({"public_key": base64.b64encode(public_key).decode()})

@app.route("/handshake/complete", methods=["POST"])
def handshake_complete():
    ciphertext_b64 = request.get_json().get("ciphertext")
    kem = kem_sessions.get("viz_session")
    if not kem: return jsonify({"error": "No active handshake viz session"}), 400
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
    message, signature_b64, public_key_b64 = data.get("message", "").encode(), data.get("signature"), data.get("public_key")
    signature, public_key = base64.b64decode(signature_b64), base64.b64decode(public_key_b64)
    sig = oqs.Signature(SIG_ALGO)
    verified = sig.verify(message, signature, public_key)
    return jsonify({"verified": verified})

if __name__ == "__main__":
    print("=" * 60)
    print("PQC MILITARY COMMUNICATION SYSTEM (Full Feature Set)")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)# server.py
from flask import Flask, request, jsonify, send_file
import oqs
import base64
import os
import uuid
import io
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# ===== Configuration =====
AUTHORIZED_DEVICES = {"soldier-001", "hq-001", "drone-001"}
KEM_ALGO = "Kyber768"
SIG_ALGO = "ML-DSA-65"
SHARED_AES_KEY = AESGCM.generate_key(bit_length=256)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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

# ===== Chat & File Endpoints =====
@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json()
    sender, receiver, msg_text = data.get("sender_id"), data.get("receiver_id"), data.get("message")
    message_bundle = {
        "id": str(uuid.uuid4()), "sender_id": sender, "receiver_id": receiver,
        "type": "text", "message": msg_text, "status": "sent"
    }
    message_store.append(message_bundle)
    return jsonify({"status": "success"})

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files: return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({"error": "No selected file"}), 400
    
    sender = request.form.get('sender_id')
    receiver = request.form.get('receiver_id')
    file_contents = file.read()

    aes_gcm = AESGCM(SHARED_AES_KEY)
    nonce = os.urandom(12)
    encrypted_contents = aes_gcm.encrypt(nonce, file_contents, None)
    
    file_id = str(uuid.uuid4())
    encrypted_filename = f"{file_id}.enc"
    encrypted_filepath = os.path.join(UPLOAD_FOLDER, encrypted_filename)

    with open(encrypted_filepath, 'wb') as f:
        f.write(base64.b64encode(nonce) + b':' + base64.b64encode(encrypted_contents))

    file_message_bundle = {
        "id": file_id, "sender_id": sender, "receiver_id": receiver,
        "type": "file", "filename": file.filename,
        "encrypted_path": encrypted_filename, "status": "sent"
    }
    message_store.append(file_message_bundle)
    return jsonify({"status": "success"})

@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    file_bundle = next((msg for msg in message_store if msg['id'] == file_id and msg.get('type') == 'file'), None)
    if not file_bundle: return "File not found.", 404
    encrypted_filepath = os.path.join(UPLOAD_FOLDER, file_bundle['encrypted_path'])
    
    try:
        with open(encrypted_filepath, 'rb') as f:
            nonce_b64, encrypted_contents_b64 = f.read().split(b':')
        nonce, encrypted_contents = base64.b64decode(nonce_b64), base64.b64decode(encrypted_contents_b64)
        aes_gcm = AESGCM(SHARED_AES_KEY)
        decrypted_contents = aes_gcm.decrypt(nonce, encrypted_contents, None)
        return send_file(io.BytesIO(decrypted_contents), as_attachment=True, download_name=file_bundle['filename'])
    except Exception as e:
        return f"Could not process file: {e}", 500

@app.route("/receive", methods=["POST"])
def receive_messages():
    client_id = request.get_json().get("client_id")
    for bundle in message_store:
        if bundle.get("receiver_id") == client_id and bundle.get("status") == "sent":
            bundle["status"] = "read"
    return jsonify({"status": "success", "messages": message_store})

@app.route("/recall_message", methods=["POST"])
def recall_message():
    message_id = request.get_json().get("message_id")
    for msg in message_store:
        if msg['id'] == message_id: msg['status'] = 'recalled'; break
    return jsonify({"status": "success"})

# ===== Visualization Endpoints =====
@app.route("/handshake/start", methods=["POST"])
def handshake_start():
    kem = oqs.KeyEncapsulation(KEM_ALGO)
    public_key = kem.generate_keypair()
    kem_sessions["viz_session"] = kem
    return jsonify({"public_key": base64.b64encode(public_key).decode()})

@app.route("/handshake/complete", methods=["POST"])
def handshake_complete():
    ciphertext_b64 = request.get_json().get("ciphertext")
    kem = kem_sessions.get("viz_session")
    if not kem: return jsonify({"error": "No active handshake viz session"}), 400
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
    message, signature_b64, public_key_b64 = data.get("message", "").encode(), data.get("signature"), data.get("public_key")
    signature, public_key = base64.b64decode(signature_b64), base64.b64decode(public_key_b64)
    sig = oqs.Signature(SIG_ALGO)
    verified = sig.verify(message, signature, public_key)
    return jsonify({"verified": verified})

if __name__ == "__main__":
    print("=" * 60)
    print("PQC MILITARY COMMUNICATION SYSTEM (Full Feature Set)")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
