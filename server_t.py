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

    # --- UPDATED: Store mimetype to differentiate files ---
    file_message_bundle = {
        "id": file_id, "sender_id": sender, "receiver_id": receiver,
        "type": "file", "filename": file.filename, "mimetype": file.mimetype,
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
        # --- UPDATED: Use mimetype to serve the file correctly ---
        return send_file(io.BytesIO(decrypted_contents), mimetype=file_bundle.get('mimetype'), download_name=file_bundle['filename'])
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
    print("PQC MILITARY COMMUNICATION SYSTEM (Video Enabled)")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)

T_drone.py
# drone.py
import streamlit as st
import requests
import time

# ==============================
# CONFIGURATION
# ==============================
BACKEND_URL = "http://10.238.242.208:5000"
DEVICE_ID = "drone-001"
COUNTERPART_ID = "hq-001"

# ==============================
# PAGE CONFIG AND THEME
# ==============================
st.set_page_config(page_title="PQC Drone Terminal", layout="wide")
st.markdown("""<style> ... </style>""", unsafe_allow_html=True) # Blue Theme CSS is unchanged

# ==============================
# SESSION STATE & HELPERS
# ==============================
if 'drone_connected' not in st.session_state: st.session_state.drone_connected = False
if 'message_history' not in st.session_state: st.session_state.message_history = []
if 'hq_status' not in st.session_state: st.session_state.hq_status = "Offline"

def post_request(endpoint, payload):
    try: return requests.post(f"{BACKEND_URL}{endpoint}", json=payload, timeout=10).json()
    except requests.RequestException: return {"error": "Connection to backend failed."}

# ==============================
# MAIN APPLICATION
# ==============================
st.title("DRONE AUTONOMOUS TERMINAL")
st.markdown("---")

if not st.session_state.drone_connected:
    if st.button("Connect DRONE-001", key="connect_drone"):
        res = post_request("/connect", {"device_id": DEVICE_ID})
        if res.get("status") == "OK": st.session_state.drone_connected = True; st.rerun()
    st.info("System is offline. Awaiting network link.")
else:
    left_panel, right_panel = st.columns([2, 1])

    with left_panel:
        st.subheader("SYSTEM STATUS")
        col1, col2 = st.columns(2)
        col1.metric("Drone Status", "Connected | Online")
        col2.metric("HQ Link Status", st.session_state.hq_status)
        st.divider()
        st.subheader("TELEMETRY DATA"); st.info("Optical sensors online. Awaiting commands.")

    with right_panel:
        st.subheader("SECURE COMMS CHANNEL")
        chat_container = st.container(height=450, border=False)
        for msg in st.session_state.message_history:
             if (msg['sender_id'] == COUNTERPART_ID and msg['receiver_id'] == DEVICE_ID) or \
               (msg['sender_id'] == DEVICE_ID and msg['receiver_id'] == COUNTERPART_ID):
                with chat_container.chat_message("user" if msg["sender_id"] == DEVICE_ID else "assistant"):
                    if msg.get('type') == 'file':
                        mimetype = msg.get('mimetype', '')
                        if 'image' in mimetype: st.write(f"Target Image Received: `{msg['filename']}`"); st.image(f"{BACKEND_URL}/download/{msg['id']}")
                        elif 'video' in mimetype: st.write(f"Target Video Received: `{msg['filename']}`"); st.video(f"{BACKEND_URL}/download/{msg['id']}")
                        else: st.write(f"Data File Received: `{msg['filename']}`")
                    elif msg["status"] == 'recalled':
                        st.markdown(f"<p class='recalled-message'>{msg['message']}</p>", unsafe_allow_html=True)
                    else:
                        msg_col, button_col = st.columns([10, 2])
                        msg_col.write(msg["message"])
                        if msg["sender_id"] == DEVICE_ID:
                            if button_col.button("R", key=f"del_{msg['id']}", help="Recall message"):
                                post_request("/recall_message", {"message_id": msg["id"]}); st.rerun()
                    if msg["sender_id"] == DEVICE_ID:
                        chat_container.caption("Recalled" if msg['status'] == 'recalled' else ("Read" if msg["status"] == "read" else "Sent"))

        if prompt := st.chat_input("Transmit telemetry to HQ..."):
            post_request("/send", {"sender_id": DEVICE_ID, "receiver_id": COUNTERPART_ID, "message": prompt}); st.rerun()
        
        uploaded_file = st.file_uploader("Send Secure Video/Image Feed", type=['png', 'jpg', 'jpeg', 'mp4', 'mov'], key="drone_uploader")
        if uploaded_file:
            if st.button("Transmit Media"):
                files = {'file': (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                payload = {'sender_id': DEVICE_ID, 'receiver_id': COUNTERPART_ID}
                requests.post(f"{BACKEND_URL}/upload", files=files, data=payload); st.rerun()

    is_hq_connected = st.session_state.hq_status == "Connection Established"
    if not is_hq_connected:
        try:
            status_res = requests.get(f"{BACKEND_URL}/status").json()
            st.session_state.hq_status = "Connection Established" if status_res.get("active_sessions", 0) > 0 else "Waiting..."
        except requests.RequestException: st.session_state.hq_status = "Offline"
        time.sleep(1)
    else:
        res = post_request("/receive", {"client_id": DEVICE_ID})
        if res and "error" not in res:
            new_history = res.get("messages", [])
            if new_history != st.session_state.message_history:
                st.session_state.message_history = new_history; st.rerun()
        time.sleep(3)
    st.rerun()
