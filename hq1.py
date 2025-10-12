# h.py
import streamlit as st
import requests
import time

# ==============================
# CONFIGURATION
# ==============================
BACKEND_URL = "http://10.50.115.208:5000"
DEVICE_ID = "hq-001"
# Define counterparts
SOLDIER_ID = "soldier-001"
DRONE_ID = "drone-001"

# ==============================
# PAGE CONFIG AND THEME
# ==============================
st.set_page_config(page_title="PQC HQ Command", layout="wide")
st.markdown("""
    <style>
    /* Main Theme */
    body, .stApp { background-color: #0a0f0a; color: #00FF41; }
    div[data-testid="stHeader"] { background: #0a0f0a; }
    .stTextInput>div>div>input, .stTextArea>div>textarea, .stButton>button, .stChatInput>div>div>input, .stFileUploader>div>div>div>button {
        background-color: #001a00 !important; color: #00FF41 !important; border: 1px solid #00FF41 !important;
    }
    .stButton>button:hover, .stFileUploader>div>div>div>button:hover { background-color: #003300 !important; }
    .st-emotion-cache-1avcm0n, .st-emotion-cache-k7vsyb p { color: #00FF41 !important; }
    hr { border-color: #00FF41; }
    /* Recall Button */
    div[data-testid="stChatMessage"] button {
        background-color: #400000 !important; color: #FF8888 !important; border: 1px solid #FF5555 !important;
        border-radius: 4px; width: 35px; height: 30px; font-weight: bold;
    }
    div[data-testid="stChatMessage"] button:hover { background-color: #660000 !important; }
    /* Recalled Message */
    .recalled-message { text-decoration: line-through; color: #777777 !important; }
    </style>
""", unsafe_allow_html=True)

# ==============================
# SESSION STATE & HELPERS
# ==============================
if 'hq_connected' not in st.session_state: st.session_state.hq_connected = False
if 'message_history' not in st.session_state: st.session_state.message_history = []

def post_request(endpoint, payload):
    try: return requests.post(f"{BACKEND_URL}{endpoint}", json=payload, timeout=10).json()
    except requests.RequestException: return {"error": "Connection to backend failed."}

# ==============================
# MAIN APPLICATION
# ==============================
st.title("PQC HQ COMMAND CONSOLE")
st.markdown("---")

if not st.session_state.hq_connected:
    if st.button("Connect HQ-001", key="connect_hq"):
        res = post_request("/connect", {"device_id": DEVICE_ID})
        if res.get("status") == "OK": st.session_state.hq_connected = True; st.rerun()
    st.info("System is offline. Connect to begin operations.")
else:
    left_panel, right_panel = st.columns([2, 1])

    # --- LEFT PANEL: Status and Visualizers ---
    with left_panel:
        st.subheader("SYSTEM STATUS")
        status_res = requests.get(f"{BACKEND_URL}/status").json()
        active_count = status_res.get("active_sessions", 0)
        col1, col2 = st.columns(2)
        col1.metric("HQ Status", "Connected")
        col2.metric("Active Field Units", f"{active_count - 1 if active_count > 0 else 0}")
        st.divider()

        st.subheader("PQC PROCESS VISUALIZER")
        with st.expander("Visualize: Quantum Key Handshake (Kyber768)"):
            if st.button("Step 1: Start Handshake"):
                res = post_request("/handshake/start", {})
                st.session_state["viz_pk"] = res.get("public_key")
            if "viz_pk" in st.session_state:
                st.success("Server generated a public key:"); st.code(st.session_state["viz_pk"], language="text")
            ciphertext = st.text_area("Step 2: Enter Ciphertext from other party")
            if st.button("Step 3: Complete Handshake"):
                res = post_request("/handshake/complete", {"ciphertext": ciphertext})
                if "shared_secret" in res:
                    st.success("Handshake complete! Derived shared secret:"); st.code(res["shared_secret"], language="text")
                else: st.error(res.get("error"))

        with st.expander("Visualize: Digital Signature (ML-DSA-65)"):
            msg = st.text_input("Message to Sign", "Alpha team go", key="viz_msg")
            if st.button("Step 1: Generate Signature"):
                res = post_request("/sign", {"message": msg})
                st.session_state.viz_sig, st.session_state.viz_sig_pk = res.get("signature"), res.get("public_key")
            if "viz_sig" in st.session_state:
                st.success("Signature generated:"); st.code(st.session_state.viz_sig, language="text")
                st.info("Public key for verification:"); st.code(st.session_state.viz_sig_pk, language="text")
            if st.button("Step 2: Verify Signature"):
                payload = {"message": msg, "signature": st.session_state.get("viz_sig"), "public_key": st.session_state.get("viz_sig_pk")}
                res = post_request("/verify", payload)
                if res.get("verified"): st.markdown("<p style='color: #00FF41;'>SIGNATURE VERIFIED</p>", unsafe_allow_html=True)
                else: st.markdown("<p style='color: #FF5555;'>VERIFICATION FAILED</p>", unsafe_allow_html=True)
    
    # --- RIGHT PANEL: Secure Communications with Tabs ---
    with right_panel:
        st.subheader("SECURE COMMS CHANNELS")
        
        soldier_tab, drone_tab = st.tabs(["Soldier Comms", "Drone Comms"])

        # --- SOLDIER CHAT TAB ---
        with soldier_tab:
            chat_container = st.container(height=400, border=False)
            for msg in st.session_state.message_history:
                if (msg['sender_id'] == SOLDIER_ID and msg['receiver_id'] == DEVICE_ID) or \
                   (msg['sender_id'] == DEVICE_ID and msg['receiver_id'] == SOLDIER_ID):
                    with chat_container.chat_message("user" if msg["sender_id"] == DEVICE_ID else "assistant"):
                        # (Display logic is the same, just filtered)
                        if msg.get('type') == 'file':
                            st.write(f"Image Received: `{msg['filename']}`"); st.image(f"{BACKEND_URL}/download/{msg['id']}")
                        elif msg["status"] == 'recalled':
                            st.markdown(f"<p class='recalled-message'>{msg['message']}</p>", unsafe_allow_html=True)
                        else:
                            msg_col, button_col = st.columns([10, 2])
                            msg_col.write(msg["message"])
                            if msg["sender_id"] == DEVICE_ID:
                                if button_col.button("R", key=f"del_soldier_{msg['id']}", help="Recall message"):
                                    post_request("/recall_message", {"message_id": msg["id"]}); st.rerun()
                        if msg["sender_id"] == DEVICE_ID:
                            chat_container.caption("Recalled" if msg['status'] == 'recalled' else ("Read" if msg["status"] == "read" else "Sent"))
            
            if prompt := st.chat_input("Message Soldier..."):
                post_request("/send", {"sender_id": DEVICE_ID, "receiver_id": SOLDIER_ID, "message": prompt}); st.rerun()
            
            uploaded_file = st.file_uploader("Send Image to Soldier", type=['png', 'jpg', 'jpeg'], key="soldier_uploader")
            if uploaded_file:
                if st.button("Transmit to Soldier"):
                    files = {'file': (uploaded_file.name, uploaded_file.getvalue())}
                    payload = {'sender_id': DEVICE_ID, 'receiver_id': SOLDIER_ID}
                    requests.post(f"{BACKEND_URL}/upload", files=files, data=payload); st.rerun()

        # --- DRONE CHAT TAB ---
        with drone_tab:
            chat_container = st.container(height=400, border=False)
            for msg in st.session_state.message_history:
                if (msg['sender_id'] == DRONE_ID and msg['receiver_id'] == DEVICE_ID) or \
                   (msg['sender_id'] == DEVICE_ID and msg['receiver_id'] == DRONE_ID):
                    with chat_container.chat_message("user" if msg["sender_id"] == DEVICE_ID else "assistant"):
                        # (Display logic is the same, just filtered)
                        if msg.get('type') == 'file':
                            st.write(f"Image Received: `{msg['filename']}`"); st.image(f"{BACKEND_URL}/download/{msg['id']}")
                        elif msg["status"] == 'recalled':
                            st.markdown(f"<p class='recalled-message'>{msg['message']}</p>", unsafe_allow_html=True)
                        else:
                            msg_col, button_col = st.columns([10, 2])
                            msg_col.write(msg["message"])
                            if msg["sender_id"] == DEVICE_ID:
                                if button_col.button("R", key=f"del_drone_{msg['id']}", help="Recall message"):
                                    post_request("/recall_message", {"message_id": msg["id"]}); st.rerun()
                        if msg["sender_id"] == DEVICE_ID:
                            chat_container.caption("Recalled" if msg['status'] == 'recalled' else ("Read" if msg["status"] == "read" else "Sent"))

            if prompt := st.chat_input("Message Drone..."):
                post_request("/send", {"sender_id": DEVICE_ID, "receiver_id": DRONE_ID, "message": prompt}); st.rerun()
            
            uploaded_file = st.file_uploader("Send Image to Drone", type=['png', 'jpg', 'jpeg'], key="drone_uploader")
            if uploaded_file:
                if st.button("Transmit to Drone"):
                    files = {'file': (uploaded_file.name, uploaded_file.getvalue())}
                    payload = {'sender_id': DEVICE_ID, 'receiver_id': DRONE_ID}
                    requests.post(f"{BACKEND_URL}/upload", files=files, data=payload); st.rerun()

    # --- AUTO-REFRESH LOGIC (Unchanged) ---
    res = post_request("/receive", {"client_id": DEVICE_ID})
    if res and "error" not in res:
        new_history = res.get("messages", [])
        if new_history != st.session_state.message_history:
            st.session_state.message_history = new_history; st.rerun()
    time.sleep(3)
    st.rerun()
