import streamlit as st
import requests
import time
import json

# ==============================
# CONFIGURATION
# ==============================
BACKEND_URL = "http://127.0.0.1:5000"
DEVICE_ID = "hq-001"
COUNTERPART_ID = "soldier-001"

# ==============================
# PAGE CONFIG AND THEME
# ==============================
st.set_page_config(page_title="PQC HQ Command", layout="wide")
st.markdown("""
    <style>
    body, .stApp { background-color: #0a0f0a; color: #00FF41; }
    div[data-testid="stHeader"] { background: #0a0f0a; }
    .stTextInput>div>div>input, .stTextArea>div>textarea, .stButton>button, .stChatInput>div>div>input {
        background-color: #001a00 !important; color: #00FF41 !important;
        border: 1px solid #00FF41 !important;
    }
    .stButton>button:hover { background-color: #003300 !important; }
    .st-emotion-cache-1avcm0n, .st-emotion-cache-k7vsyb p { color: #00FF41 !important; }
    hr { border-color: #00FF41; }

    /* --- RECALL BUTTON --- */
    div[data-testid="stChatMessage"] button {
        background-color: #400000 !important; color: #FF8888 !important;
        border: 1px solid #FF5555 !important; border-radius: 4px;
        width: 35px; height: 30px; font-weight: bold;
    }
    div[data-testid="stChatMessage"] button:hover { background-color: #660000 !important; }
    
    /* --- RECALLED MESSAGE STYLE --- */
    .recalled-message {
        text-decoration: line-through;
        color: #777777 !important;
    }
    </style>
""", unsafe_allow_html=True)

# ==============================
# SESSION STATE & HELPERS
# ==============================
if 'hq_connected' not in st.session_state: st.session_state.hq_connected = False
if 'message_history' not in st.session_state: st.session_state.message_history = []
if 'soldier_status' not in st.session_state: st.session_state.soldier_status = "Offline"

def post_request(endpoint, payload):
    try: return requests.post(f"{BACKEND_URL}{endpoint}", json=payload, timeout=5).json()
    except requests.RequestException: return {"error": "Connection to backend failed."}

# ==============================
# MAIN APPLICATION
# ==============================
st.title("PQC HQ COMMAND CONSOLE")
st.markdown("---")

if not st.session_state.hq_connected:
    if st.button("Connect HQ-001 to Secure Backend", key="connect_hq"):
        res = post_request("/connect", {"device_id": DEVICE_ID})
        if res.get("status") == "OK": st.session_state.hq_connected = True; st.rerun()
    st.info("System is offline. Connect to begin operations.")
else:
    left_panel, right_panel = st.columns([2, 1])

    # --- LEFT PANEL: Status and Visualizers ---
    with left_panel:
        st.subheader("SYSTEM STATUS")
        col1, col2 = st.columns(2)
        col1.metric("HQ Status", "Connected")
        col2.metric("Soldier Status", st.session_state.soldier_status)
        st.divider()

        # ## VISUALIZERS RESTORED ##
        st.subheader("PQC PROCESS VISUALIZER")
        with st.expander("Visualize: Quantum Key Handshake (Kyber768)"):
            if st.button("Step 1: Start Handshake"):
                res = post_request("/handshake/start", {"device_id": DEVICE_ID})
                st.session_state["viz_pk"] = res.get("public_key")
            if "viz_pk" in st.session_state:
                st.success("Server generated a public key:"); st.code(st.session_state["viz_pk"], language="text")
            ciphertext = st.text_area("Step 2: Enter Ciphertext from other party")
            if st.button("Step 3: Complete Handshake"):
                res = post_request("/handshake/complete", {"device_id": DEVICE_ID, "ciphertext": ciphertext})
                if "shared_secret" in res:
                    st.success("Handshake complete! Derived shared secret:"); st.code(res["shared_secret"], language="text")
                else: st.error(res.get("error"))

        with st.expander("Visualize: Digital Signature (ML-DSA-65)"):
            msg = st.text_input("Message to Sign", "Alpha team go", key="viz_msg")
            if st.button("Step 1: Generate Signature"):
                res = post_request("/sign", {"message": msg})
                st.session_state.viz_sig = res.get("signature"); st.session_state.viz_sig_pk = res.get("public_key")
            if "viz_sig" in st.session_state:
                st.success("Signature generated:"); st.code(st.session_state.viz_sig, language="text")
                st.info("Public key for verification:"); st.code(st.session_state.viz_sig_pk, language="text")
            if st.button("Step 2: Verify Signature"):
                payload = {"message": msg, "signature": st.session_state.get("viz_sig"), "public_key": st.session_state.get("viz_sig_pk")}
                res = post_request("/verify", payload)
                if res.get("verified"): st.markdown("<p class='success'>SIGNATURE VERIFIED</p>", unsafe_allow_html=True)
                else: st.markdown("<p class='error'>VERIFICATION FAILED</p>", unsafe_allow_html=True)

    # --- RIGHT PANEL: Secure Communications ---
    with right_panel:
        st.subheader("SECURE COMMS CHANNEL")
        chat_container = st.container(height=500, border=False)
        for msg in st.session_state.message_history:
            with chat_container.chat_message("user" if msg["sender_id"] == DEVICE_ID else "assistant"):
                msg_col, button_col = st.columns([10, 2])
                
                if msg["status"] == 'recalled':
                    msg_col.markdown(f"<p class='recalled-message'>{msg['message']}</p>", unsafe_allow_html=True)
                else:
                    msg_col.write(msg["message"])
                
                if msg["sender_id"] == DEVICE_ID and msg["status"] != 'recalled':
                    # ## UPDATED BUTTON TEXT ##
                    if button_col.button("R", key=f"del_{msg['id']}", help="Recall message"):
                        post_request("/recall_message", {"message_id": msg["id"]})
                        st.rerun()
                
                if msg["sender_id"] == DEVICE_ID:
                    if msg['status'] == 'recalled':
                         chat_container.caption("Recalled")
                    else:
                         chat_container.caption("Read" if msg["status"] == "read" else "Sent")

        if prompt := st.chat_input("Transmit encrypted message..."):
            res = post_request("/send", {"sender_id": DEVICE_ID, "receiver_id": COUNTERPART_ID, "message": prompt})
            if res and res.get("status") == "success": st.rerun()

    # --- AUTO-REFRESH LOGIC ---
    is_soldier_connected = st.session_state.soldier_status == "Connection Established"
    
    if not is_soldier_connected:
        try:
            status_res = requests.get(f"{BACKEND_URL}/status").json()
            st.session_state.soldier_status = "Connection Established" if status_res.get("active_sessions", 0) >= 2 else "Waiting..."
        except requests.RequestException: st.session_state.soldier_status = "Offline"
        time.sleep(1)
    else:
        res = post_request("/receive", {"client_id": DEVICE_ID})
        if res and "error" not in res:
            new_history = res.get("messages", [])
            if new_history != st.session_state.message_history:
                st.session_state.message_history = new_history; st.rerun()
        time.sleep(2.5)
    st.rerun()
