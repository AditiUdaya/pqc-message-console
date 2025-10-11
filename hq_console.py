# hq.py
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
        background-color: #001a00 !important;
        color: #00FF41 !important;
        border: 1px solid #00FF41 !important;
    }
    .stButton>button:hover { background-color: #003300 !important; }
    .st-emotion-cache-1avcm0n, .st-emotion-cache-k7vsyb p { color: #00FF41 !important; } /* metric colors */
    .success { color: #00FF41; font-weight: bold; }
    .error { color: #FF5555; font-weight: bold; }
    hr { border-color: #00FF41; }
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
    if st.button("Connect HQ-001 to Secure Backend"):
        res = post_request("/connect", {"device_id": DEVICE_ID})
        if res.get("status") == "OK":
            st.session_state.hq_connected = True
            st.rerun()
        else:
            st.error(res.get('message') or res.get('error'))
    st.info("System is offline. Connect to begin operations.")
else:
    # --- STATUS AND CHAT INTERFACE ---
    col1, col2 = st.columns(2)
    col1.metric("HQ Status", "Connected")
    col2.metric("Soldier Status", st.session_state.soldier_status)
    st.markdown("---")
    
    st.subheader("Secure Communication Channel")
    for msg in st.session_state.message_history:
        with st.chat_message("user" if msg["sender_id"] == DEVICE_ID else "assistant"):
            st.write(msg["message"])
    
    if prompt := st.chat_input("Transmit secure message..."):
        post_request("/send", {"sender_id": DEVICE_ID, "receiver_id": COUNTERPART_ID, "message": prompt})
        st.session_state.message_history.append({"sender_id": DEVICE_ID, "message": prompt})
        st.rerun()

    # --- VISUALIZATION EXPANDERS ---
    st.markdown("---")
    st.subheader("PQC Process Visualizer")
    
    with st.expander("Visualize: Quantum Key Handshake (Kyber768)"):
        if st.button("Step 1: Start Handshake"):
            res = post_request("/handshake/start", {"device_id": DEVICE_ID})
            st.session_state["viz_pk"] = res.get("public_key")
        if "viz_pk" in st.session_state:
            st.success("Server generated a public key:")
            st.code(st.session_state["viz_pk"], language="text")
        
        ciphertext = st.text_area("Step 2: Enter Ciphertext from other party")
        if st.button("Step 3: Complete Handshake"):
            res = post_request("/handshake/complete", {"device_id": DEVICE_ID, "ciphertext": ciphertext})
            if "shared_secret" in res:
                st.success("Handshake complete! Derived shared secret:")
                st.code(res["shared_secret"], language="text")
            else: st.error(res.get("error"))

    with st.expander("Visualize: Digital Signature (ML-DSA-65)"):
        msg = st.text_input("Message to Sign", "Alpha team go", key="viz_msg")
        if st.button("Step 1: Generate Signature"):
            res = post_request("/sign", {"message": msg})
            st.session_state.viz_sig = res.get("signature")
            st.session_state.viz_sig_pk = res.get("public_key")
        if "viz_sig" in st.session_state:
            st.success("Signature generated:")
            st.code(st.session_state.viz_sig, language="text")
            st.info("Public key for verification:")
            st.code(st.session_state.viz_sig_pk, language="text")
        
        if st.button("Step 2: Verify Signature"):
            payload = {
                "message": msg,
                "signature": st.session_state.get("viz_sig"),
                "public_key": st.session_state.get("viz_sig_pk")
            }
            res = post_request("/verify", payload)
            if res.get("verified"): st.markdown("<p class='success'>SIGNATURE VERIFIED</p>", unsafe_allow_html=True)
            else: st.markdown("<p class='error'>VERIFICATION FAILED</p>", unsafe_allow_html=True)

    # --- AUTO-REFRESH LOGIC ---
    is_soldier_connected = st.session_state.soldier_status == "Connection Established"
    
    if not is_soldier_connected:
        status_res = requests.get(f"{BACKEND_URL}/status").json()
        st.session_state.soldier_status = "Connection Established" if status_res.get("active_sessions", 0) >= 2 else "Waiting..."
        time.sleep(2)
    else:
        new_msgs = post_request("/receive", {"receiver_id": DEVICE_ID}).get("messages", [])
        if new_msgs:
            st.session_state.message_history.extend(new_msgs)
            time.sleep(1)
        
    st.rerun()
