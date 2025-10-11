# soldier001.py
import streamlit as st
import requests
import time

# ==============================
# CONFIGURATION
# ==============================
BACKEND_URL = "http://127.0.0.1:5000"
DEVICE_ID = "soldier-001"
COUNTERPART_ID = "hq-001"

# ==============================
# PAGE CONFIG AND THEME
# ==============================
st.set_page_config(page_title="PQC Field Terminal", layout="wide")

st.markdown("""
    <style>
    body, .stApp { background-color: #0a0f0a; color: #00FF41; }
    div[data-testid="stHeader"] { background: #0a0f0a; }
    .stTextInput>div>div>input, .stButton>button, .stChatInput>div>div>input {
        background-color: #001a00 !important;
        color: #00FF41 !important;
        border: 1px solid #00FF41 !important;
    }
    .stButton>button:hover { background-color: #003300 !important; }
    .st-emotion-cache-1avcm0n, .st-emotion-cache-k7vsyb p { color: #00FF41 !important; } /* metric colors */
    hr { border-color: #00FF41; }
    </style>
""", unsafe_allow_html=True)

# ==============================
# SESSION STATE & HELPERS
# ==============================
if 'soldier_connected' not in st.session_state: st.session_state.soldier_connected = False
if 'message_history' not in st.session_state: st.session_state.message_history = []
if 'hq_status' not in st.session_state: st.session_state.hq_status = "Offline"

def post_request(endpoint, payload):
    try: return requests.post(f"{BACKEND_URL}{endpoint}", json=payload, timeout=5).json()
    except requests.RequestException: return {"error": "Connection to backend failed."}

# ==============================
# MAIN APPLICATION
# ==============================
st.title("SOLDIER FIELD TERMINAL")
st.markdown("---")

if not st.session_state.soldier_connected:
    if st.button("Connect SOLDIER-001 to Secure Backend"):
        res = post_request("/connect", {"device_id": DEVICE_ID})
        if res.get("status") == "OK":
            st.session_state.soldier_connected = True
            st.rerun()
        else:
            st.error(res.get('message') or res.get('error'))
    st.info("Terminal is offline. Connect to HQ network.")
else:
    col1, col2 = st.columns(2)
    col1.metric("Soldier Status", "Connected")
    col2.metric("HQ Status", st.session_state.hq_status)
    st.markdown("---")
    
    st.subheader("Secure Comms Channel")
    for msg in st.session_state.message_history:
        with st.chat_message("user" if msg["sender_id"] == DEVICE_ID else "assistant"):
            st.write(msg["message"])
    
    if prompt := st.chat_input("Transmit secure message to HQ..."):
        post_request("/send", {"sender_id": DEVICE_ID, "receiver_id": COUNTERPART_ID, "message": prompt})
        st.session_state.message_history.append({"sender_id": DEVICE_ID, "message": prompt})
        st.rerun()

    # --- AUTO-REFRESH LOGIC ---
    is_hq_connected = st.session_state.hq_status == "Connection Established"

    if not is_hq_connected:
        status_res = requests.get(f"{BACKEND_URL}/status").json()
        st.session_state.hq_status = "Connection Established" if status_res.get("active_sessions", 0) >= 2 else "Waiting..."
        time.sleep(2)
    else:
        new_msgs = post_request("/receive", {"receiver_id": DEVICE_ID}).get("messages", [])
        if new_msgs:
            st.session_state.message_history.extend(new_msgs)
        
    st.rerun()
