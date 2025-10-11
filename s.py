# s.py
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
    if st.button("Connect SOLDIER-001 to Secure Backend", key="connect_soldier"):
        res = post_request("/connect", {"device_id": DEVICE_ID})
        if res.get("status") == "OK": st.session_state.soldier_connected = True; st.rerun()
    st.info("Terminal is offline. Connect to HQ network.")
else:
    left_panel, right_panel = st.columns([2, 1])

    with left_panel:
        st.subheader("SYSTEM STATUS")
        col1, col2 = st.columns(2)
        col1.metric("Soldier Status", "Connected")
        col2.metric("HQ Status", st.session_state.hq_status)
        st.divider()
        st.subheader("MISSION BRIEFING")
        st.info("Channel is secure. Awaiting orders from HQ.")
        st.warning("Maintain operational security. All transmissions are logged.")

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

        if prompt := st.chat_input("Transmit encrypted message to HQ..."):
            res = post_request("/send", {"sender_id": DEVICE_ID, "receiver_id": COUNTERPART_ID, "message": prompt})
            if res and res.get("status") == "success": st.rerun()

    # --- AUTO-REFRESH LOGIC ---
    is_hq_connected = st.session_state.hq_status == "Connection Established"
    
    if not is_hq_connected:
        try:
            status_res = requests.get(f"{BACKEND_URL}/status").json()
            st.session_state.hq_status = "Connection Established" if status_res.get("active_sessions", 0) >= 2 else "Waiting..."
        except requests.RequestException: st.session_state.hq_status = "Offline"
        time.sleep(1)
    else:
        res = post_request("/receive", {"client_id": DEVICE_ID})
        if res and "error" not in res:
            new_history = res.get("messages", [])
            if new_history != st.session_state.message_history:
                st.session_state.message_history = new_history; st.rerun()
        time.sleep(2.5)
    st.rerun()
