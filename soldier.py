# s.py
import streamlit as st
import requests
import time

# ==============================
# CONFIGURATION
# ==============================
BACKEND_URL = "http://10.50.115.208:5000"
DEVICE_ID = "soldier-001"
COUNTERPART_ID = "hq-001"

# ==============================
# PAGE CONFIG AND THEME
# ==============================
st.set_page_config(page_title="PQC Field Terminal", layout="wide")
st.markdown("""<style> ... </style>""", unsafe_allow_html=True) # Theme CSS is unchanged

# ==============================
# SESSION STATE & HELPERS
# ==============================
if 'soldier_connected' not in st.session_state: st.session_state.soldier_connected = False
if 'message_history' not in st.session_state: st.session_state.message_history = []
if 'hq_status' not in st.session_state: st.session_state.hq_status = "Offline"

def post_request(endpoint, payload):
    try: return requests.post(f"{BACKEND_URL}{endpoint}", json=payload, timeout=10).json()
    except requests.RequestException: return {"error": "Connection to backend failed."}

# ==============================
# MAIN APPLICATION
# ==============================
st.title("SOLDIER FIELD TERMINAL")
st.markdown("---")

if not st.session_state.soldier_connected:
    if st.button("Connect SOLDIER-001", key="connect_soldier"):
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
        st.subheader("MISSION BRIEFING"); st.info("Channel is secure. Awaiting orders.")

    with right_panel:
        st.subheader("SECURE COMMS CHANNEL")
        chat_container = st.container(height=450, border=False)
        for msg in st.session_state.message_history:
             if (msg['sender_id'] == COUNTERPART_ID and msg['receiver_id'] == DEVICE_ID) or \
               (msg['sender_id'] == DEVICE_ID and msg['receiver_id'] == COUNTERPART_ID):
                with chat_container.chat_message("user" if msg["sender_id"] == DEVICE_ID else "assistant"):
                    if msg.get('type') == 'file':
                        st.write(f"Image Recon Received: `{msg['filename']}`")
                        st.image(f"{BACKEND_URL}/download/{msg['id']}")
                    elif msg["status"] == 'recalled':
                        st.markdown(f"<p class='recalled-message'>{msg['message']}</p>", unsafe_allow_html=True)
                    else:
                        msg_col, button_col = st.columns([10, 2])
                        msg_col.write(msg["message"])
                        if msg["sender_id"] == DEVICE_ID and msg["status"] != 'recalled':
                            if button_col.button("R", key=f"del_{msg['id']}", help="Recall message"):
                                post_request("/recall_message", {"message_id": msg["id"]}); st.rerun()
                    if msg["sender_id"] == DEVICE_ID:
                        caption = "Recalled" if msg['status'] == 'recalled' else ("Read" if msg["status"] == "read" else "Sent")
                        chat_container.caption(caption)

        if prompt := st.chat_input("Transmit message to HQ..."):
            post_request("/send", {"sender_id": DEVICE_ID, "receiver_id": COUNTERPART_ID, "message": prompt}); st.rerun()
        
        uploaded_file = st.file_uploader("Send Image Recon", type=['png', 'jpg', 'jpeg'], key="soldier_uploader")
        if uploaded_file:
            if st.button("Transmit Image"):
                files = {'file': (uploaded_file.name, uploaded_file.getvalue())}
                payload = {'sender_id': DEVICE_ID, 'receiver_id': COUNTERPART_ID}
                requests.post(f"{BACKEND_URL}/upload", files=files, data=payload); st.rerun()

    # --- AUTO-REFRESH LOGIC ---
    is_hq_connected = st.session_state.hq_status == "Connection Established"
    if not is_hq_connected:
        try:
            status_res = requests.get(f"{BACKEND_URL}/status").json()
            st.session_state.hq_status = "Connection Established" if status_res.get("active_sessions", 0) > 0 else "Waiting..."
        except requests.RequestException: st.session_state.hq_status = "Offline"
        time.sleep(5)
    else:
        res = post_request("/receive", {"client_id": DEVICE_ID})
        if res and "error" not in res:
            new_history = res.get("messages", [])
            if new_history != st.session_state.message_history:
                st.session_state.message_history = new_history; st.rerun()
        time.sleep(3)
    st.rerun()
