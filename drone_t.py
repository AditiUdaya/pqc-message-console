# h.py
import streamlit as st
import requests
import time

# ==============================
# CONFIGURATION
# ==============================
BACKEND_URL = "http://10.238.242.208:5000"
DEVICE_ID = "hq-001"
SOLDIER_ID = "soldier-001"
DRONE_ID = "drone-001"
counterpart_options = {SOLDIER_ID: "Soldier", DRONE_ID: "Drone"}

# ==============================
# PAGE CONFIG AND THEME
# ==============================
st.set_page_config(page_title="PQC HQ Command", layout="wide")
st.markdown("""<style> ... </style>""", unsafe_allow_html=True) # Theme CSS is unchanged

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
    
    with right_panel:
        st.subheader("SECURE COMMS CHANNELS")
        soldier_tab, drone_tab = st.tabs(["Soldier Comms", "Drone Comms"])

        def render_chat_tab(target_id, target_name):
            chat_container = st.container(height=400, border=False)
            for msg in st.session_state.message_history:
                if (msg['sender_id'] == target_id and msg['receiver_id'] == DEVICE_ID) or \
                   (msg['sender_id'] == DEVICE_ID and msg['receiver_id'] == target_id):
                    with chat_container.chat_message("user" if msg["sender_id"] == DEVICE_ID else "assistant"):
                        if msg.get('type') == 'file':
                            mimetype = msg.get('mimetype', '')
                            if 'image' in mimetype: st.write(f"Image Received: `{msg['filename']}`"); st.image(f"{BACKEND_URL}/download/{msg['id']}")
                            elif 'video' in mimetype: st.write(f"Video Feed Received: `{msg['filename']}`"); st.video(f"{BACKEND_URL}/download/{msg['id']}")
                            else: st.write(f"File Received: `{msg['filename']}`")
                        elif msg["status"] == 'recalled':
                            st.markdown(f"<p class='recalled-message'>{msg['message']}</p>", unsafe_allow_html=True)
                        else:
                            msg_col, button_col = st.columns([10, 2])
                            msg_col.write(msg["message"])
                            if msg["sender_id"] == DEVICE_ID:
                                if button_col.button("R", key=f"del_{target_id}_{msg['id']}", help="Recall message"):
                                    post_request("/recall_message", {"message_id": msg["id"]}); st.rerun()
                        if msg["sender_id"] == DEVICE_ID:
                            chat_container.caption("Recalled" if msg['status'] == 'recalled' else ("Read" if msg["status"] == "read" else "Sent"))
            
            if prompt := st.chat_input(f"Message {target_name}..."):
                post_request("/send", {"sender_id": DEVICE_ID, "receiver_id": target_id, "message": prompt}); st.rerun()
            
            # --- UPDATED: file_uploader accepts video types ---
            uploaded_file = st.file_uploader(f"Send File to {target_name}", type=['png', 'jpg', 'jpeg', 'mp4', 'mov'], key=f"{target_id}_uploader")
            if uploaded_file:
                if st.button(f"Transmit to {target_name}"):
                    files = {'file': (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                    payload = {'sender_id': DEVICE_ID, 'receiver_id': target_id}
                    requests.post(f"{BACKEND_URL}/upload", files=files, data=payload); st.rerun()

        with soldier_tab:
            render_chat_tab(SOLDIER_ID, "Soldier")
        with drone_tab:
            render_chat_tab(DRONE_ID, "Drone")

    res = post_request("/receive", {"client_id": DEVICE_ID})
    if res and "error" not in res:
        new_history = res.get("messages", [])
        if new_history != st.session_state.message_history:
            st.session_state.message_history = new_history; st.rerun()
    time.sleep(3)
    st.rerun()
