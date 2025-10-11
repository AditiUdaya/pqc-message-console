import streamlit as st
import requests
import time
import json
from datetime import datetime

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
    .st-emotion-cache-1avcm0n, .st-emotion-cache-k7vsyb p { color: #00FF41 !important; }
    .success { color: #00FF41; font-weight: bold; }
    .error { color: #FF5555; font-weight: bold; }
    .seen-tick { color: #00BFFF; font-size: 0.8em; }
    .unseen-tick { color: #666; font-size: 0.8em; }
    .encrypted-badge { 
        background-color: #003300; 
        color: #00FF41; 
        padding: 2px 8px; 
        border-radius: 4px; 
        font-size: 0.8em;
        margin-left: 8px;
    }
    hr { border-color: #00FF41; }
    </style>
""", unsafe_allow_html=True)

# ==============================
# SESSION STATE & HELPERS
# ==============================
if 'hq_connected' not in st.session_state:
    st.session_state.hq_connected = False
if 'message_history' not in st.session_state:
    st.session_state.message_history = []
if 'soldier_status' not in st.session_state:
    st.session_state.soldier_status = "Offline"
if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = time.time()

def post_request(endpoint, payload):
    try:
        return requests.post(f"{BACKEND_URL}{endpoint}", json=payload, timeout=5).json()
    except requests.RequestException as e:
        return {"error": f"Connection to backend failed: {str(e)}"}

def get_request(endpoint):
    try:
        return requests.get(f"{BACKEND_URL}{endpoint}", timeout=5).json()
    except requests.RequestException as e:
        return {"error": f"Connection to backend failed: {str(e)}"}

def fetch_new_messages():
    """Fetch new messages from backend"""
    response = post_request("/receive", {"receiver_id": DEVICE_ID})
    if response.get("status") == "success":
        return response.get("messages", [])
    return []

def send_message(message_text):
    """Send encrypted message"""
    response = post_request("/send", {
        "sender_id": DEVICE_ID,
        "receiver_id": COUNTERPART_ID,
        "message": message_text
    })
    return response.get("status") == "success"

def mark_message_seen(message_id):
    """Mark message as seen"""
    post_request("/mark_seen", {
        "message_id": message_id,
        "receiver_id": DEVICE_ID
    })

def delete_message(message_id):
    """Delete message"""
    response = post_request("/delete_message", {
        "message_id": message_id,
        "user_id": DEVICE_ID
    })
    return response.get("status") == "success"

# ==============================
# MAIN APPLICATION
# ==============================
st.title("🎖️ PQC HQ COMMAND CONSOLE")
st.markdown("---")

if not st.session_state.hq_connected:
    if st.button("🔐 Connect HQ-001 to Secure Backend"):
        with st.spinner("Establishing secure connection..."):
            res = post_request("/connect", {"device_id": DEVICE_ID})
            if res.get("status") == "OK":
                st.session_state.hq_connected = True
                st.success("✅ Connected to secure backend")
                time.sleep(1)
                st.rerun()
            else:
                st.error(f"❌ {res.get('message') or res.get('error')}")
    st.info("🔒 System is offline. Connect to begin operations.")
else:
    # --- STATUS DASHBOARD ---
    col1, col2, col3 = st.columns(3)
    
    # Check backend status
    status_data = get_request("/status")
    
    col1.metric("🎖️ HQ Status", "Connected", delta="Active")
    col2.metric("🔐 Encryption", status_data.get("Encryption", "N/A"))
    ##col3.metric("📡 Active Sessions", status_data.get("active_sessions", 0))
    
    st.markdown("---")
    
    # --- SECURE COMMUNICATION CHANNEL ---
    st.subheader("🔐 Secure Communication Channel")
    st.caption(f"End-to-end encrypted with {status_data.get('Encryption', 'AES-256-GCM')} + {status_data.get('Signature', 'ML-DSA-65')} signatures")
    
    # Fetch new messages
    new_messages = fetch_new_messages()
    
    # Update message history (avoid duplicates)
    existing_ids = {msg.get('message_id') for msg in st.session_state.message_history}
    for msg in new_messages:
        if msg.get('message_id') not in existing_ids:
            st.session_state.message_history.append(msg)
            # Auto-mark as seen
            if msg.get('sender_id') != DEVICE_ID:
                mark_message_seen(msg.get('message_id'))
    
    # Display messages
    for idx, msg in enumerate(st.session_state.message_history):
        is_own_message = msg.get("sender_id") == DEVICE_ID
        
        with st.chat_message("user" if is_own_message else "assistant"):
            # Message text with encryption badge
            col_msg, col_actions = st.columns([4, 1])
            
            with col_msg:
                st.write(msg.get("message", ""))
                
                # Show encrypted data in expander
                if "encrypted_data" in msg:
                    with st.expander("🔒 View Encrypted Data"):
                        st.code(json.dumps(msg["encrypted_data"], indent=2), language="json")
                
                # Timestamp and seen status
                timestamp = msg.get("timestamp", "")
                if timestamp:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime("%H:%M:%S")
                else:
                    time_str = "Now"
                
                if is_own_message:
                    seen_icon = "✓✓" if msg.get("seen") else "✓"
                    seen_class = "seen-tick" if msg.get("seen") else "unseen-tick"
                    st.markdown(
                        f"<span style='font-size:0.8em; color:#666;'>{time_str}</span> "
                        f"<span class='{seen_class}'>{seen_icon}</span>",
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(f"<span style='font-size:0.8em; color:#666;'>{time_str}</span>", unsafe_allow_html=True)
            
            # Replace the delete button section
            with col_actions:
                # Only show delete for own messages
                if is_own_message:
                    if st.button("🗑️", key=f"del_{idx}_{msg.get('message_id')}"):
                        if delete_message(msg.get('message_id')):
                            st.session_state.message_history = [
                                m for m in st.session_state.message_history 
                                if m.get('message_id') != msg.get('message_id')
                            ]
                            st.rerun()
    
    # Chat input
    if prompt := st.chat_input("🔐 Transmit secure message..."):
        if send_message(prompt):
            # Add to local history immediately
            st.session_state.message_history.append({
                "sender_id": DEVICE_ID,
                "message": prompt,
                "timestamp": datetime.now().isoformat(),
                "seen": False
            })
            st.rerun()
        else:
            st.error("Failed to send message")

    # --- PQC VISUALIZATION SECTION ---
    st.markdown("---")
    st.subheader("🔬 PQC Process Visualizer")
    
    tab1, tab2 = st.tabs(["🔑 Quantum Key Exchange", "✍️ Digital Signatures"])
    
    with tab1:
        st.markdown("**Kyber768 Key Encapsulation Mechanism**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("1️⃣ Start Handshake"):
                with st.spinner("Generating Kyber768 keypair..."):
                    res = post_request("/handshake/start", {"device_id": DEVICE_ID})
                    if "public_key" in res:
                        st.session_state["viz_pk"] = res.get("public_key")
                        st.success("✅ Public key generated")
            
            if "viz_pk" in st.session_state:
                st.info("📤 Public Key (send to other party):")
                st.code(st.session_state["viz_pk"][:100] + "...", language="text")
        
        with col2:
            ciphertext = st.text_area("2️⃣ Paste Ciphertext from other party:", key="ct_input")
            
            if st.button("3️⃣ Complete Handshake"):
                if ciphertext:
                    with st.spinner("Deriving shared secret..."):
                        res = post_request("/handshake/complete", {
                            "device_id": DEVICE_ID,
                            "ciphertext": ciphertext
                        })
                        if "shared_secret" in res:
                            st.success("✅ Handshake Complete!")
                            st.code(res["shared_secret"][:64] + "...", language="text")
                            st.info("🔐 This shared secret is now used for AES-256-GCM encryption")
                        else:
                            st.error(res.get("error", "Handshake failed"))
                else:
                    st.warning("Please enter ciphertext first")

    with tab2:
        st.markdown("**ML-DSA-65 (Dilithium) Digital Signatures**")
        
        msg_to_sign = st.text_input("Message to Sign:", "Mission Alpha Go", key="sign_msg")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("1️⃣ Generate Signature"):
                with st.spinner("Signing with ML-DSA-65..."):
                    res = post_request("/sign", {"message": msg_to_sign, "device_id": DEVICE_ID})
                    if "signature" in res:
                        st.session_state.viz_sig = res.get("signature")
                        st.session_state.viz_sig_pk = res.get("public_key")
                        st.success("✅ Signature generated")
            
            if "viz_sig" in st.session_state:
                st.info("📝 Signature:")
                st.code(st.session_state.viz_sig[:100] + "...", language="text")
                st.info("🔑 Public Key:")
                st.code(st.session_state.viz_sig_pk[:100] + "...", language="text")
        
        with col2:
            if st.button("2️⃣ Verify Signature"):
                if "viz_sig" in st.session_state:
                    with st.spinner("Verifying signature..."):
                        payload = {
                            "message": msg_to_sign,
                            "signature": st.session_state.get("viz_sig"),
                            "public_key": st.session_state.get("viz_sig_pk")
                        }
                        res = post_request("/verify", payload)
                        if res.get("verified"):
                            st.markdown("<p class='success'>✅ SIGNATURE VERIFIED</p>", unsafe_allow_html=True)
                            st.balloons()
                        else:
                            st.markdown("<p class='error'>❌ VERIFICATION FAILED</p>", unsafe_allow_html=True)
                else:
                    st.warning("Generate signature first")
    
    # --- SYSTEM METRICS ---
    st.markdown("---")
    with st.expander("📊 System Metrics"):
        metrics = get_request("/metrics")
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Active Sessions", metrics.get("active_sessions", 0))
        col2.metric("Total Messages", metrics.get("total_messages", 0))
        col3.metric("Events Logged", metrics.get("total_events", 0))
    
    # Auto-refresh every 3 seconds
    if time.time() - st.session_state.last_refresh > 1:
        st.session_state.last_refresh = time.time()
        
        # Check for new messages
        new_messages = fetch_new_messages()
        existing_ids = {msg.get('message_id') for msg in st.session_state.message_history}
        
        for msg in new_messages:
            if msg.get('message_id') not in existing_ids:
                st.session_state.message_history.append(msg)
                if msg.get('sender_id') != DEVICE_ID:
                    mark_message_seen(msg.get('message_id'))
        
        time.sleep(1.15)
        st.rerun()