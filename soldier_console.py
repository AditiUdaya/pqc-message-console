import streamlit as st
import requests
import time
import json
from datetime import datetime

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
    .st-emotion-cache-1avcm0n, .st-emotion-cache-k7vsyb p { color: #00FF41 !important; }
    .seen-tick { color: #00BFFF; font-size: 0.8em; }
    .unseen-tick { color: #666; font-size: 0.8em; }
    hr { border-color: #00FF41; }
    </style>
""", unsafe_allow_html=True)

# ==============================
# SESSION STATE & HELPERS
# ==============================
if 'soldier_connected' not in st.session_state:
    st.session_state.soldier_connected = False
if 'message_history' not in st.session_state:
    st.session_state.message_history = []
if 'hq_status' not in st.session_state:
    st.session_state.hq_status = "Offline"
if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = time.time()

def post_request(endpoint, payload):
    try:
        return requests.post(f"{BACKEND_URL}{endpoint}", json=payload, timeout=5).json()
    except requests.RequestException as e:
        return {"error": f"Connection failed: {str(e)}"}

def get_request(endpoint):
    try:
        return requests.get(f"{BACKEND_URL}{endpoint}", timeout=5).json()
    except requests.RequestException:
        return {"error": "Connection failed"}

def fetch_new_messages():
    response = post_request("/receive", {"receiver_id": DEVICE_ID})
    if response.get("status") == "success":
        return response.get("messages", [])
    return []

def send_message(message_text):
    response = post_request("/send", {
        "sender_id": DEVICE_ID,
        "receiver_id": COUNTERPART_ID,
        "message": message_text
    })
    return response.get("status") == "success"

def mark_message_seen(message_id):
    post_request("/mark_seen", {
        "message_id": message_id,
        "receiver_id": DEVICE_ID
    })

def delete_message(message_id):
    response = post_request("/delete_message", {
        "message_id": message_id,
        "user_id": DEVICE_ID
    })
    return response.get("status") == "success"

# ==============================
# MAIN APPLICATION
# ==============================
st.title("🪖 SOLDIER FIELD TERMINAL")
st.markdown("---")

if not st.session_state.soldier_connected:
    if st.button("🔐 Connect SOLDIER-001 to HQ Network"):
        with st.spinner("Establishing secure connection..."):
            res = post_request("/connect", {"device_id": DEVICE_ID})
            if res.get("status") == "OK":
                st.session_state.soldier_connected = True
                st.success("✅ Connected to HQ secure network")
                time.sleep(1)
                st.rerun()
            else:
                st.error(f"❌ {res.get('message') or res.get('error')}")
    st.info("🔒 Terminal offline. Connect to HQ network.")
else:
    # --- STATUS DASHBOARD ---
    col1, col2, col3 = st.columns(3)
    
    status_data = get_request("/status")
    
    col1.metric("🪖 Soldier Status", "Connected", delta="Active")
    col2.metric("🔐 Encryption", status_data.get("Encryption", "N/A"))
    ##col3.metric("📡 HQ Status", "Online" if status_data.get("active_sessions", 0) >= 2 else "Waiting...")
    
    st.markdown("---")
    
    # --- SECURE COMMS CHANNEL ---
    st.subheader("🔐 Secure Comms to HQ")
    st.caption(f"Encrypted with {status_data.get('Encryption', 'AES-256-GCM')} + Quantum-resistant signatures")
    
    # Fetch new messages
    new_messages = fetch_new_messages()
    
    # Update history
    existing_ids = {msg.get('message_id') for msg in st.session_state.message_history}
    for msg in new_messages:
        if msg.get('message_id') not in existing_ids:
            st.session_state.message_history.append(msg)
            if msg.get('sender_id') != DEVICE_ID:
                mark_message_seen(msg.get('message_id'))
    
    # Display messages
    for idx, msg in enumerate(st.session_state.message_history):
        is_own_message = msg.get("sender_id") == DEVICE_ID
        
        with st.chat_message("user" if is_own_message else "assistant"):
            col_msg, col_actions = st.columns([4, 1])
            
            with col_msg:
                st.write(msg.get("message", ""))
                
                if "encrypted_data" in msg:
                    with st.expander("🔒 View Encrypted"):
                        st.code(json.dumps(msg["encrypted_data"], indent=2), language="json")
                
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
    if prompt := st.chat_input("🔐 Send encrypted message to HQ..."):
        if send_message(prompt):
            st.session_state.message_history.append({
                "sender_id": DEVICE_ID,
                "message": prompt,
                "timestamp": datetime.now().isoformat(),
                "seen": False
            })
            st.rerun()
        else:
            st.error("Failed to send message")
    
    # --- SYSTEM INFO ---
    st.markdown("---")
    with st.expander("📊 System Info"):
        metrics = get_request("/metrics")
        
        col1, col2 = st.columns(2)
        col1.metric("Messages Sent", metrics.get("total_messages", 0))
        col2.metric("Active Connections", metrics.get("active_sessions", 0))
        
        st.caption(f"🔐 Encryption: {status_data.get('Encryption')}")
        st.caption(f"✍️ Signature: {status_data.get('Signature')}")
    
    # Auto-refresh
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