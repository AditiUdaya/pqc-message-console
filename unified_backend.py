from flask import Flask, request, jsonify
from flask_cors import CORS
import oqs
import base64
import os
import redis
from datetime import datetime, timedelta
from dotenv import load_dotenv
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import uuid

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# ===== Configuration =====
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
AUTHORIZED_DEVICES = {"soldier-001", "hq-001", "drone-001"}
KEM_ALGO = "Kyber768"
SIG_ALGO = "ML-DSA-65"

# Redis connection
try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=False,  # Keep as bytes for encryption
        socket_connect_timeout=5
    )
    redis_client.ping()
    print(f"✅ Redis connected at {REDIS_HOST}:{REDIS_PORT}")
except Exception as e:
    print(f"⚠️  Redis connection failed: {e}")
    redis_client = None

# Log file
LOG_FILE = os.path.expanduser("~/pqc_logs/verified.txt")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# In-memory fallback
kem_sessions = {}
##device_signatures = {}  # Store device signing keys

# ===== Encryption Helpers =====
def derive_aes_key(shared_secret, context=b"message_encryption"):
    """Derive AES-256 key from shared secret using HKDF-like approach"""
    return hashlib.sha3_256(shared_secret + context).digest()

def encrypt_message(plaintext, shared_secret):
    """Encrypt message with AES-256-GCM"""
    key = derive_aes_key(shared_secret)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode()
    }

def decrypt_message(encrypted_data, shared_secret):
    """Decrypt message with AES-256-GCM"""
    key = derive_aes_key(shared_secret)
    cipher = AES.new(
        key, 
        AES.MODE_GCM, 
        nonce=base64.b64decode(encrypted_data['nonce'])
    )
    
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    tag = base64.b64decode(encrypted_data['tag'])
    
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# ===== Redis Message Storage =====
def store_message(sender_id, receiver_id, message_data):
    """Store message in Redis with metadata"""
    if not redis_client:
        return None
    
    message_id = str(uuid.uuid4())
    message_key = f"message:{message_id}"
    inbox_key = f"inbox:{receiver_id}"
    
    message_data['message_id'] = message_id
    message_data['timestamp'] = datetime.now().isoformat()
    message_data['seen'] = False
    message_data['deleted_by'] = []
    
    try:
        # Store message data
        redis_client.set(message_key, json.dumps(message_data).encode())
        redis_client.expire(message_key, 86400)  # 24 hour TTL
        
        # Add to receiver's inbox
        redis_client.lpush(inbox_key, message_id)
        
        # Log event
        log_event("MESSAGE_SENT", sender_id, f"To {receiver_id}")
        
        return message_id
    except Exception as e:
        print(f"⚠️  Failed to store message: {e}")
        return None

def get_messages(receiver_id):
    """Get all messages for a receiver"""
    if not redis_client:
        return []
    
    try:
        inbox_key = f"inbox:{receiver_id}"
        message_ids = redis_client.lrange(inbox_key, 0, -1)
        
        messages = []
        for msg_id in message_ids:
            msg_key = f"message:{msg_id.decode()}"
            msg_data = redis_client.get(msg_key)
            if msg_data:
                message = json.loads(msg_data.decode())
                # Check if deleted by this user
                if receiver_id not in message.get('deleted_by', []):
                    messages.append(message)
        
        return messages
    except Exception as e:
        print(f"⚠️  Failed to retrieve messages: {e}")
        return []

def mark_message_seen(message_id, receiver_id):
    """Mark message as seen"""
    if not redis_client:
        return False
    
    try:
        msg_key = f"message:{message_id}"
        msg_data = redis_client.get(msg_key)
        if msg_data:
            message = json.loads(msg_data.decode())
            message['seen'] = True
            message['seen_at'] = datetime.now().isoformat()
            redis_client.set(msg_key, json.dumps(message).encode())
            
            # Publish event for real-time updates
            publish_mesh_event("MESSAGE_SEEN", receiver_id, {
                "message_id": message_id,
                "sender_id": message.get('sender_id')
            })
            return True
    except Exception as e:
        print(f"⚠️  Failed to mark seen: {e}")
    return False

def delete_message(message_id, user_id):
    """Delete message - only sender can delete"""
    if not redis_client:
        return False
    
    try:
        msg_key = f"message:{message_id}"
        msg_data = redis_client.get(msg_key)
        if msg_data:
            message = json.loads(msg_data.decode())
            sender_id = message.get('sender_id')
            
            # Only sender can delete
            if sender_id != user_id:
                return False
            
            receiver_id = message.get('receiver_id')
            
            # Remove from both inboxes
            redis_client.lrem(f"inbox:{sender_id}", 0, message_id.encode())
            redis_client.lrem(f"inbox:{receiver_id}", 0, message_id.encode())
            
            # Delete the message
            redis_client.delete(msg_key)
            
            # Publish delete event
            publish_mesh_event("MESSAGE_DELETED", user_id, {
                "message_id": message_id,
                "sender_id": sender_id,
                "receiver_id": receiver_id
            })
            
            log_event("MESSAGE_DELETED", user_id, f"Message: {message_id}")
            return True
    except Exception as e:
        print(f"⚠️  Failed to delete message: {e}")
    return False

# ===== Session Management =====
def cache_session_key(device_id, shared_secret, ttl_seconds=300):
    """Store session key in Redis with TTL"""
    if redis_client:
        try:
            session_id = f"session:{device_id}"
            redis_client.setex(
                session_id,
                ttl_seconds,
                shared_secret
            )
            print(f"🔑 Session key cached for {device_id} (TTL: {ttl_seconds}s)")
            return True
        except Exception as e:
            print(f"⚠️  Failed to cache session: {e}")
    return False

def get_session_key(device_id):
    """Retrieve session key from Redis"""
    if redis_client:
        try:
            session_id = f"session:{device_id}"
            cached_key = redis_client.get(session_id)
            if cached_key:
                print(f"✅ Session key found in cache for {device_id}")
                return cached_key
            # Remove or comment out this line:
            # else:
            #     print(f"❌ No cached session for {device_id}")
        except Exception as e:
            print(f"⚠️  Failed to retrieve session: {e}")
    return None

def log_event(event_type, device_id, details=""):
    """Log events to Redis and file"""
    timestamp = datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "event": event_type,
        "device_id": device_id,
        "details": details
    }
    
    if redis_client:
        try:
            redis_client.lpush("events:log", json.dumps(log_entry).encode())
            redis_client.ltrim("events:log", 0, 99)
        except Exception as e:
            print(f"⚠️  Failed to log to Redis: {e}")
    
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} - {event_type} - {device_id} - {details}\n")

def publish_mesh_event(event_type, device_id, data=None):
    """Publish mesh network events via Redis Pub/Sub"""
    if redis_client:
        try:
            event = {
                "type": event_type,
                "device_id": device_id,
                "timestamp": datetime.now().isoformat(),
                "data": data or {}
            }
            redis_client.publish("mesh:events", json.dumps(event).encode())
            print(f"📡 Published {event_type} for {device_id}")
        except Exception as e:
            print(f"⚠️  Failed to publish event: {e}")

# ===== Health & Status =====
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": "PQC Military Communication System",
        "status": "operational",
        "redis": "connected" if redis_client else "unavailable",
        "endpoints": {
            "health": "/health",
            "connect": "/connect",
            "status": "/status",
            "handshake_start": "/handshake/start",
            "handshake_complete": "/handshake/complete",
            "sign": "/sign",
            "verify": "/verify",
            "send": "/send",
            "receive": "/receive",
            "mark_seen": "/mark_seen",
            "delete_message": "/delete_message",
            "metrics": "/metrics",
            "events": "/events"
        }
    })

@app.route("/health", methods=["GET"])
def health():
    """Docker health check endpoint"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }
    
    if redis_client:
        try:
            redis_client.ping()
            health_status["redis"] = "connected"
        except:
            health_status["redis"] = "disconnected"
            health_status["status"] = "degraded"
    else:
        health_status["redis"] = "unavailable"
        health_status["status"] = "degraded"
    
    try:
        health_status["pqc_kems"] = len(oqs.get_enabled_KEM_mechanisms())
        health_status["pqc_sigs"] = len(oqs.get_enabled_sig_mechanisms())
    except:
        health_status["pqc"] = "unavailable"
        health_status["status"] = "unhealthy"
    
    status_code = 200 if health_status["status"] == "healthy" else 503
    return jsonify(health_status), status_code

@app.route("/status", methods=["GET"])
def status():
    """Get system status and active sessions"""
    active_sessions = 0
    if redis_client:
        try:
            keys = [k for k in redis_client.scan_iter(b"session:*")]
            active_sessions = len(keys)
        except:
            pass
    else:
        active_sessions = len(kem_sessions)
    
    return jsonify({
        "KEM": KEM_ALGO,
        "Signature": SIG_ALGO,
        "Encryption": "AES-GCM-256",
        "Status": "Secure and operational",
        "active_sessions": active_sessions,
        "authorized_devices": len(AUTHORIZED_DEVICES)
    })

@app.route("/metrics", methods=["GET"])
def metrics():
    """Get system metrics from Redis"""
    metrics_data = {
        "timestamp": datetime.now().isoformat(),
        "active_sessions": 0,
        "total_events": 0,
        "total_messages": 0
    }
    
    if redis_client:
        try:
            session_keys = [k for k in redis_client.scan_iter(b"session:*")]
            metrics_data["active_sessions"] = len(session_keys)
            metrics_data["total_events"] = redis_client.llen("events:log")
            
            # Count messages across all inboxes
            for device in AUTHORIZED_DEVICES:
                inbox_key = f"inbox:{device}"
                metrics_data["total_messages"] += redis_client.llen(inbox_key)
        except Exception as e:
            metrics_data["error"] = str(e)
    
    return jsonify(metrics_data)

@app.route("/events", methods=["GET"])
def get_events():
    """Get recent events from Redis"""
    events = []
    
    if redis_client:
        try:
            event_logs = redis_client.lrange("events:log", 0, 19)
            events = [json.loads(e.decode()) for e in event_logs]
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify({"events": events, "count": len(events)})

# ===== Device Connection =====
@app.route("/connect", methods=["POST"])
def connect():
    data = request.get_json()
    device_id = data.get("device_id")

    if device_id in AUTHORIZED_DEVICES:
        # Create KEM session for this device
        kem = oqs.KeyEncapsulation(KEM_ALGO)
        kem.generate_keypair()
        kem_sessions[device_id] = kem
        
        print(f"✅ Device {device_id} connected")
        log_event("DEVICE_CONNECTED", device_id)
        publish_mesh_event("NODE_JOIN", device_id)
        
        return jsonify({
            "status": "OK",
            "message": f"Device {device_id} connected.",
            "device_id": device_id
        }), 200
    else:
        print(f"❌ Unauthorized device: {device_id}")
        log_event("AUTH_FAILED", device_id, "Unauthorized")
        
        return jsonify({
            "status": "FAIL",
            "message": "Unauthorized device."
        }), 403

# ===== KEM Handshake =====
@app.route("/handshake/start", methods=["POST"])
def handshake_start():
    data = request.get_json()
    device_id = data.get("device_id")

    kem = oqs.KeyEncapsulation(KEM_ALGO)
    public_key = kem.generate_keypair()

    # Store KEM instance temporarily
    kem_sessions[f"viz_{device_id}"] = kem

    print(f"🔑 Handshake started for {device_id}")
    log_event("HANDSHAKE_START", device_id, f"Algorithm: {KEM_ALGO}")
    
    return jsonify({
        "algorithm": KEM_ALGO,
        "public_key": base64.b64encode(public_key).decode(),
        "device_id": device_id
    })

@app.route("/handshake/complete", methods=["POST"])
def handshake_complete():
    data = request.get_json()
    device_id = data.get("device_id")
    ciphertext_b64 = data.get("ciphertext")

    kem = kem_sessions.get(f"viz_{device_id}")
    if not kem:
        return jsonify({"error": "No active session"}), 400

    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        shared_secret = kem.decap_secret(ciphertext)

        # Cache the shared secret in Redis
        cache_session_key(device_id, shared_secret, ttl_seconds=300)

        print(f"✅ Handshake completed for {device_id}")
        log_event("HANDSHAKE_COMPLETE", device_id, "Session key established")
        
        del kem_sessions[f"viz_{device_id}"]

        return jsonify({
            "status": "OK",
            "shared_secret": base64.b64encode(shared_secret).decode(),
            "device_id": device_id,
            "cached": redis_client is not None
        })
    except Exception as e:
        log_event("HANDSHAKE_FAILED", device_id, str(e))
        return jsonify({"error": f"Handshake failed: {str(e)}"}), 400

# ===== Digital Signatures (for visualization) =====
@app.route("/sign", methods=["POST"])
def sign_message():
    try:
        data = request.get_json()
        if not data or "message" not in data:
            return jsonify({"error": "Missing 'message' field"}), 400

        message = data["message"].encode()
        device_id = data.get("device_id", "unknown")

        sig = oqs.Signature(SIG_ALGO)
        public_key = sig.generate_keypair()
        signature = sig.sign(message)

        print(f"✍️  Signed message: '{data['message']}'")
        log_event("MESSAGE_SIGNED", device_id, f"Message: {data['message']}")
        
        return jsonify({
            "signature": base64.b64encode(signature).decode(),
            "public_key": base64.b64encode(public_key).decode(),
            "algorithm": SIG_ALGO,
            "device_id": device_id
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/verify", methods=["POST"])
def verify_signature():
    try:
        data = request.get_json()
        
        required = ["message", "signature", "public_key"]
        if not all(k in data for k in required):
            return jsonify({"error": "Missing required fields"}), 400

        message = data["message"].encode()
        signature = base64.b64decode(data["signature"])
        public_key = base64.b64decode(data["public_key"])
        device_id = data.get("device_id", "unknown")

        sig = oqs.Signature(SIG_ALGO)
        verified = sig.verify(message, signature, public_key)

        if verified:
            print(f"✅ Signature verified: '{data['message']}'")
            log_event("SIGNATURE_VERIFIED", device_id, f"Message: {data['message']}")
            
            return jsonify({
                "status": "success",
                "verified": True,
                "message": "Signature verified!",
                "device_id": device_id
            }), 200
        else:
            print(f"❌ Signature verification failed")
            log_event("SIGNATURE_FAILED", device_id, f"Message: {data['message']}")
            
            return jsonify({
                "status": "failure",
                "verified": False,
                "message": "Signature verification failed"
            }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===== Secure Messaging with AES-256-GCM =====
@app.route("/send", methods=["POST"])
def send_message():
    """Send encrypted and signed message"""
    try:
        data = request.get_json()
        sender_id = data.get("sender_id")
        receiver_id = data.get("receiver_id")
        message_text = data.get("message")
        
        if not all([sender_id, receiver_id, message_text]):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Create signature for this message
        sig = oqs.Signature(SIG_ALGO)
        public_key = sig.generate_keypair()  # Returns public key
        signature = sig.sign(message_text.encode())
        
        # Get session key for encryption
        session_key = get_session_key(sender_id)
        if not session_key:
            # Use a derived key from device IDs (for demo)
            session_key = hashlib.sha3_256(f"{sender_id}{receiver_id}".encode()).digest()
        
        # Encrypt message with AES-256-GCM
        encrypted = encrypt_message(message_text, session_key)
        
        # Create message bundle
        message_bundle = {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "plaintext": message_text,
            "encrypted": encrypted,
            "signature": base64.b64encode(signature).decode(),
            "public_key": base64.b64encode(public_key).decode(),
            "encryption_algo": "AES-256-GCM",
            "signature_algo": SIG_ALGO
        }
        
        # Store message
        message_id = store_message(sender_id, receiver_id, message_bundle)
        
        # Publish real-time event
        publish_mesh_event("NEW_MESSAGE", receiver_id, {
            "sender_id": sender_id,
            "message_id": message_id
        })
        
        print(f"📨 Message sent from {sender_id} to {receiver_id}")
        
        return jsonify({
            "status": "success",
            "message": "Message sent successfully",
            "message_id": message_id
        }), 200
        
    except Exception as e:
        print(f"❌ Send message error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/receive", methods=["POST"])
def receive_messages():
    """Receive and verify messages"""
    try:
        receiver_id = request.get_json().get("receiver_id")
        if not receiver_id:
            return jsonify({"error": "Missing 'receiver_id'"}), 400
        
        # Get all messages for receiver
        messages = get_messages(receiver_id)
        
        # Verify signatures and decrypt
        verified_messages = []
        sig = oqs.Signature(SIG_ALGO)
        
        for msg in messages:
            try:
                # Verify signature
                is_verified = sig.verify(
                    msg["plaintext"].encode(),
                    base64.b64decode(msg["signature"]),
                    base64.b64decode(msg["public_key"])
                )
                
                if is_verified:
                    verified_messages.append({
                        "message_id": msg["message_id"],
                        "sender_id": msg["sender_id"],
                        "message": msg["plaintext"],
                        "timestamp": msg["timestamp"],
                        "seen": msg.get("seen", False),
                        "encrypted_data": msg["encrypted"]  # Include for display
                    })
            except Exception as e:
                print(f"⚠️  Failed to verify message: {e}")
        
        return jsonify({
            "status": "success",
            "messages": verified_messages
        }), 200
        
    except Exception as e:
        print(f"❌ Receive messages error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/mark_seen", methods=["POST"])
def mark_seen():
    """Mark message as seen"""
    try:
        data = request.get_json()
        message_id = data.get("message_id")
        receiver_id = data.get("receiver_id")
        
        if not all([message_id, receiver_id]):
            return jsonify({"error": "Missing required fields"}), 400
        
        success = mark_message_seen(message_id, receiver_id)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "Message marked as seen"
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to mark message as seen"
            }), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/delete_message", methods=["POST"])
def delete_message_endpoint():
    """Delete message for a user"""
    try:
        data = request.get_json()
        message_id = data.get("message_id")
        user_id = data.get("user_id")
        
        if not all([message_id, user_id]):
            return jsonify({"error": "Missing required fields"}), 400
        
        success = delete_message(message_id, user_id)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "Message deleted"
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to delete message"
            }), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("=" * 60)
    print("🔐 PQC MILITARY COMMUNICATION SYSTEM")
    print("=" * 60)
    print(f"KEM Algorithm: {KEM_ALGO}")
    print(f"Signature Algorithm: {SIG_ALGO}")
    print(f"Encryption: AES-256-GCM")
    print(f"Authorized Devices: {', '.join(AUTHORIZED_DEVICES)}")
    print(f"Redis: {REDIS_HOST}:{REDIS_PORT}")
    print("=" * 60)
    print("🚀 Server starting on http://0.0.0.0:5000")
    print("=" * 60)
    
    app.run(host="0.0.0.0", port=5000, debug=True)