import oqs
import base64
import requests

device_id = "soldier-001"

# Step 1: Start handshake, get HQ public key
start_resp = requests.post("http://127.0.0.1:5001/handshake/start",
                           json={"device_id": device_id}).json()

hq_pub_b64 = start_resp["public_key"]
hq_pub = base64.b64decode(hq_pub_b64)

# Step 2: Create client KEM and encapsulate
client_kem = oqs.KeyEncapsulation("Kyber768")
ciphertext, shared_secret = client_kem.encap_secret(hq_pub)

ciphertext_b64 = base64.b64encode(ciphertext).decode()
shared_secret_b64 = base64.b64encode(shared_secret).decode()

print("Ciphertext (send to HQ):", ciphertext_b64)
print("Shared secret (client side):", shared_secret_b64)

# Step 3: Complete handshake by sending ciphertext to HQ
complete_resp = requests.post("http://127.0.0.1:5001/handshake/complete",
                              json={"device_id": device_id,
                                    "ciphertext": ciphertext_b64}).json()

print("Handshake complete response:", complete_resp)
