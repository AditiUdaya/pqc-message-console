#!/usr/bin/env python3
"""
PQC Hackathon Dependencies Test Script
Run this to verify all packages are installed correctly
"""

import sys
from typing import Tuple

def test_import(module_name: str, display_name: str = None) -> Tuple[bool, str]:
    """Test if a module can be imported"""
    if display_name is None:
        display_name = module_name
    
    try:
        mod = __import__(module_name)
        version = getattr(mod, '__version__', 'version unknown')
        return True, f"✅ {display_name}: {version}"
    except ImportError as e:
        return False, f"❌ {display_name}: NOT INSTALLED ({str(e)})"
    except Exception as e:
        return False, f"⚠️  {display_name}: ERROR ({str(e)})"

def test_oqs():
    """Test liboqs-python with actual PQC operations"""
    try:
        import oqs
        
        # Test KEM (Kyber)
        kem = oqs.KeyEncapsulation("Kyber512")
        public_key = kem.generate_keypair()
        ciphertext, shared_secret_client = kem.encap_secret(public_key)
        shared_secret_server = kem.decap_secret(ciphertext)
        
        assert shared_secret_client == shared_secret_server, "KEM key agreement failed"
        
        # Test Signature (Dilithium)
        sig = oqs.Signature("Dilithium2")
        public_key_sig = sig.generate_keypair()
        message = b"Test message for PQC"
        signature = sig.sign(message)
        is_valid = sig.verify(message, signature, public_key_sig)
        
        assert is_valid, "Signature verification failed"
        
        kems = oqs.get_enabled_kem_mechanisms()
        sigs = oqs.get_enabled_sig_mechanisms()
        
        return True, f"✅ liboqs-python: WORKING\n   └─ KEMs available: {len(kems)} (Kyber ✓)\n   └─ Signatures available: {len(sigs)} (Dilithium ✓)"
    
    except ImportError:
        return False, "❌ liboqs-python: NOT INSTALLED"
    except Exception as e:
        return False, f"⚠️  liboqs-python: ERROR - {str(e)}"

def test_pycryptodome():
    """Test PyCryptodome with AES-GCM"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        
        # Test AES-GCM encryption
        key = get_random_bytes(32)  # AES-256
        cipher = AES.new(key, AES.MODE_GCM)
        plaintext = b"Military communication test"
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Test decryption
        cipher_dec = AES.new(key, AES.MODE_GCM, nonce=cipher.nonce)
        decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)
        
        assert decrypted == plaintext, "AES-GCM encryption/decryption failed"
        
        from Crypto import __version__
        return True, f"✅ PyCryptodome: {__version__} (AES-GCM ✓)"
    
    except ImportError:
        return False, "❌ PyCryptodome: NOT INSTALLED"
    except Exception as e:
        return False, f"⚠️  PyCryptodome: ERROR - {str(e)}"

def test_scapy():
    """Test Scapy packet creation"""
    try:
        from scapy.all import IP, TCP, Raw, Ether
        
        # Create a test packet
        packet = IP(dst="192.168.1.1")/TCP(dport=443)/Raw(load=b"PQC payload")
        
        assert packet.haslayer(IP), "IP layer not found"
        assert packet.haslayer(TCP), "TCP layer not found"
        
        from scapy import VERSION
        return True, f"✅ Scapy: {VERSION} (Packet crafting ✓)"
    
    except ImportError:
        return False, "❌ Scapy: NOT INSTALLED"
    except Exception as e:
        return False, f"⚠️  Scapy: ERROR - {str(e)}"

def test_sha3():
    """Test SHA-3 hashing"""
    try:
        import hashlib
        
        # Test SHA3-256
        data = b"Quantum-resistant hash test"
        hash_obj = hashlib.sha3_256(data)
        digest = hash_obj.hexdigest()
        
        assert len(digest) == 64, "SHA3-256 hash length incorrect"
        
        return True, "✅ SHA-3: Available (hashlib built-in)"
    
    except AttributeError:
        return False, "⚠️  SHA-3: Not available (Python version too old)"
    except Exception as e:
        return False, f"⚠️  SHA-3: ERROR - {str(e)}"

def main():
    print("=" * 60)
    print("🔐 PQC HACKATHON DEPENDENCIES TEST")
    print("=" * 60)
    print()
    
    all_passed = True
    
    # Core PQC Libraries
    print("📦 CORE PQC LIBRARIES:")
    success, msg = test_oqs()
    print(msg)
    all_passed &= success
    
    success, msg = test_pycryptodome()
    print(msg)
    all_passed &= success
    
    success, msg = test_sha3()
    print(msg)
    all_passed &= success
    print()
    
    # Network & Packet Tools
    print("🌐 NETWORK & PACKET TOOLS:")
    success, msg = test_scapy()
    print(msg)
    all_passed &= success
    
    success, msg = test_import('niquests')
    print(msg)
    all_passed &= success
    print()
    
    # Web Frameworks
    print("🖥️  WEB FRAMEWORKS:")
    success, msg = test_import('flask', 'Flask')
    print(msg)
    all_passed &= success
    
    success, msg = test_import('streamlit', 'Streamlit')
    print(msg)
    all_passed &= success
    
    success, msg = test_import('gradio', 'Gradio')
    print(msg)
    all_passed &= success
    print()
    
    # Data Science & Visualization
    print("📊 DATA & VISUALIZATION:")
    for module in ['numpy', 'pandas', 'matplotlib', 'plotly', 'networkx']:
        success, msg = test_import(module, module.capitalize())
        print(msg)
        all_passed &= success
    print()
    
    # Summary
    print("=" * 60)
    if all_passed:
        print("✅ ALL TESTS PASSED! You're ready for the hackathon! 🚀")
    else:
        print("⚠️  SOME TESTS FAILED - Check errors above")
        print("\nTo fix missing packages:")
        print("  conda install <package>  OR  pip install <package>")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())