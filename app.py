import streamlit as st
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
def generate_key(password, salt):
    """Generate a cryptographic key from a password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_message(message, key):
    """Encrypt a message using Fernet symmetric encryption."""
    try:
        f = Fernet(key)
        encrypted_message = f.encrypt(message.encode())
        return encrypted_message.decode()
    except Exception as e:
        return f"Encryption Error: {str(e)}"

def decrypt_message(encrypted_message, key):
    """Decrypt a message using Fernet symmetric encryption."""
    try:
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message.encode())
        return decrypted_message.decode()
    except Exception as e:
        return f"Decryption Error: {str(e)}"
def main():
    st.set_page_config(page_title="CryptVault", page_icon="🔐")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Encryption")
        encrypt_message_input = st.text_input("Message", key="encrypt_msg")
        
        encryption_types = ["AES", "DSA", "RSA"]
        encrypt_type = st.selectbox("Encryption Type", encryption_types, key="encrypt_type")
        
        encrypt_key = st.text_input("Encryption Key", type="password", key="encrypt_key")
        
        if st.button("Encrypt", key="encrypt_button"):
            if encrypt_message_input and encrypt_key:
                salt = b'cryptvault_salt'
                derived_key = generate_key(encrypt_key, salt)
                
                encrypted_result = encrypt_message(encrypt_message_input, derived_key)
                st.text_area("Encrypted Result", value=encrypted_result, height=100, disabled=True)
            else:
                st.error("Please provide a message and encryption key")
    with col2:
        st.subheader("Decryption")
        decrypt_message_input = st.text_input("Encrypted Message", key="decrypt_msg")
        
        decryption_types = ["AES", "DSA", "RSA"]
        decrypt_type = st.selectbox("Decryption Type", decryption_types, key="decrypt_type")
        
        decrypt_key = st.text_input("Decryption Key", type="password", key="decrypt_key")
        
        if st.button("Decrypt", key="decrypt_button"):
            if decrypt_message_input and decrypt_key:
                salt = b'cryptvault_salt'
                derived_key = generate_key(decrypt_key, salt)
                
                decrypted_result = decrypt_message(decrypt_message_input, derived_key)
                st.text_area("Decrypted Result", value=decrypted_result, height=100, disabled=True)
            else:
                st.error("Please provide an encrypted message and decryption key")
    
    st.markdown("---")
    st.markdown("<p style='text-align: center;'>© 2024 SAMCIS SLU</p>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()