import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

st.set_page_config(page_title="CryptoVault", layout="centered")

# Title and Description
st.title("CryptoVault")
st.subheader("Secure your data with RSA, AES, and DSA algorithms")
st.markdown("""
This app provides functionalities to:
- Generate RSA keys for encryption/decryption.
- Use AES for symmetric encryption/decryption.
- Utilize DSA for signing and verifying messages.
""")

with st.sidebar:
    st.header("Menu")
    mode = st.radio(
        "Choose operation:",
        ["Home", "RSA Encryption/Decryption", "AES Encryption/Decryption", "DSA Signing/Verification"]
    )

if mode == "Home":
    st.header("Welcome to the Encryption/Decryption App!")
    st.markdown("""
    Navigate through the sidebar to explore features:
    - **RSA**: Asymmetric encryption and decryption.
    - **AES**: Symmetric encryption and decryption.
    - **DSA**: Digital signing and verification.
    """)

# RSA Section
elif mode == "RSA Encryption/Decryption":
    st.header("RSA Encryption & Decryption")

    if st.button("Generate RSA Keys"):
        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        rsa_public_key = rsa_private_key.public_key()

        st.session_state['rsa_private_key'] = rsa_private_key
        st.session_state['rsa_public_key'] = rsa_public_key
        st.success("RSA keys generated successfully!")

    # Display RSA Keys
    if 'rsa_private_key' in st.session_state:
        private_pem = st.session_state['rsa_private_key'].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_pem = st.session_state['rsa_public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        st.text_area("RSA Private Key:", private_pem, height=200)
        st.text_area("RSA Public Key:", public_pem, height=200)

    # Encryption
    rsa_plaintext = st.text_area("Enter plaintext for RSA encryption:")
    if st.button("Encrypt with RSA"):
        if 'rsa_public_key' in st.session_state:
            ciphertext = st.session_state['rsa_public_key'].encrypt(
                rsa_plaintext.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            st.session_state['rsa_ciphertext'] = ciphertext
            st.success("Text encrypted successfully!")
            st.write("Ciphertext (hex):", ciphertext.hex())
        else:
            st.error("Generate RSA keys first!")

    # Decryption
    if st.button("Decrypt with RSA"):
        if 'rsa_private_key' in st.session_state and 'rsa_ciphertext' in st.session_state:
            plaintext = st.session_state['rsa_private_key'].decrypt(
                st.session_state['rsa_ciphertext'],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            st.success("Ciphertext decrypted successfully!")
            st.write("Decrypted Text:", plaintext.decode())
        else:
            st.error("Encrypt a message first!")

# AES Section
elif mode == "AES Encryption/Decryption":
    st.header("AES Encryption & Decryption")

    if 'aes_key' not in st.session_state: 
        if st.button("Generate AES Key"):
            aes_key = os.urandom(32)
            st.session_state['aes_key'] = aes_key
            st.success("AES key generated successfully!")
    
    if 'aes_key' in st.session_state:
        st.write("**AES Key (hex):**", st.session_state['aes_key'].hex())

    aes_plaintext = st.text_area("Enter plaintext for AES encryption:")

    if st.button("Encrypt using AES"):
        if 'aes_key' in st.session_state:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(st.session_state['aes_key']), modes.CFB(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(aes_plaintext.encode()) + encryptor.finalize()
            st.session_state['aes_ciphertext'] = (iv, ciphertext)
            st.success("Text encrypted successfully!")
            st.write("**Ciphertext (hex):**", ciphertext.hex())
            st.write("**Initialization Vector (IV):**", iv.hex())
        else:
            st.error("Please generate an AES key first!")

    if st.button("Decrypt using AES"):
        if 'aes_ciphertext' in st.session_state and 'aes_key' in st.session_state:
            iv, ciphertext = st.session_state['aes_ciphertext']
            cipher = Cipher(algorithms.AES(st.session_state['aes_key']), modes.CFB(iv))
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
            st.success("Ciphertext decrypted successfully!")
            st.write("**Decrypted Text:**", decrypted_text.decode())
        else:
            st.error("Please encrypt a message first!")


# DSA Section
elif mode == "DSA Signing/Verification":
    st.header("DSA Signing & Verification")

    if st.button("Generate DSA Keys"):
        dsa_private_key = dsa.generate_private_key(key_size=2048)
        dsa_public_key = dsa_private_key.public_key()

        st.session_state['dsa_private_key'] = dsa_private_key
        st.session_state['dsa_public_key'] = dsa_public_key
        st.success("DSA keys generated successfully!")

    # Display DSA Keys
    if 'dsa_private_key' in st.session_state:
        private_pem = st.session_state['dsa_private_key'].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_pem = st.session_state['dsa_public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        st.text_area("DSA Private Key:", private_pem, height=200)
        st.text_area("DSA Public Key:", public_pem, height=200)

    # Signing
    dsa_message = st.text_area("Enter message for signing:")
    if st.button("Sign with DSA"):
        if 'dsa_private_key' in st.session_state:
            signature = st.session_state['dsa_private_key'].sign(
                dsa_message.encode(),
                hashes.SHA256()
            )
            st.session_state['dsa_signature'] = signature
            st.success("Message signed successfully!")
            st.write("Signature (hex):", signature.hex())
        else:
            st.error("Generate DSA keys first!")

    # Verification
    dsa_signature_input = st.text_area("Enter signature (hex) for verification:")
    if st.button("Verify with DSA"):
        if 'dsa_public_key' in st.session_state:
            try:
                st.session_state['dsa_public_key'].verify(
                    bytes.fromhex(dsa_signature_input),
                    dsa_message.encode(),
                    hashes.SHA256()
                )
                st.success("Signature is valid!")
            except Exception as e:
                st.error(f"Invalid signature: {e}")
        else:
            st.error("Generate DSA keys first!")
