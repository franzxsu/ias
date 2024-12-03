import streamlit as st
from crypto_utils import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt, rsa_key_pair, rsa_encrypt, rsa_decrypt
import os
from binascii import hexlify, unhexlify

st.set_page_config(page_title="CryptoVault", layout="centered")

# Header
st.title("CryptoVault: Encryption and Decryption")
st.write("Select an encryption method and enter your inputs.")

# Encryption and Decryption Type Selection
encryption_type = st.radio("Choose Encryption Type", ("AES", "DES", "RSA"))

# Message Input
message = st.text_input("Enter the message", placeholder="Type your message here")

# AES or DES Key Input
key = None
if encryption_type in ["AES", "DES"]:
    key = st.text_input(
        f"Enter a {32 if encryption_type == 'AES' else 24}-character key",
        max_chars=(32 if encryption_type == "AES" else 24),
    )

# RSA Key Pair
rsa_private_key, rsa_public_key = None, None
if encryption_type == "RSA":
    if st.button("Generate RSA Keys"):
        rsa_private_key, rsa_public_key = rsa_key_pair()
        st.success("RSA Keys generated successfully.")
        st.write("**Public Key:**", rsa_public_key.export_key().decode())
        st.write("**Private Key:**", rsa_private_key.export_key().decode())

# Encrypt and Decrypt Buttons
if st.button("Encrypt"):
    if encryption_type == "AES" and message and key:
        iv, ciphertext = aes_encrypt(message, key.encode())
        st.text_area("Encrypted Message", value=hexlify(ciphertext).decode(), height=100)
    elif encryption_type == "DES" and message and key:
        iv, ciphertext = des_encrypt(message, key.encode())
        st.text_area("Encrypted Message", value=hexlify(ciphertext).decode(), height=100)
    elif encryption_type == "RSA" and message and rsa_public_key:
        ciphertext = rsa_encrypt(message, rsa_public_key)
        st.text_area("Encrypted Message", value=hexlify(ciphertext).decode(), height=100)
    else:
        st.error("Please provide all required inputs!")

if st.button("Decrypt"):
    if encryption_type == "AES" and message and key:
        ciphertext = unhexlify(st.text_input("Enter Encrypted Message (hex)", ""))
        iv = os.urandom(16)  # Replace with saved IV in practice
        plaintext = aes_decrypt(iv, ciphertext, key.encode())
        st.text_area("Decrypted Message", value=plaintext, height=100)
    elif encryption_type == "DES" and message and key:
        ciphertext = unhexlify(st.text_input("Enter Encrypted Message (hex)", ""))
        iv = os.urandom(8)  # Replace with saved IV in practice
        plaintext = des_decrypt(iv, ciphertext, key.encode())
        st.text_area("Decrypted Message", value=plaintext, height=100)
    elif encryption_type == "RSA" and message and rsa_private_key:
        ciphertext = unhexlify(st.text_input("Enter Encrypted Message (hex)", ""))
        plaintext = rsa_decrypt(ciphertext, rsa_private_key)
        st.text_area("Decrypted Message", value=plaintext, height=100)
    else:
        st.error("Please provide all required inputs!")
