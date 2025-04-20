import streamlit as st
import hashlib
from cryptography.fernet import Fernet

st.set_page_config(page_title="🔐 Secure Data Encryption", layout="centered")

KEY = Fernet.generate_key()
cipher = Fernet(KEY)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {} 

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str):
    hashed = hash_passkey(passkey)
    entry = st.session_state.stored_data.get(encrypted_text)

    if entry and entry["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

menu = ["🏠 Home", "🗄️ Store Data", "🔓 Retrieve Data", "🔑 Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "🏠 Home":
    st.title("🔐 Secure Data Encryption System")
    st.markdown("""
    Welcome to the **Secure Data App**!  
    - Encrypt and store sensitive data with a secret passkey 🔑  
    - Retrieve it securely later  
    - Fully secure using **Fernet encryption** and **SHA-256 hashing**
    """)

elif choice == "🗄️ Store Data":
    st.header("🧾 Store Encrypted Data")

    data_input = st.text_area("Enter the data you want to secure:")
    pass_input = st.text_input("Create a secret passkey:", type="password")

    if st.button("🔐 Encrypt & Save"):
        if data_input and pass_input:
            encrypted = encrypt_data(data_input)
            hashed_pass = hash_passkey(pass_input)

            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed_pass
            }

            st.success("✅ Data encrypted and stored securely!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please enter both data and passkey!")

elif choice == "🔓 Retrieve Data":
    st.header("🔎 Retrieve Encrypted Data")

    encrypted_input = st.text_area("Paste the encrypted data:")
    pass_input = st.text_input("Enter your passkey:", type="password")

    if st.button("🔍 Decrypt Data"):
        if encrypted_input and pass_input:
            result = decrypt_data(encrypted_input, pass_input)

            if result:
                st.success("✅ Decryption Successful!")
                st.write(f"🔓 Decrypted Message: `{result}`")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Invalid passkey! Attempts remaining: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts. Please login again to continue.")
                    st.switch_page("🔑 Login") 
        else:
            st.warning("Please provide both the encrypted data and the passkey.")

elif choice == "🔑 Login":
    st.header("🔐 Reauthorization Required")
    login_key = st.text_input("Enter admin password:", type="password")

    if st.button("🔓 Login"):
        if login_key == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Access granted! You may now retrieve data.")
        else:
            st.error("❌ Incorrect password!")
