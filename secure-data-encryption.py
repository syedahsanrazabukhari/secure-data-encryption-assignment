import streamlit as st  # type: ignore
import hashlib
import base64
import json
import os
import secrets
from datetime import datetime, timedelta
from cryptography.fernet import Fernet  # type: ignore

# ----------------- File Paths ----------------- #
VAULT_FILE = "vault.json"
LOCK_FILE = "lock.json"

# ----------------- Load/Save Helpers ----------------- #
def load_records():
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "r") as f:
            return json.load(f)
    return {}

def save_records(records):
    with open(VAULT_FILE, "w") as f:
        json.dump(records, f)

def get_lock_info():
    if os.path.exists(LOCK_FILE):
        with open(LOCK_FILE, "r") as f:
            return json.load(f)
    return {}

def save_lock_info(data):
    with open(LOCK_FILE, "w") as f:
        json.dump(data, f)

# ----------------- Security Logic ----------------- #
def derive_key(secret, salt=None):
    if not salt:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 100000)
    return base64.b64encode(salt + dk).decode()

def verify_key(stored_hash, secret):
    raw = base64.b64decode(stored_hash.encode())
    salt = raw[:16]
    new_dk = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 100000)
    return new_dk == raw[16:]

def fernet_key(secret):
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())

def secure_encode(content, secret):
    f = Fernet(fernet_key(secret))
    return f.encrypt(content.encode()).decode()

def secure_decode(encrypted, secret):
    f = Fernet(fernet_key(secret))
    return f.decrypt(encrypted.encode()).decode()

# ----------------- UI Views ----------------- #
def store_view():
    st.header("➕ Secure Your Data")
    key = st.text_input("Unique Key (ID)", help="Must be unique")
    info = st.text_area("Data to Encrypt")
    passcode = st.text_input("Your Secret Passkey", type="password")

    if st.button("🔐 Encrypt & Save"):
        if not key or not info or not passcode:
            st.warning("All fields are required.")
            return

        db = load_records()
        if key in db:
            st.error("This Key already exists!")
            return

        encrypted = secure_encode(info, passcode)
        hashed = derive_key(passcode)
        db[key] = {"hash": hashed, "payload": encrypted}
        save_records(db)
        st.success("✅ Data encrypted and saved successfully!")

def retrieve_view():
    st.header("🔍 Retrieve Your Data")
    key = st.text_input("Enter Your Key")
    passcode = st.text_input("Enter Your Passkey", type="password")

    lock_info = get_lock_info()
    now = datetime.now()
    if "until" in lock_info:
        unlock_time = datetime.strptime(lock_info["until"], "%Y-%m-%d %H:%M:%S")
        if now < unlock_time:
            st.error(f"🚫 Locked. Try again after {unlock_time.strftime('%H:%M:%S')}")
            return

    if st.button("🔓 Decrypt"):
        db = load_records()
        if key not in db:
            st.error("❌ Key not found.")
            return

        entry = db[key]
        if verify_key(entry["hash"], passcode):
            text = secure_decode(entry["payload"], passcode)
            st.success("Access Granted!")
            st.info(f"Decrypted Content: {text}")
            st.session_state.attempts = 0
        else:
            st.error("Incorrect Passkey.")
            st.session_state.attempts += 1
            if st.session_state.attempts >= 3:
                lock_time = (now + timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S")
                save_lock_info({"until": lock_time})
                st.warning("Too many attempts. Locked for 30 seconds.")

# ----------------- App Entry Point ----------------- #
def run():
    st.set_page_config("Secure Vault", page_icon="🔐")
    if "attempts" not in st.session_state:
        st.session_state.attempts = 0

    menu = st.sidebar.radio("Select Option", ["Secure Data", "Retrieve Data"])

    if menu == "Secure Data":
        store_view()
    else:
        retrieve_view()

run()
