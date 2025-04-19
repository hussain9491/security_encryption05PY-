import streamlit as st
import yaml
import os
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from typing import Dict, Optional
import json

# Initialize session state variables
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'encrypted_data' not in st.session_state:
    st.session_state.encrypted_data = {}

# Constants
USERS_FILE = "users.yaml"
SALT_ROUNDS = 12

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate encryption key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def get_encryption_handler(key: bytes) -> Fernet:
    """Create Fernet encryption handler from key."""
    return Fernet(key)

def load_users() -> Dict:
    """Load users from YAML file."""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as file:
            return yaml.safe_load(file) or {}
    return {}

def save_users(users: Dict) -> None:
    """Save users to YAML file."""
    with open(USERS_FILE, 'w') as file:
        yaml.dump(users, file)

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify if provided password matches stored hash."""
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

def register_user(username: str, password: str) -> bool:
    """Register a new user."""
    users = load_users()
    if username in users:
        return False
    
    # Hash password
    salt = bcrypt.gensalt(rounds=SALT_ROUNDS)
    hashed_password = bcrypt.hashpw(password.encode(), salt).decode()
    
    # Store user
    users[username] = {
        'password': hashed_password,
        'salt': salt.decode()
    }
    save_users(users)
    return True

def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user credentials."""
    users = load_users()
    if username not in users:
        return False
    
    return verify_password(users[username]['password'], password)

def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypt data using user's key."""
    f = get_encryption_handler(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt data using user's key."""
    f = get_encryption_handler(key)
    return f.decrypt(encrypted_data).decode()

# Streamlit UI
st.title("🔐 Secure Data Vault")

# Authentication UI
if not st.session_state.authenticated:
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.header("Login")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login"):
            if authenticate_user(login_username, login_password):
                st.session_state.authenticated = True
                st.session_state.current_user = login_username
                # Generate encryption key
                users = load_users()
                salt = users[login_username]['salt'].encode()
                st.session_state.encryption_key = generate_key(login_password, salt)
                st.success("Successfully logged in!")
                st.rerun()
            else:
                st.error("Invalid username or password!")
    
    with tab2:
        st.header("Register")
        reg_username = st.text_input("Username", key="reg_username")
        reg_password = st.text_input("Password", type="password", key="reg_password")
        reg_password_confirm = st.text_input("Confirm Password", type="password", key="reg_password_confirm")
        
        if st.button("Register"):
            if reg_password != reg_password_confirm:
                st.error("Passwords do not match!")
            elif len(reg_password) < 8:
                st.error("Password must be at least 8 characters long!")
            else:
                if register_user(reg_username, reg_password):
                    st.success("Registration successful! Please login.")
                else:
                    st.error("Username already exists!")

else:
    # Authenticated UI
    st.write(f"Welcome, {st.session_state.current_user}!")
    
    if st.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        if 'encryption_key' in st.session_state:
            del st.session_state.encryption_key
        st.rerun()
    
    # Data encryption/decryption interface
    st.header("Secure Data Management")
    
    # Input for new data
    new_data = st.text_area("Enter data to encrypt")
    if st.button("Encrypt and Store"):
        if new_data:
            encrypted = encrypt_data(new_data, st.session_state.encryption_key)
            if st.session_state.current_user not in st.session_state.encrypted_data:
                st.session_state.encrypted_data[st.session_state.current_user] = []
            st.session_state.encrypted_data[st.session_state.current_user].append(encrypted)
            st.success("Data encrypted and stored!")
    
    # Display stored encrypted data
    if st.session_state.current_user in st.session_state.encrypted_data:
        st.subheader("Your Encrypted Data")
        for idx, encrypted_item in enumerate(st.session_state.encrypted_data[st.session_state.current_user]):
            if st.button(f"Decrypt Item {idx + 1}"):
                decrypted = decrypt_data(encrypted_item, st.session_state.encryption_key)
                st.info(f"Decrypted data: {decrypted}")
