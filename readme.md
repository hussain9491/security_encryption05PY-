Yeh Streamlit app aik “Secure Data Vault” banaata hai jahan users apne data ko encrypt karke store kar sakte hain aur baad mein decrypt kar sakte hain. Isme user registration aur login system hai jo bcrypt se passwords hash karta hai aur Fernet (cryptography) se data encrypt/decrypt karta hai. Aaiye ab har line ya block ko detail se Roman Urdu mein dekhte hain.

1. Import Statements
packages

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

1: import streamlit as st
Streamlit library ko st naam se import karta hai, jo UI components (buttons, text inputs) banane mein madad deta hai.

2: import yaml
YAML files ko read/write karne ke liye library.

3:import os
Operating system interactions (file existence check waghera) ke liye.

4:import bcrypt
Password hashing (secure storage) ke liye.

5:from cryptography.fernet import Fernet
Symmetric encryption/decryption ke liye Fernet class.

6: from cryptography.hazmat.primitives import hashes
Hash algorithms (SHA256) use karne ke liye.

7:from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
Password-based key derivation function (PBKDF2) ke liye.

8:import base64
Bytes ko Base64 encode/decode karne ke liye.

9:from typing import Dict, Optional
Type hints: Dict aur Optional.

10:import json
JSON data handle karne ke liye (zaroorat pad sakti hai).


2nd step

2. Session State Variables Initialization

# Initialize session state variables (code)

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'encrypted_data' not in st.session_state:
    st.session_state.encrypted_data = {}
Streamlit session_state ek dictionary jaise hota hai jo rerun ke bawajood values yaad rakhta hai.

some points here-
* Agar keys maujood nahi, to default set kar deta hai:
* authenticated: false (user abhi tak login nahi)
* current_user: None (koi user set nahin)
* encrypted_data: empty dict (data abhi store nahi hua)


3rd step

3. Constants

USERS_FILE = "users.yaml"
SALT_ROUNDS = 12

* USERS_FILE: YAML file ka naam jisme user credentials store hongi.
* SALT_ROUNDS: bcrypt ke salt generation ke rounds (complexity) — jitna zyada, hashing utni hi secure magar slow.


4th step
4. Key Generation aur Encryption Handlers

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

1:Function password + salt se 32-byte key derive karta hai PBKDF2HMAC se.
2:Phir Base64 safe encoding se return karta hai jo Fernet ko chahiye

def get_encryption_handler(key: bytes) -> Fernet:
    """Create Fernet encryption handler from key."""
    return Fernet(key)

* Fernet object banata hai jisse encrypt() aur decrypt() methods use kar sakte hain.




                                       5th step

5. Users Load/Save Functions

def load_users() -> Dict:
    """Load users from YAML file."""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as file:
            return yaml.safe_load(file) or {}
    return {}
* Agar users.yaml file maujood ho, to usay read karke Python dict return karta hai; warna empty dict.



def save_users(users: Dict) -> None:
    """Save users to YAML file."""
    with open(USERS_FILE, 'w') as file:
        yaml.dump(users, file)
* Updated users dict ko file mein dump (write) karta hai.




                                        6th step

6. Password Handling

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify if provided password matches stored hash."""
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

*Stored hashed password aur provided plain password ko compare karta hai.
(code)

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
* Agar username already exist, to False return karta hai; warna True return karta

some points here :
1st: Agar username already hai to False return.
2nd: Naya salt generate kar ke password hash karta hai.
3rd: users.yaml mein username: {password: hash, salt: salt} add karke save.

* Naya user register karne ke liye True return karta hai.
(code)
def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user credentials."""
    users = load_users()
    if username not in users:
        return False
    
    return verify_password(users[username]['password'], password)

* Login waqt username check karke password verify karta hai.


                                                step 7th

7. Data Encryption/Decryption
(code)


def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypt data using user's key."""
    f = get_encryption_handler(key)
    return f.encrypt(data.encode())

* Plain text data ko Fernet se encrypt karke bytes return.


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt data using user's key."""
    f = get_encryption_handler(key)
    return f.decrypt(encrypted_data).decode()

*Encrypted bytes ko decrypt karke wapas string return.



                                                step 8 
8. Streamlit UI

st.title("🔐 Secure Data Vault")
 * Page ka title.                                                

 

 8.1 Authentication UI


(code)
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

Some points:
1st: Agar user login nahin, to do tabs: Login aur Register.

2nd: Login tab: Username/password fields, aur “Login” button.

3rd: Button click pe authenticate_user. Agar sahi, session_state update kare, encryption key generate kare, success message dikhaye aur page reload (rerun). Warna error.


                                            next step  (code)

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

* Register tab: Aik aur set of text inputs, aur “Register” button.
* Validations: passwords match aur length ≥8. Phir register_user. Success ya error display.


                                    step 8.2  Authenticated UI
(code)
 else:
    # Authenticated UI
    st.write(f"Welcome, {st.session_state.current_user}!")
    
    if st.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        if 'encryption_key' in st.session_state:
            del st.session_state.encryption_key
        st.rerun()

* Agar authenticated == True: Welcome message aur “Logout” button.
* Logout pe session variables reset kare aur rerun.                                   


    Next step:       Secure Data Management (code)

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

1st: Header dikhata hai.
2nd: text_area se user se data leta hai.
3rd: “Encrypt and Store” pe click:

* Agar data hai to encrypt_data() call kare.

* Phir encrypted_data dict mein current_user key ke under list banaye (agar pehle nahin) aur encrypted bytes append kare.

* Success message.

(code)
    # Display stored encrypted data
    if st.session_state.current_user in st.session_state.encrypted_data:
        st.subheader("Your Encrypted Data")
        for idx, encrypted_item in enumerate(st.session_state.encrypted_data[st.session_state.current_user]):
            if st.button(f"Decrypt Item {idx + 1}"):
                decrypted = decrypt_data(encrypted_item, st.session_state.encryption_key)
                st.info(f"Decrypted data: {decrypted}")

* Agar user ka koi encrypted data hai:
* Subheader dikhaye.
* Har item par ek “Decrypt Item X” button banaye.
* Button click par decrypt_data() se wapas original text show kare.


Yeh app pure Python aur Streamlit use karke aik simple magar effective encrypted data vault banata hai jahan har user apne data ko securely encrypt/store aur decrypt kar sakta hai, bina database ke—sirf YAML aur session state ka istemal.

run command
streamlit run main.py









