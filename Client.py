import socket
import requests
import os
import json
import zlib
import base64
import hashlib
from binascii import unhexlify

# cryptography imports
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC





from os import urandom
import os
import hashlib
from hashlib import sha256
import base64


phoneNumber =""
CApublic_Key=[]
pBkeys={}
ClientpBkey=[]
userInfo=[]

secretKeys={}
key_path = "client_key.pem"
cert_path = "client_cert.pem"
# Global variable for client key
client_key = None
session_id=""
session_key=None

def getSalt():
    """
    Retrieves a cryptographic salt from a file. If the file does not exist,
    generates a new random salt and saves it to the file.

    Returns:
        bytes: The cryptographic salt.
    """
    filename = "salt.pem"
    if os.path.exists(filename):
        try:
            with open(filename, 'rb') as salt_file:
                return salt_file.read()
        except IOError as e:
            # Handle the error (e.g., file could not be read)
            print(f"Error reading salt file: {e}")
            raise RuntimeError("Failed to read salt file.")
    else:
        # Generate a new salt if the file does not exist
        new_salt = os.urandom(16)  # 16 bytes is a common salt size
        try:
            with open(filename, 'wb') as salt_file:
                salt_file.write(new_salt)
            return new_salt
        except IOError as e:
            # Handle the error if the file cannot be written
            print(f"Error writing new salt to file: {e}")
            raise RuntimeError("Failed to write new salt to file.")

def load_or_create_keys(key_path, cert_path):
    global client_key  # Use the global keyword to modify the global variable
    # Check if the private key file exists
    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            # Ensure userInfo[1] (password) is converted to bytes, also add a conditional check for password existence
            password_bytes = userInfo[1].encode('utf-8') if len(userInfo) > 1 and userInfo[1] else None
            client_key = load_pem_private_key(
                key_file.read(),
                password=password_bytes,
                backend=default_backend()
            )
        if isinstance(client_key, rsa.RSAPrivateKey):
            print("Private key loaded successfully and is a valid RSA private key.")
        else:
            raise ValueError("The loaded key is not a valid RSA private key.")
    else:
        # Generate a new RSA private key if no existing key file is found
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        print("Generated a new RSA private key.")
        # Save the newly generated private key
        with open(key_path, 'wb') as key_file:
            key_file.write(
                client_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        print("New private key saved to file.")

    return client_key


def hash_password(password):
    """
    Hash a password using SHA-256.

    Args:
        password (str): The plaintext password to hash.

    Returns:
        str: The hexadecimal representation of the hashed password.
    """
    # Create a new SHA-256 hash object
    hasher = hashlib.sha256()
    # Encode the password to bytes, then hash it
    hasher.update(password.encode('utf-8'))
    # Return the hexadecimal digest of the hash
    return hasher.hexdigest()
def load_public_key(pem_data):
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
def generate_secret_key():
    # Generate a random 256-bit key
    secret_key = urandom(32)  # 32 bytes * 8 = 256 bits
    return secret_key
def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))  # Bind to all interfaces on a free port
        return s.getsockname()[1]



portt=find_free_port()
# Generate RSA Key Pair for the client

def generate_session_key(hashed_key, salt=None, info=b'session_key', length=32):
    """
    Generate a secret key from a hashed key using HKDF.
    """
    # Use the provided salt or generate a new one if none provided
    if salt is None:
        salt = os.urandom(16)
        print("Random Salt Generated for HKDF:", salt)
    
    # Create an HKDF instance with the given parameters
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    
    # Derive the secret key
    key = hkdf.derive(hashed_key)
    return key


def CSR():
    """
    Create a Certificate Signing Request (CSR).
    """
    # Ensure the client_key is an RSA private key instance
    if not isinstance(client_key, rsa.RSAPrivateKey):
        raise TypeError("client_key must be an RSAPrivateKey instance")

    # Get the client's IP address as the common name for the certificate
    client_ip = socket.gethostbyname(socket.gethostname())
      # This should be defined appropriately

    # Create a CSR with the common name set to the client's IP
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, userInfo[0] + "-" + client_ip)
        ])
    )
    
    # Sign the CSR using the client's private key and return the PEM-encoded CSR
    csr = csr_builder.sign(private_key=client_key, algorithm=hashes.SHA256(), backend=default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)

def certify():
    """
    Request a certificate from a Certificate Authority (CA).

    This function sends a CSR to the CA server via an HTTP POST request.
    If successful, the returned certificate is saved to a file. The private key
    is also saved to a file for future use.
    """
    # Generate the CSR
    csr_pem = CSR()

    # Send the CSR to the CA server for signing
    response = requests.post('http://localhost:5080/sign-csr', files={'csr': csr_pem})
    password_bytes = userInfo[1].encode('utf-8')
    encryption_algorithm = serialization.BestAvailableEncryption(password_bytes)

    # Check the response and save the certificate
    if response.status_code == 200:
        # Extract the certificate from the server's response
        cert_pem = response.json().get("certificate").encode('utf-8')
        # Save the certificate to a file
        with open("client_cert.pem", "wb") as f:
            f.write(cert_pem)
            print("Public key certified successfully")

        # Save the private key to a file
        with open("client_key.pem", "wb") as f:
            f.write(
                client_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=encryption_algorithm,
                )
            )
    else:
        print("Failed to obtain certificate")




def signUp():
    """
    Prompt user to enter username and password, validate them, and continue to prompt
    until valid inputs are received.

    Returns:
        str: The username of the user after successful validation.
    """
    username = ""
    # while True:
    #     try:
    #         # Get username from user and validate it

    #         if username =="":
    #             username = input("Enter Username:\n")
    #             if len(username) < 5:
    #                 username=""
    #                 raise ValueError("Username must be at least 5 characters long.")
    #             if not username.isalnum():
    #                 raise ValueError("Username must be alphanumeric.")

    #         # Get password from user and validate it
    #         password = input("Enter Password:\n")
    #         if len(password) < 8:
    #             raise ValueError("Password must be at least 8 characters long.")
    #         if not any(char.isdigit() for char in password):
    #             raise ValueError("Password must contain at least one digit.")
    #         if not any(char.isalpha() for char in password):
    #             raise ValueError("Password must contain at least one letter.")

    #         # If both inputs are valid, break the loop
    #         break
    #     except ValueError as e:
    #         print(f"Error: {e}")
    #         print("Please try again.")
    #     except Exception as e:
    #         print(f"An unexpected error occurred: {e}")
    #         print("Please try again.")

    print("Signup successful!")
    userInfo.append("Takunda")
    userInfo.append("#Takunda18252707")
    return username

def compress_data(data):
    """Compress data using zlib."""
    return zlib.compress(data.encode('utf-8'))
def encrypt_data(data, secret_key):
    # Generate an IV
    iv = os.urandom(16)

    # Initialize cipher for AES encryption
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Check if data is in bytes, encode if not
    if isinstance(data, str):
        data = data.encode()

    # Pad the data using PKCS7
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()  # Data must be bytes

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_data  # Prepend IV for use in decryption



def decrypt_data(encrypted_data, secret_key):
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ct) + decryptor.finalize()
    # Unpad the decrypted data
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data


def fetch_and_verify_server_certificate(server_verify_url, ca_public_key):
    response = requests.get(server_verify_url)
    if response.status_code != 200:
        print("Failed to fetch server's certificate.")
        return False

    server_data = response.json()
    server_cert = x509.load_pem_x509_certificate(server_data['certificate'].encode('utf-8'))
    server_public_key_pem = server_data['public_key'].encode('utf-8')

    print("Server Certificate Data:", server_data['certificate'])  # Debug output
    print("Server Public Key PEM:", server_public_key_pem)  # Debug output

    try:
        # Verify the server's certificate using the correct padding
        ca_public_key.verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            server_cert.signature_hash_algorithm
        )
        print("Server's certificate is valid.")
        pBkeys["Server_publicKey"] = server_public_key_pem

        return True
    except Exception as e:
        print(f"Server certificate verification failed: {str(e)}")
        return False

def viewClients(url):
    headers = {'X-Session-ID': session_id}
    response = requests.get(url + "/view", headers=headers)
    if response.status_code != 200:
        print(f"Failed to retrieve data: {response.text}")
        return

    try:
        response_payload = response.json()
        encrypted_data = base64.b64decode(response_payload['encrypted_data'])
        signature = base64.b64decode(response_payload['signature'])
        print("Debug: Data and Signature decoded.")
    except Exception as e:
        print(f"Error decoding response data: {e}")
        return

    if not verify_signature(encrypted_data, signature, load_public_key(pBkeys["Server_publicKey"])):
        print("Failed to verify signature.")
        return

    if session_key is None:
        print("Session key is None")
        return

    try:
        decrypted_data = decrypt_data(encrypted_data, session_key)
        print("Debug: Data decrypted successfully.")
    except Exception as e:
        print(f"Decryption failed: {e}")
        return

    try:
        data = decompress_and_verify_hash(decrypted_data)
        if data is None:
            return

        print("Clients you can talk to:")
        for i, client in enumerate(json.loads(data), 1):
            print(f"{i}. {client['id']} - {client['hash']}")
    except Exception as e:
        print(f"Error processing data: {str(e)}")


def sign_data(data, receiver_public_key):
    """Encrypt data with the receiver's public key (simulating signing)."""
    return receiver_public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def reg(url, receiver_public_key_pem, session_id):
    """Register by sending secured data to the server with a session ID."""
    receiver_public_key = load_public_key(receiver_public_key_pem)
    salt = getSalt()

    # Ensure the public key is in bytes before encoding
    if isinstance(ClientpBkey[0], str):
        public_key_bytes = ClientpBkey[0].encode('utf-8')  # Convert string to bytes if necessary
    else:
        public_key_bytes = ClientpBkey[0]  # Assume it's already bytes

    data = {
        "Client": {
            "Name": userInfo[0],
            "Public_Key": base64.b64encode(public_key_bytes).decode('utf-8'),  # Encoding the public key
            "password": hash_password(userInfo[1]),
            "salt": base64.b64encode(salt).decode('utf-8')  # Encoding the salt
        }
    }

    # Convert the data to JSON, hash it, compress it, and prepare for encryption
    data_string = json.dumps(data)
    hasher = sha256()
    hasher.update(data_string.encode('utf-8'))
    data_hash = hasher.digest()

    compressed_data = zlib.compress(data_string.encode('utf-8'))
    payload_to_encrypt = compressed_data + b'|' + data_hash

    secret_key = generate_secret_key()
    encrypted_data = encrypt_data(payload_to_encrypt, secret_key)
    signed_secret_key = sign_data(secret_key, receiver_public_key)

    # Prepare payload with headers including the session ID
    headers = {'X-Session-ID': session_id}
    payload = {
        "encrypted_data": encrypted_data.hex(),
        "signed_secret_key": signed_secret_key.hex()
    }

    # Send the payload with the session ID header to authenticate the request
    response = requests.post(url + "/reg", headers=headers, json=payload)
    print("Server response:", response.text)

def fetch_and_verify_server_certificate(server_verify_url, ca_public_key):
    response = requests.get(server_verify_url)
    if response.status_code != 200:
        print("Failed to fetch server's certificate.")
        return False

    server_data = response.json()
    server_cert = x509.load_pem_x509_certificate(server_data['certificate'].encode('utf-8'))
    server_public_key_pem = server_data['public_key'].encode('utf-8')

    # print("Server Certificate Data:", server_data['certificate'])  # Debug output
    # print("Server Public Key PEM:", server_public_key_pem)  # Debug output

    try:
        # Verify the server's certificate
        ca_public_key.verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            server_cert.signature_hash_algorithm
        )
        print("Server's certificate is valid.")
        pBkeys["Server_publicKey"]=server_public_key_pem

        return True
    except Exception as e:
        print(f"Server certificate verification failed: {str(e)}")
        return False

def send_certificate_and_key(server_url,cert_path, key_path):
    global session_id
    """
    Sends the client's certificate and public key to the server after verifying the server's certificate.

    Args:
        cert_path (str): Path to the client's certificate.
        key_path (str): Path to the client's private key.
        server_url (str): Server URL to connect and send data.
    """
    # First, verify the server's identity
    server_verify_url = server_url + "/verify"
    # This should be the known and trusted CA's public key or the hardcoded certificate
    #  we have the CA's public key as `ca_public_key`
    ca_public_key_pem = CApublic_Key[0]
    ca_public_key = serialization.load_pem_public_key(ca_public_key_pem) #  loading the key
  
    
    # Load the client's certificate
    with open(cert_path, "rb") as f:
        client_cert = f.read()

    # Load the client's private key
    with open(key_path, "rb") as f:
        client_key = serialization.load_pem_private_key(f.read(), password=userInfo[1].encode('utf-8'))

    # Extract the public key from the private key
    client_public_key = client_key.public_key()
    
    client_public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Prepare the data to be sent
    data = {
        'certificate': client_cert.decode('utf-8'),
       
    }
  

    ClientpBkey.append(client_public_key_pem.decode('utf-8'))
    # Send the data to the server
    response = requests.post(server_url+"/connect", json=data)

    # Handle the response
    if response.status_code == 200:
        
        if not fetch_and_verify_server_certificate(server_verify_url, ca_public_key):
            print("Aborting connection due to failed server verification.")
            return
        print("Successfully connected to the server.")
        session_id =response.json()["session_id"]
        print(session_id)
        reg(server_url,pBkeys["Server_publicKey"],session_id)
       
      
    else:
        print(f"Failed to connect to the server. Status code: {response.status_code}")
        print(response.text)

# Use this function to initiate the process


def getCApbKey():
    response = requests.get('http://localhost:5080/public-key')
    if response.status_code == 200:
        CApublic_Key.append(response.content)
        print("CA Public Key fetched successfully.")
    else:
        print(f"Failed to fetch CA public key. Status code: {response.status_code}")

def verify_signature(data, signature, pem_public_key):
    """Verify a signature using the public key."""
    try:
        # Load the public key from PEM bytes if necessary
        if isinstance(pem_public_key, bytes):
            public_key = load_public_key(pem_public_key)
        else:
            public_key = pem_public_key  # Assuming it's already a public key object
        
        # Verify the signature
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {str(e)}")
        return False
    
def decompress_and_verify_hash(encrypted_data):
    try:
        # Split the encrypted data to separate the data from the hash
        print("after decryption",encrypted_data)
        separator_index = encrypted_data.rindex(b'|')
        compressed_data = encrypted_data[:separator_index]
        sent_hash_bytes = encrypted_data[separator_index + 1:]
        # Decompress data
        decompressed_data = zlib.decompress(compressed_data)
        # Compute hash of the decompressed data
        computed_hash = hashlib.sha256(compressed_data).digest()
        # Verify hash
        if computed_hash != sent_hash_bytes:
            print("Hash mismatch: data integrity check failed.")
            return None
        # Return decompressed data
        return json.loads(decompressed_data.decode('utf-8'))
    except Exception as e:
        print(f"Error during decompression or hash verification: {e}")
        return None

def viewClients(url):
    headers = {'X-Session-ID': session_id}
    response = requests.get(url + "/view", headers=headers)
    if response.status_code != 200:
        print(f"Failed to retrieve data: {response.text}")
        return

    try:
        response_payload = response.json()
        encrypted_data = base64.b64decode(response_payload['encrypted_data'])
        signature = base64.b64decode(response_payload['signature'])
        print("Debug: Data and Signature decoded.")
    except KeyError as e:
        print(f"Key error in response payload: {e}")
        return
    except Exception as e:
        print(f"Unexpected error parsing response: {e}")
        return

    if not verify_signature(encrypted_data, signature, load_public_key(pBkeys["Server_publicKey"])):
        print("Failed to verify signature.")
        return

    if session_key is None:
        print("Session key is None")
        return

    try:
        decrypted_data = decrypt_data(encrypted_data, session_key)
        print("Debug: Data decrypted successfully.")
    except Exception as e:
        print(f"Decryption failed: {e}")
        return

    try:
        data = decompress_and_verify_hash(decrypted_data)
        print("Clients you can talk to:")
        for i, client in enumerate(data, 1):
            print(f"{i}. {client['id']}")
    except Exception as e:
        print(f"Error processing data: {str(e)}")
def updateSessionKey():
    global session_key
    hashed_password_hex = hash_password(userInfo[1])
 
    
    # Convert the hex string to bytes
    hashed_password_bytes = bytes.fromhex(hashed_password_hex)
    # print("Hashed Password Bytes:", hashed_password_bytes)
    
    salt = getSalt()
    session_key = generate_session_key(hashed_password_bytes, salt)
    


def chat(pos,clients,fileType,url):
    clientHashedp =clients[pos]["id"][0]
   

    if fileType=="1":
        msg = input("Type your message here:\n")
        enMsg =encrypt_data(msg,session_key)
        headers = {'X-Session-ID': session_id}
        payload={
            "txt":enMsg
        }
        res= requests.post(url+"/chat",headers=headers,json=payload)


# Define paths for the key and certificate


if __name__ == "__main__":
    server_url="http://localhost:5000"
    
    signUp() 
    load_or_create_keys(key_path, cert_path)
    certify()
    getCApbKey()
    send_certificate_and_key(
        server_url,
        cert_path="client_cert.pem",
        key_path="client_key.pem",
    )
    # print("Successfully Connected to server")
    updateSessionKey()
    while True:
        print("""==================Server Services=========================
              1. View
              2. Chat

======================Settings=================================
              3. Hide Profile
              4. Change Password

              """)
        option = input("Choose your option:")
        if option =="1":
            viewClients(server_url)
        



