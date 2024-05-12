import socket
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import zlib
import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from os import urandom
import os
import hashlib
from hashlib import sha256

phoneNumber =""
CApublic_Key=[]
pBkeys={}
ClientpBkey=[]
userInfo=[]



secretKeys={}

def load_or_create_keys(key_path, cert_path):
    """
    Load or create RSA private/public key pair.
    """
    # Check if both the private key and certificate exist
    if os.path.exists(key_path):
        # Load the private key from file
        with open(key_path, 'rb') as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        if isinstance(private_key, rsa.RSAPrivateKey):
            print("Private key loaded successfully and is a valid RSA private key.")
        else:
            raise ValueError("Loaded key is not a valid RSA private key.")
    else:
        # Generate a new private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        print("Generated a new RSA private key.")

        # Optionally save the private key to a file
        with open(key_path, 'wb') as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        print("New private key saved to file.")

    return private_key
key_path = "client_key.pem"
cert_path = "client_cert.pem"

# Load or create keys

client_key = load_or_create_keys(key_path, cert_path)


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




def CSR():
    """
    Create a Certificate Signing Request (CSR).
    """
    # Ensure the client_key is an RSA private key instance
    if not isinstance(client_key, rsa.RSAPrivateKey):
        raise TypeError("client_key must be an RSAPrivateKey instance")

    # Get the client's IP address as the common name for the certificate
    client_ip = socket.gethostbyname(socket.gethostname())
    username = signUp()  # This should be defined appropriately

    # Create a CSR with the common name set to the client's IP
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username + "-" + client_ip)
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
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    else:
        print("Failed to obtain certificate")

def start_client(server_host='127.0.0.1', server_port=65432):
    """
    Start a TCP client to communicate with a server.

    This function connects to a specified server host and port using a TCP socket.
    After connecting, it sends a message to the server and waits for a response.
    """
    # Use the socket library to create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect to the specified server host and port
        s.connect((server_host, server_port))
        # Send a byte string to the server
        s.sendall(b'Hello, server!')
        # Receive the response from the server
        data = s.recv(1024)
        print(f"Received from server: {data.decode()}")




def signUp():
    """
    Prompt user to enter username and password, validate them, and continue to prompt
    until valid inputs are received.

    Returns:
        str: The username of the user after successful validation.
    """
    username = ""
    while True:
        try:
            # Get username from user and validate it

            if username =="":
                username = input("Enter Username:\n")
                if len(username) < 5:
                    raise ValueError("Username must be at least 5 characters long.")
                if not username.isalnum():
                    raise ValueError("Username must be alphanumeric.")

            # Get password from user and validate it
            password = input("Enter Password:\n")
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters long.")
            if not any(char.isdigit() for char in password):
                raise ValueError("Password must contain at least one digit.")
            if not any(char.isalpha() for char in password):
                raise ValueError("Password must contain at least one letter.")

            # If both inputs are valid, break the loop
            break
        except ValueError as e:
            print(f"Error: {e}")
            print("Please try again.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            print("Please try again.")

    print("Signup successful!")
    userInfo.append(username)
    userInfo.append(password)
    return username

def compress_data(data):
    """Compress data using zlib."""
    return zlib.compress(data.encode('utf-8'))


def encrypt_data(data, secret_key):
    """Encrypt data using the provided secret key (AES)."""
    iv = urandom(16)  # AES block size in CBC mode

    # Pad data to make it a multiple of the block size
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ct  # Prepend IV for use in decryption

def sign_data(data, receiver_public_key):
    """Encrypt data with the receiver's public key (simulating signing)."""
    return receiver_public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def reg(url, receiver_public_key_pem, session_id):
    """Register by sending secured data to the server with a session ID."""
    receiver_public_key = load_public_key(receiver_public_key_pem)
    data = {
        "Client": {
            "Name": userInfo[0],
            "Public_Key": ClientpBkey[0],
            "password": userInfo[1]        
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

    print("Server Certificate Data:", server_data['certificate'])  # Debug output
    print("Server Public Key PEM:", server_public_key_pem)  # Debug output

    try:
        # Verify the server's certificate
        ca_public_key.verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_cert.signature_hash_algorithm
        )
        print("Server's certificate is valid.")
        pBkeys[5000]=server_public_key_pem

        return True
    except Exception as e:
        print(f"Server certificate verification failed: {str(e)}")
        return False

def send_certificate_and_key(cert_path, key_path, server_url):
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
    # For this example, let's assume we have the CA's public key as `ca_public_key`
    ca_public_key_pem = CApublic_Key[0]
    ca_public_key = serialization.load_pem_public_key(ca_public_key_pem) # You need to define or load this correctly based on your setup
  
    if not fetch_and_verify_server_certificate(server_verify_url, ca_public_key):
        print("Aborting connection due to failed server verification.")
        return

    # Load the client's certificate
    with open(cert_path, "rb") as f:
        client_cert = f.read()

    # Load the client's private key
    with open(key_path, "rb") as f:
        client_key = serialization.load_pem_private_key(f.read(), password=None)

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
        print("Successfully connected to the server.")
        session_id =response.json()["session_id"]
        print(session_id)
        reg(server_url,pBkeys[5000],session_id)
       
      
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







# Define paths for the key and certificate


if __name__ == "__main__":
    certify()
    getCApbKey()
    send_certificate_and_key(
        cert_path="client_cert.pem",
        key_path="client_key.pem",
        server_url="http://localhost:5000"
    )