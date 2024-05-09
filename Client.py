import socket
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import zlib
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from os import urandom

phoneNumber =""
CApublic_Key=[]
pBkeys={}
ClientpBkey=[]
username=[]



secretKeys={}
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
client_key = rsa.generate_private_key(
    public_exponent=65537,  # Commonly used RSA public exponent
    key_size=2048,  # 2048-bit key size for secure encryption
)

def CSR():
    """
    Create a Certificate Signing Request (CSR).

    The CSR is generated for the client with a common name based on the client's IP address.
    The CSR is then signed using the client's RSA private key and hashed with SHA-256.
    The result is returned as PEM-encoded bytes.
    """
    # Get the client's IP address
    client_ip = socket.gethostbyname(socket.gethostname())

    # Build the CSR with the IP address as the common name

    username.append(signUp())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, u""+username[0]+"-" + client_ip)
            ])
        )
        .sign(client_key, hashes.SHA256())  # Sign the CSR using the private key
    )
    # Convert CSR to PEM format
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return csr_pem

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
    usrname = input("Enter User:\n")
    # phoneNumber = input("Enter phone number:\n")
    return usrname

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


def reg(url, receiver_public_key_pem):
    # Load the public key from PEM data
    receiver_public_key = load_public_key(receiver_public_key_pem)

    # Data to be sent, including client information
    data = {
        "Client": {
            "Name": username[0],
            "Public_Key": ClientpBkey[0],  # This should also be a public key object or handled similarly
            "Port_Num": portt        
        }
    }

    data_string = json.dumps(data)

    # Compress, Encrypt and then sign the secret key
    compressed_data = compress_data(data_string)
    secret_key = generate_secret_key()
    encrypted_data = encrypt_data(compressed_data, secret_key)
    print("Encrpted data: ",encrypted_data)
    signed_secret_key = sign_data(secret_key, receiver_public_key)  # receiver_public_key must be an object
    print("signed key",signed_secret_key)
    # Prepare the payload
    payload = {
        "encrypted_data": encrypted_data.hex(),
        "signed_secret_key": signed_secret_key.hex(),
       
    }

    # Send the payload to the server
    response = requests.post(url + "/reg", json=payload)
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
    print(ca_public_key)
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
        'public_key': client_public_key_pem.decode('utf-8')
    }

    ClientpBkey.append(data["public_key"])
    # Send the data to the server
    response = requests.post(server_url+"/connect", json=data)

    # Handle the response
    if response.status_code == 200:
        print("Successfully connected to the server.")
        reg(server_url,pBkeys[5000])
        print(response.json())
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

if __name__ == "__main__":
    certify()
    getCApbKey()
    send_certificate_and_key(
        cert_path="client_cert.pem",
        key_path="client_key.pem",
        server_url="http://localhost:5000"
    )