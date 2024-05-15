import socket
import requests
from cryptography import x509
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom
from cryptography.hazmat.backends import default_backend
import zlib
import json
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.padding import PKCS7

from hashlib import sha256
import hashlib
import uuid
from binascii import unhexlify
import base64
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from datetime import datetime, timezone



privateKeyRing = {}
CApublic_Key = []
clientInfor = {}
client_sessions ={}
public_keys={}
server_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

clients={}
def setCApub():
    response = requests.get('http://localhost:5080/public-key')
    
    if response.status_code == 200:
        # Load the public key from response content, assuming it's in PEM format
        CApublic_Key.append(
            serialization.load_pem_public_key(
                response.content,
                backend=default_backend()
            )
        )
        print("CA Public Key fetched successfully.")
    else:
        print(f"Failed to fetch CA public key. Status code: {response.status_code}")

def generate_session_key(hashed_key_str, salt_b64=None, info=b'session_key', length=32):
    """
    Generate a secret key from a hashed key using HKDF.
    
    Args:
        hashed_key_str (str): The hashed key (as a hex string) from which to derive the secret key.
        salt_b64 (str, optional): A salt value as a base64 encoded string. If None, a random salt is used.
        info (bytes, optional): Optional context and application specific information.
        length (int): The length of the key to generate in bytes.
    
    Returns:
        bytes: The derived secret key.
    """
    # Convert base64 string to bytes if provided, otherwise use a random salt
    try:
        salt = base64.b64decode(salt_b64) if salt_b64 else os.urandom(16)
    except Exception as e:
        print(f"Error decoding base64 salt: {e}")
        salt = os.urandom(16)  # Fallback to random salt if there's an error

    hashed_key = bytes.fromhex(hashed_key_str)  # Convert hex string to bytes

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
    server_ip = socket.gethostbyname(socket.gethostname())
    print(server_ip)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u"server-" + server_ip)])
        )
        .sign(server_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return csr_pem


def certify():
    csr_pem = CSR()
    response = requests.post('http://localhost:5080/sign-csr', files={'csr': csr_pem})

    if response.status_code == 200:
        cert_pem = response.json().get("certificate").encode('utf-8')
        with open("server_cert.pem", "wb") as f:
            f.write(cert_pem)
            print("Public key certified successfully")

        with open("server_key.pem", "wb") as f:
            f.write(
                server_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    else:
        print("Failed to obtain certificate")



from datetime import datetime, timezone
from datetime import datetime, timezone

def verify_certificate(client_cert, ca_public_key):
    # Current time as offset-aware datetime
    current_time = datetime.now(timezone.utc)

    # Using the *_utc properties that provide offset-aware datetime objects
    if not (client_cert.not_valid_before_utc <= current_time <= client_cert.not_valid_after_utc):
        print("Certificate is outside its validity period.")
        return False

    try:
        # Verify the client certificate using the CA public key
        ca_public_key.verify(
            signature=client_cert.signature,
            data=client_cert.tbs_certificate_bytes,
            padding=asym_padding.PKCS1v15(),
            algorithm=client_cert.signature_hash_algorithm,
        )
        print("Certificate signature verification succeeded.")
        return True
    except Exception as e:
        print(f"Certificate signature verification failed: {str(e)}")
        return False

certify()
setCApub()


app = Flask(__name__)

@app.route('/connect', methods=['POST'])
def connect():
    cert_str = request.json.get('certificate')
    cert_bytes = cert_str.encode('utf-8')

    # Load the client's certificate and extract public key
    client_cert = x509.load_pem_x509_certificate(cert_bytes)
    public_key = client_cert.public_key()
    
    # Generate a hash of the public key to use as a unique identifier
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_hash = hashlib.sha256(public_key_pem).hexdigest()
    
    # Verify the certificate (simplified here)
    if not verify_certificate(client_cert,CApublic_Key[0]):
        return jsonify({"error": "Certificate verification failed."}), 400
    
    # Create a session ID or use an existing one
    session_id = client_sessions.get(public_key_hash, str(uuid.uuid4()))
    client_sessions[public_key_hash] = session_id  # Store or update session ID
    
    return jsonify({"message": "Connected successfully.", "session_id": session_id})

def decrypt_data(encrypted_data, secret_key):
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ct) + decryptor.finalize()
    return decrypted_data

def decompress_and_verify_hash(data):
    separator_index = data.rindex(b'|')
    compressed_data = data[:separator_index]
    sent_hash_bytes = data[separator_index + 1:]

    decompressed_data = zlib.decompress(compressed_data)
    computed_hash = sha256(decompressed_data).digest()

    # Determine the correct length of the hash and adjust the sent hash bytes if necessary
    rightLength = len(computed_hash)
    sentLength = len(sent_hash_bytes)
    print("Computed hash length:", rightLength)
    print("Sent hash length:", sentLength)

    if sentLength > rightLength:
        # Truncate the sent hash bytes to match the length of the computed hash
        sent_hash_bytes = sent_hash_bytes[:rightLength]

    if sent_hash_bytes != computed_hash:
        print(f"Sent hash: {sent_hash_bytes.hex()}")
        print(f"Computed hash: {computed_hash.hex()}")
        raise ValueError("Data hash does not match, data may be corrupted or tampered.")
    else:
        
        print("they the same")
    return json.loads(decompressed_data.decode('utf-8')), computed_hash


def encrypt_data(data, secret_key):
    # Generate an IV
    iv = os.urandom(16)
    # Initialize cipher for AES encryption
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV for use in decryption


def sign_data(data, private_key):
    """
    Sign data using the private key.
    Args:
        data (bytes): Data to be signed.
        private_key (RSAPrivateKey): The private key used for signing the data.

    Returns:
        bytes: The digital signature of the data.
    """
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
@app.route('/verify', methods=['GET'])
def sendVerification():
    # Read the server's certificate from a file
    with open("server_cert.pem", "rb") as f:
        server_cert = f.read().decode('utf-8')

    # Get the server's public key in PEM format
    server_public_key = server_key.public_key()
    server_public_key_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Return both the certificate and public key in a JSON response
    # print("sending Server's Certificate")
    return jsonify({
        "certificate": server_cert,
        "public_key": server_public_key_pem
    })
def compute_public_key_id(public_key_pem):
    """Compute a public key ID using SHA-256 hash of the public key."""
    hash_digest = sha256(public_key_pem.encode()).hexdigest()
    return hash_digest[:16]  # Take first 16 characters for the key ID


@app.route("/reg", methods=["POST"])
def handle_registration():
    session_id = request.headers.get('X-Session-ID')
    
    # Retrieve client public key hash using session ID
    public_key_hash = next((k for k, v in client_sessions.items() if v == session_id), None)
    if not public_key_hash:
        return jsonify({"error": "Invalid session ID."}), 401
    
    # Extract encrypted data and signature
    encrypted_data = bytes.fromhex(request.json['encrypted_data'])
    signed_secret_key = bytes.fromhex(request.json['signed_secret_key'])
    try:
        secret_key = server_key.decrypt(
            signed_secret_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        return jsonify({"error": f"Failed to decrypt secret key: {str(e)}"}), 500

    try:
        decrypted_data = decrypt_data(encrypted_data, secret_key)
        original_data_json, original_hash = decompress_and_verify_hash(decrypted_data)
        


        clients[session_id]={"Client Name":original_data_json["Client"]["Name"],"hashedkeyGen":original_data_json["Client"]["password"],"Public_Key_Hash":public_key_hash,"salt":original_data_json["Client"]["salt"]}

       
        print(clients)


    except Exception as e:
        return jsonify({"error": f"Failed to process data: {str(e)}"}), 500

    return jsonify({"message": "Registration successful, data processed"})

@app.route("/view", methods=["GET"])
def get_clients():
    session_id = request.headers.get('X-Session-ID')
    if not session_id or session_id not in clients:
        return jsonify({"error": "Invalid or missing session ID."}), 400

    client_data = clients.get(session_id)
    print("Client Data",client_data)
    if not client_data:
        return jsonify({"error": "Session ID does not match any client."}), 404

    session_key = generate_session_key(client_data["hashedkeyGen"],client_data["salt"])
    names = [{"id": client["Client Name"], "hash": client["Public_Key_Hash"]} for client in clients.values()]
    
    data_bytes = json.dumps(names).encode('utf-8')
    # Compress data
    compressed_data = zlib.compress(data_bytes)
    # Calculate hash of the compressed data
    data_hash = hashlib.sha256(compressed_data).digest()
    # Combine compressed data and hash
    payload = compressed_data + b'|' + data_hash

    print("Payload before encryption:", payload)  # Debug statement

    print("Key:", session_key)


    encrypted_data = encrypt_data(payload, session_key)
    signature = sign_data(encrypted_data, server_key)

    response_payload = {
        "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8')
    }
    return jsonify(response_payload)





if __name__ == "__main__":
    app.run(port=5000, debug=True)
