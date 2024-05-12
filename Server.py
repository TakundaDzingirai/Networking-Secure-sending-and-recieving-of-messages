import socket
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom
from cryptography.hazmat.backends import default_backend
import zlib
import json
from cryptography.hazmat.primitives import padding as sym_padding
from hashlib import sha256
import hashlib
import uuid

privateKeyRing = {}
CApublic_Key = []
clientInfor = {}
client_sessions ={}
public_keys={}
server_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


def setCApub():
    response = requests.get('http://localhost:5080/public-key')
    if response.status_code == 200:
        CApublic_Key.append(response.content)
        print("CA Public Key fetched successfully.")
    else:
        print(f"Failed to fetch CA public key. Status code: {response.status_code}")


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


def verify_certificate(client_cert,ca_public_key_pem):
    """
    Verify the certificate's validity and revocation status.

    :param client_cert: The client's certificate object.
    :param ca_public_key: The public key of the CA.
    :return: True if the certificate is valid and not revoked, False otherwise.
    """
    current_time = datetime.now(timezone.utc)
    if not (client_cert.not_valid_before_utc <= current_time <= client_cert.not_valid_after_utc):
        print("Certificate is outside its validity period.")
        return False

    # Load the public key from PEM format
    ca_public_key = serialization.load_pem_public_key(
        ca_public_key_pem,
        backend=default_backend()
    )

    try:
        ca_public_key.verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm,
        )
        print("Certificate signature verification succeeded.")
    except Exception as e:
        print(f"Certificate signature verification failed: {str(e)}")
        return False

    # Additional logic to check revocation status (not fully implemented here)
    return True

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
from hashlib import sha256
import zlib
from flask import Flask, request, jsonify



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
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        return jsonify({"error": f"Failed to decrypt secret key: {str(e)}"}), 500

    try:
        decrypted_data = decrypt_data(encrypted_data, secret_key)
        original_data_json, original_hash = decompress_and_verify_hash(decrypted_data)


    except Exception as e:
        return jsonify({"error": f"Failed to process data: {str(e)}"}), 500

    return jsonify({"message": "Registration successful, data processed"})

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

if __name__ == "__main__":
    app.run(port=5000, debug=True)
