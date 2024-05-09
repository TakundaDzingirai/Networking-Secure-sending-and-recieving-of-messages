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
privateKeyRing = {}
CApublic_Key = []
clientInfor = {}

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


def verify_certificate(client_cert, ca_public_key):
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

def decrypt_data(encrypted_data, secret_key):
    """Decrypt data using the provided secret key (AES)."""
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()

    # Remove padding
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def decompress_data(compressed_data):
    """
    Decompress data using zlib.

    Args:
        compressed_data (bytes): The compressed data in bytes.

    Returns:
        bytes: The original uncompressed data.
    """
    try:
        # Decompress the data
        original_data = zlib.decompress(compressed_data)
    except zlib.error as e:
        raise Exception(f"Decompression error: {str(e)}")
    
    return original_data


certify()
setCApub()


app = Flask(__name__)

@app.route('/connect', methods=['POST'])
def connect():
    data = request.get_json()
    public_key_str = data['public_key']
    cert_str = data['certificate']
    public_key_bytes = public_key_str.encode('utf-8')
    cert_bytes = cert_str.encode('utf-8')

    ca_public_key_pem = CApublic_Key[0]
    ca_public_key = serialization.load_pem_public_key(ca_public_key_pem)

    client_cert = x509.load_pem_x509_certificate(cert_bytes)
    if not verify_certificate(client_cert, ca_public_key):
        return jsonify({"error": "Certificate verification failed."}), 400

   
    public_key_pem = client_cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    actualPBKey=public_key_pem.decode('utf-8').strip('\n').split("-----BEGIN PUBLIC KEY-----\n")[1].split("\n-----END PUBLIC KEY-----")[0].replace("\n","")
    public_key_id = actualPBKey[-16:]
    privateKeyRing[public_key_id] = actualPBKey
    # print(privateKeyRing)
    print("Client publicKey",actualPBKey)

    return jsonify({"message": "Verification successful, now send me your UserName and portnumber."})
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
    data = request.get_json()
    encrypted_data = bytes.fromhex(data['encrypted_data'])
    signed_secret_key = bytes.fromhex(data['signed_secret_key'])
   

    try:
        secret_key = server_key.decrypt(
            signed_secret_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_data = decrypt_data(encrypted_data, secret_key)
        decompressed_data = decompress_data(decrypted_data)
        original_data = decompressed_data.decode('utf-8')
        original_data_json = json.loads(original_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    client_public_key_pem = original_data_json['Client']['Public_Key']
    public_key_id = compute_public_key_id(client_public_key_pem)
    
    # Store the public key and its ID
    public_keys[public_key_id] = client_public_key_pem

    print(f"Stored Public Key ID: {public_key_id}")
    return jsonify({"message": "Registration successful, public key stored", "public_key_id": public_key_id})

if __name__ == "__main__":
    app.run(port=5000, debug=True)