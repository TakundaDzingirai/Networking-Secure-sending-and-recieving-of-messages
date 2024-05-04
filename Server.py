import socket
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from flask import Flask, request, send_file, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa

privateKeyRing ={}
CApublic_Key =[]
server_key = rsa.generate_private_key(
    public_exponent=65537,  # Commonly used RSA public exponent
    key_size=2048,  # 2048-bit key size for secure encryption
)
print("successful")
app = Flask(__name__)

def setCApub():
    response = requests.get('http://localhost:5080/public-key')
    if response.status_code == 200:
            # If the response status is OK, append the content to CApublic_Key
            CApublic_Key.append(response.content)
            print("CA Public Key fetched successfully.")

    else:
        print(f"Failed to fetch CA public key. Status code: {response.status_code}")



def CSR():
    """
    Create a Certificate Signing Request (CSR).

    The CSR is generated for the client with a common name based on the client's IP address.
    The CSR is then signed using the client's RSA private key and hashed with SHA-256.
    The result is returned as PEM-encoded bytes.
    """
    # Get the server's IP address
    server_ip = socket.gethostbyname(socket.gethostname())
    print(server_ip)

    # Build the CSR with the IP address as the common name
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, u"server-" + server_ip)
            ])
        )
        .sign(server_key, hashes.SHA256())  # Sign the CSR using the private key
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
        with open("server_cert.pem", "wb") as f:
            f.write(cert_pem)
            print("Public key certified successfully")

        # Save the private key to a file
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


@app.route('/connect', methods=['POST'])
def connect():
    data = request.get_json()

    # Extract the encrypted public key and certificate from the request
    encrypted_public_key = data['public_key']
    encrypted_cert = data['certificate']

    # Load the CA public key
    ca_public_key_pem = CApublic_Key[0]
    ca_public_key = serialization.load_pem_public_key(ca_public_key_pem)

    # Verify the certificate
    client_cert = x509.load_pem_x509_certificate(encrypted_cert)
    client_public_key = client_cert.public_key()

    try:
        ca_public_key.verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            hashes.SHA256()
        )
        print("Certificate verification succeeded.")
    except:
        print("Certificate verification failed.")
        return jsonify({"error": "Certificate verification failed."}), 400

    # Extract the public key
    public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the public key in the dictionary using the last 8 characters of the key
    public_key_id = public_key_pem.decode('utf-8')[-8:]
    privateKeyRing[public_key_id] = client_public_key

    return jsonify({"message": "Registration successful."})




if __name__ == "__main__":
    # start_server()
    certify()
    # # setCApub()
    # print(CApublic_Key[0])
    # app.run(port=5000,debug=True)
