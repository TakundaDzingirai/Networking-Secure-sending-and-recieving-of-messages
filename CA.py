from flask import Flask, request, send_file, jsonify
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import padding
import io

import os
import getpass
password = "CA0011000000jhdkbsldnf;;lngtmng;'r,v'f".encode("utf-8")
app = Flask(__name__)

def create_ca():
    # Generate RSA Key Pair for the CA
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Prompt the user for a password
 

    # Save CA Key with encryption
    with open("ca_key.pem", "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password),
            )
        )

    # Create a CA Certificate
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Cape Town"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"UCT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"PTV"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"PTV CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Save CA Certificate
    with open("ca_cert.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))


create_ca()
# Load CA private key and certificate

# Prompt for password to load the key


with open("ca_key.pem", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=password)

with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

@app.route('/sign-csr', methods=['POST'])  # Define a Flask route to handle incoming CSR signing requests
def sign_csr():
    csr_pem = request.files['csr'].read()  # Read the CSR file from the incoming request
    csr = x509.load_pem_x509_csr(csr_pem)  # Load the CSR using the cryptography library
    
    
    # Verify that the CSR is signed correctly using the client's private key
    try:
       
        csr.public_key().verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            padding.PKCS1v15(),  # Use the appropriate padding scheme for RSA
            csr.signature_hash_algorithm,
        )
        print("CSR signature verification succeeded.")
    except:
        print("CSR signature verification failed.")
        return jsonify({"error": "CSR signature verification failed."}), 400

    client_cert = (  # Build the client's certificate using the CSR details
            x509.CertificateBuilder()
            .subject_name(csr.subject)  # Set the subject of the certificate to the CSR's subject
            .issuer_name(ca_cert.subject)  # Set the issuer of the certificate to the CA's subject
            .public_key(csr.public_key())  # Set the public key of the certificate to the CSR's public key
            .serial_number(x509.random_serial_number())  # Generate a random serial number for the certificate
            .not_valid_before(datetime.utcnow())  # Set the certificate's start date to the current time
            .not_valid_after(datetime.utcnow() + timedelta(days=365))  # Set the certificate's expiration date to 1 year from now
            .add_extension(  # Add an extension to specify that this certificate is not a CA
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )
            .sign(ca_key, hashes.SHA256())  # Sign the certificate using the CA's private key and SHA-256 hash
        )

    cert_pem = client_cert.public_bytes(serialization.Encoding.PEM)
    
    return jsonify({"certificate": cert_pem.decode('utf-8')})


@app.route('/public-key', methods=['GET'])
def get_public_key():
    print("Here")
    public_key = ca_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return send_file(
        io.BytesIO(public_key_pem),
        as_attachment=True,
        download_name="ca_public_key.pem",
        mimetype="application/x-pem-file"
    )

if __name__ == '__main__':
    app.run(port=5080, debug=True)
