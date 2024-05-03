from flask import Flask, request, send_file, jsonify
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# Load CA private key and certificate
with open("ca_key.pem", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)

with open("ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())


@app.route('/sign-csr', methods=['POST'])
def sign_csr():
    csr_pem = request.files['csr'].read()
    csr = x509.load_pem_x509_csr(csr_pem)
    
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = client_cert.public_bytes(serialization.Encoding.PEM)
    print(cert_pem.decode('utf-8'))
    return jsonify({"certificate": cert_pem.decode('utf-8')})


if __name__ == '__main__':
    app.run(port=5000, debug=True)
