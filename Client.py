import socket
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa





def createCSR():
    # Generate RSA Key Pair for the client
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# Create a CSR
    # name = input("Enter clientName")
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, u"client.example.com")
            ])
        )
        .sign(client_key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return csr_pem
    


def certify():
    # Send the CSR to the CA server
    csr_pem =createCSR()
    response = requests.post('http://localhost:5000/sign-csr', files={'csr': csr_pem})

    # Check response and save certificate
    if response.status_code == 200:
        cert_pem = response.json().get("certificate").encode('utf-8')
        with open("client_cert.pem", "wb") as f:
            f.write(cert_pem)
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
    # Use socket library to create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect to the specified server host and port
        s.connect((server_host, server_port))
        # Send a byte string to the server
        s.sendall(b'Hello, server!')
        # Receive the response from the server
        data = s.recv(1024)
        print(f"Received from server: {data.decode()}")

if __name__ == "__main__":
    start_client()
