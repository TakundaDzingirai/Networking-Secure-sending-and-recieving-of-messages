import socket
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa



serverURL ="http://localhost:5000/"

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
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, u"client-" + client_ip)
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

def send_certificate_and_key(cert_path, key_path, server_url):
    """
    Sends the client's certificate and public key to the server.

    Args:
        cert_path (str): The path to the client's certificate file.
        key_path (str): The path to the client's private key file.
        server_url (str): The server URL for the /connect endpoint.
    """
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

    # Send the data to the server
    response = requests.post(server_url, json=data)

    # Handle the response
    if response.status_code == 200:
        print("Successfully connected to the server.")
        print(response.json())
    else:
        print(f"Failed to connect to the server. Status code: {response.status_code}")
        print(response.text)


# Example usage


if __name__ == "__main__":
    certify()  # Obtain the client certificate
#     send_certificate_and_key(
#     cert_path="client_cert.pem",
#     key_path="client_key.pem",
#     server_url="http://localhost:5000/connect"
# )
