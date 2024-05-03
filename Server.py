import socket

def start_server(host='127.0.0.1', port=65432):
    # Use socket library to create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind the socket to the specified host and port
        s.bind((host, port))
        # Listen for incoming connections
        s.listen()
        print(f"Server started at {host}:{port}. Waiting for connection...")
        
        # Accept a connection from a client
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                # Receive data from the client, up to 1024 bytes
                data = conn.recv(1024)
                if not data:
                    break  # Exit if no data is received
                # Send back the received data in uppercase
                conn.sendall(data.upper())

if __name__ == "__main__":
    start_server()
