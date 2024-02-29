import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def run_server():
    host = '127.0.0.1'
    port = 50001

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    while True:
        conn, addr = server_socket.accept()

        # Receive the client's public key
        serialized_client_public_key = conn.recv(1024)
        client_public_key = serialization.load_pem_public_key(
            serialized_client_public_key,
            backend=default_backend()
        )

        # Send the server's public key to the client
        serialized_server_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.send(serialized_server_public_key)

        with conn:
            print("Connected from: " + str(addr))
            while True:
                data = conn.recv(1024)
                if not data:
                    break

                # Decrypt the received message using the private key
                decrypted_data = private_key.decrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print("Received from Client:", decrypted_data.decode())

                response_data = "Message Received"
                conn.send(response_data.encode())

if __name__ == "__main__":
    run_server()
