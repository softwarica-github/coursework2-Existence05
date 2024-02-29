import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def run_client():
    host = '127.0.0.1'
    port = 50001

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize the public key
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with socket.create_connection((host, port)) as sock:
        # Send the public key to the server
        sock.send(serialized_public_key)

        # Receive the server's public key
        server_public_key = sock.recv(1024)
        server_public_key = serialization.load_pem_public_key(
            server_public_key,
            backend=default_backend()
        )

        while True:
            # Input message to send to the server
            message = input(">> ")
            if message.lower().strip() == "quit":
                break

            # Encrypt the message with server's public key
            encrypted_message = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            sock.send(encrypted_message)

            # Receive response from the server
            data = sock.recv(1024)
            print("Response from Server : " + data.decode())

if __name__ == "__main__":
    run_client()
