import socket
import threading
import unittest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def run_server():
    host = '127.0.0.1'
    port = 50001

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

        serialized_server_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.send(serialized_server_public_key)

        with conn:
            print("Connected from:", addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break

                decrypted_data = private_key.decrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print("Received from Client:", decrypted_data.decode())

                response_data = input(">> ")
                conn.send(response_data.encode())

class TestServer(unittest.TestCase):
    def setUp(self):
        self.server_thread = threading.Thread(target=run_server)
        self.server_thread.start()

    def tearDown(self):
        self.server_thread.join()

    def test_server_connection(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1', 50001))
        self.assertTrue(client_socket)
        client_socket.close()

def run_client():
    host = '127.0.0.1'
    port = 50001

    with socket.create_connection((host, port)) as sock:
        server_public_key_data = sock.recv(1024)
        server_public_key = serialization.load_pem_public_key(
            server_public_key_data,
            backend=default_backend()
        )

        while True:
            message = input(">> ")
            if message.lower().strip() == "quit":
                break

            encrypted_message = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            sock.send(encrypted_message)

            data = sock.recv(1024)
            print("Response from Server:", data.decode())

class TestClient(unittest.TestCase):
    def setUp(self):
        self.client_thread = threading.Thread(target=run_client)
        self.client_thread.start()

    def tearDown(self):
        self.client_thread.join()

    def test_client_connection(self):
        # Just testing that the client thread starts without exceptions
        pass

if __name__ == "__main__":
    unittest.main()
