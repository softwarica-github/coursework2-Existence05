import unittest
import threading
import socket
import tkinter as tk
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

        # Wait for the handshake signal from the client
        handshake_signal = conn.recv(1024)
        if handshake_signal != b"Ready":
            conn.close()
            continue

        # If handshake successful, proceed with communication
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

    def test_server_connection(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1', 50001))

        # Send a handshake signal to the server
        client_socket.send(b"Ready")

        # Wait for the server response (public key)
        server_public_key_data = client_socket.recv(1024)
        self.assertTrue(server_public_key_data)

        client_socket.close()

def run_client():
    host = '127.0.0.1'
    port = 50001

    with socket.create_connection((host, port)) as sock:
        # Send a handshake signal to the server
        sock.send(b"Ready")

        # Wait for the server response (public key)
        server_public_key_data = sock.recv(1024)
        server_public_key = serialization.load_pem_public_key(
            server_public_key_data,
            backend=default_backend()
        )

        root = tk.Tk()
        root.title("Client")
        root.geometry("400x300")

        def send_message(event=None):
            message = entry.get()
            if message.lower().strip() == "quit":
                root.quit()
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
            text.insert(tk.END, "Response from Server: " + data.decode() + "\n")
            entry.delete(0, tk.END)

        entry = tk.Entry(root, font=("Arial", 12))
        entry.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        entry.bind("<Return>", send_message)
        entry.focus_set()

        send_button = tk.Button(root, text="Send", command=send_message, font=("Arial", 12))
        send_button.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        text = tk.Text(root, wrap="word", font=("Arial", 12))
        text.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        def close():
            root.destroy()

        close_button = tk.Button(root, text="Close", command=close, font=("Arial", 12))
        close_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        # Configure grid weights for text widget to expand
        root.grid_rowconfigure(2, weight=1)
        root.grid_columnconfigure(0, weight=1)

        root.mainloop()

class TestClient(unittest.TestCase):
    def setUp(self):
        self.client_thread = threading.Thread(target=run_client)
        self.client_thread.start()

    def test_client_connection(self):
        # Just testing that the client thread starts without exceptions
        pass

if __name__ == "__main__":
    unittest.main()
