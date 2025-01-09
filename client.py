import base64
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def client_program():
    host = '127.0.0.1' # localhost
    port = 65432 # port

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("Successfully connected to the server.")

    public_key_data = client_socket.recv(2048)
    public_key = RSA.import_key(public_key_data)
    print("Server's public key received.")

    premaster_secret = b"secret"
    print(f"Generated secret: {premaster_secret.decode()}")

    cipher = PKCS1_OAEP.new(public_key)
    encrypted_secret = cipher.encrypt(premaster_secret)
    print("Secret encrypted with the server's public key. Encoded secret (Base64):", base64.b64encode(encrypted_secret).decode())
    #print("Secret encrypted with the server's public key. Encoded secret:", encrypted_secret)

    client_socket.send(encrypted_secret)
    print("Encrypted secret sent to the server.")

    ready_message = client_socket.recv(1024)
    print(f"Received message from the server: {ready_message.decode()}")

    with open("received_file.txt", "wb") as f:
        file_data = client_socket.recv(1024)
        while file_data:
            f.write(file_data)
            file_data = client_socket.recv(1024)
        print("File received.")

    client_socket.close()
    print("Connection with the server closed.")


if __name__ == "__main__":
    client_program()
