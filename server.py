import base64
import socket

from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# keys for rsa
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def server_program():
    host = '127.0.0.1'  # localhost
    port = 65432  # port

    private_key, public_key = generate_keys()
    print("Server keys generated.")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server running on {host}:{port}")

    conn, addr = server_socket.accept()
    print(f"Connected to {addr}")

    conn.send(public_key)
    print("Server's public key sent to the client.")

    premaster_secret = conn.recv(256)
    print(f"Received secret from the client (Base64): {base64.b64encode(premaster_secret).decode()}")
    #print(f"Received secret from the client: {base64.b64encode(premaster_secret).decode()}")

    private_key_obj = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key_obj)
    decrypted_secret = cipher.decrypt(premaster_secret)
    print(f"Decrypted secret: {decrypted_secret.decode('utf-8')}")

    server_random = get_random_bytes(16)
    print(f"Client random: {server_random.hex()}")

    session_key = PBKDF2(premaster_secret, server_random, dkLen=32)
    print(f"Generated session key: {session_key.hex()}")

    conn.send(b"ready")
    print("Message 'ready' sent to the client.")

    filename = "message.txt"
    with open(filename, "w") as f:
        f.write("You did it!")
    print(f"File {filename} generated.")

    with open(filename, "rb") as f:
        file_data = f.read()
    conn.send(file_data)
    print(f"File {filename} sent to the client.")

    conn.close()
    print("Connection closed.")


if __name__ == "__main__":
    server_program()
