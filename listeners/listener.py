import socket
import requests
import threading
import random
from Crypto.Cipher import ChaCha20_Poly1305

Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Sock.bind(('127.0.0.1', 4444))
Sock.listen()

print("[!] Listening for connections")

Connection, Address = Sock.accept()

def Recv(Connection):
    data = []
    while True:
        part = Connection.recv(1024)
        data.append(part)
        if len(part) < 1024:
            break
    return b''.join(data)


def read_file(path):
    with open(path, "rb") as file:
        return file.read()

def write_file(path, content):
    with open(path, "wb") as file:
        file.write(content)
        file.close()
    return "[+] Download successful!"


def Session(Connection):
    Public_P = random.randint(1, 100)
    Public_G = random.randint(1, 100)
    Private_Val = random.randint(1, 100)

    Connection.send((str(Public_G) + "+" + str(Public_P)).encode())
    Public_Key = pow(Public_G, Private_Val, Public_P)
    Shared = Recv(Connection).decode()

    Connection.send(str(Public_Key).encode())

    Secret = pow(int(Shared), Private_Val, Public_P)

    #print(Secret)
    random.seed(Secret)
    key = random.randbytes(32)
    #print(f'{key=}')

    nonce = random.randbytes(100)[-24:]
    #print(f'{nonce=}')

    dCipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    eCipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

    while True:
        msg = input("Enter in message: ").encode()
        if(msg == b'terminate'):
            Connection.send(dCipher.encrypt(msg))
            Connection.close()
            exit()
        
        Connection.send(dCipher.encrypt(msg))
        message = Recv(Connection)
        print(eCipher.decrypt(message).decode())



print(f"[+] {Address} successfully connected!")

Session(Connection)
