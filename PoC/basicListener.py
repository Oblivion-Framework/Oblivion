import zmq
import random


def Encrypt(message, key):
    cipher = ''
    for i in message:
        cipher += chr(ord(i) ^ key)
    return cipher

def Decrypt(cipher, key):
    message = ''
    for i in cipher:
        message += chr(ord(i) ^ key)
    return message


context = zmq.Context()
socket = context.socket(zmq.PAIR)
socket.bind("tcp://127.0.0.1:4444")
print("[!] Started listener")

if(socket.recv() != b"zerodium"):
    print("[-] Unauthorized connection terminating!")
    socket.close()
    context.term()
    exit()

### establish diffie hellman

Public_P = random.randint(1, 100)
Public_G = random.randint(1, 100)
Private_Val = random.randint(1, 100)

socket.send((str(Public_G) + "+" + str(Public_P)).encode())

print(f"{Public_G=} and {Public_P=}")
#Shared = socket.recv().decode()

Public_key = pow(Public_G, Private_Val, Public_P)
Shared = socket.recv().decode()

socket.send(str(Public_key).encode())

Secret = pow(int(Shared), Private_Val, Public_P)

print(f"{Secret=}")

### finish establishing diffie hellman

while True:
    message = input("Enter message: ")
    socket.send(Encrypt(message, Secret).encode())
    print(f'Recieved: {Decrypt(socket.recv().decode(), Secret)}')  
