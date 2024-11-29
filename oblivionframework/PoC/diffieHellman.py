import math
import random
import secrets
from binascii import hexlify
import hashlib
'''
Public_P and Public_G are both 
Randomly generated by the listener 
and it sends them to the victim which
it recieves as the first 2 inputs
'''

Public_P = random.randint(1, 8192)
Public_G = random.randint(1, 8192)

'''
Private_A is randomly generated by the victim
Private_A is randomly generated by the listener
'''

Private_A = random.randint(1, 8192)
Private_B = random.randint(1, 8192)

'''
Public_Key_A is calculated by the victim with
the following algorithm ->
(Public_G**Private_A) mod Public_P 
then it sends this value to the server and the
server calculates Public_Key_B with the following
algorithm (Public_G**Private_B) mod Public_P
and it sends this to the victim
'''

Public_Key_A = pow(Public_G, Private_A, Public_P) # x
Public_Key_B = pow(Public_G, Private_B, Public_P) # y

'''
Secret_Key_A is calculated on the victim machine by
(Public_Key_B**Private_A) mod Public_P and Secret_Key_B
is calculated by (Public_Key_A**Private_B) mod Public_P
on the server
'''

Secret_Key_A = pow(Public_Key_B, Private_A, Public_P)
Secret_Key_B = pow(Public_Key_A, Private_B, Public_P)

print(f'{Secret_Key_A=}')
print(f'{Secret_Key_B=}')


if(Secret_Key_A==Secret_Key_B):
    random.seed(Secret_Key_B) # and Secret_Key_A can be used interchangebly
    print(f'Encryption Key for Listener: {hexlify(random.randbytes(32)).decode()}')
    random.seed(Secret_Key_A)
    print(f'Encryption Key for Victim:   {hexlify(random.randbytes(32)).decode()}')

    random.seed(Secret_Key_B**2) # change this new seed generation

    print(f'Encryption IV for Listener:  {hexlify(random.randbytes(16)).decode()}')

    random.seed(Secret_Key_A**2) # change this new seed generation

    print(f'Encryption IV for Victim:    {hexlify(random.randbytes(16)).decode()}')