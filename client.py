"""
Client will interact with Certification authority as well as 
with itself.
"""




import socket;
from MAC import *
from RSA import encrypt,decrypt,generate_keys_RSA;
from Crypto.Cipher import AES
from AES_Algorithm import *



def getKeys(tup:str)->tuple:
    tup = tup[1:len(tup)-1];
    l = tup.split(',');
    print(l)
    return (int(l[0]),int(l[1]))

# def get_user_input()->int:
#     print("""
#         __________________________________
#         | 1. Get new Certificate.        |
#         | 2. Verify Certificate.         |
#         | 3. Chat with another client.   |
#         |                                |
#         | 0. Exit                        |
#         |________________________________|
#         """)
# def loop()->None:
#     choice = -1;
#     while choice != 0:
#         choice = get_user_input();
#         if choice == 1:
#             #get new certificate
#             3+890;
#         elif choice == 2:
#             #verify certificate
#             2+890;
#         elif choice == 3:
#             #chat with a client
#             3+4;


HOST = '127.0.0.1'
# server_KEYS = getKeys(str(input("Enter server public key : ")));
# server_e = int(server_KEYS[0])
# server_n = int(server_KEYS[1])
server_e=257
server_n=55973

# server_PORT = int(input("Enter server port number : "));
server_PORT=90

# NAME = input("Enter client Name : ");
# PORT = input("Enter "+NAME+"'s port number : ");
# print("Some suggestions [229, 233, 239, 241]")
PORT='12'
# P = int(input("Enter prime number p : "));
# Q = int(input("Enter prime number q : "));
P=229
Q=233
KEYS = generate_keys_RSA(P,Q);
e = KEYS['Public'][0];
d = KEYS['Private'][0];
n = KEYS['Public'][1];
assert(n == KEYS['Private'][1]);
print("Keys Generated succesfully!");
print("Your public key = ",(e,n));
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST,server_PORT));
    print("connected with server ....")
    # print("generating AES key ....")
    key=str(binascii.b2a_hex(os.urandom(8)),'utf-8')
    print("key generated ....")
    m = encrypt(key+'| '+str((e,n)),server_e,server_n);
    s.sendall(bytes(m.encode('utf-16','surrogatepass')));
    print('key_sent')

    data=s.recv(10024)
    da=data.decode('utf-16', 'surrogatepass')
    verify= AES_decryption(key,da)
    print("verify recieved")

    if verify=="True":
        print("Registered fingerprints :")
        print("0001,0002,0003,0004,0005,0012,0013,0014,0015")
        fingerprint = input("Add fingerprint : ")
        print("Driving Licences respectively :")
        print("1101,1102,1103,1104,1105,1112,1113,1114,1115")
        information= input("Driving License No.: ")
        info=fingerprint+'|'+information
        packet= sending_process(info,d,n)
        m = AES_encryption(key,packet);
        s.sendall(bytes(m.encode('utf-16', 'surrogatepass')));
    data = s.recv(10024);
    final = AES_decryption(key,data.decode('utf-16','surrogatepass'));
    if (compare(final, server_e, server_n)):
        check = final.split('(&)')
        # print(check[0])
print('Recieved : ',str(check[0]));