"""
Implimentation of certification authority.

Certificate will be stored as a dictionary.
Format of Certificate (as per assignment document)

Certificate (of A(client)) = {
    ID (of A): int 
    Public Key (of A): int (maintain a set of issued IDs)
    Time (of issuing) : ctime (time elapsed since epoch)
    Duration (validity of certificate) : 1000 (seconds), some constant 
    ID (of Certification authority) : 0
}

The certificate will be encrypted (as per requirement). Encryption method 
followed will be to convert dictionary to a string diretly, then encrypt each 
character.
"""
import datetime

from MAC import *
from RSA import encrypt,decrypt,generate_keys_RSA;
from AES_Algorithm import *
from time import time
import socket;
from _thread import *;


DataBase= {"0001": "1101|"+str(time()+2592000)+"| Rohit",
           "0002": "1102|"+str(time()+2592500)+"| Abhinav",
           "0003": "1103|"+str(time()+2592600)+"| Aditya",
           "0004": "1104|"+str(time()+2592700)+"| Parbinder",
           "0005": "1105|"+str(time()+2592800)+"| Pawan",
           "0006": "1106|"+str(time()+2592900)+"| Raj",
           "0007": "1107|"+str(time()+2592100)+"| Kunal",
           "0008": "1108|"+str(time()-2592300)+"| Mayank",
           "0009": "1109|"+str(time()-2592400)+"| Om",
           "0010": "1110|"+str(time()-2592500)+"| Jai",
           "0011": "1111|"+str(time()-2592600)+"| Raghav",
           "0012": "1112|"+str(time()-2592700)+"| Kritika",
           "0013": "1113|"+str(time()-2592800)+"| Nitika",
           "0014": "1114|"+str(time()-2592900)+"| Parmjeet",
           "0015": "1115|"+str(time()-2592000)+"| Karan",
           }
def provide_certificate(A_e:int, A_n:int)->str:
    """ returns string representation of certificate"""
    global ID,issuedCertificates;

    certificate = dict();
    while(ID in issuedCertificates):
        ID+=1
    certificate['ID_A'] = ID;
    certificate['PU_A'] = (A_e,A_n);
    certificate['TIME'] = time();
    certificate['DURATION'] = 1000; #seconds
    certificate['ID_CA'] = 42;
    issuedCertificates[ID] = certificate;
    return str(certificate);

def getIntTupleFromString(tup:str)->tuple:
    tup = tup[1:len(tup)-1];
    l = tup.split(',');
    return (int(l[0]),int(l[1]))

def threaded_client(conn:socket):
    print("Connected by : ",addr);
    global issuedCertificates;
    
    while True:
    
        inputBytes_fromUser = conn.recv(10024); 
        if not inputBytes_fromUser:
            break;
        encrypted_request = inputBytes_fromUser.decode('utf-16','surrogatepass');
        request = decrypt(encrypted_request,d,n).split('|');
        print(request)
        key=request[0]

        print('AES_key is recieved')
        IDs = getIntTupleFromString(''.join(request[1].split()));
        A = IDs[0];
        B = IDs[1];
        print("key :" + key)
        verifie = AES_encryption(key, "True")
        conn.sendall(verifie.encode('utf-16', 'surrogatepass'));
        print("sending verification ...")

        driver_info= conn.recv(10024);
        if not driver_info:
            break;
        encrypted_request = driver_info.decode('utf-16', 'surrogatepass');
        request = AES_decryption(key,encrypted_request);
        if(compare(request,A,B)):
            data=request.split('(&)')
            info=data[0].split('|')
            fingerprint_value = info[0]
            license_value= info[1]

            veri=''
            if fingerprint_value in DataBase:
                Dataset = DataBase.get(fingerprint_value).split('|')
                if(Dataset[0]==license_value):
                    if(float(Dataset[1])>=time()):
                        veri="All Good"
                    else:
                        veri="Licence Expired"
                else:
                    veri= "Licence is Duplicate"
            else:
                veri= "User has no licence"
        encrypted_response = AES_encryption(key,sending_process(veri,d,n))
        conn.sendall(encrypted_response.encode('utf-16','surrogatepass'));
        print("Final Process complete")

    print('Closing Connection')
    conn.close();

print("LICENCE AUTHORITY")
HOST = '127.0.0.1';
# PORT = int(input("Enter Port number : "));
PORT= 90

KEYS = generate_keys_RSA(251, 223);
e = KEYS['Public'][0];
d = KEYS['Private'][0];
n = KEYS['Public'][1];
assert(n == KEYS['Private'][1]);
print("Private Key = "+str(KEYS['Private']))



ID = 1999;
issuedCertificates = dict();

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST,PORT));
    s.listen(5);
    while True:
        conn,addr = s.accept();
        start_new_thread(threaded_client,(conn,)); 