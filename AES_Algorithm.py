import os
from math import ceil

from Crypto.Cipher import AES

def generate_AES_key()-> str:
    return os.urandom(16)

def AES_Encrypt( key, message)-> str:
    AES_Encryptor = AES.new(key, AES.MODE_CBC, b'0000000000000000')
    return AES_Encryptor.encrypt(message)

def AES_Decrypt( key, ciphertext)-> str:
    AES_Decryptor = AES.new( key, AES.MODE_CBC, b'0000000000000000')
    return AES_Decryptor.decrypt(ciphertext)

def Add_padding(message):
    global pad_length
    length= len(message)
    required_bytes=length%16
    pad_length=16-required_bytes
    if pad_length!=16:
        k=message + b' ' * pad_length
    else :
        k=message

    return k , pad_length

def AES_encryption(key, message):
    k = bytes(key, 'utf-8')
    m= bytes(message, 'utf-8')
    message_with_padding, padding_length=Add_padding(m)
    run= ceil(len(message_with_padding)/16)
    cipher=b''
    for i in range(run):
        cipher=cipher+ AES_Encrypt(k,message_with_padding[i*16:((i+1)*16)])
    return str(cipher,'utf-16','surrogatepass')+"|"+str(padding_length)

def AES_decryption(key, ciphertext ):

    spliting= ciphertext.split('|')
    k =bytes(key, 'utf-8')
    cipher=bytes(spliting[0],'utf-16','surrogatepass')[2:]
    pad_length=int(spliting[1])
    run= ceil(len(cipher)/16)
    text=b''
    for i in range(run):
        text=text+ AES_Decrypt(k,cipher[i*16:((i+1)*16)])
    return str(text[:-pad_length],'utf-8')


# key ="0123456789abcdef"
# message="asdfasdf"
# c=encryption(key,message)
# dd=decryption(key,c)
# print(dd)



