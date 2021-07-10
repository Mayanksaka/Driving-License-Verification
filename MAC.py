import binascii
import hashlib
import os

from RSA import *


def create_hash(information):
    HashedValue = hashlib.sha256(information.encode())
    return HashedValue.hexdigest()

def sending_process(information, RSA_key,n):
    print(information)
    encrypted_hash= encrypt(create_hash(information),RSA_key,n)
    concatenatedValue=information+'(&)'+encrypted_hash
    return concatenatedValue

def compare(Data,RSA_key,n):
    Value= Data.split('(&)')
    information=Value[0]
    encrypted_hash= Value[1]
    Hash_by_info= create_hash(information)
    # print(Hash_by_info)
    Hash_by_decoding= decrypt(encrypted_hash,RSA_key,n)
    # print(Hash_by_decoding)
    if(Hash_by_decoding==Hash_by_info):
        print("Hash Verified")
        return True
    else:
        print("Either information or Hash Value has been changed")
        return False

