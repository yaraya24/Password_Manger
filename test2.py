import click, csv, re, os, base64, hashlib
from pathlib import Path
import bcrypt
from cryptography.fernet import Fernet, HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# value = click.prompt("enter a username", hide_input=True)

def read_csv_to_list(username):
    csv_list = []
    with open('users/' + username + '.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            csv_list.append(row)
        
    return csv_list

def make_deposit(master_password='', username='', name='', specific_password='', auto_password=''):
    master_password = 'Respect24$$'
    
    username = 'salah'
    name = "gmail"
    specific_password = "table123"

    csv_read_list = read_csv_to_list(username)
 
    salt = csv_read_list[1][1].encode()


    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    encoding_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    encoded_password = Fernet(encoding_key).encrypt(specific_password.encode())
    '***encoded_name = Fernet(encoding_key).encrypt(name.encode)****   -  UNSURE ABOUT NAME BEING ENCRYPTED JUST YET - HARD TO READ'

    with open('users/' + username + '.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([name, encoded_password.decode()])
        

    # DECODING TIME #


    # print(f,'new')
    # print(Fernet(key11).decrypt(f).decode())


def decrypt(name='', master_password=''):

    master_password = 'Respect24$$'
    
    username = 'salah'
    name = "gmail"
    specific_password = "table123"
    read_csv_list = read_csv_to_list(username)
        
    for row in read_csv_list:
        if name in row[0]:
            name_pw = row[1]
    
    salt = read_csv_list[1][1].encode()
    # print(csv_list)
        
    print(name_pw)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    encoding_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    print(Fernet(encoding_key).decrypt(name_pw.encode()))

# make_deposit()
decrypt()


