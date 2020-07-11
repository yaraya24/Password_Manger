import click, csv, re, os, base64, hashlib
from pathlib import Path
import string, random


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


def add_service(master_password, username, name, specific_password):
    csv_read_list = read_csv_to_list(username)
    salt = csv_read_list[1][1].encode()
   
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    encoding_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    encoded_password = Fernet(encoding_key).encrypt(specific_password.encode())
    '***encoded_name = Fernet(encoding_key).encrypt(name.encode)****   -  UNSURE ABOUT NAME BEING ENCRYPTED JUST YET - HARD TO READ'

    with open('users/' + username + '.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([name, encoded_password.decode()])

            


def decrypt_service_password(name='', master_password=''):

    master_password = 'Respect24$$'
    
    username = 'salah'
    name = "-2"
    specific_password = "table123"
    read_csv_list = read_csv_to_list(username)
    print(read_csv_list)
    found_service=False
    for count, row in enumerate(read_csv_list, -1):
        if name in row or name == str(count) and name != str(0) and name != str(-1):
            encrypted_password = row[1]
            found_service = True
    
    salt = read_csv_list[1][1].encode()
        
    if found_service:  
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        encoding_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        decrypted_password = Fernet(encoding_key).decrypt(encrypted_password.encode()).decode()
        print(f"{decrypted_password}")
        print("The password is hidden - you must highlight it with your cursor")
    else:
        print(f"Could not find an entry with the name {name}")



# make_deposit()
decrypt_service_password()
# password_generator()


