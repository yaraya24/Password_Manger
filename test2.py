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



def update_service_password(master_password, username, service_name_to_update, new_service_password):
    csv_read_list = read_csv_to_list(username)
    with open('users/' + username + '.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        updated_password_confirm = False
        for count, row in enumerate(csv_read_list, -1):
            if row[0] == service_name_to_update or service_name_to_update == str(count) and service_name_to_update != '0' and service_name_to_update != '-1':
                selected_service_to_update = row[0]
                writer.writerow([row[0], new_service_password])
                updated_password_confirm = True
            else:
                writer.writerow([row[0], row[1]])
        if updated_password_confirm:
            print("UPDATED PASSWORD")
        else:
            print("YIKES -----")


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


update_service_password('Table123$$', 'snoop', 'Facebook', 'facebook password')
# make_deposit()
# decrypt_service_password()



