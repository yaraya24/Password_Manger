from colorama import Fore, Back, Style
from cryptography.fernet import Fernet
import bcrypt, base64, re, string, random, os, sys
from pathlib import Path
import click, csv
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def main():    
    while True:
        print(Style.RESET_ALL) 
        print(Fore.YELLOW + '**** Cyber Vault Z ****'.center(100), Fore.WHITE)
        # print(Style.RESET_ALL) 

        print("""

        Follow the instructions and you will have your very own secure vault to store all your passwords, sensitive data and even your deepest and darkest secrets.

        With hashing, ecndoding and other cryptography, rest assured your information will be kept secret 

        *** Instructions ****
        1. Enter 'create' if you want to sign up for a new swiss vault
        2. Enter 'login' if you have an account and wish to login
        3. Enter 'exit' if you wish to leave.

        """)

        

        user_instruction = input(':')
                
        if user_instruction == 'create' or user_instruction == '1':
            while True:
                user_name = click.prompt("Please enter a username - or type 'return' to go back to the previous page \n")
                if Path('users/' + user_name + '.csv').exists():
                    print (Fore.RED + "That username is already taken - please choose another", Fore.WHITE)
                    continue
                elif user_name.lower() == 'return':
                    break
                elif username_validator(user_name) == False:
                    continue
                else:
                    while True:
                        print("""

                        You are now going to enter your master password. This password is unrecoverable!

                        To keep your vault safe, the amster password you choose has to be complex.

                        * Password must contain at least one uppercase and lowercase letter.
                        * Password must contain at least one number.
                        * Password must contain at least one special character [!@#$%^&*].
                        * Password must be at least 10 characters long.
                        * Password not contain common password terms like 'password'.

                        """)

                        master_password = click.prompt("Please enter a password \n", hide_input=True, confirmation_prompt=True)
                        if password_complexity_checker(master_password):
                            hashing_function(master_password, user_name)
                            print(Fore.GREEN + "\n Successfully Created an account", Fore.WHITE)
                            break
                        else:
                            print(Fore.RED + "\n You have entered an invalid password - please try again", Fore.WHITE)
                            continue
                    
                    break
        
        elif user_instruction == 'login' or user_instruction == '2':
            while True:
                user_name = click.prompt("Username ")
                master_password = click.prompt("Password ", hide_input=True)
                authenticated = verify_master_password(master_password, user_name)
              
                if authenticated:
                    print(Fore.GREEN + "\n Successfully Logged In", Fore.WHITE)
                    while True:
                        print("""
                        Welcome to your security Vault.....

                        1. Add
                        2. Display
                        3. Edit
                        4. Logout

                        """)
                        user_instruction = input(":").lower()
                        if user_instruction == "add" or user_instruction == '1':
                            service_name = input("Please enter the name of the service you wish to add to your vault - or enter 'return' to go back \n:").capitalize()
                            if service_name == 'Return':
                                continue
                            elif check_for_duplicate_service(user_name, service_name):
                                confirmation = input(Fore.YELLOW + f"Enter 'yes' if you wish to add {service_name} to your vault - A password will be auto-generated for you\n:" + Fore.WHITE).lower()
                                if confirmation == 'yes' or confirmation == 'y':
                                    service_password = password_generator()
                                    add_service(master_password, user_name, service_name, service_password)
                                    print(Fore.GREEN + f"{service_name} has been added to your vault", Fore.WHITE)
                                else:
                                    print(Fore.RED + f"{service_name} has NOT been added to your vault", Fore.WHITE)
                                    continue

                            else:
                                print(Fore.RED + "You already have a service with that name", Fore.WHITE)
                        if user_instruction == 'display' or '2':
                            display_vault(user_name, master_password)
                    break   
                else:
                    print(Fore.RED + "\nUsername or Password is incorrect", Fore.WHITE)
                    continue
        elif user_instruction == 'exit':
           sys.exit()

def read_csv_to_list(username):
    csv_list = []
    with open('users/' + username + '.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            csv_list.append(row)
        
    return csv_list   

def display_vault(username, masterpassword):
    vault_list = read_csv_to_list(username)
    for count, row in enumerate(vault_list[1:], 1):
        print(Fore.LIGHTCYAN_EX, f"{count}. {row[0]}:  **********")


def check_for_duplicate_service(username, name):
    csv_list = read_csv_to_list(username)
    for row in csv_list:
        if name in row:
            return False
        else:
            continue
    return True

def hashing_function(password, username):
    salt = base64.b64encode(os.urandom(32))
       
    hashed_master_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 5000)
    hashed_master_password = base64.b64encode(hashed_master_password)  

    with open('users/' + username+'.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Hash', hashed_master_password.decode()])
        writer.writerow(["Salt", salt.decode()])
       
        

def verify_master_password(password_check, username):
    csv_list = []
    try:
        with open('users/' + username + '.csv', 'r') as f:
            reader = csv.reader(f)
            for count, row in enumerate(reader):
                if count <= 1:
                    csv_list.append(row)
                else:
                    break
    except FileNotFoundError:
        return False

    salt = csv_list[1][1].encode()
    password_hash = csv_list[0][1].encode()  
    check_hash = hashlib.pbkdf2_hmac('sha256', password_check.encode('utf-8'), salt, 5000)
    check_hash = base64.b64encode(check_hash)

    if str(check_hash) == str(password_hash):
        return True
    else:
        return False

def username_validator(username):

    username_regex = re.compile(r'^[a-zA-Z0-9_-]*$')
    if username_regex.search(username) is None:
         print(Fore.RED + "Sorry please only use letters, numbers, dashes and underscores", Fore.WHITE)
         return False
    elif len(username) > 20:
        print(Fore.RED + "Sorry but your username is too long....try again", Fore.WHITE)
        return False
    elif len(username) < 5:
        print(Fore.RED + "Sorry but your username is too short....try again", Fore.WHITE)
        return False
    else:
        print(Fore.GREEN + "That username is availeble", Fore.WHITE)
        return True



def password_complexity_checker(password):
    
    complexity_regex = re.compile(r'(?!.*(password))(?=.*[\!\@\#\$\%\^\&\*])(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{10,}')

    
    if complexity_regex.search(password) is None:
        return False
    else:
        return True

def password_generator():
    length = 10
    lower_letters = list(string.ascii_lowercase)
    upper_letters = list(string.ascii_uppercase)
    numbers = list(string.digits)
    special_characters = list('!@#$%^&*')
    total_possible_selection = lower_letters + upper_letters + numbers + special_characters
    password = random.choice(lower_letters)
    password += random.choice(upper_letters)
    password += random.choice(numbers)
    password += random.choice(special_characters)
    for x in range(length):
         password += random.choice(total_possible_selection)
    return password

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

def decrypt_service_password(name, master_password):
   
    read_csv_list = read_csv_to_list(username)
        
    for row in read_csv_list:
        if name in row:
            name_pw = row[1]
    
    salt = read_csv_list[1][1].encode()
   
        
    print(name_pw)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    encoding_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    print(Fernet(encoding_key).decrypt(name_pw.encode()).decode())


if __name__ == '__main__':
    main()

