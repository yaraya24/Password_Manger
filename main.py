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
        print(Fore.LIGHTCYAN_EX + '**** PASSWORD MANAGER X ****'.center(100), Fore.WHITE)
        print("""

        Follow the instructions and you will have your very own secure vault to store all your passwords, sensitive data and even your deepest and darkest secrets.

        With hashing, ecndoding and other cryptography, rest assured your information will be kept secret 

        """ + Fore.YELLOW + "*** Instructions ****" + Fore.WHITE + """
        1. Enter 'create' if you want to sign up for a new swiss vault
        2. Enter 'login' if you have an account and wish to login
        3. Enter 'exit' if you wish to leave.

        """)

        

        user_instruction = input(':').lower()
                
        if user_instruction == 'create' or user_instruction == '1':
            while True:
                user_name = input(Fore.YELLOW + "Please enter a username - or type 'back' to go back to the previous page \n" + Fore.WHITE)
                if Path('users/' + user_name + '.csv').exists():
                    print (Fore.RED + "That username is already taken - please choose another", Fore.WHITE)
                    continue
                elif user_name.lower() == 'back':
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
                print(Fore.YELLOW + "Enter 'back' to return to the previous page.", Fore.WHITE)
                user_name = click.prompt("Username ")
                if user_name.lower() == 'back':
                    break
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
                            service_name = input("Please enter the name of the service you wish to add to your vault - or enter 'back' to go back \n:").capitalize()
                            if service_name == 'Back':
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
                        elif user_instruction == 'display' or user_instruction == '2':
                            while True:
                                if display_vault(user_name, master_password) == False:
                                    print(Fore.RED + "You have an empty Vault - make some entries first", Fore.WHITE)
                                    break
                                else:
                                    service_name_to_reveal = input(Fore.YELLOW + "\nEnter the name of the service to view the password - or enter 'back' to go back\n:" + Fore.WHITE).capitalize()
                                    if service_name_to_reveal == 'Back':
                                        break
                                    elif check_service_exists(user_name, service_name_to_reveal):
                                        decrypt_service_password(service_name_to_reveal, user_name, master_password)
                                        break
                                    else:
                                        print(Fore.RED + f"Sorry didn't understand the selection: {service_name_to_reveal}.", Fore.WHITE)
                                        continue
                                   
                        elif user_instruction == 'update' or '3':
                            while True:
                                display_vault(user_name, master_password)
                                service_name_to_update = input(Fore.YELLOW + "\nEnter the name of the service to update the password - or enter 'back' to go back\n:" + Fore.WHITE).capitalize()
                                if service_name_to_update == 'Back':
                                    break
                                elif check_service_exists(user_name, service_name_to_update):
                                    print(Fore.YELLOW + f"\n***Options for {check_service_exists(user_name, service_name_to_update)}***\n" + Fore.WHITE + "1. Update Password\n2. Delete Entry\n")
                                    edit_user_option = input(":").lower()
                                    if edit_user_option == 'back':
                                        continue
                                    elif edit_user_option == "update" or edit_user_option == "update password" or edit_user_option == "1":
                                        confirmation_input = input(Fore.YELLOW + f"Confirm by entering 'yes' - A password will be auto-generated for you\n" + Fore.RED + "WARNING: THE CURRENT PASSWORD WILL BE REMOVED FOREVER \n" + Fore.WHITE + ":").lower()
                                        if confirmation_input == 'yes' or confirmation_input == 'y':
                                            update_service_password(master_password, user_name, service_name_to_update)
                                            break
                                        else:
                                            print(Fore.RED + f"Confirmation Failed - Nothing was updated", Fore.WHITE)
                                            continue
                                    elif edit_user_option == "delete" or edit_user_option == "delete entry" or edit_user_option == "2":
                                        "================================= WRITE HERE ======================="
                                    else:
                                        print(Fore.RED + f"Sorry didn't understand the selection: {edit_user_option}.", Fore.WHITE)
                                else:
                                    print(Fore.RED + f"Sorry didn't understand the selection: {service_name_to_update}.", Fore.WHITE)
                                    continue


                    break #no idea what this break down

                else:
                    print(Fore.RED + "\nUsername or Password is incorrect", Fore.WHITE)
                    continue
        elif user_instruction == 'exit' or user_instruction == '3':
           sys.exit()
        else:
            print(Fore.RED + f"Don't understand the instruction: {user_instruction}")
            continue

def read_csv_to_list(username):
    csv_list = []
    with open('users/' + username + '.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            csv_list.append(row)
        
    return csv_list   

def display_vault(username, masterpassword):
    vault_list = read_csv_to_list(username)
    print()
    if len(vault_list) < 3:
        return False
    else:
        for count, row in enumerate(vault_list[2:], 1):
            print(Fore.LIGHTCYAN_EX, f"{count}. {row[0]}", Fore.WHITE)


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
    
    complexity_regex = re.compile(r'(?=.*[\!\@\#\$\%\^\&\*])(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{10,}')

    
    if complexity_regex.search(password) is None:
        return False
    else:
        return True

def password_generator():
    length = 10
    lower_letters = list(string.ascii_lowercase)
    upper_letters = list(string.ascii_uppercase)
    numbers = list(string.digits)
    special_characters = list('!@#$%^&*' * 3)
    total_possible_selection = lower_letters + upper_letters + numbers + special_characters
    password = random.choice(lower_letters)
    password += random.choice(upper_letters)
    password += random.choice(numbers)
    password += random.choice(special_characters)
    for x in range(length):
         password += random.choice(total_possible_selection)
    return password

def encrypt_password_function(master_password, username, specific_password):
    csv_read_list = read_csv_to_list(username)
    salt = csv_read_list[1][1].encode()
   
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    encoding_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    encoded_password = Fernet(encoding_key).encrypt(specific_password.encode())
    return encoded_password

def add_service(master_password, username, name, specific_password):

    encrypted_password = encrypt_password_function(master_password, username, specific_password)
    '***encoded_name = Fernet(encoding_key).encrypt(name.encode)****   -  UNSURE ABOUT NAME BEING ENCRYPTED JUST YET - HARD TO READ'

    with open('users/' + username + '.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([name, encrypted_password.decode()])

def check_service_exists(username, service_name):
    read_csv_list = read_csv_to_list(username)
    found_service = False   
    for count, row in enumerate(read_csv_list, -1): 
        if service_name in row or service_name == str(count) and service_name != '0' and service_name != '-1':
            found_service_name = row[0]
            found_service = True
    if found_service == True:
        return found_service_name
    else:
        return False

def decrypt_service_password(service_name, username, master_password):
   
    read_csv_list = read_csv_to_list(username)
    found_service = False   
    for count, row in enumerate(read_csv_list, -1): 
        if service_name in row or service_name == str(count) and service_name != '0' and service_name != '-1':
            encrypted_password = row[1]
            found_service_name = row[0]
            found_service = True
    
    salt = read_csv_list[1][1].encode()
   
    if found_service:  
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        encoding_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        decrypted_password = Fernet(encoding_key).decrypt(encrypted_password.encode()).decode()
        print(Fore.LIGHTCYAN_EX + f"{found_service_name}:")
        print(Fore.LIGHTGREEN_EX + "->" + Fore.BLACK + f"{decrypted_password}" + Fore.LIGHTGREEN_EX + "<-")
        print(Fore.YELLOW + "The password is hidden - you must highlight it with your cursor", Fore.WHITE)
    else:
        print(Fore.RED + f"Invalid option - could not find that service", Fore.WHITE)

def update_service_password(master_password, username, service_name_to_update):
    csv_read_list = read_csv_to_list(username)
    new_service_password = password_generator()
    new_encrypted_password = encrypt_password_function(master_password, username, new_service_password)
    with open('users/' + username + '.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        updated_password_confirm = False
        for count, row in enumerate(csv_read_list, -1):
            if row[0] == service_name_to_update or service_name_to_update == str(count) and service_name_to_update != '0' and service_name_to_update != '-1':
                selected_service_to_update = row[0]
                writer.writerow([row[0], new_encrypted_password.decode()])
                updated_password_confirm = True
            else:
                writer.writerow([row[0], row[1]])
        if updated_password_confirm:
            print(Fore.GREEN + f"Password for {selected_service_to_update} has been successfully updated." + Fore.WHITE)
        else:
            print(Fore.RED + "Password has not been updated - could not recognise selection" + Fore.WHITE)


if __name__ == '__main__':
    main()

