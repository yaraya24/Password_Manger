from colorama import Fore, Back, Style
from cryptography.fernet import Fernet
import bcrypt, base64, re

from pathlib import Path
import click, csv
import os 
import hashlib

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
                    print ("That username is already taken - please choose another")
                    continue
                elif user_name == 'return':
                    break
                elif len(user_name) > 18:
                    print("Sorry but that is too long of a username....try again")
                    continue
                elif len(user_name) < 5:
                    print("Sorry but that username is too short...try again")
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
                            print(Fore.YELLOW + "\n Successfully Created an account", Fore.WHITE)
                            break
                        else:
                            print(Fore.YELLOW + "\n You have entered an invalid password - please try again", Fore.WHITE)
                            continue
                    
                    break
        
        elif user_instruction == 'login' or user_instruction == '2':
            while True:
                user_name = click.prompt("Username ")
                master_password = click.prompt("Password ", hide_input=True)
                authenticated = verify_master_password(master_password, user_name)
              
                if authenticated:
                    print(Fore.RED + "\n Successfully Logged In", Fore.WHITE)
                    while True:
                        print("""
                        Welcome to your security Vault.....

                        1. add
                        2. Edit
                        3. Display
                        4. Logout

                        """)
                        user_instruction = input(":")
                        if user_instruction.lower() == "add" or user_instruction == '1':
                            security_name = input("Please ")

                    break   
                else:
                    print(Fore.RED + "\nUsername or Password is incorrect", Fore.WHITE)
                    continue


    


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


def password_complexity_checker(password):
    
    complexity_regex = re.compile(r'(?!.*(password))(?=.*[\!\@\#\$\%\^\&\*])(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{10,}')

    
    if complexity_regex.search(password) is None:
        return False
    else:
        return True


            
if __name__ == '__main__':
    main()

