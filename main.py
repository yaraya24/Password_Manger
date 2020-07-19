from colorama import Fore, Back, Style
from cryptography.fernet import Fernet
import base64, re, string, random, os, sys
from pathlib import Path
import click, csv
import hashlib
 
from datetime import date, datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def main():   
   
 # Opening screen when the program is first run, provides options to create an account, login or exit
 # While loop used so that screen is repeatedly shown unless client enters 'exit' or goes further into the application
    while True:
        print(Style.RESET_ALL) 
        print(Fore.LIGHTCYAN_EX + '**** PASSWORD MANAGER X ****'.center(100), Fore.WHITE)
        # Basic insutrcutions for the user and brief description of the application
        print("""

        Welcome to Password Manager X. With an ever increasing emphasis on security on the world wide web, 
        Password Manager X will allow you to store all your passwordws in a safe place. 

        Utilising the most effective cryptography technology - rest assured your passwords will ketp safe.



        """ + Fore.YELLOW  + """
        1. Enter 'CREATE' if you want to sign up for a Password Manager X account
        2. Enter 'LOGIN' if you have an account and wish to login
        3. Enter 'EXIT' if you wish to leave.

        """ + Fore.WHITE)

        user_instruction = input(':').lower()

        # If function if user enters 'create' or '1' will allow user to create an account    
        if user_instruction == 'create' or user_instruction == '1':
            while True:
                user_name = input(Fore.YELLOW + "Please enter a username - or type 'back' to go back to the previous page \n" + Fore.WHITE)
                # Checks if the username that is provided already exists by checking the path ./users
                if Path('users/' + user_name + '.csv').exists(): 
                    print (Fore.RED + "That username is already taken - please choose another", Fore.WHITE)
                    continue
                # Breaks out of loop if client wants to return to opening screen  
                elif user_name.lower() == 'back':
                    break
                elif username_validator(user_name) == False:
                    continue
                else:
                    while True:
                         # Provides user instructions on what is required for the password
                        print("""

                        You are now going to enter your master password. This password is unrecoverable!

                        To keep your vault safe, the master password you choose has to be sufficiently complex.

                        * Password must contain at least one uppercase and lowercase letter.
                        * Password must contain at least one number.
                        * Password must contain at least one special character [!@#$%^&*].
                        * Password must be at least 10 characters long.
                        
                        """)

                      

                        master_password = click.prompt("Please enter a password \n", hide_input=True, confirmation_prompt=True)
                        
                        # Checks if password meets the complexity requirements using regular expression
                        if password_complexity_checker(master_password):
                            # Calls the hashing function providing the accepted master password and username to hash the master password and store it
                            # in a new csv file with the user_naame as the name of the csv file
                            hashing_function(master_password, user_name)
                            print(Fore.GREEN + "\n Successfully Created an account", Fore.WHITE)
                            break
                        else:
                            # Return to top of the loop in line 54 so client can re-attempt providing a valud password and creating an account
                            print(Fore.RED + "\n You have entered an invalid password - please try again", Fore.WHITE)
                            continue
                    
                    break
        
        # To enter the below loop if client wishes to login
        elif user_instruction == 'login' or user_instruction == '2':
            while True:
                # Read the 'check.csv' file to see if the user is locked out from logging in
                # If the second value is the string 'locked' it will read the third item which is a timestamp
                # It will then compare the timestamp in the csv to the timestamp now and if it's been less than 5 minutes, it will break to the previous loop so the user cannot continue
                lockout_list = read_csv_to_list('check')
                if lockout_list[0][1] == 'locked':
                    time_now = datetime.now()
                    date = lockout_list[0][2].split()[0]
                    time = lockout_list[0][2].split()[1]
                    year, month, day = map(int, date.split('-'))
                    hour, minute, second = map(int, time.split(':'))
                    check_time = datetime(year, month, day, hour, minute, second)
                    difference_lockout_time = time_now - check_time
                    if difference_lockout_time.seconds < 300:
                        print(Fore.RED + "You have been locked out for 5 minutes" + Fore.WHITE)
                        break
                            
                   
                print(Fore.YELLOW + "Enter 'back' to return to the previous page.", Fore.WHITE)
                user_name = click.prompt("Username ")
                if user_name.lower() == 'back':
                    break
                master_password = click.prompt("Password ", hide_input=True)

                # Function that returns True if the password matches and False if it doesn't
                authenticated = verify_master_password(master_password, user_name)

                if authenticated:
                    # Resets the number of time client has failed to login once there is a successful login
                    lockout_timer(0)
                    print(Fore.GREEN + "\n Successfully Logged In", Fore.WHITE)
                    login_attempt_count = 0 
                    while True:
                        # Checks if there are any passwords that haven't been updated in 90 days, if so it prints a caution at the top of the screen every time user returns to their account
                        check_expiry_password(user_name)
                        print('\n')
                        print(Fore.LIGHTCYAN_EX + '**** PASSWORD MANAGER X ****'.center(100) + Fore.WHITE + f"""

                        Welcome to your Passowrd Manager X account {user_name}

                        Please enter the one of the below options by entering the option's name or corresponding number.

                        From this page, you can add a service with an auto-generated password, display all your passwords and update or remove your choice of passwords.

                        """ + Fore.YELLOW + f"""
                        1. Enter 'ADD' to add a service to the password manager
                        2. Enter 'DISPLAY' to reveal the password for a specific service
                        3. Enter 'EDIT' to update your password or remove a service
                        4. Enter 'LOGOUT' to leave your account 

                        """ + Fore.WHITE)
                        user_instruction = input(":").lower()
                        # Conditional that will lead to adding a service to the user's csv file, password is auto-generated, encrypted and stored with a time-stamp
                        if user_instruction == "add" or user_instruction == '1':
                            service_name = input(Fore.YELLOW + "Please enter the name of the service you wish to add to your vault - or enter 'back' to go back \n:" + Fore.WHITE).capitalize()
                            if service_name == 'Back':
                                continue
                            if len(service_name) < 1:
                                print(Fore.RED + "Please ensure you provide a name to the service you want to add" + Fore.WHITE) 
                                continue
                            # Checks to see if the service name provided by the user doesn't exist in the csv file already
                            elif check_for_duplicate_service(user_name, service_name):
                                confirmation = input(Fore.YELLOW + f"Enter 'yes' if you wish to add {service_name} to your vault - A password will be auto-generated for you\n:" + Fore.WHITE).lower()
                                if confirmation == 'yes' or confirmation == 'y':

                                    # Generated the password and encrypts it in the following two lines
                                    service_password = password_generator()
                                    add_service(master_password, user_name, service_name, service_password)
                                    print(Fore.GREEN + f"{service_name} has been added to your vault", Fore.WHITE)
                                else:
                                    print(Fore.RED + f"{service_name} has NOT been added to your vault", Fore.WHITE)
                                    continue

                            else:
                                print(Fore.RED + "You already have a service with that name", Fore.WHITE)

                        # Conditional that will allow user to display a particular service's password
                        elif user_instruction == 'display' or user_instruction == '2':
    
                            while True:
                                # If there are no services to print error and return to the previous screen
                                if display_vault(user_name, master_password) == False:
                                    print(Fore.RED + "You have an empty Vault - make some entries first", Fore.WHITE)
                                    break
                                else:
                                    # If not empty - user can select the particular service by entering the name or corresponding number
                                    service_name_to_reveal = input(Fore.YELLOW + "\nEnter the name of the service to view the password - or enter 'back' to go back\n:" + Fore.WHITE).capitalize()
                                    if service_name_to_reveal == 'Back':
                                        break

                                    # If the services exists in the csv file to decrypt the password and reveal it using the color black for the password
                                    # so that it must be highlighted to be viewed (only workes in dark terminals) 
                                    elif check_service_exists(user_name, service_name_to_reveal):
                                        decrypt_service_password(service_name_to_reveal, user_name, master_password)
                                        break
                                    else:
                                        print(Fore.RED + f"Sorry didn't understand the selection: {service_name_to_reveal}.", Fore.WHITE)
                                        continue
                        
                        #Conditional allowing user to edit a particular service's password - either update it or remove it entirerly    
                        elif user_instruction == 'update' or user_instruction == '3':
                            while True:
                                # Checks to see that the csv vault isn't empty
                                if display_vault(user_name, master_password) == False:
                                    print(Fore.RED + "You have an empty Vault - make some entries first", Fore.WHITE)
                                    break
                                else:
                                    # Prompts user to select the service to edit
                                    service_name_to_update = input(Fore.YELLOW + "\nEnter the name of the service to update the password - or enter 'back' to go back\n:" + Fore.WHITE).capitalize()
                                    if service_name_to_update == 'Back':
                                        break
                                    # If the service that is selected exists - client given the option to get a new password or to remove the service entireely    
                                    elif check_service_exists(user_name, service_name_to_update):
                                        print(Fore.YELLOW + f"\n***Options for {check_service_exists(user_name, service_name_to_update)}***\n" + Fore.WHITE + "1. Update Password\n2. Delete Entry\n")
                                        edit_user_option = input(":").lower()
                                        if edit_user_option == 'back':
                                            continue
                                        elif edit_user_option == "update" or edit_user_option == "update password" or edit_user_option == "1":
                                            confirmation_input = input(Fore.YELLOW + f"Confirm by entering 'yes' - A password will be auto-generated for you\n" + Fore.RED + "WARNING: THE CURRENT PASSWORD WILL BE REMOVED FOREVER \n" + Fore.WHITE + ":").lower()
                                            if confirmation_input == 'yes' or confirmation_input == 'y':
                                                # Updates the pasword after a confirmation, saves it to the csv file with a new encrypted password and new time stamp
                                                update_service_password(master_password, user_name, service_name_to_update)
                                                break
                                            else:
                                                print(Fore.RED + f"Confirmation Failed - Nothing was updated", Fore.WHITE)
                                                continue
                                        # Removes the service from the csv file if client selects delete and responds with a yes to confirmation
                                        elif edit_user_option == "delete" or edit_user_option == "delete entry" or edit_user_option == "2":
                                            removal_confirmation = input(Fore.YELLOW + f"Confirm by entering 'yes' - The service and password will be removed forever\n" + Fore.RED + "WARNING: THIS CANNOT BE UNDONE \n" + Fore.WHITE + ":").lower()
                                            if removal_confirmation == 'yes' or removal_confirmation == 'y':
                                                delete_entries(user_name, service_name_to_update)
                                                break
                                            else:
                                                print(Fore.RED + f"Confirmation Failed - Nothing was updated", Fore.WHITE)
                                                continue
                                         
                                        else:
                                            print(Fore.RED + f"Sorry didn't understand the selection: {edit_user_option}.", Fore.WHITE)
                                    else:
                                        print(Fore.RED + f"Sorry didn't understand the selection: {service_name_to_update}.", Fore.WHITE)
                                        continue
                    
                    # Will break from the loop which is the client's account page if client wishes to logout
                    # Reset the values for user_name and master_password
                        elif user_instruction == 'logout' or user_instruction == '4':
                            master_password = ''
                            user_name = ''
                            logout = True
                            break
                        else:
                            print(Fore.RED + f"Do not understand the instruction {user_instruction}", Fore.WHITE)
                            continue

                    break 

                else:
                    # Will increment the faield login_attempt_count variable for every failed attempt and save it to the check.csv file
                    print(Fore.RED + "\nUsername or Password is incorrect", Fore.WHITE)
                    login_list = read_csv_to_list('check')
                    login_attempt_count = int(login_list[0][0]) + 1
                    lockout_timer(login_attempt_count)                                
                    continue

        # Conditional that allows users to exit the application or to display error if it doesn't understand the input
        elif user_instruction == 'exit' or user_instruction == '3':
           sys.exit()
        else:
            print(Fore.RED + f"Don't understand the instruction: {user_instruction}")
            continue

# Function that writes the lockout counter to the check.csv file and updates the timestamp and status (not_locked or locked)
def lockout_timer(counter):
    with open('users/check.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        if counter < 3:
            writer.writerow([counter, 'not_locked'])
        else:
            writer.writerow([counter, 'locked',  datetime.now().strftime("%Y-%m-%d %H:%M:%S")] )


# Function that when called will read a csv file and return a list that holds values from the list
def read_csv_to_list(username):
    csv_list = []
    with open('users/' + username + '.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            csv_list.append(row)
        
    return csv_list   

# Function that reads the user's csv file and then prints the services that are being stored
def display_vault(username, masterpassword):
    vault_list = read_csv_to_list(username)
    print()
    # If it's an empty account ie only hash and salt are being stored in the csv file - function will return false
    if len(vault_list) < 3:
        return False
    else:
        # Loop that will display the services starting not including the first 2 lines in the csv file
        for count, row in enumerate(vault_list[2:], 1):
            print(Fore.LIGHTCYAN_EX, f"{count}. {row[0]}", Fore.WHITE)


# Function that loops throught the items in a csv file and checks if the name that is being passed doesn't already exist
def check_for_duplicate_service(username, name):
    csv_list = read_csv_to_list(username)
    for row in csv_list:
        if name in row:
            return False
        else:
            continue
    return True

# Function that hashes the master_password that has passed complexity requirements by first generating a random 32 byte string and then being encoded to be saved into csv file
def hashing_function(password, username):
    salt = base64.b64encode(os.urandom(32))

    # Using salt and master password to hash using hashlib module   
    hashed_master_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 5000)
    hashed_master_password = base64.b64encode(hashed_master_password)  

    # Saving the encoded salt and hash and saving it to a new csv file with the username as the csv file name inside users directory
    with open('users/' + username+'.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Hash', hashed_master_password.decode()])
        writer.writerow(["Salt", salt.decode()])
       
        
# Function that is called when client attempts to login - will check the password provided - hash it - and then compare it to the hash stored in the csv file
def verify_master_password(password_check, username):
    csv_list = []
    # Error checking in place to ensure that file not found error is raised when application tries to read username.csv file
    try:
        with open('users/' + username + '.csv', 'r') as f:
            reader = csv.reader(f)
            # Below loop only reads the first 2 rows (ie only salt and hash)
            for count, row in enumerate(reader):
                if count <= 1:
                    csv_list.append(row)
                else:
                    break
    except FileNotFoundError:
        return False

    # The salt is stored in the second list, second index and is being encoded as it was stored as a sting so that it can be used to generate the hash to be checked
    salt = csv_list[1][1].encode()
    # The password found in the csv file, first list, second index, being encoded so that it can be compared 
    password_hash = csv_list[0][1].encode()  
    check_hash = hashlib.pbkdf2_hmac('sha256', password_check.encode('utf-8'), salt, 5000)
    check_hash = base64.b64encode(check_hash)

    # Conditiontal that checks if the two passwords are a match and returns a corresponding boolean value
    if str(check_hash) == str(password_hash):
        return True
    else:
        return False

# Function that uses regular expressions to check that the username provided is valid
# As the username is being used to name the .csv file, only underscores and hyphens can be used along with letters and numbers
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


# Functiont that checks if the passowrd provided to create an account meets the complexity requirements using regular expressions
def password_complexity_checker(password):
    
    # Uses regex to ensure that there are least 10 characters and looks forward to ensure at least one lower and uppercase,digit and special character.
    complexity_regex = re.compile(r'(?=.*[\!\@\#\$\%\^\&\*])(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{10,}')

    # Returns true for conditional if search returns a value - if none it means that it didn't meet the above requirements
    if complexity_regex.search(password) is None:
        return False
    else:
        return True

# Fucntin that will randomly create a 10 character length password to be used by the services that are added
def password_generator():
    length = 10
    # Created a list for lowercase, uppercase, numbers and special characters
    lower_letters = list(string.ascii_lowercase)
    upper_letters = list(string.ascii_uppercase)
    numbers = list(string.digits)
    # Multiplied the number of occurences to increase probability that special characters are selected
    special_characters = list('!@#$%^&*' * 3)
    # Once selected at least one from each list - created a total possible selection to select the remaining characters
    total_possible_selection = lower_letters + upper_letters + numbers + special_characters
    password = random.choice(lower_letters)
    password += random.choice(upper_letters)
    password += random.choice(numbers)
    password += random.choice(special_characters)
    for x in range(length):
         password += random.choice(total_possible_selection)
    return password


# Function that enrypts the auto-generated password using Fernet and the master password as the key
def encrypt_password_function(master_password, username, specific_password):
    csv_read_list = read_csv_to_list(username)
    
    # Using the same salt to hash thte master password to generate a key
    salt = csv_read_list[1][1].encode()
   
    # Ferent key requires 32 bytes thus the length, using sha256 and default backend to create key using PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())

    # The final key is bast64 url safe encoded as per Fenet requirements and using derive function so that only the master password which isn't stored anywhere can be used to replicate the key
    encoding_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    # Using Fernet function to encode the password using the above key
    encoded_password = Fernet(encoding_key).encrypt(specific_password.encode())
    return encoded_password


# Function that adds the service namee, encrypted password and time stamp to the corresponding csv file
def add_service(master_password, username, name, specific_password):

    # Uses above function to obtian encrypted password
    encrypted_password = encrypt_password_function(master_password, username, specific_password)
  
    # Appends the service name, encrypted password and time stamp to csv file
    with open('users/' + username + '.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([name, encrypted_password.decode(), date.today()])

# Function that reads the csv file to check that the service being added doesn't already exist
def check_service_exists(username, service_name):
    read_csv_list = read_csv_to_list(username)
    found_service = False 
    # Loop will the counter from -1 so that the user can enter the 'number' next to the service name along with the service name to select the service  
    for count, row in enumerate(read_csv_list, -1): 
        if service_name in row or service_name == str(count) and service_name != '0' and service_name != '-1':
            found_service_name = row[0]
            found_service = True
    if found_service == True:
        return found_service_name
    else:
        return False

# Function that decrypts the selected service's password and displays it to the user, can provide the service name or corresponind number being displayed as the user input
def decrypt_service_password(service_name, username, master_password):
   
    read_csv_list = read_csv_to_list(username)
    found_service = False  
    # Loop that will check the service actually exists and assigns the encrypted password and service name to variables 
    for count, row in enumerate(read_csv_list, -1): 
        if service_name in row or service_name == str(count) and service_name != '0' and service_name != '-1':
            encrypted_password = row[1]
            found_service_name = row[0]
            found_service = True
    
    salt = read_csv_list[1][1].encode()
   
#   If service name exists, to use PBKDF2HMAC to generate the encryption key from the master password and then using Fernet to decrypt it
    if found_service:  
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        encoding_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        decrypted_password = Fernet(encoding_key).decrypt(encrypted_password.encode()).decode()
        print(Fore.LIGHTCYAN_EX + f"{found_service_name}:")
        # Coloured the decrypted password black to add superficial security so it can't be read unless highlighted - only works in terminals with black/dark background
        print(Fore.LIGHTGREEN_EX + "->" + Fore.BLACK + f"{decrypted_password}" + Fore.LIGHTGREEN_EX + "<-")
        print(Fore.YELLOW + "The password is hidden - you must highlight it with your cursor", Fore.WHITE)
    else:
        # Returns error if can't find the service
        print(Fore.RED + f"Invalid option - could not find that service", Fore.WHITE)

# Function that will delete the service from the csv file by copying the whole csv file and re-writing it back into the csv file except for the selected service which is to be deleted
def delete_entries(username, service_name_to_delete):
    csv_read_list = read_csv_to_list(username)
    with open('users/' + username + '.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        deleted_service = False
        for count, row in enumerate(csv_read_list, -1):
            # If the service to be deleted has been found to continue and not to write it to the csv file
            if row[0] == service_name_to_delete or service_name_to_delete == str(count) and service_name_to_delete != '0' and service_name_to_delete != '-1':
                selected_service_to_delete = row[0]
                deleted_service = True
                continue
            elif count > 0:
                writer.writerow([row[0], row[1], row[2]])
            else:
                writer.writerow([row[0], row[1]])
        if deleted_service:
            print(Fore.GREEN + f"Password for {selected_service_to_delete} has been successfully removed." + Fore.WHITE)
        else:
            print(Fore.RED + "No services have been removed - could not recognise selection" + Fore.WHITE)


# Function that will generate a new password and save it to csv file with a new timestamp
def update_service_password(master_password, username, service_name_to_update):
    csv_read_list = read_csv_to_list(username)
    # Generates new password and encryptes it
    new_service_password = password_generator()
    new_encrypted_password = encrypt_password_function(master_password, username, new_service_password)
    with open('users/' + username + '.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        updated_password_confirm = False
        # Loop that if the updated password is found, to add the new password and timestamp and for all other rows, to just copy and paste them back into the same csv file
        for count, row in enumerate(csv_read_list, -1):
            if row[0] == service_name_to_update or service_name_to_update == str(count) and service_name_to_update != '0' and service_name_to_update != '-1':
                selected_service_to_update = row[0]
                writer.writerow([row[0], new_encrypted_password.decode(), date.today()])
                updated_password_confirm = True
            elif count > 0:
                writer.writerow([row[0], row[1], row[2]])
            else:
                writer.writerow([row[0], row[1]])
        if updated_password_confirm:
            print(Fore.GREEN + f"Password for {selected_service_to_update} has been successfully updated." + Fore.WHITE)
        else:
            print(Fore.RED + "Password has not been updated - could not recognise selection" + Fore.WHITE)

# Functiont that checks if it has been 30 days since a password has been updated, if to to provide warning message
def check_expiry_password(username):
    csv_vault = read_csv_to_list(username)
    check_date = date.today()
    if len(csv_vault) > 2:
        for row in csv_vault[2:]:
            year, month, day = map(int, row[2].split('-'))
            original_date = date(year, month, day)
            difference = check_date - original_date
            if difference.days >= 30:
                print(Fore.RED + f"The password for {row[0]} needs to be updated - it has been {difference.days} days since you last updated!", Fore.WHITE)

# Calls the main function after it has read all the functions required to run main()
if __name__ == '__main__':
    main()

