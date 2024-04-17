import getpass
import hashlib
import random
import string
import time

import LogIN
import OTP


# Function to maintain the strictness of the password
def pass_check(password):
    if len(password) < 8:
        print("Enter at least 8 characters")
        return False
    j, k, m, n = 0, 0, 0, 0
    for i in password:
        c = ord(i)
        if 65 <= c <= 90:
            j = 1
        elif 97 <= c <= 122:
            k = 1
        elif 48 <= c <= 57:
            m = 1
        else:
            n = 1
    if j == 0 or k == 0 or m == 0 or n == 0:
        return False
    return True


# Function to generate strong passwords
def generate_password():
    while True:
        try:
            length = int(input("How long password would you like (minimum 8 characters) : "))
            if length <= 7:
                print("\nPlease enter a number >= 8 : ")
            else:
                break
        except ValueError:
            print("\nPlease enter the correct input .".upper())
    characters = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(random.choice(characters) for i in range(int(length)))
        if pass_check(password):
            print("Your password is : ", password)
            return password


# Function to sign up
def sign_up():
    username = input("Enter a Email Account : ").lower().strip()
    try:
        with open("accounts.txt", "r") as file:
            for line in file:
                try:
                    user, pwd, salt = line.strip().split(":")
                    if user == username:
                        print('\n** Username is already exist. Please try again. **\n'.upper())
                        return
                except ValueError:
                    pass
    except FileNotFoundError:
        pass
    print("Loading... Thank you for your patience! ")
    username = OTP.otp(username, 100)
    z = input("Do you want to auto-generate password (y) : ")
    if z == "y" or z == "Y":
        password = generate_password()
    else:
        print("Password Requirements : ".upper())
        print("  -Minimum password length: 8 characters\n  -Contains 1 alphanumeric character\n"
              "  -Contains 1 Upper case character\n  -Contains 1 lower case character"
              "\n  -Contains 1 number digit\n")

        password = getpass.getpass("Enter your password : ")
        confirm_password = getpass.getpass("Enter confirm password : ")
        while password != confirm_password:
            print("Password does not match. Please try again.")
            password = getpass.getpass("Enter your password : ")
            confirm_password = getpass.getpass("Enter confirm password : ")

        a = False
        while a is False:
            a = pass_check(password)
            if a is False:
                print("Enter strong password.")
                while password != confirm_password:
                    if password != confirm_password:
                        print("\nPassword does not match. Please try again.")
                    password = getpass.getpass("Enter your password : ")
                    confirm_password = getpass.getpass("Enter confirm password : ")

    add_data(username, password)
    print("\n** Account created successfully! **\n".upper())


# Function to log in
def log_in():
    username = input("Enter your Email Account : ").strip().lower()
    z = 105
    with open("accounts.txt", "r") as file:
        for line in file:
            user, pwd, salt = line.strip().split(":")
            if user == username:
                z = 106
                i = 0
                while i < 3:
                    password = getpass.getpass("Enter your password: ")
                    if compare_password(password, salt, pwd):
                        print("\n** Password successful! "
                              "\nPlease verify yourself by OTP and Check Email. **\n".upper())
                        OTP.otp(username, 101)
                        print('** LOGGED IN SUCCESSFULLY **\n')
                        LogIN.main(username)
                        return
                    else:
                        print("Invalid username or password.\nPlease try again")
                        i += 1
                if i == 3:
                    print("You have entered the wrong password three times.")
    if z == 105:
        print("You have entered the wrong Email ID .")
    a = input("Do you want to Exit Login Page (if Yes Enter '0') : ")
    print('\n')
    if a == '0':
        return
    log_in()


# Function to edit account
def edit_account():
    username = input("Enter your Email Address : ").strip().lower()
    z = 105
    try:
        with open("accounts.txt", "r") as file:
            for line in file:
                user, pwd, salt = line.strip().split(":")
                if user == username:
                    z = 106
                    print("Loading... Thank you for your patience! ")
                    username = OTP.otp(username, 101)
                    password = getpass.getpass("Enter a  new password : ")
                    confirm_password = getpass.getpass("Enter a  new confirm password : ")
                    while password != confirm_password:
                        print("Passwords do not match. Please try again..")
                        password = getpass.getpass("Enter a  new password : ")
                        confirm_password = input("Enter a  new confirm password : ")
                    print('Loading...')
                    time.sleep(1)
                    LogIN.delete_account(username)
                    add_data(username, password)
                    print("\n** Account edited successfully! **\n".upper())
        if z == 105:
            print("\n** You have entered the wrong Email ID **\n".upper())
    except FileNotFoundError:
        print("\n** No account created **\n".upper())


# Function to add line to the csv file
def add_data(username, password):
    characters = string.ascii_letters + string.digits
    salted = ''.join(random.choice(characters) for _ in range(16))
    hashed_password = hash_password(password, salted)
    with open("accounts.txt", "a") as file:
        file.write(f"{username}:{hashed_password}:{salted}\n")


# Function to show list of accounts
def list_accounts():
    try:
        with open("accounts.txt", "r") as file:
            print("List of accounts : ")
            for line in file:
                username, password, hashed = line.strip().split(":")
                print(username)
        print('\n')
    except FileNotFoundError:
        print("\n** No account created **\n".upper())
        pass


# Function for making of the salted+hashed password
def hash_password(password, salt):
    """Hash a password with salt using SHA-256."""
    salted_password = password.encode() + salt.encode()
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password


# Function for showing details of the options
def menu():
    print("--------------------------------")
    print(" GHATE'S PASSWORD MANAGER ")
    print("--------------------------------")
    print("1. Sign UP Account")
    print("2. Log IN Account")
    print("3. Edit Account")
    print("4. List Account")
    print("5. Quit Application")
    print("--------------------------------\n")

    user = input("Enter option : ")
    return user


# Function to compare the input password to the stored one
def compare_password(input_password, salt, hashed_password):
    given_password = hash_password(input_password, salt)
    if given_password == hashed_password:
        return True
    return False


# Main function
def main():
    while True:
        choice = menu()

        if choice == "1":
            sign_up()
        elif choice == "2":
            log_in()
        elif choice == "3":
            edit_account()
        elif choice == "4":
            list_accounts()
        elif choice == "5":
            print("\nThank you for using Ghate's Password Manager :) \n".upper())
            break
        else:
            print("\n**Invalid choice. Please try again. **\n".upper())


if __name__ == "__main__":
    main()
