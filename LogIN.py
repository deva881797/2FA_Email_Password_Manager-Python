import base64
import csv
import getpass
import os

from cryptography.fernet import Fernet

import MAIN


# Generating the Fernet encryption key
def generate_key(username):
    padded_string = username.ljust(32, '\0')  # encoding string to byte format in 32 bits
    key_bytes = padded_string.encode('utf-8')
    encoded_bytes = base64.urlsafe_b64encode(key_bytes)
    fernet_key = encoded_bytes.decode('utf-8')  # making fernet key
    return fernet_key


# Encrypt the site information to virtual one
def encrypt_password(key, password):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(password.encode())


# Decrypt the site information to actual as it is
def decrypt_password(key, encrypted_password):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_password).decode()


# Write line to password csv file
def writecsv(site, username, password):
    try:  # making file if not exist
        readcsv("site")
    except FileNotFoundError:
        with open(CSV_FILE, mode='a') as password_file:
            password_writer = csv.writer(password_file, delimiter=',', quotechar='"')
            password_writer.writerow(["1", "2", "3"])
    with open(CSV_FILE, mode='a') as password_file:  # writing particular data
        password_writer = csv.writer(password_file, delimiter=',', quotechar='"')
        password_writer.writerow([site, username, password])


# Read csv file and return site as list if it exists
def readcsv(site):
    try:
        with open(CSV_FILE) as password_file:
            password_reader = csv.reader(password_file, delimiter=',')
            line_count = 0
            for row in password_reader:
                if line_count != 0:
                    if row[0] == site:
                        return row
                line_count += 1
    except FileNotFoundError:
        with open(CSV_FILE, mode='a') as password_file:
            password_writer = csv.writer(password_file, delimiter=',', quotechar='"')
            password_writer.writerow(["1", "2", "3"])


# Delete row from csv file (stores password file in variable and rewrites password file with given site removed)
def deletecsv(site):
    changes = list()
    with open(CSV_FILE) as password_file:
        password_reader = csv.reader(password_file, delimiter=',')
        for row in password_reader:
            if row[0] != site:
                changes.append(row)

    with open(CSV_FILE, mode="w") as password_file:
        password_writer = csv.writer(password_file, delimiter=',', quotechar='"')
        password_writer.writerows(changes)


# Edit the csv file input for particular site
def editcsv(site, key):
    deletecsv(site)
    username = input("Enter username for %s : " % site)
    password = getpass.getpass("Enter password for %s : " % site)
    encrypted_password = encrypt_password(key, password)
    encrypted_string = encrypted_password.decode()  # Decode bytes to string
    writecsv(site, username, encrypted_string)


# List all sites in file and return as list
def listsites():
    try:
        with open(CSV_FILE) as password_file:
            password_reader = csv.reader(password_file, delimiter=',')
            sites = list()
            line_count = 0
            for row in password_reader:
                if line_count != 0:
                    sites.append(row[0])
                line_count += 1
        return sites
    except FileNotFoundError:
        with open(CSV_FILE, mode='a') as password_file:
            password_writer = csv.writer(password_file, delimiter=',', quotechar='"')
            password_writer.writerow(["1", "2", "3"])


# Function to delete account
def delete_account(username):
    with open("accounts.txt", "r") as file:
        lines = file.readlines()

    with open("accounts.txt", "w") as file:
        for line in lines:
            if line.startswith(username + ":"):
                break

        for line in lines:
            if not line.startswith(username + ":"):
                file.write(line)

    with open("accounts.txt", "r") as file:  # removing accounts file if empty
        lines = file.readlines()
    if len(lines) == 0:
        os.remove("accounts.txt")


# delete the csv file if empty
def delete_csv_file(ujCSV_FILE):
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)


# Menu of the application
def menu():
    print("--------------------------------")
    print("GHATE'S PASSWORD MANAGER")
    print("--------------------------------")
    print("1. Add password")
    print("2. Retrieve password")
    print("3. Delete password")
    print("4. Edit password")
    print("5. List Sites")
    print("6. Log out")
    print("7. Delete Account")
    print("--------------------------------\n")

    user = input("Enter option : ")
    return user


# Main Function
def main(username):
    key = generate_key(username)
    filename = MAIN.hash_password(key, '0')
    global CSV_FILE
    CSV_FILE = f"{filename}.csv"
    while True:
        # call menu function and handle user input exceptions
        try:
            choice = menu()
            if choice < '1' or choice > '7':
                print("\n**INVALID MENU OPTION**\n")
        except ValueError:
            print("\n**INVALID MENU OPTION**\n")
            continue

        if choice == '1':
            site = input("Enter site name : ").strip().lower()
            if site == "site":
                print("\n**INVALID SITE NAME**\n")
                continue
            try:
                if readcsv(site) is not None:
                    print("\n**SITE ALREADY EXISTS**\n")
                    continue
            except FileNotFoundError:
                pass
            username = input("Enter username for %s : " % site)
            z = input("Do you want to auto-generate password (y) : ")
            if z == "y" or z == "Y":
                password = MAIN.generate_password()
            else:
                password = input("Enter password for %s : " % site)
                while True:
                    if not MAIN.pass_check(password):
                        print("Following password is weak.")
                        a = input("Do you want to enter password again? (y) : ")
                        if a == 'y' or a == 'Y':
                            password = input("Enter strong password for %s : " % site)
                        else:
                            break
                    else:
                        break

            encrypted_password = encrypt_password(key, password)
            encrypted_string = encrypted_password.decode()  # Decode bytes to string
            writecsv(site, username, encrypted_string)
            print("\n** PASSWORD SAVED SUCCESSFULLY **\n")

        if choice == '2':
            site = input("Enter site to retrieve : ").lower().strip()
            if site == "site":
                print("\n** INVALID SITE NAME **\n")
                continue
            try:
                if readcsv(site) is None:
                    print("\n** NO SITE FOUND **\n")
                    continue
                else:
                    csvrow = readcsv(site)
                    print("\n")
                    print("SITE : %s" % csvrow[0])
                    print("USERNAME : %s" % csvrow[1])
                    encrypted_password = csvrow[2]
                    decrypted_password = decrypt_password(key, encrypted_password.encode())
                    print("PASSWORD : %s" % decrypted_password)
                    print("\n")
            except FileNotFoundError:
                print("\n** PASSWORDS FILE DOES NOT EXIST, CREATE A PASSWORD **\n")

        if choice == '3':
            site = input("Enter site to delete : ").lower().strip()
            if site == "site":
                print("\n** INVALID SITE NAME** \n")
                continue
            elif readcsv(site) is None:
                print("\n** NO SITE FOUND **\n")
                continue
            else:
                print("CONFIRMATION : Do you want to delete the %s Site ." % site)
                print("**CAUTION : This will permanently delete the details for %s site **" % site.upper())
                confirm_delete = input("(IF YES ENTER '0') : ")
                if confirm_delete == "0":
                    deletecsv(site)
                    print("\n** SITE DELETED SUCCESSFULLY **\n")
                else:
                    main(username)
        if choice == '4':
            site = input("Enter site to edit password : ").lower().strip()
            if site == "site":
                print("\n** INVALID SITE NAME **\n")
                continue
            elif readcsv(site) is None:
                print("\n** NO SITE FOUND **\n")
                continue
            else:
                editcsv(site, key)
                print("\n** PASSWORD EDITED SUCCESSFULLY **\n")
        if choice == '5':
            if listsites():
                counter = 1
                print("\n")
                for site in listsites():
                    print("%i: %s" % (counter, site))
                    counter += 1
                print("\n")
            else:
                print("\n** NO SITES IN FILE **\n")

        if choice == '6':
            print("\nLOG OUT SUCCESSFULLY :)\n")
            return

        if choice == '7':
            print("CONFIRMATION : Do you want to delete the Account ")
            print("CAUTION : This will permanently delete your account ".upper())
            confirm_delete = input("(IF YES ENTER '0') : ")
            if confirm_delete == "0":
                delete_account(username)
                print("\n** Account deleted successfully! **\n".upper())
                delete_csv_file(CSV_FILE)
                print("\nGOODBYE! :)\n")
                return
