import random
import smtplib


def otp(receiver_email, z):
    make_otp = str(random.randint(100000, 999999))  # generating a random 6-digit OTP
    global sender_email
    sender_email = 'devashishghate02@gmail.com'  # sender Email address
    global server  # setting up server
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    valid_receiver_email = email_verification(receiver_email)  # verify receiver email address
    password = "ksabmgphcdljusch"
    server.login(sender_email, password)
    # Email details
    body = "Dear," + "\n" + "\n" + "Your OTP for Password Manager is " + str(make_otp) + "."
    subject = "Ghate's Password Manager OTP verification"
    message = f'subject:{subject}\n\n{body}'

    server.sendmail(sender_email, valid_receiver_email, message)
    print("OTP has been sent to " + valid_receiver_email + ' .')
    received_otp = input("Enter OTP : ")
    if received_otp == make_otp:  # OTP verification
        print("\n** OTP verified **\n".upper())
    elif z == 100:
        print("\n** Invalid OTP **\n".upper())
        answer = input("Enter 'Y' to resend OTP on same email and any key to enter a new Email ID : ")
        yes = ['y', 'Y']
        if answer in yes:
            print("Loading... Thank you for your patience! ")
            sending_otp(valid_receiver_email)
        else:
            receiver_email = input("Enter new Email ID : ").strip().lower()
            receiver_email = email_verification(receiver_email)
            print("Loading... Thank you for your patience! ")
            otp(receiver_email, 100)
    elif z == 101:
        print("\n** Invalid OTP **\n".upper())
        sending_otp(receiver_email)

    server.quit()
    return receiver_email


def email_verification(receiver_email):  # checking email format
    email_check1 = ["gmail", "hotmail", "yahoo", "outlook", "nituk"]
    email_check2 = [".com", ".in", ".org", ".edu", ".co.in", ".ac.in"]
    count = 0

    for domain in email_check1:
        if domain in receiver_email:
            count += 1
    for site in email_check2:
        if site in receiver_email:
            count += 1

    if "@" not in receiver_email or count != 2:
        print("\n** invalid email id **\n".upper())
        new_receiver_email = input("Enter correct Email ID :")
        email_verification(new_receiver_email)
        return new_receiver_email
    return receiver_email


def sending_otp(receiver_email):  # function for sending otp
    new_otp = str(random.randint(100000, 999999))
    print("Loading... Thank you for your patience! ")
    body = "Dear," + "\n" + "\n" + "Your OTP for Password Manager is " + str(new_otp) + "."
    subject = "Ghate's Password Manager OTP verification"
    message = f'subject:{subject}\n\n{body}'
    server.sendmail(sender_email, receiver_email, message)
    print("OTP has been sent to " + receiver_email)
    received_otp = input("Enter the OTP : ")
    if received_otp == new_otp:
        print("\n** OTP verified **\n".upper())
    else:
        print("\n** Invalid OTP **\n".upper())
        print("Resending OTP.....")
        print("Loading... Thank you for your patience! ")
        sending_otp(receiver_email)
