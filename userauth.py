# tkinter for GUI
from tkinter import *
from tkinter import ttk
# datetime for Certification timestamping - UTC fulcrum
from datetime import *
from datetime import timezone
# uuid for unique identifiers
import uuid
# re for user input validation
import re
# os to detect if file is missing
import os
# hashlib for SHA256 algorithm
import hashlib

class Certification:
    def __init__(self, name:str, uuid_user:str, sec_level:str):
        # uuid_user is unique for each user account instead of each user machine
        self.username = name
        self.uuid_user = uuid_user
        self.sec_level = sec_level
        self.auth_time = datetime.now(timezone.utc).strftime("%d/%m/%Y, %H:%M:%S [%z]")
        self.hard_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        self.str = f"User {name} [uuid: {uuid_user}] with security level {sec_level} authenticated at {self.auth_time} on machine with address {self.hard_address}."

    def __str__(self):
        return self.str

root = Tk()
root.title("User Authentication")
root.geometry("500x160")
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
frame = ttk.Frame(root)
frame.grid(column=0, row=0, sticky=N)

username_entry = StringVar()
email_entry = StringVar()
password_entry = StringVar()
password_entry_2 = StringVar()
sec_level_entry = StringVar()
status = StringVar()
user_authenticated = None # empty variable, assigned instance of Certification() if authentication is successful 

sec_level_list = ["guest","member","moderator","supervisor","admin","overseer"]
valid_tlds = [".com", ".co.uk", ".gov", ".net", ".io"]


def clearvariables():
    username_entry.set("")
    email_entry.set("")
    password_entry.set("")
    password_entry_2.set("")
    sec_level_entry.set("")
    status.set("Awaiting entry...")

def resetframe():
    global frame
    if frame:
        frame.destroy()
    frame = ttk.Frame(root, padding = "3 3 12 12")
    frame.grid(column=0, row=0, sticky=N)

def newuserwindow():
    
    resetframe()
    clearvariables()

    ttk.Label(frame, text = "Username: ").grid(column=0, row=0, sticky=N)
    ttk.Label(frame, text = "Email Address: ").grid(column=0, row=1, sticky=N)
    ttk.Label(frame, text = "Password: ").grid(column=0, row=2, sticky=N)
    ttk.Label(frame, text = "Confirm password: ").grid(column=0, row=3, sticky=N)
    ttk.Label(frame, text = "Security level: ").grid(column=0, row=4, sticky=N)
    ttk.Label(frame, text = "Status: ").grid(column=0, row=5, sticky=N)
    ttk.Label(frame, textvariable = status).grid(column=1, row=5, sticky=N)

    ttk.Entry(frame, textvariable = username_entry).grid(column=1, row=0, sticky=N)
    ttk.Entry(frame, textvariable = email_entry).grid(column=1, row=1, sticky=N)
    ttk.Entry(frame, textvariable = password_entry, show = "*").grid(column=1, row=2, sticky=N)
    ttk.Entry(frame, textvariable = password_entry_2, show = "*").grid(column=1, row=3, sticky=N)
    ttk.Entry(frame, textvariable = sec_level_entry).grid(column=1, row=4, sticky=N)
    
    ttk.Button(frame, text = "Submit.", command = submitnewuser).grid(column=0, row=6, sticky=N)

def existinguserwindow():

    resetframe()
    clearvariables()

    ttk.Label(frame, text = "Username: ").grid(column=0, row=0, sticky=N)
    ttk.Label(frame, text = "Password: ").grid(column=0, row=1, sticky=N)
    ttk.Label(frame, text = "Status: ").grid(column=0, row=2, sticky=N)
    ttk.Label(frame, textvariable = status).grid(column=1, row=2, sticky=N)

    ttk.Entry(frame, textvariable = username_entry).grid(column=1, row=0, sticky=N)
    ttk.Entry(frame, textvariable = password_entry, show = "*").grid(column=1, row=1, sticky=N)

    ttk.Button(frame, text = "I am a new user.", command = newuserwindow).grid(column=0, row=3, sticky=N)
    ttk.Button(frame, text = "Submit.", command = submitentry).grid(column=1, row=3, sticky=N)


def userdatainit():
    if not os.path.exists("userdata.txt"):
        with open("userdata.txt", "w") as file:
            pass

def gethash(uuid, password):
    # obtains list of Unicode values from characters of password
    ordinal_numlist = [ord(char) for char in password]
    # casts values to str and appends to ordinal_str
    ordinal_str = ""
    for val in ordinal_numlist:
        ordinal_str += str(val)
    # converts uuid and ordinal_str to byte-like objects
    b_uuid = bytes(uuid, "utf-8")
    b_ordinal_str = bytes(ordinal_str, "utf-8")
    # instantiates SHA256 hashing algorithm
    hash = hashlib.new("sha256")
    # updates hash with uuid and password strings
    hash.update(b_uuid)
    hash.update(b_ordinal_str)
    # gets string output of hash in hexadecimal
    hash_out = hash.hexdigest()
    return hash_out
    
def deriveuserseclevel(uuid, user_sec_hash):
    global sec_level_list
    for level in sec_level_list:
        if user_sec_hash == gethash(uuid, level):
            return level
    else:
        # defaults to lowest security level if no match found
        return "guest"

def getuseruuid():
    # returns a unique uuid each time the fuction is run
    # this holds if function is run multiple times within a short timespan
    # or if function is run multiple times on the same machine
    uuid_out = str(uuid.uuid1())
    return uuid_out


def validateusername(username):
    # username rules: 
    # must be 20 characters or less
    # must be alphanumeric
    out = False

    if len(username) > 20:
        status.set("Username must be 20 characters or shorter.")

    elif not username.isalnum():
        status.set("Username must not contain special characters.")

    else:
        out = True
    return out

def validateemail(email):
    # email rules:
    # address must contain at least one . and one @
    # [a@b.com] <-- a and b must have a minimum length of 1
    # address top-level domain must be valid
    global valid_tlds
    
    # check address contains 1 @
    email_parts = email.split("@")
    if len(email_parts) != 2:
        pass
    # check address before @ does not contain .
    elif email_parts[0].count(".") != 0:
        pass
    # check address after @ contains 1 or 2 .
    elif (email_parts[1].count(".") == 0) or (email_parts[1].count(".") > 2):
        pass
    # check at least 1 character is around/between each @ and .
    elif [True for part in re.split("[@.]", email) if len(part) == 0]:
        pass
    # check address after @ contains a valid top-level domain
    elif not [True for tld in valid_tlds if tld == ("." + email_parts[1].split(".")[1])]:
        status.set("Email address does not contain a valid top-level domain.")
    else:
        return True
    
    status.set("Email address is not valid.")
    return False

def validatepassword(password):
    # password rules:
    # must be at least 6 characters in length
    # must contain a mix of uppercase and lowercase letters
    # at least one number and one special character
    out = False

    if len(password) < 6:
        status.set("Password must be six characters or longer.")

    elif not re.findall("[0-9]", password):
        status.set("password must contain at least one number.")

    elif not (re.findall("[a-zA-Z]", password)):
        status.set("Password must contain characters in the alphabet.")

    elif password.isupper() or password.islower():
        status.set("Password must contain a mix of uppercase and lowercase letters.")

    elif password.isalnum():
        status.set("Password must contain at least one special character.")

    else:
        out = True
    return out


def submitnewuser():
    username = username_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    password_2 = password_entry_2.get()
    user_sec = sec_level_entry.get()

    # confirms security level is valid
    # assigns lowest security level otherwise
    global sec_level_list
    if user_sec not in sec_level_list:
        user_sec = sec_level_list[0]

    # confirm username, email and passwords have been entered
    if not username:
        status.set("Username has not been entered.")
        return None
    if not email:
        status.set("Email address has not been entered.")
        return None
    if not password:
        status.set("Password has not been entered.")
        return None
    if not password_2:
        status.set("Password has not been confirmed.")
        return None

    # confirm username, email and password meet requirements
    if not (validateusername(username) and validateemail(email) and validatepassword(password)):
        return None
    
    # confirm entered passwords match
    if password != password_2:
        status.set("Passwords do not match.")
        return None

    uuid_user = getuseruuid()
    user_hash = gethash(uuid_user, password)
    sec_hash = gethash(uuid_user, user_sec)

    # add user parameters to userdata.txt
    user_accepted = adduserparams(username, email, uuid_user, user_hash, sec_hash)
    if not user_accepted:
        status.set("Username has already been taken.")
        return None

    # load login window
    existinguserwindow()
    status.set("New user registered. Awaiting entry...")

def submitentry():
    username = username_entry.get()
    password = password_entry.get()
    user_params = getuserparams(username)

    # confirm username and password have been entered
    if not username:
        status.set("Username has not been entered.")
        return None
    if not password:
        status.set("Password has not been entered.")
        return None

    # check for exception of user not existing
    if not user_params:
        status.set("Username not found.")
        return None

    uuid_user = user_params[0]
    user_hash = user_params[1]
    user_sec_hash = user_params[2]

    # check if hashed password input matches stored hash
    if user_hash != gethash(uuid_user, password):
        status.set("Password is incorrect.")
        return None
    
    global user_authenticated
    # obtain user's security level
    user_sec_level = deriveuserseclevel(uuid_user, user_sec_hash)
    user_authenticated = Certification(username, uuid_user, user_sec_level)
    root.destroy()


def getuserparams(username):
    # each line in file contains parameters of specific user
    # (username);(email address);(unique user ID);(hash of uuid and password);(hash of security level and uuid);(newline)
    # read user parameters into variables, then return them
    # if no matching user is found, returns an empty list
    with open("userdata.txt", "r") as file:
        file_lines = file.readlines()
        for line in file_lines:
            line_list = line.split(";")
            if username == line_list[0]:
                return line_list[2:5]
        else:
            return []

def adduserparams(username, email, uuid, user_hash, sec_hash):
    new_user = ";".join([username, email, uuid, user_hash, sec_hash, "\n"])
    with open("userdata.txt", "r") as file:
        file_lines = file.readlines()
        # checks that username argument does not already exist within userdata.txt
        for line in file_lines:
            line_list = line.split(";")
            if line_list[0] == username:
                return False
            
    # if no early return occurs, new_user is appended to userdata.txt
    with open("userdata.txt", "a") as file:
        file.write(new_user)
    return True

def removeuserparams(uuid):
    with open("userdata.txt", "r") as file:
        file_lines = file.readlines()
    new_file_lines = [line for line in file_lines if uuid not in line]
    with open("userdata.txt", "w") as file:
        file_string = "\n".join(new_file_lines)
        file.write(file_string)


def auth():
    userdatainit()
    existinguserwindow()
    root.mainloop()
    return user_authenticated

if __name__ == "__main__":
    cert = auth()
    print(cert)


# import userauth as UA
# auth_cert = UA.auth(parameters)
# --WEAK--
# if auth_cert:
#     giveaccess()
# else:
#     print("Access denied.")
#
# --STRONG--
# if valcheck(auth_cert):
#     giveaccess(auth_cert.sec_level)
# else:
#     print("Access denied.")
