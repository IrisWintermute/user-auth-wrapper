When run, this script opens a tkinter GUI that prompts the user to enter a username and password. 
Once the user submits these details, the script looks for a match in the userdata.txt file created in the local directory.
If a match is found, the program compares a SHA256 hash of the entered password with the hash stored in userdata. 
If a match is returned, the program then identifies the user's security level by sequentially hashing each predefined security level until a match is found with the hashed string in userdata.
Finally, the script casts a Certification object to a global variable, kills the GUI root - which terminates the .mainloop() and permits the script to conclude, and returns the global variable.
The Certification object contains the user's name, a unique identifier, their security level, as well as the datetime of the authentication instance and the 48-bit hardware address of the machine on which the validation occured.

If a user does not already have an account in the database, they can choose to create one.
Choosing this option replaces the GUI window with a second instance for instantiating a new user.
Here, the user is prompted to enter their username, email address, two instances of their password, and their security level.
Their username must be less than 20 characters in length, only contain alphanum characters, and not already exist in the database.
Their password must be at least 6 characters long, contain both uppercase and lowercase letters, and have at least one number and one special character.
Their email address must adhere to a correct syntax e.g: one @ symbol, approprate . numbers before and after @, sufficient alphanum characters, and a valid domain name.
If the security level they enter does not match any predefined value, the program defaults to granting them the minimum security level.
If all requirements are met, the user's username, email address, UUID, and the hashes of their password and security level are appended to the database.
