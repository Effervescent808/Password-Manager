# Password Manager
**A terminal application password manager built on Python and SQLite**
---
## Install
1. Copy the python script "passMngrV2" to anywhere on your filesystem
2. Change the filepath for the database file to current directory + /{nameOfDataBase}.db
3. Make the file executable
---
## Usage
### Commands
#### add
Adds a new password to the database
- Requires a password name arg
#### listPass
lists currently saved password names
#### gen
Generates a new password of a specified length
- Requires a password name arg
###### flags:
  "--length" - Sets password length, defualt is 16
#### get
Pulls password from database
- Requires a password name arg
#### remove
Removes an entry from the database
- Requires a password name arg
