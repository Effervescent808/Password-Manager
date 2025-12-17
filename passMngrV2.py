#!/usr/sbin/python3

import typer
import sqlite3
import bcrypt
import cryptography
import random
import string
import sys

# Initialize Database ===========================================================
# Change path to wherever db is stored
con = sqlite3.connect("/home/thaufschild/Documents/code/Python/encryptPass.db")
cur = con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, passName TEXT, username TEXT, password TEXT, hash TEXT)")

app = typer.Typer()

# Start Typer App ==============================================================
def main():
    app()

# Pull Key from Hash ============================================================
def getKey(hash):
    temp = hash.decode()[6:15] 
    charlist = []
    for char in temp:
        if char in string.ascii_letters:
            charlist.append(char)
    return''.join(charlist)[:5]

# Encrytion Algorithm ===========================================================
def encrypt(password):
    #Encode password to bytes for fast encryption
    toEncrypt = password.encode();

    #Gen hash of password with salt
    hashed = bcrypt.hashpw(toEncrypt, bcrypt.gensalt())
    sym_key=getKey(hashed)

    #Remove bad char from end of printable list
    alpha = list(string.printable)[:-6]

    #Rotate letters
    rotate=[]
    for i in range(len(sym_key)):
        rotate.append(alpha.index(sym_key[i]))
    counter = 0
    rotatedPass = ""
    for char in password:
        charValue = (alpha.index(char) + rotate[counter]) % 94
        rotatedPass = rotatedPass + alpha[charValue]
        counter = (counter +1)%5

    #Xor encrypt using sum of key
    xor_key = sum(rotate) % 256
    fullEncrypt = ""
    for char in rotatedPass:
        fullEncrypt += (chr(ord(char)^xor_key))

    return fullEncrypt, hashed

# Add Command ==================================================================
@app.command()
def add(pass_name: str):
    while True:
        typer.echo("Username:")
        username = typer.prompt(">>> ")
        typer.echo("Password:")
        password = typer.prompt(">>> ")
        typer.echo("Are you sure these are correct? (Y/n)")
        answer = typer.prompt(">>> ", default = "")
        while True:
            if answer.lower() in ("y",""):
                encrypted_pass, hash = encrypt(password)
                cur.execute("INSERT INTO passwords (passName, username, password, hash) VALUES (?,?,?,?)", [pass_name.lower(), username, encrypted_pass, hash])
                con.commit()
                typer.echo("Password Successfully Saved")
                sys.exit()
            elif answer.lower() != "n":
                typer.echo("Bad Input")
                answer = typer.prompt(">>> ")
            else:
                break

# List Command =================================================================
@app.command()
def ls():
    res = cur.execute("SELECT passName, username FROM passwords")
    rows = res.fetchall()
    counter = 1
    if len(rows) == 0:
        typer.echo("No Passwords Saved")
    else:
        for row in rows:
            print(f"{counter}. {str(row[0]).replace('(','').replace(')','').replace("'","").replace(',','').capitalize()} - {row[1]}")
            counter += 1

# Gen Command ==================================================================
@app.command()
def gen(pass_name: str, length: int = 16):
    alpha = list(string.printable)[:-6]
    while True:
        typer.echo("Enter a Username:")
        username = typer.prompt(">>> ")
        newPass = "".join(random.choice(alpha) for i in range(length))
        typer.echo("Does this password look good? (Y/n)")
        typer.echo(newPass)
        answer = typer.prompt(">>> ", default="")
        while True:
            if answer.lower() in ("y",""):
                encrypted_pass, hash = encrypt(newPass)
                cur.execute("INSERT INTO passwords (passName, username, password, hash) VALUES (?,?,?,?)", [pass_name.lower(), username, encrypted_pass, hash])
                con.commit()
                typer.echo("Password Successfully Saved")
                sys.exit() 
            elif answer.lower() != "n":
                typer.echo("Bad Input")
                answer = typer.prompt(">>> ")
            else:
                break

# Get Command ===================================================================
@app.command()
def get(pass_name: str):
    res = cur.execute("SELECT * FROM passwords WHERE passName = ?", [pass_name.lower()])
    rows = res.fetchall()
    index = 1
    if len(rows) > 1:
        typer.echo("Which Number?")
        count = 1
        for row in rows:
            typer.echo(f"{count}. {str(row[1]).replace('(','').replace(')','').replace("'","").replace(',','').capitalize()} - {row[2]}")
            count += 1
        index = typer.prompt(">>> ", type = int)
        while True:
            if index not in range(len(rows) + 1):
                typer.echo("Bad Input")
                index = typer.prompt(">>> ", type = int)
            else:
                break
    id, pass_name, username, password, hash = rows[index - 1]

    alpha = list(string.printable)[:-6]

    #Get key + values
    sym_key = getKey(hash)
    charlist=[]
    for j in sym_key:
        charlist.append(alpha.index(j))

    #Undo the xor with same key
    xor_key = sum(charlist) % 256
    unxor = ""
    for char in password:
        unxor += chr(ord(char)^xor_key)
    #Undo the rotation
    counter=0
    unrotatedPass=""
    for i in unxor:
        unrotatedValue = (alpha.index(i) - charlist[counter]) % 94
        unrotatedPass += alpha[unrotatedValue] 
        counter = (counter +1) % 5

    typer.echo(f"Password is: {unrotatedPass}")

# Remove Command ===============================================================
@app.command()
def remove(pass_name: str):
    res = cur.execute("SELECT * FROM passwords WHERE passName = ?", [pass_name.lower()])
    rows = res.fetchall()
    index = 1
    if len(rows) > 1:
        typer.echo("Which Number?")
        count = 1
        for row in rows:
            typer.echo(f"{count}. {str(row[1]).replace('(','').replace(')','').replace("'","").replace(',','').capitalize()} - {row[2]}")
            count += 1
        index = typer.prompt(">>> ", type = int)
        while True:
            if index not in range(len(rows) + 1):
                typer.echo("Bad Input")
                index = typer.prompt(">>> ", type = int)
            else:
                break
    id, pass_name, username, password, hash = rows[index - 1]

    cur.execute("DELETE FROM passwords WHERE id = ?", [id])
    con.commit()

# Call main to start app at runtime =============================================
if __name__ == "__main__":
    main()
