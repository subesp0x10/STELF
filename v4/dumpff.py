#!/usr/bin/env python
# -*- coding: utf-8 -*-
 
#Kudos to www.dumpzilla.com
import sys
from sys import stdout as out
from sys import stderr as err
import os
import sqlite3
import json
from ConfigParser import ConfigParser
from base64 import b64decode
from os import path
from ctypes import c_uint, c_void_p, c_char_p, cast, byref, string_at
from ctypes import Structure, CDLL
from getpass import getpass
 
 
class NotFoundError(Exception):
    pass
 
 
class Item(Structure):
    _fields_ = [('type', c_uint), ('data', c_void_p), ('len', c_uint)]
 
 
class Credentials(object):
    def __init__(self, db):
        self.db = db
 
        if not path.isfile(db):
            raise NotFoundError("Error - {0} database not found\n".format(db))
 
    def __iter__(self):
        pass
 
    def done(self):
        pass
 
 
class SqliteCredentials(Credentials):
    def __init__(self, profile):
        db = profile + "/signons.sqlite"
 
        super(SqliteCredentials, self).__init__(db)
 
        self.conn = sqlite3.connect(db)
        self.c = self.conn.cursor()
 
    def __iter__(self):
        self.c.execute("SELECT hostname, encryptedUsername, encryptedPassword, encType "
                       "FROM moz_logins")
        for i in self.c:
            # yields hostname, encryptedUsername, encryptedPassword, encType
            yield i
 
    def done(self):
        super(SqliteCredentials, self).done()
 
        self.c.close()
        self.conn.close()
 
 
class JsonCredentials(Credentials):
    def __init__(self, profile):
        db = profile + "/logins.json"
 
        super(JsonCredentials, self).__init__(db)
 
    def __iter__(self):
        with open(self.db) as fh:
            data = json.load(fh)
 
            try:
                logins = data["logins"]
            except:
                raise Exception("Unrecognized format in {0}".format(self.db))
 
            for i in logins:
                # yields hostname, encryptedUsername, encryptedPassword
                yield (i["hostname"], i["encryptedUsername"],
                       i["encryptedPassword"], i["encType"])
 
 
def handle_error():
    pass
 
 
def decrypt_passwords(profile, password, libnss):
    """
    Decrypt requested profile using the provided password and print out all
    stored passwords.
    """
 
    if libnss.NSS_Init(profile) != 0:
        return "NSSERROR"
 
    if password:
        password = c_char_p(password)
        keyslot = libnss.PK11_GetInternalKeySlot()
        if keyslot is None:
            return "BADKEYSLOT"
 
        if libnss.PK11_CheckUserPassword(keyslot, password) != 0:
            return "BADMASPASS"
    else:
        pass
 
    username = Item()
    passwd = Item()
    outuser = Item()
    outpass = Item()
 
    # Any password in this profile store at all?
    got_password = False
 
    try:
        credentials = JsonCredentials(profile)
    except NotFoundError:
        try:
            credentials = SqliteCredentials(profile)
        except NotFoundError:
            return "NOCREDS"
    output = ""
    for host, user, passw, enctype in credentials:
        #if not output: output = ""
        got_password = True
 
        if enctype:
            username.data = cast(c_char_p(b64decode(user)), c_void_p)
            username.len = len(b64decode(user))
            passwd.data = cast(c_char_p(b64decode(passw)), c_void_p)
            passwd.len = len(b64decode(passw))
 
            if libnss.PK11SDR_Decrypt(byref(username), byref(outuser), None) == -1:
                return("MASPASS")
 
            if libnss.PK11SDR_Decrypt(byref(passwd), byref(outpass), None) == -1:
                return("BADMASPASS")
 
            output += "Website:  {0}\n".format(host.encode("utf-8"))
            output += "Username: {0}\n".format(string_at(outuser.data,
                                                           outuser.len))
            output += "Password: {0}\n\n".format(string_at(outpass.data,
                                                             outpass.len))
        else:
            output += "Website:  {0}\n".format(host.encode("utf-8"))
            output += "Username: {0}\n".format(user)
            output += "Password: {0}\n\n".format(passw)
 
    credentials.done()
    libnss.NSS_Shutdown()
 
    if not got_password:
        return "NOPASSES"
 
    return output
 
 
def ask_section(profiles):
    """
    Prompt the user which profile should be used for decryption
    """
    sections = {}
    i = 1
    for section in profiles.sections():
        if section.startswith("Profile"):
            sections[str(i)] = profiles.get(section, "Path")
        else:
            continue
        i += 1
    return sections['1']
 
def main():
     
    firefox = ""
 
    if os.name == "nt":
        nssname = "nss3.dll"
        firefox = r"c:\Program Files (x86)\Mozilla Firefox"
        os.environ["PATH"] = ';'.join([os.environ["PATH"], firefox])
 
    else:
        nssname = "libnss3.so"
 
    try:
        libnss = CDLL(os.path.join(firefox, nssname))
 
    except Exception as e:
        return str(e)
        return "LIBNSSERROR"
 
    profile_path = "~\\AppData\\Roaming\\Mozilla\\Firefox"
 
    basepath = path.expanduser(profile_path)
    profileini = os.path.join(basepath, "profiles.ini")
 
    if not os.path.isfile(profileini):
        return "BADPROFINI"
 
    # Read profiles from Firefox profile folder
    profiles = ConfigParser()
    profiles.read(profileini)
 
    # Ask user which profile want's to open
    section = ask_section(profiles)
 
    # Prompt for Master Password
    profile = os.path.join(basepath, section)
 
    # And finally decode all passwords
    output = decrypt_passwords(profile, "", libnss)
    return(output)
 
if __name__ == "__main__":
    main()