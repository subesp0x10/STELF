import socket, time, os, sys, urllib, base64, subprocess as sp, threading, binascii, SimpleHTTPServer, SocketServer, Queue
from Crypto.Cipher import AES

aesobj = AES.new('brvty5b6BB7y56b754BBERBT', AES.MODE_CFB, 'odiryvt93y489yrv')
														#Cryptography stuff
EncodeAES = lambda  s: base64.b64encode(aesobj.encrypt(s))
DecodeAES = lambda  e: aesobj.decrypt(base64.b64decode(e))

marker = chr(255)
TIMEOUT = 30

server_sock = socket.socket()
server_sock.bind(("0.0.0.0",80))
server_sock.listen(5)


comm_socket, addr = server_sock.accept()
sys.stdout.write(comm_socket.recv(4096)[:-1])

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

	def run(self):
		try:
			while True:
				user_input = raw_input()
				self.send(user_input)
				sys.stdout.write(self.input_queue.get())
		except EOFError:
			os._exit(0)
			
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
	
	if data.startswith(chr(1)):
		user_input_handler.input_queue.put(data[1:])
		
	elif data.startswith(chr(9)):
		pass