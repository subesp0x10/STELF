from defines import *
import Queue
from twisted.internet import reactor
from twisted.protocols import socks

pivots = []
pivot_num = 0
fuck = Queue.Queue()

portfwd_queue = Queue.Queue()

class StoppableThread(threading.Thread):
	def __init__(self, target):
		super(StoppableThread, self).__init__()
		self.run = target
		self._stop = threading.Event()
		
	def stop(self):
		self._stop.set()
		
	def stopped(self):
		return self._stop.isSet()

def create_tcp_relay():
	local_addr, local_port, remote_addr, remote_port = fuck.get()
	current_thread = threading.currentThread()
	local_port = int(local_port)
	remote_port = int(remote_port)
	print "creating TCP relay"
	local_socket_server = socket.socket() # Binds to local port and listens for connections
	
	try:
		local_socket_server.bind((local_addr, local_port))
	except Exception as e:
		print e
		return
		
	print "bound"
		
	local_socket_server.listen(5)
	while not current_thread.stopped():
		local_socket, addr = local_socket_server.accept()
		print "got local"
		#local_socket.setblocking(0)
		
		remote_socket = socket.socket()
		
		try:
			remote_socket.connect((remote_addr, remote_port))
			print "got remote"
		except Exception as e:
			print e
			continue
			
		#remote_socket.setblocking(0)
			
		while not current_thread.stopped():
			try:
				readable, writable, errored = select.select([local_socket, remote_socket], [], [])
			except Exception as e:
				print e
				break
				
			if local_socket in readable:
				try:
					local_data = local_socket.recv(4096)
					if not local_data: break
					remote_socket.sendall(local_data)
				except Exception as e:
					print e
				
			if remote_socket in readable:
				try:
					remote_data = remote_socket.recv(4096)
					if not remote_data: break
					local_socket.sendall(remote_data)
				except Exception as e:
					print e
				
		print "closing"
		local_socket.close()
		remote_socket.close()
		del local_socket
		del remote_socket
	print "done"
	return
		
def create_pivot(proto, local_addr, local_port, remote_addr, remote_port):
	global pivot_num
	proto = proto.upper()
	if proto == "TCP":
		fuck.put((local_addr, local_port, remote_addr, remote_port))
		t = StoppableThread(target=create_tcp_relay)
		t.daemon = True
		t.start()
		pivots.append((pivot_num, t, proto, local_addr, local_port, remote_addr, remote_port))
		pivot_num += 1
	return "ok"
	
def list_pivots():
	pivot_list = ""
	for tuple in pivots:
		num, t, proto, local_addr, local_port, remote_addr, remote_port = tuple
		pivot_list += str(num) + ": "+proto+", "+local_addr+":"+str(local_port)+" -> "+remote_addr+":"+str(remote_port)
		
	return pivot_list
	
def delete_pivot(number):
	for tuple in pivots:
		num, t, proto, local_addr, local_port, remote_addr, remote_port = tuple
		if num == int(number):
			t.stop()
			pivots.remove(tuple)
			return "pivot will close on next connection attempt"
			
def socks_proxy():
	reactor.listenTCP(2080,socks.SOCKSv4Factory("./socks.log"))
	reactor.run()
	print "SOCKS EXITED!!"
			
def handle_portfwd():
	while True:
		current_thread = threading.currentThread()
		
		handler_socks_socket = socket.socket()
		handler_socks_socket.connect(("192.168.0.101",8080))
		
		local_socks_socket = socket.socket()
		local_socks_socket.connect(("localhost",2080))
		
		while not current_thread.stopped():
			try:
				readable, writable, errored = select.select([handler_socks_socket, local_socks_socket], [], [])
			except Exception as e:
				print e
				break
				
			if handler_socks_socket in readable:
				try:
					local_data = handler_socks_socket.recv(4096)
					print "got local data"
					if not local_data: break
					local_socks_socket.sendall(local_data)
				except Exception as e:
					print e
					break
					
			if local_socks_socket in readable:
				try:
					remote_data = local_socks_socket.recv(4096)
					print "got remote data"
					if not remote_data: break
					handler_socks_socket.sendall(remote_data)
				except Exception as e:
					print e
					break
					
		print "closing"
		handler_socks_socket.close()
		local_socks_socket.close()
		del handler_socks_socket
		del local_socks_socket
		
t = StoppableThread(target=socks_proxy)
t.daemon = True
t.start()

t = StoppableThread(target=handle_portfwd)
t.daemon = True
t.start()