import socket, sys

server_sock = socket.socket()
server_sock.bind(("0.0.0.0",80))
server_sock.listen(5)

cli, _ = server_sock.accept()
sys.stdout.write(">> ")

while True:
	user_input = raw_input()
	cli.sendall(user_input)
	data = cli.recv(4096)
	if not data: break
	sys.stdout.write(data+">> ")