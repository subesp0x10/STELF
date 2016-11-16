import socket, sys, json

class Handler:
    def __init__(self, bind, port):
        self.bind = bind
        self.port = port

        self.server_sock = socket.socket()
        self.server_sock.bind((self.bind, self.port))
        
        self.commands = []
        
    def send_cmd(self, command):
        self.commands.append(command)
        self.client_socket.sendall(command)

    def start(self):
        self.server_sock.listen(5)
        self.client_socket, _ = self.server_sock.accept()
        while True:
            user_input = raw_input()
            self.send_cmd(user_input)
            data = self.client_socket.recv(4096)
            print json.loads(data)

handler = Handler("0.0.0.0", 8080)
handler.start()
