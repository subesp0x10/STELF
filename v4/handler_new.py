import socket, sys

class Handler:
    def __init__(self, bind, port):
        self.bind = bind
        self.port = port

        self.server_sock = socket.socket()
        self.server_sock.bind((self.bind, self.port))
        
        self.commands = []
        
    def send_cmd(self, command):
        return "bitch"
    def start(self):
        self.server_sock.listen(5)
        self.client_socket, _ = self.server_sock.accept()
        while True:
            user_input = raw_input()
            self.client_socket.sendall(user_input)
            data = self.client_socket.recv(4096)
            print data

handler = Handler("0.0.0.0", 8080)
handler.start()
