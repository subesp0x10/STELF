import socket, sys

class Handler:
    def __init__(self, bind, port):
        self.bind = bind
        self.port = port

        self.server_sock = socket.socket()
        self.server_sock.bind((self.bind, self.port))
    def start():
        self.server_sock.listen(5)
