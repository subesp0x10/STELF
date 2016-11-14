import subprocess, threading

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
			
def test(data):
	return data.upper()[::-1]