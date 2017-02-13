import subprocess
import threading
import logging

class Execute:
	"""
	Functions related to executing programs.
	"""
	def __init__(self):
		self.shell = None
		
	def __init__(self):
		self.killed = False
		
	def kill_proc(self, pid):
		logging.warn("Killing command after taking over a minute to execute.")
		process = psutil.Process(pid)
		for proc in process.children(recursive=True): # Kill the children first so the parent has to suffer
			proc.terminate()
		process.terminate()
		self.killed = True
		
	def execute_shell_command(self, command):
		"""
		The core of the whole shell, this function executes shell commands. If the process takes longer than 60 seconds to return, it is killed, and the user is notified about it.
		"""
		logging.info("Executing shell command: "+command.strip())
		proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		timer = threading.Timer(60, self.kill_proc, [proc.pid])
		timer.start()
		out = proc.stdout.read() + proc.stderr.read()
		if self.killed: out += "\n(Process terminated after taking too long to execute)"
		timer.cancel()
		self.killed = False
		logging.debug("Result of shell command: "+out.strip())
		return out
		
execute = Execute()