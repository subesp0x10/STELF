import os
import threading

def windows_only(func):
	"""
	This decorator can be used to mark functions that will only work on Windows.
	"""
	def tester(*args):
		if os.name != "nt": return "Command not available on non-windows OS."
		else: return func(*args)
	return tester
	
class StoppableThread(threading.Thread):
	"""
	Thread that can be stopped by an external force. All threads should get a handle to themselves using threading.currentThread(), then check the stopped() flag every loop.
	"""
	def __init__(self, target, args=()):
		super(StoppableThread, self).__init__(target=target, args=args)
		self._stop = threading.Event()
		
	def stop(self):
		self._stop.set()
		
	def stopped(self):
		return self._stop.isSet()