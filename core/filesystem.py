import os
import base64

class Filesystem:
	"""
	Functions related to interacting with the file system.
	"""
	def __init__(self):
		self.shell = None
		
	def change_directory(self, dir):
		try:
			os.chdir(dir)
			return ""
		except Exception as e:
			return str(e)
			
	def download(self, path, channel):
		##logging.info("Starting download of file: "+path)
		try:
			with open(path, "rb") as f:
				while True:
					data = f.read(8192)
					if not data: break
					channel.write_output(base64.b64encode(data))
					time.sleep(0.1) # Sleep, otherwise some data will be missing and jumbled
			
			channel.write_output(base64.b64encode(chr(255)))
			
		except Exception as e:
			channel.write_output("Error: "+str(e))
		
		return ""
			
	def upload(self, path, channel):
		##logging.info("Starting upload of file: "+path)
		
		with open(path, "wb") as f:
			while True:
				data = channel.read_input()
				if data == "CONN_LOST": return True
				data = base64.b64decode(data)
				if data.endswith(chr(255)):
					data = data[:-1]
					if not data: break
					f.write(data)
					break
				f.write(data)
			##logging.info("Upload complete.")
			return ""
			
fs = Filesystem()