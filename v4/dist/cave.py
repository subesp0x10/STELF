with open("shell.exe", "rb") as f:
	req = 180
	cursize = 0
	offset = 0
	for i in range(5000):
		if f.read(1) == chr(0): cursize += 1
		else:
			cursize = 0
			cave_start = i
		
		if cursize >= req: break
	print cursize, cave_start