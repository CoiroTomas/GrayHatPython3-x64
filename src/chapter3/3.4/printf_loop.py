from ctypes import *
from time import sleep

msvcrt = windll.msvcrt
counter = 0

while 1:
    msvcrt.printf(b"Loop iteration %d!\n", counter)
    sleep(2)
    counter += 1