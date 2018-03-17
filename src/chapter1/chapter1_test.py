from ctypes import *

msvcrt = cdll.msvcrt

message_string = b"Hello world!\n"

msvcrt.printf(b"Testing: %s", message_string)
