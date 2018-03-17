from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class Debugger():
    def __init__(self):
        pass
    
    def load(self, path_to_exe):
        
        #dwCreation flag determines how to create the process
        #set creation flags = CREATE_NEW_CONSOLE if you want
        #to see Calculator GUI
        creation_flags = DEBUG_PROCESS
        
        #instantiate structs
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        
        #The following 2 options allow the started process
        #to be shown as a separate window. This also illustrates
        #how different settings in the STARTUPINFO struct can affect
        #the debuggee
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0
        
        #We then initializa the cb variable in the STARTUPINFO struct
        #which is just the size of the struct itself
        startupinfo.cb = sizeof(startupinfo)
        
        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   False,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):
            print("[*] We have succesfully launched the process!")
            print("[*] PID: ", process_information.dwProcessId)
        else:
            print("[*] Error: ", kernel32.GetLastError())