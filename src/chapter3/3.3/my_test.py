from my_debugger import *

debugger = Debugger()

pid = input("Enter the PID of the process to attach to: ")


debugger.attach(int(pid))
debugger.run()
debugger.detach()