from my_debugger import *

debugger = Debugger()

pid = input("Enter the PID of the process to attach to: ")
debugger.attach(int(pid))

lst = debugger.enumerate_threads()

# For each thread, grab the values of registers
for thread in lst:
    thread_context = debugger.get_thread_context(thread)

    # Now we output the registers
    print("[*] Dumping registers for thread ID: ", thread)
    print("[*] RIP: 0x{0:X}".format(thread_context.Rip))
    print("[*] RSP: 0x{0:X}".format(thread_context.Rsp))
    print("[*] RBP: 0x{0:X}".format(thread_context.Rbp))
    print("[*] RAX: 0x{0:X}".format(thread_context.Rax))
    print("[*] RBX: 0x{0:X}".format(thread_context.Rbx))
    print("[*] RCX: 0x{0:X}".format(thread_context.Rcx))
    print("[*] RDX: 0x{0:X}".format(thread_context.Rdx))
    print("[*] END DUMP")

debugger.detach()