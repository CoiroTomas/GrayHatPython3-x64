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
    print("[*] RIP: ", thread_context.Rip)
    print("[*] RSP: ", thread_context.Rsp)
    print("[*] RBP: ", thread_context.Rbp)
    print("[*] RAX: ", thread_context.Rax)
    print("[*] RBX: ", thread_context.Rbx)
    print("[*] RCX: ", thread_context.Rcx)
    print("[*] RDX: ", thread_context.Rdx)
    print("[*] END DUMP")

debugger.detach()