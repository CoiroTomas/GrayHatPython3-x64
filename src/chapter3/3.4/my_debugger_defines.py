from ctypes import *

# Let's map the Microsoft types to ctypes for clarity
BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_ulong
DWORD64   = c_ulonglong
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char) 
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
UINT_PTR  = c_ulong
SIZE_T    = c_size_t

class M128A(Structure):
    _fields_ = [
        ("High", DWORD64),
        ("Low", DWORD64),
        ]

# Constants
DEBUG_PROCESS         = 0x00000001
CREATE_NEW_CONSOLE    = 0x00000010
PROCESS_ALL_ACCESS    = 0x001F0FFF
INFINITE              = 0xFFFFFFFF
DBG_CONTINUE          = 0x00010002


# Debug event constants
EXCEPTION_DEBUG_EVENT      =    0x1
CREATE_THREAD_DEBUG_EVENT  =    0x2
CREATE_PROCESS_DEBUG_EVENT =    0x3
EXIT_THREAD_DEBUG_EVENT    =    0x4
EXIT_PROCESS_DEBUG_EVENT   =    0x5
LOAD_DLL_DEBUG_EVENT       =    0x6
UNLOAD_DLL_DEBUG_EVENT     =    0x7
OUTPUT_DEBUG_STRING_EVENT  =    0x8
RIP_EVENT                  =    0x9

# debug exception codes.
EXCEPTION_ACCESS_VIOLATION     = 0xC0000005
EXCEPTION_BREAKPOINT           = 0x80000003
EXCEPTION_GUARD_PAGE           = 0x80000001
EXCEPTION_SINGLE_STEP          = 0x80000004


# Thread constants for CreateToolhelp32Snapshot()
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST |
                       TH32CS_SNAPPROCESS |
                       TH32CS_SNAPTHREAD |
                       TH32CS_SNAPMODULE)
THREAD_ALL_ACCESS   = 0x001F0FFF

# Context flags for GetThreadContext()
CONTEXT_AMD64                  = 0x00100000
CONTEXT_CONTROL                = 0x00000001 | CONTEXT_AMD64
CONTEXT_INTEGER                = 0x00000002 | CONTEXT_AMD64
CONTEXT_SEGMENTS               = 0x00000004 | CONTEXT_AMD64
CONTEXT_FLOATING_POINT         = 0x00000008 | CONTEXT_AMD64
CONTEXT_DEBUG_REGISTERS        = 0x00000010 | CONTEXT_AMD64
CONTEXT_FULL                   = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
CONTEXT_ALL                    = CONTEXT_FULL | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS

# Memory permissions
PAGE_EXECUTE_READWRITE         = 0x00000040

# Hardware length of breakpoints
HW_LEN_1 = 0x0
HW_LEN_2 = 0x1
HW_LEN_4 = 0x3
HW_LEN_8 = 0x2

# Hardware breakpoint conditions
HW_ACCESS                      = 0x00000003
HW_EXECUTE                     = 0x00000000
HW_WRITE                       = 0x00000001

# Memory page permissions, used by VirtualProtect()
PAGE_NOACCESS                  = 0x00000001
PAGE_READONLY                  = 0x00000002
PAGE_READWRITE                 = 0x00000004
PAGE_WRITECOPY                 = 0x00000008
PAGE_EXECUTE                   = 0x00000010
PAGE_EXECUTE_READ              = 0x00000020
PAGE_EXECUTE_READWRITE         = 0x00000040
PAGE_EXECUTE_WRITECOPY         = 0x00000080
PAGE_GUARD                     = 0x00000100
PAGE_NOCACHE                   = 0x00000200
PAGE_WRITECOMBINE              = 0x00000400


# Structures for CreateProcessA() function
# STARTUPINFO describes how to spawn the process
class STARTUPINFO(Structure):
    _fields_ = [
        ("cb",            DWORD),        
        ("lpReserved",    LPTSTR), 
        ("lpDesktop",     LPTSTR),  
        ("lpTitle",       LPTSTR),
        ("dwX",           DWORD),
        ("dwY",           DWORD),
        ("dwXSize",       DWORD),
        ("dwYSize",       DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",       DWORD),
        ("wShowWindow",   WORD),
        ("cbReserved2",   WORD),
        ("lpReserved2",   LPBYTE),
        ("hStdInput",     HANDLE),
        ("hStdOutput",    HANDLE),
        ("hStdError",     HANDLE),
        ]

# PROCESS_INFORMATION receives its information
# after the target process has been successfully
# started.
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
        ]

# When the dwDebugEventCode is evaluated
class EXCEPTION_RECORD(Structure):
    pass
    
EXCEPTION_RECORD._fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
        ]

class _EXCEPTION_RECORD(Structure):
    _fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
        ]

# Exceptions
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord",    EXCEPTION_RECORD),
        ("dwFirstChance",      DWORD),
        ]

#Create Processes
class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile",               HANDLE),
        ("hProcess",            HANDLE),
        ("hThread",             HANDLE),
        ("lpBaseOfImage",       LPVOID),
        ("dwDebugInfoFileOffset",DWORD),
        ("nDebugInfoSize",      DWORD),
        ("lpThreadLocalBase",   LPVOID),
        ("lpStartAddress",      HANDLE),#LPSTARTTHREAD
        ("lpImageName",         LPVOID),
        ("fUnicode",            WORD)
    ]

#Create threads
class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("hThread",             HANDLE),
        ("lpThreadLocalBase",   LPVOID),
        ("lpStartAddress",      HANDLE)#LPSTARTTHREAD
        ]

#Exit threads
class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode",  DWORD)
        ]
    
#Exit processes
class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode",  DWORD)
        ]
    
#Load dlls
class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile",                   HANDLE),
        ("lpBaseOfDll",             LPVOID),
        ("dwDebugInfoFileOffset",   DWORD),
        ("nDebugInfoSize",          DWORD),
        ("lpImageName",             LPVOID),
        ("fUnicode",                WORD)
        ]

#Unload dlls
class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", LPVOID)
        ]

#Output debug strings
class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ("lpDebugStringData",       LPTSTR),
        ("fUnicode",                WORD),
        ("nDebugStringLength",      WORD)
        ]

#RIP info
class RIP_INFO(Structure):
    _fields_ = [
        ("dwError", DWORD),
        ("dwType",  DWORD)
        ]

# it populates this union appropriately
class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",         EXCEPTION_DEBUG_INFO),
        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo",           RIP_INFO),
        ]   

# DEBUG_EVENT describes a debugging event
# that the debugger has trapped
class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId",      DWORD),
        ("dwThreadId",       DWORD),
        ("u",                DEBUG_EVENT_UNION),
        ]

class XMM_SAVE_AREA32(Structure):
    _pack_ = 1
    _fields_ = [
        ("ControlWord", c_ushort),
        ("DataOffset", c_ulong),
        ("DataSelector", c_ushort),
        ("ErrorOffset", c_ulong),
        ("ErrorOpcode", c_ushort),
        ("ErrorSelector", c_ushort),
        ("FloatRegisters", M128A * 1),
        ("MxCsr", c_ulong),
        ("MxCsr_Mask", c_ulong),
        ("Reserved1", c_ubyte),
        ("Reserved2", c_ushort),
        ("Reserved3", c_ushort),
        ("Reserved4", c_ubyte * 96),
        ("StatusWord", c_ushort),
        ("TagWord", c_ubyte),
        ("XmmRegisters", M128A * 2),
        ] 
    

class DUMMYSTRUCTNAME(Structure):
    _fields_ = [
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
        ]
     
class DUMMYUNIONNAME(Union):
    _fields_ = [
        ("FltSave", XMM_SAVE_AREA32),
        ("DUMMYSTRUCTNAME", DUMMYSTRUCTNAME)
        ]

# The CONTEXT structure which holds all of the 
# register values after a GetThreadContext() call
#This Structure depends on your computer's architecture
#This one is for AMD64, if you have a different arch search your WinNT.h file
class CONTEXT(Structure):
    _fields_ = [
    
        # Register parameter home addresses.

        ("P1Home", DWORD64),
        ("P2Home", DWORD64),
        ("P3Home", DWORD64),
        ("P4Home", DWORD64),
        ("P5Home", DWORD64),
        ("P6Home", DWORD64),    

        # Control flags.

        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),

        # Segment Registers and processor flags.

        ("SegCs",WORD),
        ("SegDs",WORD),
        ("SegEs",WORD),
        ("SegFs",WORD),
        ("SegGs",WORD),
        ("SegSs",WORD),
        ("EFlags",WORD),

        # Debug registers

        ("Dr0",DWORD64),
        ("Dr1",DWORD64),
        ("Dr2",DWORD64),
        ("Dr3",DWORD64),
        ("Dr6",DWORD64),
        ("Dr7",DWORD64),

        # Integer registers.

        ("Rax",DWORD64),
        ("Rcx",DWORD64),
        ("Rdx",DWORD64),
        ("Rbx",DWORD64),
        ("Rsp",DWORD64),
        ("Rbp",DWORD64),
        ("Rsi",DWORD64),
        ("Rdi",DWORD64),
        ("R8",DWORD64),
        ("R9",DWORD64),
        ("R10",DWORD64),
        ("R11",DWORD64),
        ("R12",DWORD64),
        ("R13",DWORD64),
        ("R14",DWORD64),
        ("R15",DWORD64),

        # Program counter.

        ("Rip", DWORD64),

        # Floating point state.

        ("DUMMYUNIONNAME", DUMMYUNIONNAME),
    
        # Vector registers.
    
        ("VectorRegister", M128A * 26),
        ("VectorControl", DWORD64),
    
        # Special debug control registers.
    
        ("DebugControl", DWORD64),
        ("LastBranchToRip", DWORD64),
        ("LastBranchFromRip", DWORD64),
        ("LastExceptionToRip", DWORD64),
        ("LastExceptionFromRip", DWORD64)
]

# THREADENTRY32 contains information about a thread
# we use this for enumerating all of the system threads

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",             DWORD),
        ("cntUsage",           DWORD),
        ("th32ThreadID",       DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri",          DWORD),
        ("tpDeltaPri",         DWORD),
        ("dwFlags",            DWORD),
    ]

# Supporting struct for the SYSTEM_INFO_UNION union
class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture",    WORD),
        ("wReserved",                 WORD),
]


# Supporting union for the SYSTEM_INFO struct
class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dwOemId",    DWORD),
        ("sProcStruc", PROC_STRUCT),
]
# SYSTEM_INFO structure is populated when a call to 
# kernel32.GetSystemInfo() is made. We use the dwPageSize
# member for size calculations when setting memory breakpoints
class SYSTEM_INFO(Structure):
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
]

# MEMORY_BASIC_INFORMATION contains information about a 
# particular region of memory. A call to kernel32.VirtualQuery()
# populates this structure.
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
]
    
