# libelevate - Bypass ObRegisterCallbacks via elevation

## ObRegisterCallbacks
One of the goals of antivirus and anticheat software is to block malicious programs from reading and writing memory of other processes. Before more advanced enhancements to **PatchGuard**, anticheat and antivirus software were notorious for hooking the kernel, via an SSDT (System Service Dispatch Table) hook or straight up byte-patching, in order to monitor API calls from user-mode. **ObRegisterCallbacks** is Microsoft's official and supported method to intercept API calls that grant access rights of a process to another process. A very nice article that explains the internals of it can be found here: https://douggemhax.wordpress.com/2015/05/27/obregistercallbacks-and-countermeasures/.

## Reversing OpenProcess
By design, a modern operating system implements **virtual memory** and **process isolation**, meaning that an arbitrary process X cannot reference memory in another arbitrary process Y.  ```OpenProcess``` is a powerful WinAPI function that allows a user-mode process to gain access rights to other processes by asking for permission granted by the kernel. This access right is the entrypoint to enable many other powerful functions that manipulate other processes such as ```ReadProcessMemory```, ```WriteProcessMemory```, and ```VirtualAllocEx```.

```OpenProcess``` is an API that exported by **kernel32.dll**, which is part of the Windows subsystem that links against **ntdll.dll**, the library that contains all of the syscall stubs that will eventually call into the code in **ntoskrnl.exe** which does most of the work when it comes to implementing the higher level WinAPI functions.  

Let's talk about the flow of code that gets executed when someone links against the Window SDK and calls ```OpenProcess```. The first thing that happens is that ```NtOpenProcess```, the underlying **ntdll.dll** API, gets called. Then, a syscall instruction gets executed with the index that maps to the equivalent to ```NtOpenProcess``` on the syscall table. At this point, execution is transferred to the kernel, where the actual implementation lives. Finally, an internal and undocumented function inside **ntoskrnl.exe**, ```PsOpenProcess``` gets called, and the result of that function is returned. 

Here's a diagram that is basically a tl;dr.
![alt text](https://i.imgur.com/NqWD34r.png)

## Registering Callbacks
```ObRegisterCallbacks``` is a pretty well documented API on MSDN that clearly defines all the structures and parameters. Each callback you want to register is defined by the following structure and function prototypes:
```cpp
OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(
  PVOID RegistrationContext,
  POB_PRE_OPERATION_INFORMATION OperationInformation
);

void PobPostOperationCallback(
  PVOID RegistrationContext,
  POB_POST_OPERATION_INFORMATION OperationInformation
);

typedef struct _OB_OPERATION_REGISTRATION {
  POBJECT_TYPE                *ObjectType;
  OB_OPERATION                Operations;
  POB_PRE_OPERATION_CALLBACK  PreOperation;
  POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;
```

Example code for how to properly register callbacks can be found here: https://github.com/Microsoft/Windows-driver-samples/blob/master/general/obcallback/driver/callback.c

## Intercepting an OpenProcess Call
So the next logical question at this point would be: where do these callbacks actually get called? Recall the diagram for the flow of execution for ```OpenProcess``` and all the steps that are taken to transition from user mode to kernel mode. It makes sense that somewhere along that path of code execution, the callback registered via ```ObRegisterCallbacks``` will be called, and it makes sense that this gets called in the kernel. Let's take a look at the disassembly starting from the implementation of ```NtOpenProcess``` inside **ntoskrnl.exe**.

Disassembly from IDA shows us the following code:
```nasm 
PAGE:0000000140583180 NtOpenProcess   proc near               ; CODE XREF: PfpSourceGetPrefetchSupport+A5↓p
PAGE:0000000140583180                                         ; DATA XREF: .pdata:0000000140423B20↑o
PAGE:0000000140583180
PAGE:0000000140583180 var_18          = byte ptr -18h
PAGE:0000000140583180 var_10          = byte ptr -10h
PAGE:0000000140583180
PAGE:0000000140583180                 sub     rsp, 38h
PAGE:0000000140583184                 mov     rax, gs:188h
PAGE:000000014058318D                 mov     r10b, [rax+232h]
PAGE:0000000140583194                 mov     [rsp+38h+var_10], r10b
PAGE:0000000140583199                 mov     [rsp+38h+var_18], r10b
PAGE:000000014058319E                 call    PsOpenProcess
PAGE:00000001405831A3                 add     rsp, 38h
PAGE:00000001405831A7                 retn
PAGE:00000001405831A7 NtOpenProcess   endp
```
Cool, we don't see anything regarding ```ObRegisterCallbacks```, but we do see a call to ```PsOpenProcess```. Unfortunately, this function is extremely involved, so it doesn't make sense to paste an entire snippet here. Instead, let's look at a portion that may be related to ```ObRegisterCallbacks```.

```nasm
PAGE:00000001405836E0 PsOpenProcess   proc near               ; CODE XREF: NtAlpcOpenSenderProcess+194↑p
PAGE:00000001405836E0                                         ; NtOpenProcess+1E↑p
PAGE:00000001405836E0                                         ; DATA XREF: ...
PAGE:0000000140583950 loc_140583950:                          ; CODE XREF: PsOpenProcess+411↓j
PAGE:0000000140583950                 lea     rax, [rsp+2D8h+var_248]
PAGE:0000000140583958                 mov     qword ptr [rsp+2D8h+var_2A8], rax ; int
PAGE:000000014058395D                 mov     [rsp+2D8h+var_2B0], dil ; char
PAGE:0000000140583962                 mov     rax, cs:PsProcessType
PAGE:0000000140583969                 mov     [rsp+2D8h+var_2B8], rax ; __int64
PAGE:000000014058396E                 xor     r9d, r9d
PAGE:0000000140583971                 lea     r8, [rsp+2D8h+var_1E8]
PAGE:0000000140583979                 mov     edx, [rsp+2D8h+var_294]
PAGE:000000014058397D                 mov     rdi, [rsp+2D8h+BugCheckParameter2]
PAGE:0000000140583985                 mov     rcx, rdi        ; BugCheckParameter2
PAGE:0000000140583988                 call    ObOpenObjectByPointer
PAGE:000000014058398D                 mov     ebx, eax
PAGE:000000014058398F                 lea     rcx, [rsp+2D8h+var_1E8]
PAGE:0000000140583997                 call    SepDeleteAccessState
PAGE:000000014058399C                 lea     rcx, [rsp+2D8h+var_1C8]
PAGE:00000001405839A4                 call    SeReleaseSubjectContext
PAGE:00000001405839A9                 mov     eax, [rdi+2E0h]
PAGE:00000001405839AF                 mov     [rsp+2D8h+var_288], eax
PAGE:00000001405839B3                 mov     edx, 746C6644h
PAGE:00000001405839B8                 mov     rcx, rdi        ; BugCheckParameter2
PAGE:00000001405839BB                 call    ObfDereferenceObjectWithTag
PAGE:00000001405839C0                 test    ebx, ebx
PAGE:00000001405839C2                 js      short loc_1405839D8
```

We see a function call to ```ObOpenObjectByPointer```. Symbols in the kernel are generally prefixed with an identifier that describes what type of data it manipulates. As seen here ```ObOpenObjectByPointer``` and ```ObRegisterCallbacks``` are both prefixed with ```Ob```, which would be the **Object Manager**. 

```nasm
PAGE:00000001405831B0 ObOpenObjectByPointer proc near         ; CODE XREF: PspCreateObjectHandle+38↑p
PAGE:00000001405831B0                                         ; NtQueryInformationProcess+35F0↑p ...
PAGE:000000014058323F loc_14058323F:                          ; CODE XREF: ObOpenObjectByPointer+16E↓j
PAGE:000000014058323F                 mov     [rsp+258h+var_208], r14
PAGE:0000000140583244                 xor     r8d, r8d
PAGE:0000000140583247                 mov     [rsp+258h+var_210], r13
PAGE:000000014058324C                 mov     r9, rbx
PAGE:000000014058324F                 mov     [rsp+258h+var_218], r13d
PAGE:0000000140583254                 mov     rdx, rsi
PAGE:0000000140583257                 mov     [rsp+258h+var_220], r13
PAGE:000000014058325C                 mov     byte ptr [rsp+258h+var_228], r15b
PAGE:0000000140583261                 lea     ecx, [r8+1]
PAGE:0000000140583265                 mov     [rsp+258h+var_230], ebp
PAGE:0000000140583269                 mov     dword ptr [rsp+258h+var_238], r13d
PAGE:000000014058326E                 call    ObpCreateHandle
PAGE:0000000140583273                 mov     edi, eax
PAGE:0000000140583275                 test    eax, eax
PAGE:0000000140583277                 js      loc_14058334F
```

Inside ```ObOpenObjectByPointer```, we see another call to an **Object Manager** related function, ```ObpCreateHandle```.

```nasm
PAGE:00000001404DBEB0 ObpCreateHandle proc near               ; CODE XREF: ObInsertObjectEx+109↑p
PAGE:00000001404DBEB0                                         ; ObInsertObjectEx+397↑p ...
PAGE:00000001404DC7C1 loc_1404DC7C1:                          ; CODE XREF: ObpCreateHandle+324↑j
PAGE:00000001404DC84A                 xor     eax, eax
PAGE:00000001404DC84C                 mov     [rbp+110h+var_88], rax
PAGE:00000001404DC853                 mov     [rbp+110h+Dst], 1
PAGE:00000001404DC85A                 mov     [rbp+110h+var_90], rbx
PAGE:00000001404DC861                 mov     dword ptr [rbp+110h+var_C8+4], edi
PAGE:00000001404DC864                 mov     dword ptr [rbp+110h+var_C8], edi
PAGE:00000001404DC867                 call    ObpCallPreOperationCallbacks
PAGE:00000001404DC86C                 mov     ebx, eax
PAGE:00000001404DC86E                 test    eax, eax
PAGE:00000001404DC870                 js      loc_1406796F5
```

And finally, we find what we're looking for. ```ObpCallPreOperationCallbacks``` is the function that ultimately calls the ```POB_PRE_OPERATION_CALLBACK PreOperation``` function defined in the ```_OB_OPERATION_REGISTRATION``` structure initially passed into ```ObRegisterCallbacks```. In summary, this function loops over all of the ```_OB_OPERATION_REGISTRATION``` structures that are registered, and then sequentially calls each **PreOperation** function defined by a kernel mode driver.

## Bypassing ObRegisterCallbacks
Douggem's article details a method of bypassing these callbacks by using DKOM (Direct Kernel Object Manipulation) in order to locate the callbacks in kernel memory, and then remove them so that ```ObpCallPreOperationCallbacks``` has nothing to call. This method, though effective, has a few drawbacks.  
1. Using undocumented structures could be dangerous due to Windows updates
2. Forcibly removing callbacks means that the driver that registered them can execute sanity checks
3. PatchGuard may someday decide to check for tampering of these kernel structures

**libelevate** takes a different approach. Instead of directly touching callbacks to prevent stripping of access rights, why not elevate those rights after the fact that they have been stripped? 

### Locating a HANDLE in the kernel
An exported, but undocumented function ```ExEnumHandleTable``` does exactly what we want: execute a driver-defined function for every handle table entry in the handle table. Let's take a look at the disassembly:

```nasm
PAGE:000000014050E4C0 ExEnumHandleTable proc near             ; CODE XREF: IoRevokeHandlesForProcess+11E↑p
PAGE:000000014050E4C0                                         ; NtQueryInformationProcess+29DE↑p ...
PAGE:000000014050E5AF loc_14050E5AF:                          ; CODE XREF: ExEnumHandleTable+7A↑j
PAGE:000000014050E5AF                                         ; DATA XREF: .pdata:000000014041EA38↑o ...
PAGE:000000014050E5AF                 add     r9, 4
PAGE:000000014050E5B3                 mov     rcx, rbp
PAGE:000000014050E5B6                 mov     rdx, r9
PAGE:000000014050E5B9                 call    ExpLookupHandleTableEntry
PAGE:000000014050E5BE                 mov     rdi, rax
PAGE:000000014050E5C1                 jmp     loc_14050E540
```

Sweet, ```ExpLookupHandleTableEntry``` looks like a function that does what we actually want. This undocumented function takes in a **pointer to the object table**, found in the ```EPROCESS``` structure for a process, and the ```HANDLE``` value to look for. What this returns is a pointer to a ```_HANDLE_TABLE_ENTRY``` structure, which looks like this:
```C
typedef struct _HANDLE_TABLE_ENTRY
{
     union
     {
          PVOID Object;
          ULONG ObAttributes;
          PHANDLE_TABLE_ENTRY_INFO InfoTable;
          ULONG Value;
     };
     union
     {
          ULONG GrantedAccess;
          struct
          {
               WORD GrantedAccessIndex;
               WORD CreatorBackTraceIndex;
          };
          LONG NextFreeTableEntry;
     };
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
```

### Leveraging libcapcom
Implementing the handle elevation technique is quite simple given all the information above. The flow of execution is the following:
1. Open a handle with your desired access rights using ```OpenProcess```
2. Antivirus/anticheat driver's callback strips your handle access rights
3. In the context of the kernel:
    * Find the ```HANDLE_TABLE_ENTRY``` that maps to the initial handle from step 1. 
    * Set the ```GrantedAccess``` member to your desired access rights
4. Do whatever you want in user mode with your newly elevated handle

### Caveats
1. I have basically copy-pasted decompiled code for ```ExpLookupHandleTableEntry``` to be called in the context of the kernel. I can either do that, or implement a signature scan for the function, and call it directly. Either way, it is still Windows update dependent.
2. Antivirus/anticheat drivers can still strip handles by **manually iterating the handle table** and stripping unauthorized handles. If I am able to elevate handles, then they can strip them after ```ObRegisterCallbacks``` too.

## How to use this library
1. Build the project
2. Link against **libelevate.lib**
3. Include **libelevate.h**
4. Call ```OpenProcess```
5. Call ```grant_access(HANDLE, ACCESS_MASK)``` with the returned ```HANDLE``` and your desired access rights

An example of the list above can be found in the **testlibelevate** project.
![alt text](https://puu.sh/BxY5s/b1b4c4d15b.png)