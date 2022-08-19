# HookInject
&nbsp;&nbsp;&nbsp;&nbsp;This program was written for a university project. It monitors function calls in a process. For this, the Hook &amp; Inject technique is used, which consists in forcing the target process to load the specified DLL, which, in turn, changes tables with DLL functions, intercepting them. When using this technique, it is possible to monitor the call of specified functions, and it is also possible to replace the values ​​of the result of the function, changing the behavior of the target process.

____

&nbsp;&nbsp;&nbsp;&nbsp;The MS Detours library was used in the work to use ready-to-call library functions and simplify the work with hooks.
**How the injector program works:**<br/>
• At the start of the program, the program checks whether the process has administrator rights, if not, the program exits. <br/>
• Next, the input parameters are parsed (-pid, -name. -func, -hide). The PID of the process is found, either specified in the input argument, or by the specified process name (using CreateToolhelp32Snapshot() we find the PID of the process by its name)<br/>
• Then there is a parameter with the name of the function or the name of the hidden object.<br/>
• To connect the injector and the dll, a tcp client-server connection is used via localhost (127.0.0.1) and port 9000, the injector acts as a server. The server is being initialized.<br/>
• Open an existing process object, among the import tables you need to find the table corresponding to kernel32.dll. In this table, we look for the address of the function whose call needs to be tracked - we look for LoadLibrary (GetProcAddress()), we allocate memory for the LoadLibrary argument, namely, the string with the address of the injected dll (VirtualAllocEx()). After that, the address is overwritten with the address of the function that implements the hook itself.<br/>
• The dll is loaded (using CreateRemoteThread()). The server then waits for the client to connect, receives an "OK" confirmation message, and sends the parameters specified by the user.<br/>
• If we send a function, the server prints the received messages, if we hide the object, the server stops.<br/>

&nbsp;&nbsp;&nbsp;&nbsp;Communication between the injector and the dll is carried out using a client-server connection. When connecting, the client (ie dll) sends a success message, and the server (ie injector) sends a message with information about the purpose of the work: intercepting a function or hiding a file and the name of the function or file name, respectively.
  
&nbsp;&nbsp;&nbsp;&nbsp;**The principle of the dll, if you need to intercept the function:**<br/>
• Using DetourFindFunction we get the address of the original function.<br/>
• The DetourTransactionBegin and DetourUpdateThread functions are required to declare the bypass and update the thread.<br/>
• Next, DetourAttach replaces the original function with ours. Our function is a small assembly language function in which we save the state of the stack, call our function (DynamicDetour (), restore the state of the stack and transfer control to the original function. Our function's job is to send a message to the injector with the name of the function and the time it was called.
 
&nbsp;&nbsp;&nbsp;&nbsp;Since the library is in process memory, the DLLMain function can be called. This function is called with the PROCESS_ATTACH flag, after which the required hooks are set.
  
&nbsp;&nbsp;&nbsp;&nbsp;**If the purpose of the work is to hide the file:**<br/>
• The previously known functions are replaced - CreateFileA, CreateFileW, FindFirstFileA, FindFirstFileW, FindNextFileA, FindNextFileW, FindFirstFileExW, FindFirstFileExA. In these functions, their original counterparts are called, but before that it is checked if the name of the file to be worked with matches the name of the file that we need to hide, then either INVALID_HANDLE_VALUE is returned, or the file is ignored by moving to the next file using FindNextFile .
