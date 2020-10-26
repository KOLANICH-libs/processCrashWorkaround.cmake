Process crash workaround
========================

This program allow the children process to crash without parent process returning an error. There is also a CMake module for that, since you cannot ignore errors in processes called as part of target building - not be CMake, but by the build system itself. Using a CMake script for that in `-p` mode is unacceptable, since CMake will parse and use its arguments and there is no way to disable it.

CMake module
------------

To use this as a CMake module

1. Add it as a submodule into your git repo.
2. 

```cmake
set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_LIST_DIR}/thirdparty/cmakeProcessCrashWorkaround")  # add it to search path of CMake modules
include(cmakeProcessCrashWorkaround)  # include it
programCrashWorkaroundInit(${your_name_of_the_workaround_app_target})  # choose a name of the target for this program and build this program. You may want the name of the target to be unique, alphanum and human-readable.
```

3. If you have a command in [`add_custom_command`](https://cmake.org/cmake/help/latest/command/add_custom_command.html) that is expected to crash
```cmake
COMMAND "${your_executable_path}" ARGS ${args_for_it}
```
, replace it with
```cmake
COMMAND "$<TARGET_FILE:${your_name_of_the_workaround_app_target}>" ARGS "${your_executable_path}" ${args_for_it}
```
. Of course it makes no sense to use the variable `${your_name_of_the_workaround_app_target}`, just replace it with the name you have chosen.

Implementation details
----------------------

It also prevents Windows Error Report modal dialogs from appearing, which is not good for processing from other programs, such as makefiles, because as long as the dialog is not closed, the execution stops and waits for it being closed.

To do it we need to call [`SetErrorMode`](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode), but there is a nuance, this function must be called the current process. Though the effects of this function are inherited to child processes, it is ideologically incorrect to call it within parent process, since it opens a window for which crashes of parent process won't be handled, which is not an intended effect for this tool.

So we have to inject code into a child process. Since I am a newbie for that, I have implemented 3 ways of passing params there, just to learn them and just to make a tutorial, since it seems to be a lack of information in the Net about doing this.

So, this can also be considered a tutorial in
* code injection into foreign processes;
* writing the payload as an inline assembly, working around some issues related to it;
* writing position-independent code in assembly.

3 methods of passing params (in our case it is the address of [`SetErrorMode`](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode), which is the same for all the processes currently running on the machine due to the way [ASLR](https://en.wikipedia.org/wiki/ASLR) is implemented on Windows) have been implemented:
* The most convenient and trivial one: via an argument`lpThreadParameter` of a thread function with type `PTHREAD_START_ROUTINE`. Pass `-m param` to use it.
* via an immediate in x86 `mov` instruction, then an indirect call using it (indirect call using immediate is not really useful for that). It is a single byte encoding the instruction, followed by a value. We just rewrite that value. Pass `-m immed` to use it.
* The most convenient variant from the ones assumming we cannot provide the params directly - using the table in front of payload with the address in it, and using an indirect call to that address. We have to obtain `EIP` with a hack of calling the next instruction, and then popping it from stack into a register. Then we add there the compile-time-calculated offset of the pointer in the table. And after it we can make an indirect call. Why is it the most convenient? Because we don't have to edit opcodes ourselves!

Limitations
-----------

1. This program requres the child process to have the same bitness and architecture as the parent one.
2. So, not very suitable for cross-compilation using CMake i its current state.
