/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software, either in source code form or as a compiled binary, for any purpose, commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this software dedicate any and all copyright interest in the software to the public domain. We make this dedication for the benefit of the public at lele and to the detriment of our heirs and successors. We intend this dedication to be an overt act of relinquishment in perpetuity of all present and future rights to this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org/>
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <shlwapi.h>
#include <wchar.h>
#include <windows.h>

void which(wchar_t *ifn, wchar_t *ofn) {
	const wchar_t ext[] = L".exe";
	SearchPathW(NULL, ifn, ext, PATH_MAX, ofn, NULL);
}

typedef UINT(NTAPI *SetErrorModePtr)(UINT uMode);
SetErrorModePtr SetErrorModeAddr = NULL;

struct payload_info {
	void *payloadStartAddr;
	size_t size, pageAlignedSize, funcOffset, setErrModeStaticConstAddrOffset, payloadImmediateMovInstrOffset;
};

enum TestOnMyselfMode{
	DONT_TEST=0,
	TEST_BY_CONTROL_FLOW=1,
	TEST_BY_NEW_THREAD=2,
	TEST_BY_NEW_REMOTE_THREAD=3,
};


enum WER_DISABLE_METHOD
{
	WER_DISABLE_METHOD_INVALID = 0,
	WER_DISABLE_METHOD_INHERIT,
	WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_PARAMS ,
	WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_IMMEDIATE,
	WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_STATIC,
};

struct CLIArgs {
	BOOL showHelp;
	enum TestOnMyselfMode testOnMyself;
	enum WER_DISABLE_METHOD method;
	size_t startOfPosArgs;
	size_t cumLen;
	wchar_t *childCommandLine;
	wchar_t *executableName;
};

/* some dummy functions pointers, otherwise the pInfo is NOT imported */
extern void payloadImmediateStart(void);
extern void payloadImmediateEnd(void);
extern void payloadImmediateMovInstrOffset(void);
extern DWORD WINAPI payloadImmediateFunc(LPVOID lpParam);

extern void payloadParamsStart(void);
extern void payloadParamsEnd(void);
extern DWORD WINAPI payloadParamsFunc(LPVOID lpParam);

extern void payloadConstStart(void);
extern void payloadConstEnd(void);
extern DWORD WINAPI payloadConstFunc(LPVOID lpParam);
extern void payloadConstSetErrorModeAddrVolatileAddrFunc(void);

asm(".section .payload\n"
	".p2align 8\n"
	"_payloadParamsStart:\n"
	"_payloadParamsFunc@4:\n"
	"push   %ebp\n"
	"mov    %esp,%ebp\n"
	"sub    $0x8,%esp\n"
	"mov    0x8(%ebp),%eax\n"
	"movl   $0x3,(%esp)\n"
	"mov    %eax,-0x4(%ebp)\n"
	"call   *0x8(%ebp)\n"
	"add    $0x4,%esp\n"
	"pop    %ebp\n"
	"ret    $0x4\n"
	"_payloadParamsEnd:\n");

asm(".section .payload\n"
	".p2align 8\n"
	"_payloadImmediateStart:\n"
	"_payloadImmediateFunc@4:\n"
	"push   %ebp\n"
	"mov    %esp,%ebp\n"
	"sub    $0x8,%esp\n"
	"mov    0x8(%ebp),%eax\n"
	"movl   $0x3,(%esp)\n"
	"_payloadImmediateMovInstrOffset:mov    $0xdeadbeef,%ecx\n"
	"mov    %eax,-0x4(%ebp)\n"
	"call   *%ecx\n"// indirect calls are always absolute in x86! Why do they use call mnemonic instead of lcall?
	"add    $0x4,%esp\n"
	"pop    %ebp\n"
	"ret    $0x4\n"
	"_payloadImmediateEnd:\n");

asm(
	".section .payload\n"
	".p2align 8\n"
	"_payloadConstStart:\n"
	"_payloadConstSetErrorModeAddrVolatileAddrFunc:.quad 0xB4DF00D0DEADBEEF\n"
	"_payloadConstFunc@4:\n"
	"push   %ebp\n"
	"mov    %esp,%ebp\n"
	"sub    $0x10,%esp\n"
	"mov    0x8(%ebp),%eax\n"
	"call   payloadConstSaveEipNext\n"	// short call in at&t syntax, calls by absolute addresses are lcall in at&t syntax
	"payloadConstSaveEipNext:pop %ecx\n"// with payloadConstSaveEip effectively moves %eip to %ecx, which is not natively supported
	".set _SetErrorModeAddrOffsetFromEcxSaveSite, _payloadConstSetErrorModeAddrVolatileAddrFunc - payloadConstSaveEipNext\n"
	"movl   $0x3,(%esp)\n"
	"mov    %eax,-0x8(%ebp)\n"
	"add $_SetErrorModeAddrOffsetFromEcxSaveSite, %ecx\n"
	"call   *(%ecx)\n"// indirect calls are always absolute in x86! Why do they use call mnemonic instead of lcall?
	"sub    $0x4,%esp\n"
	"mov    -0x4(%ebp),%ecx\n"
	"mov    %eax,-0xc(%ebp)\n"
	"mov    %ecx,%eax\n"
	"add    $0x10,%esp\n"
	"pop    %ebp\n"
	"ret    $0x4\n"
	"_payloadConstEnd:\n");

// extern void SetErrorModeAddrVolatileAddrFunc(void);

// const void * SetErrorModeAddrVolatileAddr = (void*)
// &SetErrorModeAddrVolatileAddrFunc;

/*
asm (
		".global _payloadStart\n"
		"_payloadStart:\n"
);
volatile const SetErrorModePtr SetErrorModeAddrVolatile = (SetErrorModePtr)(0xDEADBEEF);
DWORD WINAPI payloadFunc(void *unneeded){
		(*(&SetErrorModeAddrVolatile))(SEM_FAILCRITICALERRORS |
SEM_NOGPFAULTERRORBOX);
}
asm (
		".global _payloadEnd\n"
		"_payloadEnd:\n"
);
const void * SetErrorModeAddrVolatileAddr = (void*) &SetErrorModeAddrVolatile;
DWORD WINAPI payloadFunc2(void *unneeded){
	return ((SetErrorModePtr) 0xdeadbeef)(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
}*/


SYSTEM_INFO sinfo;
HANDLE job;
HANDLE currentProcess;

size_t size2alloc(size_t size) {
	DWORD gran = sinfo.dwPageSize;
	return ((size + gran - 1) / gran ) * gran ;
}

struct payload_info getPayloadpInfo(enum WER_DISABLE_METHOD method) {
	struct payload_info pInfo;

	void *payloadStart = NULL, *payloadFunc = NULL, *payloadEnd = NULL;
	if(method == WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_PARAMS) {
		payloadStart = (void *) (&payloadParamsStart);
		payloadFunc = (void *) (&payloadParamsFunc);
		payloadEnd = (void *) (&payloadParamsEnd);
	} else if(method == WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_IMMEDIATE) {
		payloadStart = (void *) (&payloadImmediateStart);
		payloadFunc = (void *) (&payloadImmediateFunc);
		payloadEnd = (void *) (&payloadImmediateEnd);
	} else if(method == WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_STATIC) {
		payloadStart = (void *) (payloadConstStart);
		payloadFunc = (void *) (payloadConstFunc);
		payloadEnd = (void *) (payloadConstEnd);
	}

	fwprintf(stderr, L"payloadStart is %d\n", payloadStart);

	pInfo.payloadStartAddr = payloadStart;
	pInfo.size = payloadEnd - payloadStart;
	pInfo.funcOffset = (void *) payloadFunc - payloadStart;
	if(method == WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_IMMEDIATE) {
		pInfo.payloadImmediateMovInstrOffset = (void *) (&payloadImmediateMovInstrOffset) - payloadStart;
	} else {
		pInfo.payloadImmediateMovInstrOffset = 0;
	}
	if(method == WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_STATIC) {
		C_ASSERT(pInfo.funcOffset != 0);
		pInfo.setErrModeStaticConstAddrOffset = (void *) payloadConstSetErrorModeAddrVolatileAddrFunc - payloadStart;
		fwprintf(stderr, L"pInfo.setErrModeStaticConstAddrOffset is %p\n", pInfo.setErrModeStaticConstAddrOffset);
		C_ASSERT(pInfo.funcOffset != pInfo.setErrModeStaticConstAddrOffset);
	} else {
		pInfo.setErrModeStaticConstAddrOffset = 0;
	}

	fwprintf(stderr, L"pInfo.payloadStartAddr is %p\n", pInfo.payloadStartAddr);
	fwprintf(stderr, L"pInfo.size is %p\n", pInfo.size);
	fwprintf(stderr, L"pInfo.funcOffset is %p\n", pInfo.funcOffset);

	pInfo.pageAlignedSize = size2alloc(pInfo.size);
	return pInfo;
}

void prepareBuffer(uint8_t *buf, struct payload_info *pInfo, enum WER_DISABLE_METHOD method) {
	SetErrorModePtr *SetErrorModeFuncAddr = NULL;
	memcpy(buf, pInfo->payloadStartAddr, pInfo->size);
	if(method == WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_IMMEDIATE) {
		SetErrorModeFuncAddr = (SetErrorModePtr *) (buf + pInfo->payloadImmediateMovInstrOffset + 1);// 1 byte for the instr, the rest are LE ptr
	} else if(method == WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_STATIC) {
		SetErrorModeFuncAddr = (SetErrorModePtr *) (buf + pInfo->setErrModeStaticConstAddrOffset);
	}
	if(SetErrorModeFuncAddr) {
		*SetErrorModeFuncAddr = SetErrorModeAddr;
	}
}

void* injectPayload(HANDLE proc, struct payload_info *pInfo, enum WER_DISABLE_METHOD method, _Bool WxX){
	void *payloadAddr;
	if(WxX){
		payloadAddr = VirtualAllocEx(proc, NULL, pInfo->pageAlignedSize, MEM_COMMIT, PAGE_READWRITE);
	}else{
		payloadAddr = VirtualAllocEx(proc, NULL, pInfo->pageAlignedSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	}

	//uint8_t *buf = (uint8_t *) alloca(pInfo->size);
	uint8_t *buf = (uint8_t *) malloc(pInfo->size);
	prepareBuffer(buf, pInfo, method);
	WriteProcessMemory(proc, payloadAddr, buf, pInfo->size, 0);
	DWORD unneededPreviousProtection;
	if(WxX){
		VirtualProtectEx(proc, payloadAddr, pInfo->pageAlignedSize, PAGE_EXECUTE_READ, &unneededPreviousProtection); // Fuck, sigsegvs, when other process
	}
	free(buf);
	return payloadAddr;
}

void deWER(HANDLE proc, struct payload_info *pInfo, enum WER_DISABLE_METHOD method) {
	void * payloadAddr = injectPayload(proc, pInfo, method, 0);
	if(!payloadAddr) {
		fprintf(stderr, "Failed to allocate memory in remote process!");
		return;
	}
	HANDLE thr = CreateRemoteThreadEx(proc, NULL, 0, (LPTHREAD_START_ROUTINE) payloadAddr + pInfo->funcOffset, SetErrorModeAddr, 0, NULL, NULL);
	WaitForSingleObject(thr, INFINITE);
	VirtualFreeEx(proc, payloadAddr, pInfo->pageAlignedSize, MEM_RELEASE);
}

void testDeWERLocal(struct payload_info *pInfo, struct CLIArgs *cliArgs) {
	void * payloadAddr = injectPayload(currentProcess, pInfo, cliArgs->method, 1);
	if(!payloadAddr) {
		fprintf(stderr, "Failed to allocate memory in current process!");
		return;
	}
	LPTHREAD_START_ROUTINE func2test = (LPTHREAD_START_ROUTINE)(payloadAddr + pInfo->funcOffset);
	HANDLE newThreadHandle = NULL;
	switch(cliArgs->testOnMyself){
		case TEST_BY_CONTROL_FLOW:
			func2test(SetErrorModeAddr);
		break;
		case TEST_BY_NEW_THREAD:
			newThreadHandle = CreateThread(NULL, 0,func2test, SetErrorModeAddr, 0, NULL);
			WaitForSingleObject(newThreadHandle, INFINITE);
		break;
	}

	VirtualFree(payloadAddr, pInfo->size, MEM_RELEASE);
}

void testDeWER(struct payload_info *pInfo, struct CLIArgs *cliArgs) {
	if(cliArgs->testOnMyself == TEST_BY_NEW_REMOTE_THREAD){
		deWER(currentProcess, pInfo, cliArgs->method);
	}else{
		testDeWERLocal(pInfo, cliArgs);
	}
	fprintf(stderr, "This message is printed after the code execution! We have not crashed during it!");
}

typedef LONG(NTAPI *NtResumeProcessPtr)(HANDLE ProcessHandle);
NtResumeProcessPtr NtResumeProcess = NULL;

enum WER_DISABLE_METHOD parseInfoPassMethod(wchar_t *methodStr) {
	if(wcscmp(methodStr, L"inherit") == 0) {
		return WER_DISABLE_METHOD_INHERIT;
	} else if(wcscmp(methodStr, L"param") == 0) {
		return WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_PARAMS;
	} else if(wcscmp(methodStr, L"immed") == 0) {
		return WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_IMMEDIATE;
	} else if(wcscmp(methodStr, L"const") == 0) {
		return WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_STATIC;
	} else {
		fprintf(stderr, "Invalid method %ls", methodStr);
		return WER_DISABLE_METHOD_INVALID;
	}
}

const char HELP_TEXT[] =
	("processCrashWorkaround [params] executable_name args for executable...\n"
	 "\t-t --test : test on oneself (only for injecting methods) by transfer control\n"
	 "\t-T --TEST : test on oneself (only for injecting methods) by spawning a new thread\n"
	 "\t-m --method (inherit|param|immed|const) : method of disabling WER\n"
	 "\t-h --help show this help\n");

struct CLIArgs parseCLIArgs(size_t wargc, wchar_t **wargv, wchar_t *raw_command_line) {
	struct CLIArgs res;
	res.testOnMyself = DONT_TEST;
	res.showHelp = FALSE;
	res.method = WER_DISABLE_METHOD_INHERIT;
	res.cumLen = wcslen(wargv[0]);
	res.executableName = NULL;
	res.childCommandLine = raw_command_line;

	res.startOfPosArgs = 0;

	wchar_t *startOfArg = NULL, *endOfArg = NULL;

	for(; res.startOfPosArgs < wargc; ++res.startOfPosArgs) {
		wchar_t *curArg = wargv[res.startOfPosArgs];
		size_t argl = wcslen(curArg);
		res.cumLen += argl;// for space
		BOOL isLong = FALSE;

		BOOL isNamed = (curArg[0] == L'-');

		startOfArg = wcsstr(res.childCommandLine, curArg);
		endOfArg = &startOfArg[argl];

		if(isNamed) {
			++curArg;
			--argl;
			if(argl > res.startOfPosArgs) {
				if(curArg[0] == L'-') {
					isLong = TRUE;
					++curArg;
					--argl;
				} else {
					isLong = FALSE;
				}
			}
			if(isLong) {
				if(wcscmp(curArg, L"method") == 0) {
					if(wargc - res.startOfPosArgs > 1) {
						++res.startOfPosArgs;
						res.method = parseInfoPassMethod(wargv[res.startOfPosArgs]);
					}
				} else if(wcscmp(curArg, L"test") == 0) {
					res.testOnMyself = TEST_BY_CONTROL_FLOW;
				} else if(wcscmp(curArg, L"Test") == 0) {
					res.testOnMyself = TEST_BY_NEW_THREAD;
				} else if(wcscmp(curArg, L"TEST") == 0) {
					res.testOnMyself = TEST_BY_NEW_REMOTE_THREAD;
				} else if(wcscmp(curArg, L"help") == 0) {
					res.showHelp = TRUE;
				} else {
					fprintf(stderr, "Invalid long arg --%ls\n", curArg);
				}
			} else {
				if(wcscmp(curArg, L"m") == 0) {
					if(wargc - res.startOfPosArgs > 1) {
						++res.startOfPosArgs;
						res.method = parseInfoPassMethod(wargv[res.startOfPosArgs]);
					}
				} else if(wcscmp(curArg, L"t") == 0) {
					res.testOnMyself = TEST_BY_CONTROL_FLOW;
				} else if(wcscmp(curArg, L"T") == 0) {
					res.testOnMyself = TEST_BY_NEW_REMOTE_THREAD;
				} else if(wcscmp(curArg, L"h") == 0) {
					res.showHelp = TRUE;
				} else {
					fprintf(stderr, "Invalid short arg -%ls\n", curArg);
				}
			}
		}

		if(startOfArg) {
			if(*endOfArg == L'"' && (startOfArg - raw_command_line) >= 1 && startOfArg[-1] == L'"') {
				endOfArg++;
				startOfArg--;
			}

			while(*endOfArg != L' ' && *endOfArg != L'\0') {
				endOfArg++;
			}
			if(*endOfArg == L' ') {
				endOfArg++;
			}
			res.childCommandLine = startOfArg;
		}

		if(!isNamed && res.startOfPosArgs) {
			res.executableName = curArg;
			break;
		}
	}

	return res;
}

void printErrorMessage(char *operation) {
	fprintf(stderr, "Failed to %s", operation);
	int err = GetLastError();
	wchar_t *msg;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPWSTR) &msg, 0, NULL);
	fwprintf(stderr, L"Error: %ls", msg);
	LocalFree(msg);
}

int werDisableMethodInject(struct CLIArgs *cliArgsParsed, wchar_t *resolvedProcessName, STARTUPINFOW *sinfo, PROCESS_INFORMATION *pinfo){
	DWORD exitCode = 0;
	struct payload_info pInfo = getPayloadpInfo(cliArgsParsed->method);
	if(cliArgsParsed->testOnMyself) {
		testDeWER(&pInfo, cliArgsParsed);
	} else {
		if(CreateProcessW(resolvedProcessName, cliArgsParsed->childCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, sinfo, pinfo)) {
			deWER(pinfo->hProcess, &pInfo, cliArgsParsed->method);
			NtResumeProcess(pinfo->hProcess);
			WaitForSingleObject(pinfo->hProcess, INFINITE);
			if(!GetExitCodeProcess(pinfo->hProcess, &exitCode)) {
				printErrorMessage("get process exit code");
			}
			CloseHandle(pinfo->hProcess);
			CloseHandle(pinfo->hThread);
		} else {
			printErrorMessage("create process");
		}
	}
	return exitCode;
}

int werDisableMethodInherit(struct CLIArgs *cliArgsParsed, wchar_t *resolvedProcessName, STARTUPINFOW *sinfo, PROCESS_INFORMATION *pinfo){
	UINT prevMode, newMode;
	DWORD exitCode = 0;
	prevMode = SetErrorMode(0);
	newMode = prevMode | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX;
	SetErrorMode(newMode);
	if(CreateProcessW(resolvedProcessName, cliArgsParsed->childCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, sinfo, pinfo)) {
		SetErrorMode(prevMode);
		WaitForSingleObject(pinfo->hProcess, INFINITE);
		if(!GetExitCodeProcess(pinfo->hProcess, &exitCode)) {
			printErrorMessage("get process exit code");
		}
		CloseHandle(pinfo->hProcess);
		CloseHandle(pinfo->hThread);
	} else {
		printErrorMessage("create process");
	}
	return exitCode;
}

int callProcess() {
	STARTUPINFOW sinfo;
	PROCESS_INFORMATION pinfo;
	int exitCode = 0;

	wchar_t *cl = GetCommandLineW();
	size_t wargc = 0u;
	wchar_t **wargv = CommandLineToArgvW(cl, (int *) &wargc);

	struct CLIArgs cliArgsParsed = parseCLIArgs(wargc, wargv, cl);

	fwprintf(stderr, L"command line is %ls\n", cl);
	fwprintf(stderr, L"child command line is %ls\n", cliArgsParsed.childCommandLine);

	if(cliArgsParsed.showHelp) {
		fprintf(stdout, "%s\n", HELP_TEXT);
		return 0;
	}

	if(!cliArgsParsed.executableName) {
		fprintf(stderr, "You have missed the executable name\n");
		fprintf(stdout, "%s\n", HELP_TEXT);
		return 1;
	}

	if(cliArgsParsed.method == WER_DISABLE_METHOD_INVALID){
		fprintf(stderr, "You have chosen an invalid method\n");
		fprintf(stdout, "%s\n", HELP_TEXT);
		return 1;
	}

	wchar_t expanded[PATH_MAX];
	ExpandEnvironmentStringsW(cliArgsParsed.executableName, expanded, sizeof(expanded));

	wchar_t whiched[PATH_MAX];
	which(expanded, whiched);

	memset(&pinfo, 0, sizeof(pinfo));
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);


	switch(cliArgsParsed.method){
		case WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_PARAMS:
		case WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_IMMEDIATE:
		case WER_DISABLE_METHOD_INJECT_PAYLOAD_PASS_VIA_STATIC:
			exitCode = werDisableMethodInject(&cliArgsParsed, whiched, &sinfo, &pinfo);
		break;
		case WER_DISABLE_METHOD_INHERIT:
			exitCode = werDisableMethodInherit(&cliArgsParsed, whiched, &sinfo, &pinfo);
		break;
	}
	if(exitCode){
		printf("The command has failed (exit code %d), but the failure has been eaten.\n", exitCode);
	}
	return 0;
}

void init() {
	HMODULE ntdll = LoadLibraryA("ntdll.dll");
	HMODULE kernel32 = LoadLibraryA("kernel32.dll");
	NtResumeProcess = (NtResumeProcessPtr) GetProcAddress(ntdll, "NtResumeProcess");
	if(!NtResumeProcess) {
		fprintf(stderr, "Failed to get NtResumeProcess from ntdll.dll");
	}
	SetErrorModeAddr = (SetErrorModePtr) GetProcAddress(kernel32, "SetErrorMode");
	if(!SetErrorModeAddr) {
		fprintf(stderr, "Failed to get SetErrorMode from kernel32.dll");
	}
	GetSystemInfo(&sinfo);

	currentProcess = GetCurrentProcess();

	// make child be closed if parent crashes
	/*job = CreateJobObjectA(NULL, NULL);
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo;
	memset(&jobInfo, 0, sizeof(jobInfo));
	jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo));
	AssignProcessToJobObject(job, currentProcess);*/
}

void deinit() {
	CloseHandle(job);
}
#endif

int main(void) {
	init();
	int res = callProcess();
	deinit();
	return res;
}
