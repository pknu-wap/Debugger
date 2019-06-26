#include <windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <iostream>
#include "distorm.h"
#pragma comment(lib, "distorm.lib")

using namespace std;

#define EVTIDX_EXIT		0	// quit
#define EVTIDX_DISAS	1	// disas
#define EVTIDX_CONTEXT	2	// regs
#define EVTIDX_STEP		3	// step
#define EVTIDX_CONTINUE	4	// continue
#define EVTIDX_BREAK	5	// breakpoint
#define EVTIDX_DUMP		6	// dump
#define EVTIDX_DEBUG	7	// 디버깅 예외 처리
#define EVTIDX_COUNT	8

struct INIT_INFO
{
	PCWSTR	ExePath;				// 디버기 실행 파일 경로
	HANDLE	DbgEvts[EVTIDX_COUNT];	// 디버깅 메뉴 처리를 위한 이벤트 배열
	HANDLE	WaitSig;				// 디버깅 스레드 처리 대기를 위한 이벤트
	EXCEPTION_RECORD	ExRecord;
	ULONG	tmp_addr;
	PVOID	start_addr;
	BOOL	BpOnceHit;
	BOOL	Cont;
	BYTE	OrigOp;
};
typedef INIT_INFO* PINIT_INFO;

int Get_RegisterContext(DWORD threadid)
{
	HANDLE hThread = NULL;
	CONTEXT ct;

	ct.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

	if (!(hThread = OpenThread(THREAD_ALL_ACCESS, NULL, threadid)))
	{
		printf("OpenThread Error %d\n", GetLastError());
	}

	if (!GetThreadContext(hThread, &ct))
	{
		printf("GetThreadContext Error %d\n", GetLastError());
	}

	printf("[*] DUMP Register of Thread \n");
	printf("EAX: 0x%08x / EBX: 0x%08x / ECX: 0x%08x / EDX: 0x%08x \n", ct.Eax, ct.Ebx, ct.Ecx, ct.Edx);
	printf("ESI: 0x%08x / EDI: 0x%08x / ESP: 0x%08x / EIP: 0x%08x \n", ct.Esi, ct.Edi, ct.Esp, ct.Eip);
	printf("--------------------------------------------------------\n");

	return 0;
}

int Get_Memory(HANDLE hProcess, void * base)
{
	unsigned char buf[100];

	if (!ReadProcessMemory(hProcess, (LPCVOID)base, buf, 100, NULL))
	{
		printf("ReadProcessMemory Error %d\n", GetLastError());
	}
	unsigned char* p = (unsigned char*)base;

	printf("# %p : ", p);

	for (int i = 0; i < 8; i++)
	{
		printf("%0.2x ", buf[i]);
	}
	printf("\n");

	return 0;
}

int Get_Disas(HANDLE hProcess, void * base)
{
	_DecodeResult res;
	_DecodedInst decodedIns[1000];
	_OffsetType offset = 0;
	_DecodeType dt = Decode32Bits;

	unsigned int decodedInsCnt = 0;

	unsigned char buf[100];
	unsigned char* p = (unsigned char*)base;

	if (!ReadProcessMemory(hProcess, (LPCVOID)base, buf, 100, NULL))
	{
		printf("ReadProcessMemory Error %d\n", GetLastError());
	}

	res = distorm_decode(offset, (const unsigned char*)buf, 8, dt, decodedIns, 100, &decodedInsCnt);
	if (res == DECRES_INPUTERR)
	{
		printf("Disassemble Error\n");
	}

	for (int i = 0; i < decodedInsCnt; i++)
	{
		printf("0x%08x", decodedIns[i].offset + (int)p);
		cout << (char*)decodedIns[i].instructionHex.p << '\t';
		cout << (char*)decodedIns[i].mnemonic.p << " " << (char*)decodedIns[i].operands.p << endl;
	}
	// 00400000 e8 5b push ebp

	return 0;
}

BYTE Set_BreakPoint(HANDLE hProcess, LPCVOID Addr)
{
	BYTE TmpOp = 0xcc, OrigOp;

	printf("\bBP Address: 0x%08x", Addr);
	if (!ReadProcessMemory(hProcess, Addr, &OrigOp, sizeof(BYTE), NULL))
	{
		printf("ReadProcessMemory Error %d\n", GetLastError());
	}
	printf("Original Byte - %x\n", OrigOp);

	if (!WriteProcessMemory(hProcess, (LPVOID)Addr, (LPVOID)&TmpOp, sizeof(BYTE), NULL))
	{
		printf("WriteProcessMemory Error %d\n", GetLastError());
	}

	FlushInstructionCache(hProcess, Addr, sizeof(BYTE));
	printf("Breakpoint is set at %p", Addr);

	return OrigOp;
}

void Restore_BreakPoint(HANDLE hProcess, LPCVOID Addr, BYTE OrigOp)
{
	if (!WriteProcessMemory(hProcess, (LPVOID)Addr, (LPVOID)&OrigOp, sizeof(BYTE), NULL))
	{
		printf("WriteProcessMemory Error %d\n", GetLastError());
	}

	FlushInstructionCache(hProcess, Addr, sizeof(BYTE));
	printf("Breakpoint is restored\n");
}

bool CreateDbgEvents(PHANDLE pDbgEvts)
{
	int i = 0;
	for (; i < EVTIDX_COUNT; i++)
	{
		pDbgEvts[i] = CreateEvent(NULL, (i == EVTIDX_EXIT || i == EVTIDX_DEBUG) ? TRUE : FALSE, (i == EVTIDX_DEBUG) ? TRUE : FALSE, NULL);
		
			if (pDbgEvts[i] == NULL)
			{
				printf("CreateEvent error, code=%d\n", GetLastError());
				break;
			}
	}
	if (i < EVTIDX_COUNT)
	{
		for (int j = 0; j < i; j++)
		{
			CloseHandle(pDbgEvts[j]);
			pDbgEvts[j] = NULL;
		}
		return false;
	}
	return true;
}

DWORD WINAPI DebugThreadProc(PVOID pParam)
{
	PINIT_INFO pdi = (PINIT_INFO)pParam;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	WCHAR szCmdLine[] = L"C:\\windows\\system32\\notepad.exe";
	//WCHAR szCmdLine[] = L"C:\\windows\\SysWOW64\\notepad.exe";

	if (!CreateProcess(NULL, szCmdLine, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi))
	{
		std::cout << "CreateProcess Error - " << GetLastError() << endl;
		return -1;
	}

	bool bIsOK = CreateDbgEvents(pdi->DbgEvts);
	SetEvent(pdi->WaitSig);

	if (!bIsOK)
	{
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return 0;
	}

	DEBUG_EVENT de = { 0 };
	bool bRunDbg = true;

	while (bRunDbg)
	{
		DWORD dwIdx = WaitForMultipleObjects(EVTIDX_COUNT, pdi->DbgEvts, FALSE, INFINITE);

		if (dwIdx == WAIT_FAILED)
		{
			printf("... WaitForMultipleObject failed, code=0x%08X. \n", GetLastError());
			break;
		}

		switch (dwIdx)
		{
		case EVTIDX_EXIT:
			bRunDbg = false;
			break;

		case EVTIDX_DISAS:
		{
			if (pdi->ExRecord.ExceptionAddress != 0x0)
			{
				Get_Memory(pi.hProcess, (void*)pdi->ExRecord.ExceptionAddress);
			}
		}
		break;

		case EVTIDX_CONTEXT:
		{
			Get_RegisterContext(pi.dwThreadId);
		}
		break;

		case EVTIDX_STEP:
		{
			pdi->Cont = FALSE;

			CONTEXT ctx;
			ctx.ContextFlags = CONTEXT_CONTROL;
			GetThreadContext(pi.hThread, &ctx);
			ctx.EFlags != 0x100;
			SetThreadContext(pi.hThread, &ctx);

			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
		}
		break;

		case EVTIDX_CONTINUE:
		{
			pdi->Cont = TRUE;
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
		}
		break;

		case EVTIDX_BREAK:
		{
			pdi->OrigOp = Set_BreakPoint(pi.hProcess, (LPCVOID)pdi->tmp_addr);
		}
		break;

		case EVTIDX_DUMP:
		{
			std::cout << "\ndump address: " << pdi->tmp_addr << endl;
			Get_Memory(pi.hProcess, (void*)pdi->tmp_addr);
		}
		break;

		case EVTIDX_DEBUG:
		{
			if (!WaitForDebugEvent(&de, 200))
				continue;
			
			switch (de.dwDebugEventCode)
			{
			case CREATE_PROCESS_DEBUG_EVENT:
			{
				std::cout << "\n========================================================" << endl;
				std::cout << "** CREATE_PROCESS [ProcessId = " << de.dwProcessId << " ThreadId = " << de.dwThreadId << "]\n";

				CREATE_PROCESS_DEBUG_INFO& di = de.u.CreateProcessInfo;
				printf("	File			= %d\n", (UINT)di.hFile);
				printf("	Process			= %d\n", (UINT)di.hProcess);
				printf("	Thread			= %d\n", (UINT)di.hThread);
				printf("	BaseOfImage		= %d\n", di.lpBaseOfImage);
				printf("	ThreadLocalBase	= %d\n", di.lpThreadLocalBase);
				printf("	StartAddress	= %d\n", di.lpStartAddress);
				std::cout << "\n========================================================" << endl;
				pdi->start_addr = di.lpStartAddress;
			}
			break;

			case EXCEPTION_DEBUG_EVENT:
			{
				EXCEPTION_DEBUG_INFO& di = de.u.Exception;

				printf("	FirstChance		= %d\n", di.dwFirstChance);
				printf("	ExceptionCode	= 0x%08X, Address = 0x%p\n", di.ExceptionRecord.ExceptionCode, di.ExceptionRecord);

				pdi->ExRecord = de.u.Exception.ExceptionRecord;

				DWORD exception;
				PVOID exception_addr;

				exception = de.u.Exception.ExceptionRecord.ExceptionCode;
				exception_addr = de.u.Exception.ExceptionRecord.ExceptionAddress;

				if (exception == EXCEPTION_ACCESS_VIOLATION)
				{
					printf("[**] Access Violation\n");
				}
				else if (exception == EXCEPTION_BREAKPOINT)
				{
					if (!pdi->BpOnceHit)	// 사용자가 설정한 BP가 아닌 경우
					{
						pdi->OrigOp = Set_BreakPoint(pi.hProcess, (LPCVOID)pdi->start_addr);
						pdi->BpOnceHit = TRUE;
					}
					else                   // 사용자가 설정한 BP의 경우 Restore 
					{
						std::cout << "[**] Breakpoint hit at " << exception_addr << endl;
						CONTEXT ctx;
						ctx.ContextFlags = CONTEXT_CONTROL;
						GetThreadContext(pi.hThread, &ctx);
						ctx.Eip--;
						ctx.EFlags != 0x100;	// TF_BIT
						SetThreadContext(pi.hThread, &ctx);

						Restore_BreakPoint(pi.hProcess, (PBYTE)de.u.Exception.ExceptionRecord.ExceptionAddress, pdi->OrigOp); //정확하진 않음

						Get_Memory(pi.hProcess, (void*)exception_addr);
						Get_RegisterContext(pi.dwThreadId);
					}
					
				}
				else if (exception == EXCEPTION_SINGLE_STEP)
				{
					printf("[**] Single Stepping\n");
					if (pdi->Cont)
					{
						ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
					}
					else
					{
						Get_Memory(pi.hProcess, (void*)exception_addr);
						Get_RegisterContext(pi.dwThreadId);
					}
				}
			}
			break;
			}
			
			if (de.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
			{
				ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
				break;
			}
		}
		break;
		}
	}

	for (int i = 0; i < EVTIDX_COUNT; i++)
	{
		CloseHandle(pdi->DbgEvts[i]);
		pdi->DbgEvts[i] = NULL;
	}
} 

	

int _tmain(int argc, TCHAR* argv[])
{
	char input[100];
	HANDLE hDbgThr = NULL;

	INIT_INFO di;
	memset(&di, 0, sizeof(di));
	di.ExePath = L"C:\\windows\\system32\\notepad.exe";
	di.WaitSig = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (di.WaitSig == NULL)
	{
		printf("CreateEvent Error : %d\n", GetLastError());
	}

	std::cout << "====================================================" << endl;
	std::cout << " Mini Debugger Started.. Please input command \n";
	std::cout << "----------------------------------------------------" << endl;
	std::cout << " (Debugger Start/Stop) : start / stop\n";
	std::cout << " ( Debugging Control ) : step / continue / bp XX\n";
	std::cout << " ( Debug Information ) : disas / regs / dump XX\n";
	std::cout << "  Made by Kw\n";
	std::cout << "====================================================" << endl;

	while (true)
	{
		printf("Command > ");
		gets_s(input);

		if (_stricmp(input, "start") == 0)
		{
			if (hDbgThr != NULL)
			{
				if (WaitForSingleObject(hDbgThr, 0) != WAIT_OBJECT_0)
					continue;
				CloseHandle(hDbgThr);
			}
			DWORD dwThreadId = 0;
			hDbgThr = CreateThread(NULL, 0, DebugThreadProc, &di, 0, &dwThreadId);
			if (hDbgThr == NULL)
			{
				printf("CreateThread Error : %d\n", GetLastError());
			}
			WaitForSingleObject(di.WaitSig, INFINITE);
			
		}
		else if (_stricmp(input, "stop") == 0 || _stricmp(input, "quit") == 0)
		{
			bool bStop = (_stricmp(input, "stop") == 0);
			if (hDbgThr != NULL)
			{
				ResetEvent(di.DbgEvts[EVTIDX_DEBUG]);
				SetEvent(di.DbgEvts[EVTIDX_EXIT]);
				WaitForSingleObject(hDbgThr, INFINITE);
				if (bStop)
				{
					CloseHandle(hDbgThr);
					hDbgThr = NULL;
				}
			}
			if (!bStop)
				break;
		}
		else if (_stricmp(input, "disas") == 0)
		{
			SetEvent(di.DbgEvts[EVTIDX_DISAS]);
		}
		else if (_stricmp(input, "regs") == 0)
		{
			SetEvent(di.DbgEvts[EVTIDX_CONTEXT]);
		}
		else if (_stricmp(input, "step") == 0)
		{
			SetEvent(di.DbgEvts[EVTIDX_STEP]);
		}
		else if (_stricmp(input, "continue") == 0)
		{
			SetEvent(di.DbgEvts[EVTIDX_CONTINUE]);
		}
		else if (_stricmp(input, "bp") == 0)
		{
			printf("BP at ->");
			scanf("%x", &di.tmp_addr);
			SetEvent(di.DbgEvts[EVTIDX_BREAK]);
		}
		else if (_stricmp(input, "dump") == 0)
		{
			printf("DUMP at ->");
			scanf("%x", &di.tmp_addr);
			SetEvent(di.DbgEvts[EVTIDX_DUMP]);
		}
		else
		{
			printf("Please Input PROPER command\n");
		}
	}

	

	

	return 0;
}
