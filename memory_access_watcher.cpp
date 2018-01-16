// memory_access_watcher.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

PVOID g_exception_handler = NULL;
const ULONG g_first_handler = 1;

typedef DWORD(*pfnMemoryWatchCallback)(const PVOID address, BOOL write_access);

PVOID g_address = NULL;
SIZE_T g_length = 0;
DWORD g_old_protect = 0;
DWORD g_new_protect = 0;
BOOL g_write_access = TRUE;

DWORD call_back(const PVOID address, BOOL write_access)
{
	printf("access 0x%p, access: %s, value: 0x%08X\n", address, write_access ? "write" : "read", *((DWORD *)address));

	return 0;
}

LONG CALLBACK vectored_handler(PEXCEPTION_POINTERS pexception_pointers)
{
	PEXCEPTION_RECORD pexception_record = pexception_pointers->ExceptionRecord;
	PCONTEXT pcontext = pexception_pointers->ContextRecord;

	if (EXCEPTION_ACCESS_VIOLATION == pexception_record->ExceptionCode)
	{
		printf("EXCEPTION_ACCESS_VIOLATION\n");

		DWORD *exception_address = (DWORD *)(pexception_record->ExceptionInformation[1]);
		DWORD old_protect = 0;

		if (exception_address >= (DWORD *)g_address && exception_address < (DWORD *)g_address + g_length)
		{
			BOOL ret = VirtualProtectEx(GetCurrentProcess(), g_address, g_length, g_old_protect, &old_protect);
			if (!ret)
			{
				printf("VirtualProtectEx failed, error: %d\n", GetLastError());
				return EXCEPTION_CONTINUE_EXECUTION;
			}

			if (1 == pexception_record->ExceptionInformation[0])
			{
				printf("attempt write 0x%p, before write its value: 0x%08X\n",
					exception_address, *((DWORD *)exception_address));

				g_write_access = TRUE;
				pcontext->EFlags |= 256;
			}
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (EXCEPTION_SINGLE_STEP == pexception_record->ExceptionCode)
	{
		printf("EXCEPTION_SINGLE_STEP\n");

		BOOL ret = VirtualProtectEx(GetCurrentProcess(), g_address, g_length, g_new_protect, &g_old_protect);
		if (!ret)
		{
			printf("VirtualProtectEx failed, error: %d\n", GetLastError());
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		call_back(g_address, g_write_access);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

bool init_memory_watcher(const PVOID address, const SIZE_T length, DWORD new_protect)
{
	BOOL ret = FALSE;

	g_address = address;
	g_length = length;
	g_new_protect = new_protect;

	ret = VirtualProtectEx(GetCurrentProcess(), address, length, new_protect, &g_old_protect);
	if (!ret)
	{
		printf("VirtualProtectEx failed, error: %d\n", GetLastError());
		return false;
	}

	return true;
}

DWORD WINAPI thread_proc(PVOID arg)
{
	DWORD i = 0;

	while (true)
	{
		*((DWORD *)arg) = i;
		Sleep(1000);
	}

	return 0;
}

int main()
{
	g_exception_handler = AddVectoredExceptionHandler(g_first_handler, vectored_handler);
	if (NULL == g_exception_handler)
	{
		printf("AddVectoredExceptionHandler failed\n");
		return -1;
	}

	DWORD *pdw = NULL;
	pdw = (DWORD *)VirtualAlloc(NULL, sizeof(DWORD), MEM_COMMIT, PAGE_READWRITE);
	*pdw = 1;

	init_memory_watcher(pdw, sizeof(DWORD), PAGE_NOACCESS);

	HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_proc, pdw, 0, NULL);
	CloseHandle(h);

	getchar();

	VirtualFree(pdw, 0, MEM_RELEASE);
	RemoveVectoredExceptionHandler(g_exception_handler);

	return 0;
}

