// memory_access_watcher.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "memory_access_watcher.h"

DWORD WINAPI thread_proc_w(PVOID arg)
{
	DWORD i = 0;

	while (true)
	{
		*((DWORD *)arg) = i;
		Sleep(1000);
		++i;
	}

	return 0;
}

DWORD WINAPI thread_proc_r(PVOID arg)
{
	while (true)
	{
		int r = *((DWORD *)arg);
		Sleep(500);
	}

	return 0;
}

memory_access_watcher *memory_access_watcher::m_p_this = NULL;

int main()
{
	DWORD *pdw = NULL;
	pdw = (DWORD *)VirtualAlloc(NULL, sizeof(DWORD), MEM_COMMIT, PAGE_READWRITE);
	*pdw = 1;

	memory_access_watcher maw;
	if (!maw.init(pdw, sizeof(DWORD), PAGE_NOACCESS))
	{
		printf("memory_access_monitor::init() failed\n");
		VirtualFree(pdw, 0, MEM_RELEASE);
		return -1;
	}

	HANDLE h = INVALID_HANDLE_VALUE;
	DWORD tid = 0;

	h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_proc_w, pdw, 0, &tid);
	printf("thread_proc_w id: %d\n", tid);
	CloseHandle(h);

	h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_proc_r, pdw, 0, &tid);
	printf("thread_proc_r id: %d\n", tid);
	CloseHandle(h);

	getchar();

	VirtualFree(pdw, 0, MEM_RELEASE);

	return 0;
}

