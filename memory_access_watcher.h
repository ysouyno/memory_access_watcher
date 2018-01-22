#pragma once

#include <Windows.h>
#include <stdio.h>

class memory_access_watcher
{
public:
	memory_access_watcher() :
		m_exception_handler(NULL),
		m_address(NULL),
		m_length(0),
		m_old_protect(0),
		m_new_protect(0),
		m_write_access(FALSE),
		m_single_step(0)
	{
		m_p_this = this;

		InitializeCriticalSection(&m_cs);
	}

	~memory_access_watcher()
	{
		if (NULL != m_exception_handler)
		{
			RemoveVectoredExceptionHandler(m_exception_handler);
		}

		DeleteCriticalSection(&m_cs);
	}

	BOOL init(const PVOID address, const SIZE_T length, DWORD new_protect)
	{
		m_exception_handler = AddVectoredExceptionHandler(EXCEPTION_FIRST_HANDLER, vectored_handler_wrap);
		if (NULL == m_exception_handler)
		{
			printf("AddVectoredExceptionHandler failed\n");
			return FALSE;
		}

		return init_memory_watcher(address, length, new_protect);
	}

private:
	BOOL init_memory_watcher(const PVOID address, const SIZE_T length, DWORD new_protect)
	{
		m_address = address;
		m_length = length;
		m_new_protect = new_protect;

		if (!VirtualProtectEx(GetCurrentProcess(), address, length, new_protect, &m_old_protect))
		{
			printf("VirtualProtectEx failed, error: %d\n", GetLastError());
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}

	static LONG CALLBACK vectored_handler_wrap(PEXCEPTION_POINTERS pexception_pointers)
	{
		return m_p_this->vectored_handler(pexception_pointers);
	}

	LONG CALLBACK vectored_handler(PEXCEPTION_POINTERS pexception_pointers)
	{
		PEXCEPTION_RECORD pexception_record = pexception_pointers->ExceptionRecord;
		PCONTEXT pcontext = pexception_pointers->ContextRecord;

		if (EXCEPTION_ACCESS_VIOLATION == pexception_record->ExceptionCode)
		{
			DWORD *exception_address = (DWORD *)(pexception_record->ExceptionInformation[1]);
			DWORD old_protect = 0;

			if (exception_address >= (DWORD *)m_address && exception_address < (DWORD *)m_address + m_length)
			{
				EnterCriticalSection(&m_cs);

				BOOL ret = VirtualProtectEx(GetCurrentProcess(), m_address, m_length, m_old_protect, &old_protect);
				if (!ret)
				{
					printf("VirtualProtectEx failed, error: %d\n", GetLastError());
					LeaveCriticalSection(&m_cs);

					return EXCEPTION_CONTINUE_EXECUTION;
				}

				if (MEMORY_ACCESS_W == pexception_record->ExceptionInformation[0])
				{
					m_write_access = TRUE;
					m_single_step = 1;
				}
				else if (MEMORY_ACCESS_R == pexception_record->ExceptionInformation[0])
				{
					m_write_access = FALSE;
					m_single_step = 1;
				}

				LeaveCriticalSection(&m_cs);
			}

			if (m_single_step)
			{
				pcontext->EFlags |= 0x0100; // bit 8 - Trap Flag
			}

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (EXCEPTION_SINGLE_STEP == pexception_record->ExceptionCode)
		{
			if (m_single_step)
			{
				call_back(m_address, m_write_access);

				EnterCriticalSection(&m_cs);

				BOOL ret = VirtualProtectEx(GetCurrentProcess(), m_address, m_length, m_new_protect, &m_old_protect);
				if (!ret)
				{
					printf("VirtualProtectEx failed, error: %d\n", GetLastError());
					LeaveCriticalSection(&m_cs);

					return EXCEPTION_CONTINUE_EXECUTION;
				}

				m_single_step = 0;

				LeaveCriticalSection(&m_cs);
			}

			return EXCEPTION_CONTINUE_EXECUTION;
		}

		return EXCEPTION_CONTINUE_SEARCH;
	}

	DWORD call_back(const PVOID address, BOOL write_access)
	{
		printf("thread id: %d, access 0x%p, access: %s, value: 0x%08X\n", GetCurrentThreadId(),
			address, write_access ? "write" : "read", *((DWORD *)address));

		return 0;
	}

private:
	enum
	{
		MEMORY_ACCESS_R,
		MEMORY_ACCESS_W
	};

	enum
	{
		EXCEPTION_LAST_HANDLER,
		EXCEPTION_FIRST_HANDLER
	};

	PVOID m_exception_handler;
	PVOID m_address;
	SIZE_T m_length;
	DWORD m_old_protect;
	DWORD m_new_protect;
	BOOL m_write_access;
	DWORD m_single_step;
	CRITICAL_SECTION m_cs;

	static memory_access_watcher *m_p_this;
};
