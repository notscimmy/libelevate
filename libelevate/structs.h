#pragma once
#define WIN32_NO_STATUS
#include <Windows.h>
#include <Winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

namespace native::structs
{
	typedef struct _HANDLE_TABLE_ENTRY
	{
		union
		{
			PVOID Object;
			ULONG ObAttributes;
		};
		union
		{
			union
			{
				ACCESS_MASK GrantedAccess;
				struct
				{
					USHORT GrantedAccessIndex;
					USHORT CreatorBackTraceIndex;
				};
			};
			LONG NextFreeTableEntry;
		};
	} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

	typedef struct _HANDLE_TABLE
	{
		char padding[100]; // we don't care about this actual structure
	} HANDLE_TABLE, *PHANDLE_TABLE;

	typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(IN PHANDLE_TABLE_ENTRY, IN HANDLE, IN PVOID);

	typedef CLIENT_ID* PCLIENT_ID;
	typedef ULONG(*DbgPrintEx_t)(_In_ ULONG, _In_ ULONG, _In_ PCSTR, ...);
	typedef PVOID(*PsGetCurrentProcess_t)();
	typedef VOID(*RtlInitUnicodeString_t)(PUNICODE_STRING, PCWSTR);
	typedef PVOID(NTAPI* MmGetSystemRoutineAddress_t)(PUNICODE_STRING);
}
