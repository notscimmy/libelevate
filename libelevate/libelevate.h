#pragma once

#include <Windows.h>

/*
	Grants the given `handle` the access rights defined by `access`

	@param handle a handle that is created by a call to OpenProcess or
	OpenThread 
	@param access a 32-bit mask that defines the access rights that a
	handle grants. More information can be found on MSDN:
	https://docs.microsoft.com/en-us/windows/desktop/ProcThread/process-security-and-access-rights

	@return true if the exploit was loaded, executed, and unloaded properly
*/
extern bool grant_access(HANDLE handle, ACCESS_MASK access);