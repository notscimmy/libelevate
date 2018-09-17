#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <map>
#include <string>

#include "libelevate.h"

std::map<std::string, DWORD> GetProcessList()
{
	std::map<std::string, DWORD> processList;
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == 0)
		return processList;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnapshot, &pe32))
	{
		CloseHandle(hSnapshot);
		return processList;
	}

	do
	{
		processList[pe32.szExeFile] = pe32.th32ProcessID;
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);
	return processList;
}

int main()
{
	DWORD notepadPID = GetProcessList()["notepad.exe"];
	HANDLE notepadHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, notepadPID);
	printf("Elevating handle 0x%llx for PID %i from %s to %s\n", notepadHandle, notepadPID, "PROCESS_QUERY_LIMITED INFORMATION", "PROCESS_ALL_ACCESS");
	grant_access(notepadHandle, PROCESS_ALL_ACCESS);
	system("pause");
	return 0;
}