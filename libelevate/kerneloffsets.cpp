#include "kerneloffsets.h"

windows_version kernel_offsets::version;
uint64_t kernel_offsets::name;
uint64_t kernel_offsets::pid;
uint64_t kernel_offsets::base;
uint64_t kernel_offsets::link;
uint64_t kernel_offsets::protection;
uint64_t kernel_offsets::flags2;
uint64_t kernel_offsets::objecttable;
uint64_t kernel_offsets::vadroot;

windows_version get_windows_version()
{
	std::wstring wskernel32 = L"\\kernel32.dll";

	wchar_t *path = NULL;
	void *ver = NULL, *block;
	windows_version version;
	UINT n;
	BOOL r;
	DWORD versz, blocksz;
	VS_FIXEDFILEINFO *vinfo;

	path = (wchar_t*)malloc(sizeof(*path) * MAX_PATH);
	if (!path)
		abort();

	n = GetSystemDirectoryW(path, MAX_PATH);
	if (n >= MAX_PATH || n == 0 ||
		n > MAX_PATH - wskernel32.length())
		abort();
	memcpy(path + n, wskernel32.c_str(), wskernel32.length() * sizeof(wchar_t) + 2);

	versz = GetFileVersionInfoSizeW(path, NULL);
	if (versz == 0)
		abort();
	ver = malloc(versz);
	if (!ver)
		abort();
	r = GetFileVersionInfoW(path, 0, versz, ver);
	if (!r)
		abort();
	r = VerQueryValueA(ver, "\\", &block, (PUINT)&blocksz);
	if (!r || blocksz < sizeof(VS_FIXEDFILEINFO))
		abort();
	vinfo = (VS_FIXEDFILEINFO *)block;
	if ((int)HIWORD(vinfo->dwProductVersionMS) == 10)
		version = WINDOWS10;
	else if ((int)HIWORD(vinfo->dwProductVersionMS) == 6)
	{
		switch ((int)LOWORD(vinfo->dwProductVersionMS))
		{
		case 0:
			version = UNSUPPORTED;
			break;
		case 1:
			version = WINDOWS7;
			break;
		case 2:
			version = WINDOWS8;
			break;
		case 3:
			version = WINDOWS81;
			break;
		default:
			version = UNSUPPORTED;
		}
	}
	else
		version = UNSUPPORTED;

	free(path);
	free(ver);
	return version;
}