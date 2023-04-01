#include "shared.h"

// Adapted from https://stackoverflow.com/questions/14157001/readprocessmemory-to-find-a-pattern-granularity
char* find_addr(HANDLE hProc, const unsigned char *magic, SIZE_T magic_len, SIZE_T step, DWORD page_protect) {
	char* buffer = NULL;
	char* addr = NULL;
	char* match = NULL;
	SIZE_T bytesRead;

	MEMORY_BASIC_INFORMATION mbi = { 0 };

	while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)))
	{
		if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_NOACCESS) && (mbi.Protect & page_protect))
		{
			if (buffer) {
				free(buffer);
				buffer = NULL;
			}
			buffer = malloc(mbi.RegionSize);

			ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
			for (SIZE_T i = 0; i < bytesRead; i += step) {
				if ((bytesRead - i) < magic_len)
					break;
				
				if (!memcmp(buffer + i, magic, magic_len)) {
					match = (char*)mbi.BaseAddress + i;
					break;
				}
			}

			if (match)
				break;
		}
		addr += mbi.RegionSize;
	}

	return match;
}