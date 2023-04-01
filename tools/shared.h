#ifndef __H_SHARED
#define __H_SHARED

#include <Windows.h>

char* find_addr(HANDLE hProc, const unsigned char *magic, SIZE_T magic_len, SIZE_T step, DWORD page_protect);

#endif