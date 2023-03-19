/**
 * Packet Dumper
 * It prints them in the same way that they are deserialized (sort of)
 * Hangs sometimes, need to figure out why
 */

#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <winuser.h>
#include <stdint.h>

DWORD get_process_id_by_name(const char *process_name)
{
	DWORD process_ids[1024], bytes_needed, num_processes;
	if (!EnumProcesses(process_ids, sizeof(process_ids), &bytes_needed))
	{
		printf("Failed to enumerate processes.\n");
		return 0;
	}

	num_processes = bytes_needed / sizeof(DWORD);
	for (DWORD i = 0; i < num_processes; i++)
	{
		HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_ids[i]);
		if (process)
		{
			char name[MAX_PATH];
			if (GetModuleBaseName(process, NULL, name, sizeof(name)))
			{
				if (strcmp(name, process_name) == 0)
				{
					CloseHandle(process);
					return process_ids[i];
				}
			}

			CloseHandle(process);
		}
	}

	printf("Failed to find process '%s'.\n", process_name);
	return 0;
}

typedef struct Breakpoint
{
	BYTE old_instruction;
	LPVOID address;
} Breakpoint;

const BYTE int3 = 0xCC;	// INT 3

Breakpoint set_breakpoint(HANDLE process, LPVOID address)
{
	Breakpoint bp = { .address = address };

	DWORD old_protection;

	if (!VirtualProtectEx(process, address, 1, PAGE_EXECUTE_READWRITE, &old_protection))
	{
		printf("Failed to set memory protection.\n");
		return bp;
	}

	if (!ReadProcessMemory(process, address, &bp.old_instruction, 1, NULL))
	{
		printf("Failed to read memory.\n");
		return bp;
	}

	if (!WriteProcessMemory(process, address, &int3, 1, NULL))
	{
		printf("Failed to write memory.\n");
		return bp;
	}

	if (!VirtualProtectEx(process, address, 1, old_protection, &old_protection))
	{
		printf("Failed to set memory protection.\n");
		return bp;
	}

	return bp;
}

int reset_breakpoint(HANDLE process, HANDLE thread, DEBUG_EVENT *debug_event, const Breakpoint *bp)
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(thread, &context)) {
		printf("Failed to get thread context.\n");
		return 1;
	}
	// Move back one byte to re-execute the original instruction
	context.Rip -= 1;
	// Set the thread context to resume execution with a single step
	context.EFlags |= 0x100;
	if (!SetThreadContext(thread, &context))
	{
		printf("Failed to set thread context. Error %u\n", GetLastError());
		return 1;
	}

	// Rewrite the original instruction
	DWORD old_protection;
	if (!VirtualProtectEx(process, bp->address, 1, PAGE_EXECUTE_READWRITE, &old_protection))
	{
		printf("Failed to set memory protection.\n");
		return 1;
	}

	if (!WriteProcessMemory(process, bp->address, &bp->old_instruction, 1, NULL))
	{
		printf("Failed to restore original instruction.\n");
		return 1;
	}

	if (!VirtualProtectEx(process, bp->address, 1, old_protection, &old_protection))
	{
		printf("Failed to set memory protection.\n");
		return 1;
	}

	if (!ContinueDebugEvent(debug_event->dwProcessId, debug_event->dwThreadId, DBG_CONTINUE))
	{
		printf("Failed to continue debug event.\n");
		return 1;
	}

	DEBUG_EVENT debug_event2;
	// Wait for the single step to complete
	while (WaitForDebugEvent(&debug_event2, INFINITE))
	{
		if (debug_event2.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
			debug_event2.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
		{
			// Rewrite the INT3 breakpoint
			if (!VirtualProtectEx(process, bp->address, 1, PAGE_EXECUTE_READWRITE, &old_protection))
			{
				printf("Failed to set memory protection.\n");
				return 1;
			}

			if (!WriteProcessMemory(process, bp->address, &int3, 1, NULL))
			{
				printf("Failed to rewrite breakpoint.\n");
				return 1;
			}

			if (!VirtualProtectEx(process, bp->address, 1, old_protection, &old_protection))
			{
				printf("Failed to set memory protection.\n");
				return 1;
			}

			CONTEXT context_inner;
			context_inner.ContextFlags = CONTEXT_CONTROL;
			if (!GetThreadContext(thread, &context_inner))
			{
				printf("Failed to get thread context_inner.\n");
				return 1;
			}

			// Clear the single step flag in the EFLAGS register
			context_inner.EFlags &= ~0x100;

			if (!SetThreadContext(thread, &context_inner))
			{
				printf("Failed to set thread context_inner.\n");
				return 1;
			}

			break;
		}
		else
		{
			//printf("Inner Got other ExceptionCode %u 0x%08X\n", debug_event2.dwDebugEventCode, debug_event2.u.Exception.ExceptionRecord.ExceptionCode);
			if (!ContinueDebugEvent(debug_event2.dwProcessId, debug_event2.dwThreadId, DBG_CONTINUE))
			{
				printf("Failed to continue debug event.\n");
				return 1;
			}
		}
	}

	return 0;
}

typedef struct StreamWatch {
	char buf[8192];
	size_t cur_idx;
	int last_was_one;
	size_t total_bytes;
} StreamWatch;

void push_bytes(StreamWatch *sw, const unsigned char *bytes, size_t len) {
	size_t i;

	if (len == 0)
		return;

	if (len > 1 && sw->last_was_one)
		sw->cur_idx += snprintf(&sw->buf[sw->cur_idx], 8192 - sw->cur_idx, "\n");

	for (i = 0; i < len; ++i)
		sw->cur_idx += snprintf(&sw->buf[sw->cur_idx], 8192 - sw->cur_idx, "%02X ", bytes[i]);

	if (len > 1) {
		sw->cur_idx += snprintf(&sw->buf[sw->cur_idx], 8192 - sw->cur_idx, "\n");
		sw->last_was_one = 0;
	} else {
		sw->last_was_one = 1;
	}

	sw->total_bytes += len;
}

void print_stream(StreamWatch *sw) {
	printf("(%zu)\n", sw->total_bytes);
	printf("%s\n", sw->buf);
	memset(sw, 0, sizeof(StreamWatch));
}

// TODO: magic signatures rather than hard offsets
#define GET_BYTES_OFFSET 0x162c6d2
#define DESERIALISE_OFFSET 0x1AE4710

#define WRITE_BYTES_OFFSET 0x162C700
#define SEND_PACKET_OFFSET 0x162C860

int main()
{
	DWORD pid = get_process_id_by_name("PathOfExile.exe");
	if (!pid)
	{
		printf("Failed to get PID %u\n", pid);
		return 1;
	}

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	DWORD lpcbNeeded;

	StreamWatch read_stream = { 0 };
	StreamWatch write_stream = { 0 };

	// Retrieve the process' base address
	MODULEINFO module_info;
	HMODULE module_handle;
	if (!EnumProcessModules(process, &module_handle, sizeof(module_handle), &lpcbNeeded))
	{
		printf("Failed to retrieve module handle. Error %u\n", GetLastError());
		return 1;
	}

	if (!GetModuleInformation(process, module_handle, &module_info, sizeof(module_info)))
	{
		printf("Failed to retrieve module information.\n");
		return 1;
	}

	printf("Process base address: %p\n", module_info.lpBaseOfDll);

	if (!DebugActiveProcess(pid))
	{
		printf("Failed to attach debugger to process %d.\n", pid);
		return 1;
	}

	printf("Debugger attached to process %d.\n", pid);

	Breakpoint bp_get_bytes = set_breakpoint(process, (LPVOID)((char*) module_info.lpBaseOfDll + GET_BYTES_OFFSET));
	Breakpoint bp_deserialize = set_breakpoint(process, (LPVOID)((char*) module_info.lpBaseOfDll + DESERIALISE_OFFSET));
	Breakpoint bp_write_bytes = set_breakpoint(process, (LPVOID)((char*) module_info.lpBaseOfDll + WRITE_BYTES_OFFSET));
	Breakpoint bp_send_packet = set_breakpoint(process, (LPVOID)((char*) module_info.lpBaseOfDll + SEND_PACKET_OFFSET));

	// Wait for breakpoint
	DEBUG_EVENT debug_event;
	DWORD continue_status = DBG_CONTINUE;
	while (continue_status == DBG_CONTINUE)
	{
		if (!WaitForDebugEvent(&debug_event, INFINITE))
		{
			printf("Failed to wait for debug event.\n");
			return 1;
		}

		switch (debug_event.dwDebugEventCode)
		{
			case EXCEPTION_DEBUG_EVENT:
				if (debug_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
				{
				 	//printf("Breakpoint hit at address %p\n", debug_event.u.Exception.ExceptionRecord.ExceptionAddress);
					if (debug_event.u.Exception.ExceptionRecord.ExceptionAddress == bp_get_bytes.address)
					{
						HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, debug_event.dwThreadId);
						if (!thread) {
							printf("Failed to open thread.\n");
							return 1;
						}

						CONTEXT context;
						context.ContextFlags = CONTEXT_INTEGER;
						if (!GetThreadContext(thread, &context)) {
							printf("Failed to get thread context.\n");
							return 1;
						}

						continue_status = DBG_CONTINUE;
						// Read bytes at the address contained in RDX, size R8
						BYTE buffer[32000];
						size_t bytes_read;
						if (!ReadProcessMemory(process, (LPCVOID) context.Rdx, buffer, context.R8, &bytes_read)) {
							printf("Failed to read memory.\n");
							return 1;
						}

						if (bytes_read != context.R8)
							printf("size mismatch %llu %llu\n", bytes_read, context.R8);

						push_bytes(&read_stream, buffer, bytes_read);
						reset_breakpoint(process, thread, &debug_event, &bp_get_bytes);
						CloseHandle(thread);
					}
					else if (debug_event.u.Exception.ExceptionRecord.ExceptionAddress == bp_write_bytes.address)
					{
						HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, debug_event.dwThreadId);
						if (!thread) {
							printf("Failed to open thread.\n");
							return 1;
						}

						CONTEXT context;
						context.ContextFlags = CONTEXT_INTEGER;
						if (!GetThreadContext(thread, &context)) {
							printf("Failed to get thread context.\n");
							return 1;
						}

						continue_status = DBG_CONTINUE;
						// Read bytes at the address contained in RDX, size R8
						BYTE buffer[32000];
						size_t bytes_read;
						if (!ReadProcessMemory(process, (LPCVOID) context.Rdx, buffer, context.R8, &bytes_read)) {
							printf("Failed to read memory.\n");
							return 1;
						}

						if (bytes_read != context.R8)
							printf("size mismatch %llu %llu\n", bytes_read, context.R8);

						push_bytes(&write_stream, buffer, bytes_read);
						reset_breakpoint(process, thread, &debug_event, &bp_write_bytes);
						CloseHandle(thread);
					}
					else if (debug_event.u.Exception.ExceptionRecord.ExceptionAddress == bp_deserialize.address)
					{
						if (read_stream.total_bytes > 0) {
							printf("Server -> Client ");
							print_stream(&read_stream);
							printf("\n");
						}

						HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, debug_event.dwThreadId);
						if (!thread) {
							printf("Failed to open thread.\n");
							return 1;
						}

						reset_breakpoint(process, thread, &debug_event, &bp_deserialize);
						CloseHandle(thread);
					}
					else if (debug_event.u.Exception.ExceptionRecord.ExceptionAddress == bp_send_packet.address)
					{
						if (write_stream.total_bytes > 0) {
							printf("Client -> Server ");
							print_stream(&write_stream);
							printf("\n");
						}

						HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, debug_event.dwThreadId);
						if (!thread) {
							printf("Failed to open thread.\n");
							return 1;
						}

						reset_breakpoint(process, thread, &debug_event, &bp_send_packet);
						CloseHandle(thread);
					}
				}
				else
				{
				 	//printf("Outer Got other ExceptionCode %u 0x%08X\n", debug_event.dwDebugEventCode, debug_event.u.Exception.ExceptionRecord.ExceptionCode);
					continue_status = DBG_EXCEPTION_NOT_HANDLED;
				}

				break;
			case CREATE_THREAD_DEBUG_EVENT:
				//printf("CREATE_THREAD_DEBUG_EVENT.\n");
				CloseHandle(debug_event.u.CreateThread.hThread);
				continue_status = DBG_CONTINUE;
				break;
			case CREATE_PROCESS_DEBUG_EVENT:
				//printf("CREATE_PROCESS_DEBUG_EVENT.\n");
				CloseHandle(debug_event.u.CreateProcessInfo.hFile);
				continue_status = DBG_CONTINUE;
				break;
			case EXIT_THREAD_DEBUG_EVENT:
				continue_status = DBG_CONTINUE;
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
				continue_status = DBG_CONTINUE;
				break;
			case LOAD_DLL_DEBUG_EVENT:
				//printf("LOAD_DLL_DEBUG_EVENT.\n");
				CloseHandle(debug_event.u.LoadDll.hFile);
				continue_status = DBG_CONTINUE;
				break;
			case UNLOAD_DLL_DEBUG_EVENT:
				printf("UNLOAD_DLL_DEBUG_EVENT.\n");
				continue_status = DBG_CONTINUE;
				break;
			case OUTPUT_DEBUG_STRING_EVENT:
				printf("OUTPUT_DEBUG_STRING_EVENT.\n");
				continue_status = DBG_CONTINUE;
				break;
			case RIP_EVENT:
				printf("RIP_EVENT.\n");
				continue_status = DBG_CONTINUE;
				break;
			default:
				printf("Unhandled event 0x%08X\n", debug_event.dwDebugEventCode);
				continue_status = DBG_EXCEPTION_NOT_HANDLED;
				break;
		}
		if (!ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status))
		{
			printf("Failed to continue debug event.\n");
			return 1;
		}
		continue_status = DBG_CONTINUE;
	}

	printf("Out of loop!\n");
	// Detach the debugger and clean up
	if (!DebugActiveProcessStop(pid))
	{
		printf("Failed to detach debugger from process %d.\n", pid);
		return 1;
	}

	CloseHandle(process);
	return 0;
}