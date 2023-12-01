#pragma once
#include<Windows.h>
#include<vector>
#include<string>
#include<memory>

#include<d3d12.h>
#include<d3d11.h>
#include<d3d10.h>
#include<d3d9.h>

#include<chrono>
#include<thread>
#include<iostream>

#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3d10.lib")
#pragma comment(lib, "d3d9.lib")

#include"spoofer/spoofer.hpp"
#pragma section(".text")
__declspec(allocate(".text")) unsigned const char JmpRbx[] = { 0xff, 0x23 };

typedef struct SysMem {
	DWORD64 dwEP;
	LPVOID dwParam;
}SysMem, * pSysMem;
typedef DWORD64(*InitMem)(void* Param);
__declspec(dllexport) void InitThread(pSysMem pMem) {
	if (pMem != NULL && pMem->dwEP != NULL) {
		InitMem CallMem = (InitMem)pMem->dwEP;
		CallMem(pMem->dwParam);
	}
}

class WinApi {
private:
	// put win api funcs here
public:
	__declspec(dllexport) auto CurrentProcess() -> HANDLE {
		auto ret_addr = spoof_call_ex(JmpRbx, GetCurrentProcess);
		return ret_addr;
	}
	__declspec(dllexport) auto ExitHandle(HANDLE Handle) -> BOOL {
		auto ret_addr = spoof_call_ex(JmpRbx, CloseHandle, Handle);
		return ret_addr;
	}
public:
	__declspec(dllexport) auto GetVirtualAlloc(LPVOID Inst, size_t Size, DWORD AllocType, DWORD Protect) -> LPVOID {
		auto ret_addr = spoof_call_ex(JmpRbx, VirtualAlloc, Inst, Size, AllocType, Protect);
		return ret_addr;
	}
	__declspec(dllexport) auto GetVirtualProtect(LPVOID Inst, size_t Size, DWORD OldProtect, PDWORD Protect) -> BOOL {
		auto ret_addr = spoof_call_ex(JmpRbx, VirtualProtect, Inst, Size, OldProtect, Protect);
		return ret_addr;
	}
public:
	__declspec(dllexport) auto GetMemcpy(void* ptr, const void* offset, size_t max) -> LPVOID {
		auto ret_addr = spoof_call_ex(JmpRbx, memcpy, ptr, offset, max);
		return ret_addr;
	}
}; WinApi* pWinApi = new WinApi();

class ModuleApi : public WinApi {
public:
	__declspec(dllexport) auto GetModuleName(LPCSTR module_name) -> HMODULE {
		auto ret_addr = spoof_call_ex(JmpRbx, GetModuleHandleA, module_name);
		return ret_addr;
	}
	__declspec(dllexport) auto GetModuleProcAddr(HMODULE module_name, LPCSTR module_proc) -> FARPROC {
		auto ret_addr = spoof_call_ex(JmpRbx, GetProcAddress, module_name, module_proc);
		return ret_addr;
	}
public:
	__declspec(dllexport) auto GetModuleSize(DWORD64 module_image) -> DWORD64 {
		this->dos_header = *(IMAGE_DOS_HEADER*)module_image;
		this->nt_headers = *(IMAGE_NT_HEADERS*)(module_image + this->dos_header.e_lfanew);
		return (DWORD64)this->nt_headers.OptionalHeader.SizeOfImage;
	}
	__declspec(dllexport) auto GetModuleBytes(HMODULE module_image, DWORD64 module_size, DWORD64 max_size) -> PBYTE {
		return (PBYTE)module_image + module_size - max_size;
	}
private:
	IMAGE_DOS_HEADER dos_header = {};
	IMAGE_NT_HEADERS nt_headers = {};
}; ModuleApi* pModuleApi = new ModuleApi();

class ThreadApi : public ModuleApi {
private:
	__declspec(dllexport) auto MakeRemoteThread(HANDLE Handle, LPSECURITY_ATTRIBUTES Attr, size_t Size, 
		LPTHREAD_START_ROUTINE StartRoutine, LPVOID lpVoid, DWORD Flags, LPDWORD ThreadId) -> HANDLE {
		auto ret_addr = spoof_call_ex(JmpRbx, CreateRemoteThread, Handle, Attr, Size, StartRoutine, lpVoid, Flags, ThreadId);
		return ret_addr;
	}
public:
	__declspec(dllexport) auto MakeThread(LPTHREAD_START_ROUTINE StartRoutine, LPVOID lpVoid, LPDWORD ThreadId) {
		this->hModule = this->GetModuleName("ntdll.dll");
		this->hModuleSize = this->GetModuleSize((DWORD64)this->hModule);
		this->hModuleBytes = this->GetModuleBytes(this->hModule, this->hModuleSize, 0x400);

		this->GetVirtualProtect(this->hModuleBytes, 0x100, PAGE_EXECUTE_READWRITE, &this->hProtect);
		pSysMem pMem = (pSysMem)this->GetVirtualAlloc(NULL, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		pMem->dwEP = (DWORD64)(StartRoutine);
		pMem->dwParam = lpVoid;

		this->GetMemcpy((LPVOID)this->hModuleBytes, (LPVOID)InitThread, 0x100);
		this->hRemoteThread = this->MakeRemoteThread(this->CurrentProcess(), NULL, 0x100, (LPTHREAD_START_ROUTINE)this->hModuleBytes, pMem, 0, ThreadId);
		this->ExitHandle(this->hRemoteThread);

		return nullptr;
	}
private:
	HMODULE hModule = 0;
	DWORD64 hModuleSize = 0;
	PBYTE hModuleBytes = nullptr;
	HANDLE hRemoteThread = 0;
	DWORD hProtect = 0;
}; ThreadApi* pThreadApi = new ThreadApi();