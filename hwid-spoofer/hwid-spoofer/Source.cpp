/*
	Base By Sudo

	CreateThread Func Highly detected In Kernel Protected Games 
	All Windows Api Functions Are Spoof Returned so it doesn't return them out side the memory stack in the process
	
	use this for your cheat base 
	spoof return calls only work on x64 bit games not 32
	if you want to use this base for x32 remove spoof_call_ex();

*/

#include"sdk/sdk.hpp"

__declspec(dllexport) auto MainThread(HINSTANCE hInstance, LPVOID hBuffer) -> VOID {
	while (!pModuleApi->GetModuleName(NULL))
		std::this_thread::sleep_for(std::chrono::milliseconds(420));

	AllocConsole();
	FILE* file = {};
	freopen_s(&file, "CONOUT$", "w", stdout);

	std::cout << "[ - LOGS - ] -> Game Base: 0x" << std::hex << (uintptr_t)pModuleApi->GetModuleName(NULL) << "\n";
}

__declspec(dllexport) auto DllMain(HINSTANCE hInstance, DWORD hReasons, LPVOID hBuffer) -> BOOL {
	if (hReasons != DLL_PROCESS_ATTACH)
		return FALSE;

	HANDLE hThread = pThreadApi->MakeThread((LPTHREAD_START_ROUTINE)MainThread, 0, 0);
	if (hThread)
		pWinApi->ExitHandle(hThread);

	return TRUE;
}