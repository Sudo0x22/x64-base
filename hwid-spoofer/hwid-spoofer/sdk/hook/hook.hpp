#pragma once
#include<cstdint>
#include<cassert>
#include"minhook/include/MinHook.h"

// put x86 for 32 bit games and x64 for 64 bit games
static uint64_t* Table_x64 = nullptr;
static uint32_t* Table_x86 = nullptr;

class Hook {
public:
	__declspec(dllexport) auto CreateHook(uint16_t pIndex, void* pDet, void** pOriginal) -> BOOL {
		assert(index >= 0 && det != NULL && original != NULL);
		void* pTarget = (void*)Table_x64[pIndex];
		if (MH_CreateHook(pTarget, pDet, pOriginal) != MH_STATUS::MH_OK)
			return FALSE;
		if (MH_EnableHook(pTarget) != MH_STATUS::MH_OK)
			return FALSE;
		return TRUE;
	}
	__declspec(dllexport) auto RemoveHook(uint16_t pIndex) -> VOID {
		MH_DisableHook((void*)Table_x64[pIndex]);
		MH_RemoveHook((void*)Table_x64[pIndex]);
	}
};